import abc
import json
import subprocess
import shlex
from pathlib import Path
from typing import List, Iterator
import sys
import logging

from impact_scan.utils import schema

# Set up logging
logger = logging.getLogger(__name__)


class DependencyAuditor(abc.ABC):
    """Abstract base class for dependency vulnerability scanners."""

    @abc.abstractmethod
    def audit(self, root_path: Path) -> Iterator[schema.Finding]:
        """
        Audits dependencies for a specific ecosystem.

        Args:
            root_path: The root directory of the project to audit.

        Yields:
            An iterator of Finding objects for each vulnerability discovered.
        """
        raise NotImplementedError


def _run_osv_scanner(file_path: Path) -> str:
    """Helper to run osv-scanner on a given file and return JSON output."""
    try:
        # Validate and sanitize file path
        if not file_path.exists() or not file_path.is_file():
            logger.warning(f"File path does not exist or is not a file: {file_path}")
            return ""
        
        # Resolve path to prevent directory traversal
        file_path = file_path.resolve()
        
        # Use list format for command to prevent shell injection
        cmd = ["osv-scanner", "--format", "json", str(file_path)]
        
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            shell=False,  # Explicitly disable shell to prevent injection
            cwd=file_path.parent,
            timeout=60  # Add timeout to prevent hanging
        )

        logger.debug(f"OSV-Scanner output for {file_path}:")
        logger.debug(f"STDOUT: {proc.stdout}")
        logger.debug(f"STDERR: {proc.stderr}")

        return proc.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"OSV-scanner timed out for {file_path}")
        return ""
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning(f"osv-scanner failed for {file_path}. Error: {e}")
        return ""


def _parse_osv_output(json_output: str, source_file: Path) -> Iterator[schema.Finding]:
    """
    Parses the JSON output from osv-scanner, grouping vulnerabilities by package.
    """
    try:
        data = json.loads(json_output)
        if not data.get("results"):
            return

        # Group vulnerabilities by the package they affect
        grouped_vulns = {}
        for result in data.get("results", []):
            for pkg_info in result.get("packages", []):
                package = pkg_info.get("package", {})
                pkg_id = (package.get("name"), package.get("version"))
                if pkg_id not in grouped_vulns:
                    grouped_vulns[pkg_id] = {
                        "package": package,
                        "vulns": [],
                    }
                grouped_vulns[pkg_id]["vulns"].extend(pkg_info.get("vulnerabilities", []))

        # Create a single finding for each package
        for (name, version), data in grouped_vulns.items():
            if data["vulns"]:
                yield _create_finding_from_grouped_vulns(data["package"], data["vulns"], source_file)

    except json.JSONDecodeError:
        logger.warning("osv-scanner output was not valid JSON")
        return


def _create_finding_from_grouped_vulns(
    package: dict, vulns: List[dict], source_file: Path
) -> schema.Finding:
    """Creates a single Finding object from a list of grouped vulnerabilities."""
    # Combine summaries and get the highest severity
    all_summaries = [v.get("summary", "No summary available.") for v in vulns]
    description = "\n".join(f"- {s}" for s in all_summaries)
    
    highest_severity = schema.Severity.LOW
    all_aliases = []
    all_ids = []

    for v in vulns:
        severity = _map_osv_severity(v.get("severity", []))
        if severity.value > highest_severity.value:
            highest_severity = severity
        all_aliases.extend(v.get("aliases", []))
        all_ids.append(v.get("id", "UNKNOWN_OSV_ID"))

    # Create a single, comprehensive finding
    # Limit IDs to fit within 200 character constraint
    vuln_ids_str = ", ".join(all_ids)
    if len(vuln_ids_str) > 190:  # Leave some buffer
        vuln_ids_str = vuln_ids_str[:190] + "..."

    rule_ids_str = ", ".join(all_ids)
    if len(rule_ids_str) > 190:  # Leave some buffer
        rule_ids_str = rule_ids_str[:190] + "..."

    return schema.Finding(
        file_path=source_file,
        line_number=1,
        vuln_id=vuln_ids_str,
        rule_id=rule_ids_str,
        title=f"Vulnerable Dependency: {package.get('name')}@{package.get('version')}",
        severity=highest_severity,
        source=schema.VulnSource.DEPENDENCY,
        code_snippet=f"{package.get('name')}=={package.get('version')}",
        description=description,
        metadata={"aliases": all_aliases, "all_vuln_ids": all_ids},
    )


def _map_osv_severity(severities: List[dict]) -> schema.Severity:
    """Maps OSV severity levels to our internal Severity enum."""
    if not severities:
        return schema.Severity.LOW

    # Find the highest CVSS V3 score if available, otherwise default
    max_severity = schema.Severity.LOW
    for sev in severities:
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score")
            try:
                # Extract numerical score (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
                # A simple heuristic for mapping scores to high/critical
                if score_str and "CVSS:3." in score_str:
                    # Very basic parsing, would typically use a dedicated CVSS parser
                    # This maps common CVSS score ranges to our enum
                    if "A:H" in score_str or "I:H" in score_str or "C:H" in score_str:
                        max_severity = max(max_severity, schema.Severity.CRITICAL, key=lambda x: schema.Severity.__members__[x.name].value)
                    elif "A:L" in score_str or "I:L" in score_str or "C:L" in score_str:
                        max_severity = max(max_severity, schema.Severity.MEDIUM, key=lambda x: schema.Severity.__members__[x.name].value)
            except Exception:
                pass # Continue if score parsing fails
        
        # Also check for direct string severities like "CRITICAL", "HIGH"
        if "CRITICAL" in sev.get("score", "").upper() or "CRITICAL" in sev.get("type", "").upper():
            max_severity = max(max_severity, schema.Severity.CRITICAL, key=lambda x: schema.Severity.__members__[x.name].value)
        elif "HIGH" in sev.get("score", "").upper() or "HIGH" in sev.get("type", "").upper():
            max_severity = max(max_severity, schema.Severity.HIGH, key=lambda x: schema.Severity.__members__[x.name].value)
        elif "MEDIUM" in sev.get("score", "").upper() or "MEDIUM" in sev.get("type", "").upper():
            max_severity = max(max_severity, schema.Severity.MEDIUM, key=lambda x: schema.Severity.__members__[x.name].value)

    return max_severity


class PythonPoetryAuditor(DependencyAuditor):
    """Audits Python dependencies using 'poetry' and 'osv-scanner'."""

    def audit(self, root_path: Path) -> Iterator[schema.Finding]:
        lock_file = root_path / "poetry.lock"
        if not lock_file.is_file():
            return

        # Create secure temporary file name
        requirements_path = root_path / ".impact-scan.poetry-reqs.txt"
        
        try:
            # Validate root_path to prevent directory traversal
            root_path = root_path.resolve()
            requirements_path = requirements_path.resolve()
            
            # Ensure output path is within the root directory
            if not str(requirements_path).startswith(str(root_path)):
                logger.error(f"Output path {requirements_path} is outside root directory {root_path}")
                return
            
            # Build secure command list
            cmd = [
                sys.executable, "-m", "poetry", "export", 
                "-f", "requirements.txt", 
                "--output", str(requirements_path), 
                "--without-hashes"
            ]
            
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                shell=False,  # Disable shell to prevent injection
                cwd=root_path,
                timeout=120  # Add timeout for poetry export
            )

            # Now run osv-scanner on the generated file
            json_output = _run_osv_scanner(requirements_path)
            if json_output:
                yield from _parse_osv_output(json_output, lock_file)

        except subprocess.TimeoutExpired:
            logger.error(f"Poetry export timed out for {lock_file}")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"Poetry export failed for {lock_file}. Is poetry installed and in PATH? Error: {e}")
        finally:
            # Clean up the temporary requirements file
            if requirements_path.exists():
                requirements_path.unlink()


class PythonRequirementsAuditor(DependencyAuditor):
    """Audits Python dependencies from a 'requirements.txt' file using 'osv-scanner'."""

    def audit(self, root_path: Path) -> Iterator[schema.Finding]:
        req_file = root_path / "requirements.txt"
        if not req_file.is_file():
            return

        json_output = _run_osv_scanner(req_file)
        if json_output:
            yield from _parse_osv_output(json_output, req_file)


class NodePnpmAuditor(DependencyAuditor):
    """Audits Node.js dependencies using 'pnpm audit'."""

    def audit(self, root_path: Path) -> Iterator[schema.Finding]:
        if not (root_path / "pnpm-lock.yaml").is_file():
            return

        try:
            # Validate and resolve root path
            root_path = root_path.resolve()
            
            cmd = ["pnpm", "audit", "--json"]
            proc = subprocess.run(
                cmd,
                check=False, 
                capture_output=True, 
                text=True, 
                shell=False,  # Disable shell to prevent injection
                cwd=root_path,
                timeout=60  # Add timeout
            )
            if proc.stdout:
                yield from self._parse_pnpm_output(proc.stdout, root_path / "package.json")
        except subprocess.TimeoutExpired:
            logger.error("pnpm audit timed out")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"pnpm audit failed. Error: {e}")

    def _parse_pnpm_output(self, json_output: str, source_file: Path) -> Iterator[schema.Finding]:
        """Parses the JSON output from pnpm into Finding objects."""
        try:
            data = json.loads(json_output)
            for key, advisory in data.get("advisories", {}).items():
                yield schema.Finding(
                    file_path=source_file,
                    line_number=1,
                    vuln_id=advisory.get("cve") or f"GHSA-{advisory.get('github_advisory_id', 'UNKNOWN')}",
                    title=f"Vulnerable Dependency: {advisory.get('module_name', 'Unknown Module')}",
                    severity=schema.Severity(advisory.get("severity", "low")),
                    source=schema.VulnSource.DEPENDENCY,
                    code_snippet=f"{advisory.get('module_name', 'Unknown Module')}@{advisory.get('vulnerable_versions', 'Unknown Version')}",
                    description=advisory.get("overview", "No overview available."),
                    metadata={"via": [v["name"] for v in advisory.get("via", []) if isinstance(v, dict) and "name" in v]}
                )
        except json.JSONDecodeError:
            logger.warning("pnpm audit output was not valid JSON")
            return


def audit_dependencies(root_path: Path) -> List[schema.Finding]:
    """
    Runs all applicable dependency auditors on the given codebase.

    Args:
        root_path: The root directory of the codebase.

    Returns:
        A list of all dependency-related findings.
    """
    auditors: List[DependencyAuditor] = [
        PythonPoetryAuditor(),
        PythonRequirementsAuditor(), # <-- NEW AUDITOR ADDED
        NodePnpmAuditor(),
    ]

    all_findings: List[schema.Finding] = []
    for auditor in auditors:
        all_findings.extend(auditor.audit(root_path))
    return all_findings


def run_scan(scan_config: schema.ScanConfig) -> List[schema.Finding]:
    """
    Runs the dependency audit scan.
    """
    logger.info("Starting dependency audit scan...")
    findings = audit_dependencies(scan_config.root_path)
    logger.info(f"Found {len(findings)} dependency issues")
    return findings
