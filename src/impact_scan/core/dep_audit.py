import abc
import json
import subprocess
from pathlib import Path
from typing import List, Iterator
import sys

from impact_scan.utils import schema


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
        proc = subprocess.run(
            ["osv-scanner", "--format", "json", str(file_path)],
            check=False,
            capture_output=True,
            text=True,
            cwd=file_path.parent
        )

        # --- START DEBUG PRINTS ---
        print(f"\n--- OSV-Scanner STDOUT for {file_path} ---")
        print(proc.stdout)
        print(f"--- End OSV-Scanner STDOUT for {file_path} ---\n")

        print(f"\n--- OSV-Scanner STDERR for {file_path} ---")
        print(proc.stderr)
        print(f"--- End OSV-Scanner STDERR for {file_path} ---\n")
        # --- END DEBUG PRINTS ---

        return proc.stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Warning: osv-scanner failed for {file_path}. Error: {e}")
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
        print("Warning: osv-scanner output was not valid JSON.")
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
    return schema.Finding(
        file_path=source_file,
        line_number=1,
        vuln_id=", ".join(all_ids),
        rule_id=", ".join(all_ids),
        title=f"Vulnerable Dependency: {package.get('name')}@{package.get('version')}",
        severity=highest_severity,
        source=schema.VulnSource.DEPENDENCY,
        code_snippet=f"{package.get('name')}=={package.get('version')}",
        description=description,
        metadata={"aliases": all_aliases},
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

        requirements_path = root_path / ".impact-scan.poetry-reqs.txt"
        try:
            # This command generates a requirements.txt from poetry.lock
            # We use sys.executable to ensure we're using the poetry from the correct venv
            subprocess.run(
                [sys.executable, "-m", "poetry", "export", "-f", "requirements.txt", "--output", str(requirements_path), "--without-hashes"],
                check=True,
                capture_output=True,
                text=True,
                cwd=root_path
            )

            # Now run osv-scanner on the generated file
            json_output = _run_osv_scanner(requirements_path)
            if json_output:
                yield from _parse_osv_output(json_output, lock_file)

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Warning: 'poetry export' failed for {lock_file}. Is poetry installed and in your PATH? Error: {e}")
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
            proc = subprocess.run(
                ["pnpm", "audit", "--json"],
                check=False, capture_output=True, text=True, cwd=root_path
            )
            if proc.stdout:
                yield from self._parse_pnpm_output(proc.stdout, root_path / "package.json")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Warning: pnpm audit failed. Error: {e}")

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
            print("Warning: pnpm audit output was not valid JSON.")
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
    print("Starting dependency audit scan...")
    findings = audit_dependencies(scan_config.root_path)
    print(f"Found {len(findings)} dependency issues.")
    return findings
