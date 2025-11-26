import abc
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Iterator, List

from ..utils import schema

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
            timeout=60,  # Add timeout to prevent hanging
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
                grouped_vulns[pkg_id]["vulns"].extend(
                    pkg_info.get("vulnerabilities", [])
                )

        # Create a single finding for each package
        for (name, version), data in grouped_vulns.items():
            if data["vulns"]:
                yield _create_finding_from_grouped_vulns(
                    data["package"], data["vulns"], source_file
                )

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
                        max_severity = max(
                            max_severity,
                            schema.Severity.CRITICAL,
                            key=lambda x: schema.Severity.__members__[x.name].value,
                        )
                    elif "A:L" in score_str or "I:L" in score_str or "C:L" in score_str:
                        max_severity = max(
                            max_severity,
                            schema.Severity.MEDIUM,
                            key=lambda x: schema.Severity.__members__[x.name].value,
                        )
            except Exception:
                pass  # Continue if score parsing fails

        # Also check for direct string severities like "CRITICAL", "HIGH"
        if (
            "CRITICAL" in sev.get("score", "").upper()
            or "CRITICAL" in sev.get("type", "").upper()
        ):
            max_severity = max(
                max_severity,
                schema.Severity.CRITICAL,
                key=lambda x: schema.Severity.__members__[x.name].value,
            )
        elif (
            "HIGH" in sev.get("score", "").upper()
            or "HIGH" in sev.get("type", "").upper()
        ):
            max_severity = max(
                max_severity,
                schema.Severity.HIGH,
                key=lambda x: schema.Severity.__members__[x.name].value,
            )
        elif (
            "MEDIUM" in sev.get("score", "").upper()
            or "MEDIUM" in sev.get("type", "").upper()
        ):
            max_severity = max(
                max_severity,
                schema.Severity.MEDIUM,
                key=lambda x: schema.Severity.__members__[x.name].value,
            )

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
                logger.error(
                    f"Output path {requirements_path} is outside root directory {root_path}"
                )
                return

            # Build secure command list
            cmd = [
                sys.executable,
                "-m",
                "poetry",
                "export",
                "-f",
                "requirements.txt",
                "--output",
                str(requirements_path),
                "--without-hashes",
            ]

            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                shell=False,  # Disable shell to prevent injection
                cwd=root_path,
                timeout=120,  # Add timeout for poetry export
            )

            # Now run osv-scanner on the generated file
            json_output = _run_osv_scanner(requirements_path)
            if json_output:
                yield from _parse_osv_output(json_output, lock_file)

        except subprocess.TimeoutExpired:
            logger.error(f"Poetry export timed out for {lock_file}")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(
                f"Poetry export failed for {lock_file}. Is poetry installed and in PATH? Error: {e}"
            )
        finally:
            # Clean up the temporary requirements file
            if requirements_path.exists():
                requirements_path.unlink()


class PythonRequirementsAuditor(DependencyAuditor):
    """Audits Python dependencies from a 'requirements.txt' file using pip-audit or safety."""

    def audit(self, root_path: Path) -> Iterator[schema.Finding]:
        req_file = root_path / "requirements.txt"
        if not req_file.is_file():
            return

        # Try pip-audit first (better OSV integration)
        findings = list(self._try_pip_audit(req_file))
        if findings:
            yield from findings
            # Don't return - also check for outdated packages below

        # Fallback to osv-scanner if installed (only if no findings yet)
        if not findings:
            json_output = _run_osv_scanner(req_file)
            if json_output:
                findings = list(_parse_osv_output(json_output, req_file))
                yield from findings

        # Fallback to safety (only if no findings yet)
        if not findings:
            findings = list(self._try_safety(req_file))
            yield from findings

        # Check for outdated packages (informational)
        try:
            outdated_findings = list(self._check_outdated_packages(req_file))
            if outdated_findings:
                logger.info(f"Found {len(outdated_findings)} outdated packages")
                yield from outdated_findings
        except Exception as e:
            logger.debug(f"Outdated package check failed: {e}")

    def _try_pip_audit(self, req_file: Path) -> Iterator[schema.Finding]:
        """Try to use pip-audit for vulnerability scanning."""
        try:
            cmd = [
                "pip-audit",
                "--requirement",
                str(req_file),
                "--format",
                "json",
                "--progress-spinner",
                "off",
            ]

            logger.info(f"Running pip-audit on {req_file}")

            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                timeout=120,
            )

            logger.debug(f"pip-audit return code: {proc.returncode}")
            logger.debug(f"pip-audit stdout length: {len(proc.stdout)}")

            if proc.stdout:
                # Parse pip-audit JSON output
                try:
                    data = json.loads(proc.stdout)
                    logger.info(
                        f"pip-audit found {len(data.get('dependencies', []))} dependencies"
                    )

                    count = 0
                    for vuln in data.get("dependencies", []):
                        package_name = vuln.get("name")
                        package_version = vuln.get("version")
                        vulns_list = vuln.get("vulns", [])

                        if not vulns_list:
                            continue

                        for issue in vulns_list:
                            count += 1
                            # Map CVSS score to severity
                            severity = (
                                schema.Severity.HIGH
                            )  # Default to HIGH for vulnerabilities

                            # Get fix versions and latest version
                            fix_versions_list = issue.get("fix_versions", [])
                            if fix_versions_list:
                                latest_safe = fix_versions_list[
                                    -1
                                ]  # Last version is usually newest
                                fix_text = f"Upgrade to {latest_safe} (safe versions: {', '.join(fix_versions_list)})"
                            else:
                                latest_safe = "No fix available"
                                fix_text = (
                                    "No fix available - consider alternative packages"
                                )

                            # Enhanced description with upgrade path
                            description = issue.get("description", "No description")[
                                :400
                            ]
                            description += f"\n\n📦 Current version: {package_name}@{package_version}\n✅ Recommended: {latest_safe}"

                            yield schema.Finding(
                                file_path=req_file,
                                line_number=1,
                                vuln_id=issue.get("id", "UNKNOWN"),
                                rule_id=f"pip-audit:{issue.get('id', 'UNKNOWN')}",
                                title=f"Vulnerable Dependency: {package_name}@{package_version} → Update to {latest_safe}",
                                severity=severity,
                                source=schema.VulnSource.DEPENDENCY,
                                code_snippet=f"{package_name}=={package_version}",
                                description=description,
                                fix_suggestion=fix_text,
                                metadata={
                                    "current_version": package_version,
                                    "safe_versions": fix_versions_list,
                                    "latest_safe_version": latest_safe,
                                    "cve_id": issue.get("id"),
                                    "aliases": issue.get("aliases", []),
                                },
                            )

                    logger.info(f"pip-audit generated {count} findings")

                except json.JSONDecodeError as e:
                    logger.warning(f"pip-audit output was not valid JSON: {e}")
                    logger.debug(f"Output was: {proc.stdout[:500]}")
            else:
                logger.debug("pip-audit produced no output")

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"pip-audit not available or failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in pip-audit: {e}", exc_info=True)

    def _try_safety(self, req_file: Path) -> Iterator[schema.Finding]:
        """Try to use safety for vulnerability scanning."""
        try:
            cmd = [
                "safety",
                "scan",  # Use new scan command instead of deprecated check
                "--target",
                str(req_file),
                "--output",
                "json",
            ]

            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                timeout=120,
            )

            if proc.returncode == 0 or proc.stdout:
                # Parse safety JSON output
                try:
                    data = json.loads(proc.stdout)
                    # Safety scan output format
                    for vuln in data.get("vulnerabilities", []):
                        package_name = vuln.get("package_name")
                        package_version = vuln.get("analyzed_version")

                        yield schema.Finding(
                            file_path=req_file,
                            line_number=1,
                            vuln_id=vuln.get("vulnerability_id", "UNKNOWN"),
                            rule_id=f"safety:{vuln.get('vulnerability_id', 'UNKNOWN')}",
                            title=f"Vulnerable Dependency: {package_name}@{package_version}",
                            severity=self._map_safety_severity(vuln.get("severity")),
                            source=schema.VulnSource.DEPENDENCY,
                            code_snippet=f"{package_name}=={package_version}",
                            description=vuln.get("advisory", "No description"),
                            fix_suggestion=f"Upgrade to: {vuln.get('fixed_version', 'unknown')}",
                        )
                except json.JSONDecodeError:
                    logger.debug("safety output was not valid JSON")
                    pass

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"safety not available or failed: {e}")
            pass

    def _map_safety_severity(self, severity: str) -> schema.Severity:
        """Map safety severity string to Severity enum."""
        if not severity:
            return schema.Severity.MEDIUM

        severity_upper = severity.upper()
        if "CRITICAL" in severity_upper:
            return schema.Severity.CRITICAL
        elif "HIGH" in severity_upper:
            return schema.Severity.HIGH
        elif "MEDIUM" in severity_upper:
            return schema.Severity.MEDIUM
        else:
            return schema.Severity.LOW

    def _check_outdated_packages(self, req_file: Path) -> Iterator[schema.Finding]:
        """
        Check for outdated packages and suggest upgrades.

        Uses pip list --outdated to find packages that have newer versions available.
        """
        try:
            # Parse requirements file to get installed packages
            with open(req_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            packages_to_check = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse package==version format
                if "==" in line:
                    package_name = line.split("==")[0].strip()
                    current_version = line.split("==")[1].split("#")[0].strip()
                    packages_to_check.append((package_name, current_version))

            if not packages_to_check:
                return

            logger.info(f"Checking {len(packages_to_check)} packages for updates...")

            # Check each package for latest version using pip index
            for package_name, current_version in packages_to_check:
                try:
                    # Use pip index versions to get latest version
                    cmd = ["pip", "index", "versions", package_name]
                    proc = subprocess.run(
                        cmd,
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,
                        timeout=10,
                    )

                    if proc.returncode == 0 and proc.stdout:
                        # Parse output to find available versions
                        # Format: "package-name (X.Y.Z)"
                        lines = proc.stdout.split("\n")
                        latest_version = None

                        for line in lines:
                            if "Available versions:" in line or "LATEST:" in line:
                                continue
                            # Extract version numbers
                            if package_name.lower() in line.lower():
                                # Try to extract version from parentheses
                                import re

                                match = re.search(r"\(([0-9.]+)\)", line)
                                if match:
                                    latest_version = match.group(1)
                                    break
                            # Also check for version list format
                            elif line.strip() and line.strip()[0].isdigit():
                                latest_version = line.strip().split(",")[0].strip()
                                break

                        if latest_version and latest_version != current_version:
                            # Compare versions to see if update is needed
                            from packaging import version

                            try:
                                if version.parse(latest_version) > version.parse(
                                    current_version
                                ):
                                    yield schema.Finding(
                                        file_path=req_file,
                                        line_number=1,
                                        vuln_id=f"outdated-{package_name}",
                                        rule_id=f"dependency:outdated:{package_name}",
                                        title=f"Outdated Package: {package_name}@{current_version} → Update to {latest_version}",
                                        severity=schema.Severity.LOW,  # Informational
                                        source=schema.VulnSource.DEPENDENCY,
                                        code_snippet=f"{package_name}=={current_version}",
                                        description=f"Package {package_name} has a newer version available.\n\n📦 Current: {current_version}\n✨ Latest: {latest_version}\n\nUpdate command: pip install {package_name}=={latest_version}",
                                        fix_suggestion=f"Update to latest version: {latest_version}",
                                        metadata={
                                            "current_version": current_version,
                                            "latest_version": latest_version,
                                            "package_name": package_name,
                                            "update_available": True,
                                        },
                                    )
                            except Exception as e:
                                logger.debug(
                                    f"Version comparison failed for {package_name}: {e}"
                                )

                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    logger.debug(f"Failed to check {package_name}: {e}")
                    continue

        except Exception as e:
            logger.debug(f"Outdated package check error: {e}")


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
                timeout=60,  # Add timeout
            )
            if proc.stdout:
                yield from self._parse_pnpm_output(
                    proc.stdout, root_path / "package.json"
                )
        except subprocess.TimeoutExpired:
            logger.error("pnpm audit timed out")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"pnpm audit failed. Error: {e}")

    def _parse_pnpm_output(
        self, json_output: str, source_file: Path
    ) -> Iterator[schema.Finding]:
        """Parses the JSON output from pnpm into Finding objects."""
        try:
            data = json.loads(json_output)
            for key, advisory in data.get("advisories", {}).items():
                yield schema.Finding(
                    file_path=source_file,
                    line_number=1,
                    vuln_id=advisory.get("cve")
                    or f"GHSA-{advisory.get('github_advisory_id', 'UNKNOWN')}",
                    title=f"Vulnerable Dependency: {advisory.get('module_name', 'Unknown Module')}",
                    severity=schema.Severity(advisory.get("severity", "low")),
                    source=schema.VulnSource.DEPENDENCY,
                    code_snippet=f"{advisory.get('module_name', 'Unknown Module')}@{advisory.get('vulnerable_versions', 'Unknown Version')}",
                    description=advisory.get("overview", "No overview available."),
                    metadata={
                        "via": [
                            v["name"]
                            for v in advisory.get("via", [])
                            if isinstance(v, dict) and "name" in v
                        ]
                    },
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
        PythonRequirementsAuditor(),  # <-- NEW AUDITOR ADDED
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
