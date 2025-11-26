"""
JavaScript/Node.js ecosystem dependency scanner
Supports: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
Uses: npm audit, yarn audit, pnpm audit, osv-scanner
"""

import asyncio
import json
from pathlib import Path
from typing import List, Optional

from rich.console import Console

from impact_scan.core.unified_dependency_scanner import (
    EcosystemScanner,
    RawVulnerability,
)
from impact_scan.utils import schema

console = Console()


class JavaScriptScanner(EcosystemScanner):
    """Scanner for JavaScript/Node.js dependencies"""

    def __init__(self):
        super().__init__("javascript")

    async def detect_manifest_files(self, root_path: Path) -> List[Path]:
        """Find JavaScript/Node.js dependency manifest files"""
        manifests = []

        # Look for package.json files
        package_jsons = list(root_path.rglob("package.json"))

        # Filter out node_modules directories
        package_jsons = [p for p in package_jsons if "node_modules" not in p.parts]

        manifests.extend(package_jsons)

        return list(set(manifests))

    async def scan_manifest(self, manifest_path: Path) -> List[RawVulnerability]:
        """
        Scan Node.js manifest for vulnerabilities.
        Tries npm audit, yarn audit, pnpm audit, and OSV in order.
        """
        project_dir = manifest_path.parent

        # Detect which package manager is used
        has_package_lock = (project_dir / "package-lock.json").exists()
        has_yarn_lock = (project_dir / "yarn.lock").exists()
        has_pnpm_lock = (project_dir / "pnpm-lock.yaml").exists()

        vulnerabilities = []

        # Try appropriate package manager audit
        if has_pnpm_lock:
            try:
                vulns = await self._scan_with_pnpm(project_dir)
                vulnerabilities.extend(vulns)
                return vulnerabilities
            except Exception as e:
                console.log(f"[yellow]pnpm audit failed: {e}[/yellow]")

        if has_yarn_lock:
            try:
                vulns = await self._scan_with_yarn(project_dir)
                vulnerabilities.extend(vulns)
                return vulnerabilities
            except Exception as e:
                console.log(f"[yellow]yarn audit failed: {e}[/yellow]")

        if has_package_lock:
            try:
                vulns = await self._scan_with_npm(project_dir)
                vulnerabilities.extend(vulns)
                return vulnerabilities
            except Exception as e:
                console.log(f"[yellow]npm audit failed: {e}[/yellow]")

        # Fallback to OSV-scanner
        try:
            vulns = await self._scan_with_osv(manifest_path)
            vulnerabilities.extend(vulns)
        except Exception as e:
            console.log(f"[yellow]OSV-scanner failed: {e}[/yellow]")

        return vulnerabilities

    async def _scan_with_npm(self, project_dir: Path) -> List[RawVulnerability]:
        """Scan using npm audit"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "npm",
                "audit",
                "--json",
                cwd=str(project_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()

            # npm audit returns non-zero if vulnerabilities found
            if proc.returncode > 1:
                raise Exception(f"npm audit error: {stderr.decode()}")

            data = json.loads(stdout.decode())
            return self._parse_npm_audit_output(data)

        except FileNotFoundError:
            raise Exception("npm not installed")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse npm audit output: {e}")

    async def _scan_with_yarn(self, project_dir: Path) -> List[RawVulnerability]:
        """Scan using yarn audit"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "yarn",
                "audit",
                "--json",
                cwd=str(project_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()

            # Parse line-delimited JSON
            vulnerabilities = []
            for line in stdout.decode().splitlines():
                try:
                    data = json.loads(line)
                    if data.get("type") == "auditAdvisory":
                        advisory = data.get("data", {}).get("advisory", {})
                        vuln = self._parse_yarn_advisory(advisory)
                        if vuln:
                            vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    continue

            return vulnerabilities

        except FileNotFoundError:
            raise Exception("yarn not installed")

    async def _scan_with_pnpm(self, project_dir: Path) -> List[RawVulnerability]:
        """Scan using pnpm audit"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "pnpm",
                "audit",
                "--json",
                cwd=str(project_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()

            # pnpm audit returns non-zero if vulnerabilities found
            if proc.returncode > 1:
                raise Exception(f"pnpm audit error: {stderr.decode()}")

            data = json.loads(stdout.decode())
            return self._parse_pnpm_audit_output(data)

        except FileNotFoundError:
            raise Exception("pnpm not installed")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse pnpm audit output: {e}")

    async def _scan_with_osv(self, manifest_path: Path) -> List[RawVulnerability]:
        """Scan using OSV-scanner CLI"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "osv-scanner",
                "--format=json",
                "--lockfile",
                str(manifest_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()

            if proc.returncode not in [0, 1]:
                raise Exception(f"OSV-scanner error: {stderr.decode()}")

            data = json.loads(stdout.decode())
            return self._parse_osv_output(data)

        except FileNotFoundError:
            raise Exception("osv-scanner not installed")

    def _parse_npm_audit_output(self, data: dict) -> List[RawVulnerability]:
        """Parse npm audit JSON output"""
        vulnerabilities = []

        # npm audit v7+ format
        advisories = data.get("vulnerabilities", {})

        for pkg_name, vuln_data in advisories.items():
            for via in vuln_data.get("via", []):
                if isinstance(via, dict):
                    vulnerabilities.append(
                        RawVulnerability(
                            package_name=pkg_name,
                            package_version=vuln_data.get("range", "*"),
                            vuln_id=str(via.get("source", "npm-advisory")),
                            severity=via.get("severity", "moderate").upper(),
                            description=via.get("title", "No description"),
                            affected_versions=[vuln_data.get("range", "*")],
                            patched_versions=[
                                vuln_data.get("fixAvailable", {}).get(
                                    "version", "unknown"
                                )
                            ],
                            source="npm",
                            raw_data=via,
                        )
                    )

        return vulnerabilities

    def _parse_yarn_advisory(self, advisory: dict) -> Optional[RawVulnerability]:
        """Parse yarn audit advisory"""
        if not advisory:
            return None

        return RawVulnerability(
            package_name=advisory.get("module_name", "unknown"),
            package_version=advisory.get("findings", [{}])[0].get("version", "unknown"),
            vuln_id=str(advisory.get("id", "yarn-advisory")),
            severity=advisory.get("severity", "moderate").upper(),
            description=advisory.get("title", "No description"),
            affected_versions=[advisory.get("vulnerable_versions", "*")],
            patched_versions=[advisory.get("patched_versions", "unknown")],
            source="yarn",
            raw_data=advisory,
        )

    def _parse_pnpm_audit_output(self, data: dict) -> List[RawVulnerability]:
        """Parse pnpm audit JSON output"""
        vulnerabilities = []

        advisories = data.get("advisories", {})

        for advisory_id, advisory in advisories.items():
            vulnerabilities.append(
                RawVulnerability(
                    package_name=advisory.get("module_name", "unknown"),
                    package_version=advisory.get("findings", [{}])[0].get(
                        "version", "unknown"
                    ),
                    vuln_id=str(advisory_id),
                    severity=advisory.get("severity", "moderate").upper(),
                    description=advisory.get("title", "No description"),
                    affected_versions=[advisory.get("vulnerable_versions", "*")],
                    patched_versions=[advisory.get("patched_versions", "unknown")],
                    source="pnpm",
                    raw_data=advisory,
                )
            )

        return vulnerabilities

    def _parse_osv_output(self, data: dict) -> List[RawVulnerability]:
        """Parse OSV-scanner JSON output"""
        vulnerabilities = []

        for result in data.get("results", []):
            for package_data in result.get("packages", []):
                pkg_name = package_data.get("package", {}).get("name", "unknown")
                pkg_version = package_data.get("package", {}).get("version", "unknown")

                for vuln in package_data.get("vulnerabilities", []):
                    vulnerabilities.append(
                        RawVulnerability(
                            package_name=pkg_name,
                            package_version=pkg_version,
                            vuln_id=vuln.get("id", "UNKNOWN"),
                            severity=self._extract_osv_severity(vuln),
                            description=vuln.get("summary", "No description"),
                            affected_versions=self._extract_affected_versions(vuln),
                            patched_versions=self._extract_patched_versions(vuln),
                            source="OSV",
                            raw_data=vuln,
                        )
                    )

        return vulnerabilities

    def _extract_osv_severity(self, vuln: dict) -> str:
        """Extract severity from OSV vulnerability data"""
        if "severity" in vuln:
            return (
                vuln["severity"][0].get("score", "MODERATE")
                if vuln["severity"]
                else "MODERATE"
            )

        if "database_specific" in vuln:
            return vuln["database_specific"].get("severity", "MODERATE")

        return "MODERATE"

    def _extract_affected_versions(self, vuln: dict) -> List[str]:
        """Extract affected version ranges"""
        affected = []
        for affect in vuln.get("affected", []):
            for range_data in affect.get("ranges", []):
                for event in range_data.get("events", []):
                    if "introduced" in event:
                        affected.append(f">={event['introduced']}")
                    if "fixed" in event:
                        affected.append(f"<{event['fixed']}")

        return affected or ["*"]

    def _extract_patched_versions(self, vuln: dict) -> List[str]:
        """Extract patched/fixed versions"""
        patched = []
        for affect in vuln.get("affected", []):
            for range_data in affect.get("ranges", []):
                for event in range_data.get("events", []):
                    if "fixed" in event:
                        patched.append(event["fixed"])

        return patched

    def normalize_severity(self, severity: str) -> schema.Severity:
        """Normalize npm/yarn/pnpm severity to standard levels"""
        severity_upper = severity.upper()

        if severity_upper in ["CRITICAL", "HIGH"]:
            return schema.Severity.HIGH
        elif severity_upper in ["MODERATE", "MEDIUM"]:
            return schema.Severity.MEDIUM
        elif severity_upper in ["LOW", "INFO"]:
            return schema.Severity.LOW
        else:
            return schema.Severity.MEDIUM
