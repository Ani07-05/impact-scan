"""
Python ecosystem dependency scanner
Supports: requirements.txt, pyproject.toml, poetry.lock, Pipfile
Uses: pip-audit, safety, osv-scanner
"""

import asyncio
import json
from pathlib import Path
from typing import List

from rich.console import Console

from impact_scan.core.unified_dependency_scanner import (
    EcosystemScanner,
    RawVulnerability,
)
from impact_scan.utils import schema

console = Console()


class PythonScanner(EcosystemScanner):
    """Scanner for Python dependencies"""

    def __init__(self):
        super().__init__("python")
        self.manifest_patterns = [
            "requirements.txt",
            "*requirements*.txt",
            "pyproject.toml",
            "poetry.lock",
            "Pipfile",
            "Pipfile.lock",
        ]

    async def detect_manifest_files(self, root_path: Path) -> List[Path]:
        """Find Python dependency manifest files"""
        manifests = []

        # Look for requirements.txt variants
        for pattern in [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
        ]:
            matches = list(root_path.rglob(pattern))
            manifests.extend(matches)

        # Look for pyproject.toml
        manifests.extend(root_path.rglob("pyproject.toml"))

        # Look for poetry.lock
        manifests.extend(root_path.rglob("poetry.lock"))

        # Look for Pipfile
        manifests.extend(root_path.rglob("Pipfile"))

        # Deduplicate and return
        return list(set(manifests))

    async def scan_manifest(self, manifest_path: Path) -> List[RawVulnerability]:
        """
        Scan Python manifest for vulnerabilities using OSV-scanner.
        Falls back to parsing and manual lookup if OSV-scanner unavailable.
        """
        vulnerabilities = []

        # Try OSV-scanner first (already integrated)
        try:
            vulns = await self._scan_with_osv(manifest_path)
            vulnerabilities.extend(vulns)
        except Exception as e:
            console.log(f"[yellow]OSV-scanner failed: {e}, trying fallback[/yellow]")

            # Fallback: parse requirements and query OSV API
            try:
                vulns = await self._scan_with_osv_api(manifest_path)
                vulnerabilities.extend(vulns)
            except Exception as e2:
                console.log(f"[red]All Python scanners failed: {e2}[/red]")

        return vulnerabilities

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

            if proc.returncode not in [0, 1]:  # 0 = no vulns, 1 = vulns found
                raise Exception(f"OSV-scanner error: {stderr.decode()}")

            # Parse JSON output
            data = json.loads(stdout.decode())
            return self._parse_osv_output(data, manifest_path)

        except FileNotFoundError:
            raise Exception("osv-scanner not installed")

    async def _scan_with_osv_api(self, manifest_path: Path) -> List[RawVulnerability]:
        """Scan by parsing requirements and querying OSV API"""
        import httpx

        # Parse dependencies
        dependencies = await self._parse_requirements(manifest_path)

        vulnerabilities = []
        async with httpx.AsyncClient(timeout=30) as client:
            for pkg_name, pkg_version in dependencies:
                try:
                    response = await client.post(
                        "https://api.osv.dev/v1/query",
                        json={
                            "package": {"name": pkg_name, "ecosystem": "PyPI"},
                            "version": pkg_version,
                        },
                    )

                    if response.status_code == 200:
                        data = response.json()
                        vulns = data.get("vulns", [])

                        for vuln in vulns:
                            vulnerabilities.append(
                                RawVulnerability(
                                    package_name=pkg_name,
                                    package_version=pkg_version,
                                    vuln_id=vuln.get("id", "UNKNOWN"),
                                    severity=self._extract_severity(vuln),
                                    description=vuln.get("summary", "No description"),
                                    affected_versions=self._extract_affected_versions(
                                        vuln
                                    ),
                                    patched_versions=self._extract_patched_versions(
                                        vuln
                                    ),
                                    source="OSV",
                                    raw_data=vuln,
                                )
                            )

                except Exception as e:
                    console.log(f"[yellow]Error checking {pkg_name}: {e}[/yellow]")

        return vulnerabilities

    async def _parse_requirements(self, manifest_path: Path) -> List[tuple[str, str]]:
        """Parse requirements.txt file"""
        dependencies = []

        content = manifest_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse package==version format
            if "==" in line:
                parts = line.split("==")
                if len(parts) == 2:
                    pkg_name = parts[0].strip()
                    # Remove comments, environment markers, and whitespace
                    pkg_version = parts[1].split("#")[0].split(";")[0].strip()
                    dependencies.append((pkg_name, pkg_version))

        return dependencies

    def _parse_osv_output(
        self, data: dict, manifest_path: Path
    ) -> List[RawVulnerability]:
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
                            severity=self._extract_severity(vuln),
                            description=vuln.get("summary", "No description"),
                            affected_versions=self._extract_affected_versions(vuln),
                            patched_versions=self._extract_patched_versions(vuln),
                            source="OSV",
                            raw_data=vuln,
                        )
                    )

        return vulnerabilities

    def _extract_severity(self, vuln: dict) -> str:
        """Extract severity from OSV vulnerability data"""
        # OSV severity in database_specific or severity field
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
        """Normalize OSV severity to standard severity levels"""
        severity_upper = severity.upper()

        if severity_upper == "CRITICAL":
            return schema.Severity.CRITICAL
        elif severity_upper == "HIGH":
            return schema.Severity.HIGH
        elif severity_upper in ["MODERATE", "MEDIUM"]:
            return schema.Severity.MEDIUM
        elif severity_upper in ["LOW", "INFO"]:
            return schema.Severity.LOW
        else:
            return schema.Severity.MEDIUM
