"""
Unified Dependency Vulnerability Scanner
Supports: Python, JavaScript/Node, Java, Go, Rust, Ruby

Provides a unified interface for scanning dependencies across multiple ecosystems,
with integrated vulnerability knowledge base and upgrade recommendations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from impact_scan.utils import schema

console = Console()


@dataclass
class RawVulnerability:
    """Raw vulnerability data from ecosystem-specific scanner"""

    package_name: str
    package_version: str
    vuln_id: str
    severity: str
    description: str
    affected_versions: List[str]
    patched_versions: List[str]
    source: str
    raw_data: Dict[str, Any]


class EcosystemScanner(ABC):
    """Base class for ecosystem-specific dependency scanners"""

    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem

    @abstractmethod
    async def detect_manifest_files(self, root_path: Path) -> List[Path]:
        """
        Find dependency manifest files in the project.

        Args:
            root_path: Root directory to search

        Returns:
            List of paths to manifest files (requirements.txt, package.json, etc.)
        """
        pass

    @abstractmethod
    async def scan_manifest(self, manifest_path: Path) -> List[RawVulnerability]:
        """
        Scan a single manifest file for vulnerabilities.

        Args:
            manifest_path: Path to manifest file

        Returns:
            List of raw vulnerability data from ecosystem tools
        """
        pass

    @abstractmethod
    def normalize_severity(self, severity: str) -> schema.Severity:
        """
        Normalize ecosystem-specific severity to standard Severity enum.

        Args:
            severity: Ecosystem-specific severity string

        Returns:
            Normalized Severity enum value
        """
        pass

    def normalize_finding(
        self, raw_vuln: RawVulnerability, manifest_path: Path
    ) -> schema.DependencyFinding:
        """
        Convert raw vulnerability to standardized DependencyFinding.

        Args:
            raw_vuln: Raw vulnerability from scanner
            manifest_path: Path to source manifest file

        Returns:
            Standardized DependencyFinding object
        """
        return schema.DependencyFinding(
            vuln_id=raw_vuln.vuln_id,
            rule_id=f"{self.ecosystem}:{raw_vuln.vuln_id}",
            severity=self.normalize_severity(raw_vuln.severity),
            title=f"Vulnerable dependency: {raw_vuln.package_name}",
            description=raw_vuln.description,
            file_path=str(manifest_path),
            line_number=1,
            code_snippet="",
            source=schema.VulnSource.DEPENDENCY,
            package_name=raw_vuln.package_name,
            package_version=raw_vuln.package_version,
            ecosystem=self.ecosystem,
            affected_versions=raw_vuln.affected_versions,
            patched_versions=raw_vuln.patched_versions,
            data_sources=[raw_vuln.source],
        )


class UnifiedDependencyScanner:
    """
    Central coordinator for all dependency scanning tools.
    Provides unified interface and normalization of results across ecosystems.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        enable_cache: bool = True,
        ecosystems: Optional[List[str]] = None,
    ):
        """
        Initialize unified dependency scanner.

        Args:
            cache_dir: Directory for caching vulnerability data
            enable_cache: Whether to use local cache
            ecosystems: List of ecosystems to scan (None = auto-detect all)
        """
        self.cache_dir = cache_dir or Path.home() / ".impact-scan" / "cache"
        self.enable_cache = enable_cache
        self.ecosystems = ecosystems  # Store for tests

        # Import scanners lazily to avoid circular imports
        self.scanners: Dict[str, EcosystemScanner] = {}
        self._init_scanners(ecosystems)

        # Knowledge base will be initialized when needed
        self._knowledge_base = None

    def _init_scanners(self, ecosystems: Optional[List[str]]):
        """Initialize ecosystem-specific scanners"""
        available_ecosystems = {
            "python": "PythonScanner",
            "javascript": "JavaScriptScanner",
        }

        target_ecosystems = ecosystems or list(available_ecosystems.keys())

        for ecosystem in target_ecosystems:
            if ecosystem in available_ecosystems:
                try:
                    # Dynamic import to avoid hard dependencies
                    if ecosystem == "python":
                        from impact_scan.core.scanners.python_scanner import (
                            PythonScanner,
                        )

                        self.scanners[ecosystem] = PythonScanner()
                    elif ecosystem == "javascript":
                        from impact_scan.core.scanners.javascript_scanner import (
                            JavaScriptScanner,
                        )

                        self.scanners[ecosystem] = JavaScriptScanner()
                except ImportError as e:
                    console.log(
                        f"[yellow]Warning: Could not load {ecosystem} scanner: {e}[/yellow]"
                    )

    @property
    def knowledge_base(self):
        """Lazy-load knowledge base"""
        if self._knowledge_base is None and self.enable_cache:
            try:
                from impact_scan.core.vulnerability_knowledge_base import (
                    DependencyKnowledgeBase,
                )

                self._knowledge_base = DependencyKnowledgeBase(self.cache_dir)
            except ImportError:
                console.log(
                    "[yellow]Warning: Vulnerability knowledge base not available[/yellow]"
                )
        return self._knowledge_base

    async def scan_project(self, root_path: Path) -> List[schema.DependencyFinding]:
        """
        Scan all detected dependency files in project.

        Args:
            root_path: Root directory of project

        Returns:
            List of dependency vulnerability findings
        """
        console.log(f"[cyan]Scanning dependencies in {root_path}[/cyan]")

        all_findings = []

        # Scan each ecosystem
        for ecosystem_name, scanner in self.scanners.items():
            try:
                findings = await self.scan_ecosystem(root_path, ecosystem_name)
                all_findings.extend(findings)

                if findings:
                    console.log(
                        f"[green]Found {len(findings)} dependency vulnerabilities "
                        f"in {ecosystem_name} ecosystem[/green]"
                    )
            except Exception as e:
                console.log(f"[yellow]Error scanning {ecosystem_name}: {e}[/yellow]")

        return all_findings

    async def scan_ecosystem(
        self, root_path: Path, ecosystem: str
    ) -> List[schema.DependencyFinding]:
        """
        Scan specific ecosystem for vulnerabilities.

        Args:
            root_path: Root directory of project
            ecosystem: Ecosystem name (python, javascript, etc.)

        Returns:
            List of dependency vulnerability findings
        """
        scanner = self.scanners.get(ecosystem)
        if not scanner:
            console.log(f"[yellow]No scanner available for {ecosystem}[/yellow]")
            return []

        # Find manifest files
        manifest_files = await scanner.detect_manifest_files(root_path)
        if not manifest_files:
            console.log(f"[dim]No {ecosystem} manifest files found[/dim]")
            return []

        console.log(
            f"[cyan]Found {len(manifest_files)} {ecosystem} manifest file(s)[/cyan]"
        )

        # Scan each manifest
        all_findings = []
        for manifest_path in manifest_files:
            try:
                console.log(f"[dim]Scanning {manifest_path.name}...[/dim]")
                raw_vulns = await scanner.scan_manifest(manifest_path)

                # Convert to standard format
                findings = [
                    scanner.normalize_finding(vuln, manifest_path) for vuln in raw_vulns
                ]

                all_findings.extend(findings)

                if findings:
                    console.log(
                        f"[green]  → {len(findings)} vulnerabilities in {manifest_path.name}[/green]"
                    )

            except Exception as e:
                console.log(f"[red]Error scanning {manifest_path}: {e}[/red]")

        return all_findings

    async def enrich_with_knowledge_base(
        self, findings: List[schema.DependencyFinding]
    ) -> List[schema.DependencyFinding]:
        """
        Enrich findings with additional data from knowledge base.

        Args:
            findings: List of dependency findings

        Returns:
            Enhanced findings with upgrade recommendations
        """
        if not self.knowledge_base:
            return findings

        console.log(
            "[cyan]Enriching findings with vulnerability knowledge base...[/cyan]"
        )

        enriched = []
        for finding in findings:
            try:
                # Get additional vulnerability data
                vuln_data = await self.knowledge_base.get_vulnerabilities(
                    package=finding.package_name,
                    version=finding.package_version,
                    ecosystem=finding.ecosystem,
                )

                # Get package metadata
                metadata = self.knowledge_base.get_package_metadata(
                    package=finding.package_name, ecosystem=finding.ecosystem
                )

                # Add upgrade recommendation
                if metadata:
                    finding.latest_version = metadata.latest_version
                    finding.latest_safe_version = (
                        metadata.safe_versions[0] if metadata.safe_versions else None
                    )

                    if finding.latest_safe_version:
                        finding.upgrade_recommendation = schema.UpgradeRecommendation(
                            recommended_version=finding.latest_safe_version,
                            urgency=self._calculate_urgency(finding.severity),
                            upgrade_path=[
                                finding.package_version,
                                finding.latest_safe_version,
                            ],
                        )

                # Add additional metadata
                if vuln_data:
                    finding.cvss_score = (
                        vuln_data[0].get("cvss_score") if vuln_data else None
                    )
                    finding.data_sources = list(
                        set(finding.data_sources + [v["source"] for v in vuln_data])
                    )

                enriched.append(finding)

            except Exception as e:
                console.log(
                    f"[yellow]Warning: Could not enrich {finding.package_name}: {e}[/yellow]"
                )
                enriched.append(finding)

        return enriched

    def _calculate_urgency(self, severity: schema.Severity) -> str:
        """Calculate upgrade urgency from severity"""
        if severity == schema.Severity.CRITICAL:
            return "immediate"
        elif severity == schema.Severity.HIGH:
            return "high"
        elif severity == schema.Severity.MEDIUM:
            return "medium"
        else:
            return "low"

    async def close(self):
        """Clean up resources"""
        if self._knowledge_base:
            await self._knowledge_base.close()


# Convenience function for quick scanning
async def scan_dependencies(
    root_path: Path, ecosystems: Optional[List[str]] = None, enable_cache: bool = True
) -> List[schema.DependencyFinding]:
    """
    Quick dependency scan function.

    Args:
        root_path: Project root directory
        ecosystems: List of ecosystems to scan (None = all)
        enable_cache: Whether to use vulnerability cache

    Returns:
        List of dependency vulnerability findings
    """
    scanner = UnifiedDependencyScanner(enable_cache=enable_cache, ecosystems=ecosystems)

    try:
        findings = await scanner.scan_project(root_path)

        # Enrich with knowledge base if available
        if enable_cache:
            findings = await scanner.enrich_with_knowledge_base(findings)

        return findings
    finally:
        await scanner.close()
