"""
Dependency Security Agent

Specialized agent for dependency vulnerability scanning with CVE analysis
and mandatory web search citations for all vulnerabilities found.

Uses UnifiedDependencyScanner for multi-ecosystem support (Python, JavaScript, etc.)
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Union

from ..core.dep_audit import audit_dependencies
from ..core.unified_dependency_scanner import UnifiedDependencyScanner
from ..utils.schema import Finding, ScanConfig, Severity
from .base import AgentResult, MultiModelAgent


class DependencyAgent(MultiModelAgent):
    """
    Specialized agent for dependency vulnerability analysis.

    This agent scans project dependencies for known CVEs and security vulnerabilities,
    providing AI-enhanced risk assessment and upgrade recommendations.
    """

    # Agent metadata for factory registration
    required_tools = ["osv-scanner"]
    default_tools = ["osv-scanner", "safety"]
    dependencies = []

    def __init__(
        self, name: str, config: ScanConfig, tools: List[str] = None, **kwargs
    ):
        super().__init__(
            name=name, config=config, tools=tools or self.default_tools, **kwargs
        )
        self.agent_type = "dependency"

    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """
        Execute dependency vulnerability analysis with AI-enhanced risk assessment.
        """
        target_path = Path(target) if isinstance(target, str) else target

        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target_path}")

        print(f"[{self.name}] Starting dependency analysis of: {target_path}")

        # Step 1: Discover dependency files
        dep_files = await self._discover_dependency_files(target_path)
        if not dep_files:
            print(f"[{self.name}] No dependency files found")
            result.data["dependency_files"] = []
            result.findings = []
            return

        print(
            f"[{self.name}] Found {len(dep_files)} dependency files: {[f.name for f in dep_files]}"
        )

        # Step 2: Scan dependencies for vulnerabilities
        findings = await self._scan_dependencies(dep_files, result)

        # Step 3: AI-enhanced risk assessment and upgrade recommendations
        if self.config.enable_ai_fixes and findings:
            await self._enhance_with_ai_risk_assessment(findings, target_path, result)

        # Step 4: Populate results
        result.findings = findings
        result.data.update(
            {
                "scan_type": "dependency_analysis",
                "target_path": str(target_path),
                "dependency_files": [str(f) for f in dep_files],
                "tools_used": self.tools,
                "findings_count": len(findings),
                "vulnerability_breakdown": self._get_vulnerability_breakdown(findings),
            }
        )

        print(f"[{self.name}] Completed analysis: {len(findings)} vulnerabilities")

    async def _discover_dependency_files(self, target_path: Path) -> List[Path]:
        """Discover dependency manifest files in the project"""

        dependency_patterns = [
            "requirements.txt",
            "requirements-dev.txt",
            "Pipfile",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "Gemfile",
            "Gemfile.lock",
            "pom.xml",
            "build.gradle",
            "composer.json",
            "composer.lock",
            "go.mod",
            "go.sum",
        ]

        found_files = []

        if target_path.is_file():
            # Single file provided
            if target_path.name in dependency_patterns:
                found_files.append(target_path)
        else:
            # Directory - search for dependency files
            for pattern in dependency_patterns:
                matches = list(target_path.rglob(pattern))
                found_files.extend(matches)

        # Deduplicate and return
        return list(set(found_files))

    async def _scan_dependencies(
        self, dep_files: List[Path], result: AgentResult
    ) -> List[Finding]:
        """Scan dependency files for vulnerabilities using UnifiedDependencyScanner"""

        # Determine which ecosystems to scan based on found files
        ecosystems = self._detect_ecosystems(dep_files)

        if not ecosystems:
            print(f"[{self.name}] No supported ecosystems detected")
            return []

        print(f"[{self.name}] Detected ecosystems: {', '.join(ecosystems)}")

        # Get root path (parent of first dep file)
        root_path = dep_files[0].parent if dep_files else Path.cwd()

        try:
            # Initialize UnifiedDependencyScanner
            cache_dir = Path.home() / ".impact_scan" / "vuln_cache"
            scanner = UnifiedDependencyScanner(
                cache_dir=cache_dir, enable_cache=True, ecosystems=ecosystems
            )

            # Scan project for dependency vulnerabilities
            print(
                f"[{self.name}] Scanning {root_path} with UnifiedDependencyScanner..."
            )
            dep_findings = await scanner.scan_project(root_path)

            # Filter by severity threshold
            filtered_findings = [
                f for f in dep_findings if self._meets_severity_threshold(f.severity)
            ]

            print(
                f"[{self.name}] Found {len(filtered_findings)} vulnerabilities "
                f"({len(dep_findings)} total, {len(dep_findings) - len(filtered_findings)} filtered by severity)"
            )

            return filtered_findings

        except Exception as e:
            print(f"[{self.name}] UnifiedDependencyScanner failed: {e}")
            print(f"[{self.name}] Falling back to legacy dep_audit...")

            # Fallback to legacy scanning
            return await self._legacy_scan_dependencies(dep_files, result)

    def _detect_ecosystems(self, dep_files: List[Path]) -> List[str]:
        """Detect ecosystems from dependency files"""
        ecosystems = set()

        for dep_file in dep_files:
            name = dep_file.name.lower()

            # Python
            if (
                name in ["requirements.txt", "pipfile", "pyproject.toml", "poetry.lock"]
                or name.startswith("requirements")
                and name.endswith(".txt")
            ):
                ecosystems.add("python")

            # JavaScript/Node
            elif name in [
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
            ]:
                ecosystems.add("javascript")

            # Java
            elif name in ["pom.xml", "build.gradle", "build.gradle.kts"]:
                ecosystems.add("java")

            # Go
            elif name in ["go.mod", "go.sum"]:
                ecosystems.add("go")

            # Ruby
            elif name in ["gemfile", "gemfile.lock"]:
                ecosystems.add("ruby")

            # PHP
            elif name in ["composer.json", "composer.lock"]:
                ecosystems.add("php")

        return list(ecosystems)

    async def _legacy_scan_dependencies(
        self, dep_files: List[Path], result: AgentResult
    ) -> List[Finding]:
        """Legacy fallback scanning method using dep_audit"""

        all_findings = []

        for dep_file in dep_files:
            print(f"[{self.name}] Scanning {dep_file.name}...")

            try:
                # Use existing dependency audit functionality
                findings = await asyncio.to_thread(
                    audit_dependencies,
                    dep_file.parent,  # Pass directory containing the file
                )

                # Filter and enhance findings
                file_findings = [
                    f
                    for f in findings
                    if str(dep_file) in str(f.file_path)
                    and self._meets_severity_threshold(f.severity)
                ]

                all_findings.extend(file_findings)
                print(
                    f"[{self.name}] Found {len(file_findings)} vulnerabilities in {dep_file.name}"
                )

            except Exception as e:
                print(f"[{self.name}] Failed to scan {dep_file}: {e}")
                continue

        return all_findings

    async def _enhance_with_ai_risk_assessment(
        self, findings: List[Finding], target_path: Path, result: AgentResult
    ) -> None:
        """
        Enhance vulnerability findings with AI-powered risk assessment and upgrade recommendations.
        """
        print(
            f"[{self.name}] Enhancing {len(findings)} vulnerabilities with AI risk assessment..."
        )

        for i, finding in enumerate(findings):
            try:
                # Create AI prompt for vulnerability risk assessment
                prompt = self._create_risk_assessment_prompt(finding, target_path)

                # Get AI analysis
                ai_analysis = await self._get_ai_analysis(
                    prompt, context={"finding": finding, "target": str(target_path)}
                )

                # Apply AI insights
                if ai_analysis:
                    finding.ai_explanation = ai_analysis

                    # Try to extract upgrade recommendations
                    upgrade_rec = self._extract_upgrade_recommendation(ai_analysis)
                    if upgrade_rec:
                        existing_fix = finding.fix_suggestion or ""
                        finding.fix_suggestion = f"{existing_fix}\n\nAI Recommendation: {upgrade_rec}".strip()

                print(
                    f"[{self.name}] AI enhanced vulnerability {i + 1}/{len(findings)}"
                )

            except Exception as e:
                print(
                    f"[{self.name}] AI enhancement failed for vulnerability {i + 1}: {e}"
                )
                continue

    def _create_risk_assessment_prompt(
        self, finding: Finding, target_path: Path
    ) -> str:
        """Create AI prompt for vulnerability risk assessment"""

        return f"""
Analyze this dependency vulnerability for risk assessment and upgrade recommendations:

**Vulnerability Details:**
- CVE/ID: {finding.vuln_id}
- Package: {finding.title}
- Severity: {finding.severity.value.upper()}
- Description: {finding.description}

**Context:**
- Project: {target_path.name}
- File: {finding.file_path}
- Current Code: {finding.code_snippet}

**Risk Assessment Required:**
1. **Business Risk**: How critical is this vulnerability for typical applications?
2. **Exploitability**: How easily can this be exploited in practice?
3. **Upgrade Path**: What's the safest way to address this vulnerability?
4. **Breaking Changes**: Are there potential compatibility issues with upgrades?

**Please provide:**
1. **Risk Level**: Practical risk assessment (Critical/High/Medium/Low)
2. **Urgency**: How quickly should this be patched?
3. **Upgrade Recommendation**: Specific version to upgrade to and any migration notes
4. **Workarounds**: If upgrade isn't immediately possible

Focus on actionable security guidance for developers.
"""

    def _extract_upgrade_recommendation(self, ai_analysis: str) -> str:
        """Extract upgrade recommendation from AI analysis"""
        lines = ai_analysis.split("\n")

        for line in lines:
            line_lower = line.lower().strip()
            if any(
                keyword in line_lower
                for keyword in ["upgrade to", "update to", "version", "recommended"]
            ):
                if any(char.isdigit() for char in line):  # Contains version numbers
                    return line.strip()

        return None

    def _meets_severity_threshold(self, severity: Severity) -> bool:
        """Check if vulnerability meets minimum severity threshold"""
        severity_order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        finding_level = severity_order.get(severity, 1)
        threshold_level = severity_order.get(self.config.min_severity, 2)

        return finding_level >= threshold_level

    def _get_vulnerability_breakdown(self, findings: List[Finding]) -> Dict[str, Any]:
        """Get breakdown of vulnerabilities by various metrics"""
        breakdown = {
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_package": {},
            "total_packages_affected": 0,
            "most_critical": None,
        }

        packages_affected = set()
        most_critical = None

        for finding in findings:
            # Severity breakdown
            severity_key = finding.severity.value.lower()
            if severity_key in breakdown["by_severity"]:
                breakdown["by_severity"][severity_key] += 1

            # Package breakdown (extract package name from title/vuln_id)
            package_name = self._extract_package_name(finding)
            if package_name:
                packages_affected.add(package_name)
                breakdown["by_package"][package_name] = (
                    breakdown["by_package"].get(package_name, 0) + 1
                )

            # Track most critical
            if not most_critical or finding.severity == Severity.CRITICAL:
                most_critical = finding

        breakdown["total_packages_affected"] = len(packages_affected)
        breakdown["most_critical"] = (
            {
                "vuln_id": most_critical.vuln_id,
                "severity": most_critical.severity.value,
                "title": most_critical.title,
            }
            if most_critical
            else None
        )

        return breakdown

    def _extract_package_name(self, finding: Finding) -> str:
        """Extract package name from finding"""
        # Try to extract from title or vuln_id
        title_lower = finding.title.lower()

        # Common patterns for package names in vulnerability titles
        if " in " in title_lower:
            parts = title_lower.split(" in ")
            if len(parts) > 1:
                return parts[-1].split()[0]  # First word after "in"

        if finding.vuln_id and "-" in finding.vuln_id:
            # CVE format might contain package info
            parts = finding.vuln_id.split("-")
            if len(parts) > 2:
                return parts[1]  # Middle part might be package

        return "unknown"

    async def _is_tool_available(self, tool: str) -> bool:
        """Check if dependency scanning tool is available"""
        import shutil

        return shutil.which(tool) is not None

    def get_capabilities(self) -> Dict[str, Any]:
        """Return agent capabilities"""
        capabilities = super().get_capabilities()
        capabilities.update(
            {
                "agent_type": "dependency_analysis",
                "supported_ecosystems": [
                    "python",
                    "javascript",
                    "ruby",
                    "java",
                    "go",
                    "php",
                ],
                "vulnerability_sources": ["OSV", "CVE", "GHSA", "PyPI"],
                "ai_enhanced": True,
                "risk_assessment": True,
                "upgrade_recommendations": True,
                "mandatory_citations": True,
            }
        )
        return capabilities
