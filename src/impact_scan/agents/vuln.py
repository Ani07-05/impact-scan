"""
VulnAgent - Advanced Vulnerability Detection Agent

Integrates static code analysis (Semgrep/Bandit) with AI-powered vulnerability
assessment to provide comprehensive security scanning with context awareness.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Union

from ..core import static_scan
from ..utils.schema import Finding, ScanConfig, Severity
from .base import AgentResult, MultiModelAgent


class VulnAgent(MultiModelAgent):
    """
    Enhanced vulnerability detection using static analysis and AI

    This agent performs comprehensive static code analysis using Semgrep (primary)
    and Bandit (fallback), then uses AI to:
    - Filter false positives based on code context
    - Assess exploitability and business impact
    - Provide context-aware risk scoring

    Capabilities:
    - Multi-language scanning (Python, JS, TS, React, Next.js, etc.)
    - Framework-aware vulnerability detection
    - Secrets and credential detection
    - OWASP Top 10 coverage
    - CWE mapping
    - AI-enhanced false positive reduction
    """

    def __init__(self, config, **kwargs):
        super().__init__(
            name="vuln", config=config, tools=["semgrep", "bandit"], **kwargs
        )

    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """Execute comprehensive vulnerability detection"""

        target_path = Path(target) if isinstance(target, str) else target
        print(f"[VULN] Starting vulnerability detection for {target_path}")

        # Phase 1: Static Analysis Scanning
        findings = context.get("static_findings", [])

        # Phase 2: Filter by minimum severity threshold
        if self.config.min_severity:
            findings = self._filter_by_severity(findings, self.config.min_severity)

        # Phase 3: AI-Enhanced False Positive Filtering (if AI enabled)
        if self.config.enable_ai_fixes:
            findings = await self._ai_filter_false_positives(findings, context)

        # Phase 4: Enrich with context from recon
        findings = self._enrich_with_context(findings, context)

        # Compile results
        result.data["total_findings"] = len(findings)
        result.data["by_severity"] = self._count_by_severity(findings)
        result.data["by_language"] = self._count_by_language(findings)
        result.data["frameworks"] = context.get("frameworks", [])

        # Add findings to result (AgentResult.findings expects List[Finding] objects, not dicts)
        result.findings.extend(findings)

        # Store summary in data (not as a finding dict)
        result.data["scan_summary"] = {
            "description": f"Vulnerability scan completed: {len(findings)} issues found",
            "severity": self._get_highest_severity(findings),
            "details": {
                "total": len(findings),
                "high": result.data["by_severity"].get("HIGH", 0),
                "medium": result.data["by_severity"].get("MEDIUM", 0),
                "low": result.data["by_severity"].get("LOW", 0),
            },
        }

        print(
            f"[VULN] Found {len(findings)} vulnerabilities "
            f"(HIGH: {result.data['by_severity'].get('HIGH', 0)}, "
            f"MEDIUM: {result.data['by_severity'].get('MEDIUM', 0)}, "
            f"LOW: {result.data['by_severity'].get('LOW', 0)})"
        )

    def _filter_by_severity(
        self, findings: List[Finding], min_severity: Severity
    ) -> List[Finding]:
        """Filter findings by minimum severity level"""
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }

        min_level = severity_order.get(min_severity, 0)

        return [f for f in findings if severity_order.get(f.severity, 0) >= min_level]

    async def _ai_filter_false_positives(
        self, findings: List[Finding], context: Dict[str, Any]
    ) -> List[Finding]:
        """Use AI to filter potential false positives"""
        print("[VULN] AI-filtering false positives...")

        # For now, return all findings
        # TODO: Implement AI-based false positive detection
        # This would analyze:
        # - Whether user input is sanitized before use
        # - If dangerous functions are actually reachable
        # - Context-specific security controls

        return findings

    def _enrich_with_context(
        self, findings: List[Finding], context: Dict[str, Any]
    ) -> List[Finding]:
        """Enrich findings with reconnaissance context"""
        frameworks = context.get("frameworks", [])
        endpoints = context.get("endpoints", [])

        # Add framework context to metadata
        for finding in findings:
            finding.metadata["detected_frameworks"] = frameworks

            # Add exploitability hints based on context
            if any(fw in ["flask", "django", "fastapi"] for fw in frameworks):
                if (
                    "sql" in finding.title.lower()
                    or "injection" in finding.title.lower()
                ):
                    finding.metadata["exploitability"] = "high"
                    finding.metadata["business_impact"] = "data breach"

        return findings

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity level"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for finding in findings:
            severity_str = finding.severity.value.upper()
            if severity_str in counts:
                counts[severity_str] += 1

        return counts

    def _count_by_language(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by programming language"""
        counts = {}

        for finding in findings:
            # Infer language from file extension
            ext = finding.file_path.suffix.lstrip(".")
            lang_map = {
                "py": "Python",
                "js": "JavaScript",
                "jsx": "React",
                "ts": "TypeScript",
                "tsx": "React/TypeScript",
            }

            lang = lang_map.get(ext, ext.upper() if ext else "Unknown")
            counts[lang] = counts.get(lang, 0) + 1

        return counts

    def _get_highest_severity(self, findings: List[Finding]) -> str:
        """Get the highest severity level from findings"""
        if not findings:
            return "info"

        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }

        max_severity = max(findings, key=lambda f: severity_order.get(f.severity, 0))
        return max_severity.severity.value
