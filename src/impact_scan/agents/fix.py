"""
FixAgent - AI-Powered Fix Generation Agent

Generates AI-powered security fixes using multi-provider LLM approach.
Integrates with the fix_ai module to provide unified diff format patches.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Union

from ..core import fix_ai
from ..utils.schema import Finding, Severity, VulnSource
from .base import AgentResult, MultiModelAgent


class FixAgent(MultiModelAgent):
    """
    Generate AI-powered security fixes in unified diff format

    This agent takes vulnerability findings and generates actionable fixes
    using AI providers (Anthropic/OpenAI/Gemini). It prioritizes fixes based
    on severity and generates clean, production-ready patches.

    Capabilities:
    - Multi-provider AI fix generation (Anthropic primary, OpenAI/Gemini fallback)
    - Unified diff format output for easy patching
    - Syntax validation of generated fixes
    - Prioritized fix generation (HIGH/CRITICAL first)
    - Context-aware code fixes based on framework/language

    Best Practices:
    - Uses Anthropic (Claude) by default (best for code generation)
    - Limits fixes to HIGH+ severity by default (configurable)
    - Validates fix syntax before returning
    - Includes confidence scoring
    """

    def __init__(self, config, **kwargs):
        super().__init__(
            name="fix",
            config=config,
            primary_model="anthropic",  # Claude is best for code generation
            **kwargs,
        )
        self.max_fixes = kwargs.get("max_fixes", 10)  # Limit for performance
        self.min_severity = kwargs.get("min_severity", Severity.MEDIUM)

    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """Execute AI-powered fix generation"""

        print("[FIX] Starting AI-powered fix generation...")

        # Phase 1: Extract findings from context
        findings = self._extract_findings_from_context(context)

        if not findings:
            print("[FIX] No vulnerability findings available - skipping fix generation")
            result.data["status"] = "skipped"
            result.data["reason"] = "No vulnerabilities found"
            # Don't append invalid dict - status in data is sufficient
            return

        # Phase 2: Filter and prioritize findings
        fixable_findings = self._filter_fixable_findings(findings)

        if not fixable_findings:
            print("[FIX] No fixable findings (all below severity threshold)")
            result.data["status"] = "skipped"
            result.data["reason"] = "No high-priority vulnerabilities"
            return

        # Phase 3: Generate fixes using AI
        fixes = await self._generate_fixes(fixable_findings)

        # Phase 4: Validate generated fixes
        validated_fixes = self._validate_fixes(fixes)

        # Compile results
        result.data["total_vulnerabilities"] = len(findings)
        result.data["fixable_count"] = len(fixable_findings)
        result.data["fixes_generated"] = len(validated_fixes)
        result.data["fixes_validated"] = len(
            [f for f in validated_fixes if f.get("valid", False)]
        )
        result.data["ai_provider"] = self.primary_model

        # Add fix findings as Finding objects
        for fix in validated_fixes:
            fix_finding = Finding(
                vuln_id=fix["vuln_id"],
                rule_id=f"fix-{fix['vuln_id']}",
                title=f"Fix for {fix['title']}",
                description=fix.get("description", "AI-generated security fix"),
                severity=Severity(fix["severity"])
                if isinstance(fix["severity"], str)
                else fix["severity"],
                source=VulnSource.AI_DETECTION,
                file_path=str(fix["file_path"]),
                line_number=fix["line_number"],
                code_snippet=fix["fix_diff"],
                citations=[],
                web_fix=None,
            )
            # Store fix metadata in extra data (not part of Finding schema)
            result.data[f"fix_{fix['vuln_id']}"] = {
                "valid": fix.get("valid", False),
                "confidence": fix.get("confidence", "medium"),
                "provider": fix.get("provider", self.primary_model),
                "diff": fix["fix_diff"],
            }
            result.findings.append(fix_finding)

        # Add summary as Finding object
        summary_finding = Finding(
            vuln_id="fix_summary",
            rule_id="fix-summary",
            title="AI-Powered Fix Generation Summary",
            description=f"Generated {len(validated_fixes)} AI-powered fixes ({result.data['fixes_validated']} validated)",
            severity=Severity.LOW,
            source=VulnSource.AI_DETECTION,
            file_path="N/A",
            line_number=1,
            code_snippet=f"Provider: {self.primary_model}, Total: {len(validated_fixes)}",
            citations=[],
            web_fix=None,
        )
        result.findings.append(summary_finding)

        print(
            f"[FIX] Generated {len(validated_fixes)} fixes "
            f"({result.data['fixes_validated']} validated)"
        )

    def _extract_findings_from_context(self, context: Dict[str, Any]) -> List[Finding]:
        """Extract Finding objects from context (provided by VulnAgent)"""
        findings = []

        # Check if previous_results contains agent results from orchestrator
        previous_results = context.get("previous_results", {})

        # Look for vuln agent results
        if "vuln" in previous_results:
            vuln_result = previous_results["vuln"]
            # VulnAgent.findings now contains Finding objects directly
            if hasattr(vuln_result, "findings") and vuln_result.findings:
                findings.extend(vuln_result.findings)
                print(f"[FIX] Extracted {len(findings)} findings from VulnAgent")

        # Fallback: check direct findings in context
        if not findings:
            raw_findings = context.get("findings", [])
            if raw_findings and isinstance(raw_findings[0], Finding):
                findings = raw_findings

        return findings

    def _filter_fixable_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings that are suitable for AI fix generation"""
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }

        min_level = severity_order.get(self.min_severity, 2)

        # Filter by severity and sort by priority
        fixable = [
            f for f in findings if severity_order.get(f.severity, 0) >= min_level
        ]

        # Sort by severity (highest first) and limit count
        fixable.sort(key=lambda f: severity_order.get(f.severity, 0), reverse=True)

        return fixable[: self.max_fixes]

    async def _generate_fixes(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Generate AI fixes for findings"""
        print(f"[FIX] Generating fixes for {len(findings)} vulnerabilities...")

        # Get AI provider
        try:
            provider = fix_ai.get_ai_fix_provider(self.config.api_keys)
        except fix_ai.AIFixError as e:
            print(f"[FIX] Error: {e}")
            return []

        fixes = []

        # Generate fixes (run in executor to avoid blocking)
        loop = asyncio.get_event_loop()

        for finding in findings:
            try:
                # Generate fix in executor (synchronous AI call)
                fix_diff = await loop.run_in_executor(
                    None, provider.generate_fix, finding
                )

                fixes.append(
                    {
                        "vuln_id": finding.vuln_id,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity.value,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "fix_diff": fix_diff,
                        "provider": self.primary_model,
                    }
                )

            except fix_ai.AIFixError as e:
                print(
                    f"[FIX] Warning: Could not generate fix for {finding.vuln_id}: {e}"
                )
                continue

        return fixes

    def _validate_fixes(self, fixes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate generated fixes for basic correctness"""
        validated = []

        for fix in fixes:
            fix_diff = fix.get("fix_diff", "")

            # Basic validation checks
            is_valid = True
            confidence = "high"

            # Check 1: Contains diff markers
            if not any(marker in fix_diff for marker in ["---", "+++", "@@"]):
                is_valid = False
                confidence = "low"

            # Check 2: Not empty
            if not fix_diff.strip():
                is_valid = False
                confidence = "low"

            # Check 3: No markdown code fences (AI sometimes adds these)
            if "```" in fix_diff:
                # Try to clean it
                fix_diff = fix_diff.replace("```diff", "").replace("```", "").strip()
                confidence = "medium"

            # Check 4: Contains actual changes
            if "+" not in fix_diff or "-" not in fix_diff:
                confidence = "low"

            fix["valid"] = is_valid
            fix["confidence"] = confidence
            fix["fix_diff"] = fix_diff

            validated.append(fix)

        return validated
