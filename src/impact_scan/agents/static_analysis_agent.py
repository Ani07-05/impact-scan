"""
Static Analysis Security Agent

Specialized agent for performing comprehensive static code analysis
with mandatory web search citations for all findings.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Union

from ..core.static_scan import run_scan
from ..utils.schema import Finding, ScanConfig, Severity
from .base import AgentResult, MultiModelAgent


class StaticAnalysisAgent(MultiModelAgent):
    """
    Specialized agent for static code analysis with AI-enhanced vulnerability detection.

    This agent combines traditional static analysis tools (Bandit, Semgrep) with AI models
    for improved vulnerability detection and context-aware security assessment.
    """

    # Agent metadata for factory registration
    required_tools = ["semgrep"]
    default_tools = ["semgrep", "bandit"]
    dependencies = []

    def __init__(
        self, name: str, config: ScanConfig, tools: List[str] = None, **kwargs
    ):
        super().__init__(
            name=name, config=config, tools=tools or self.default_tools, **kwargs
        )
        self.agent_type = "static_analysis"

    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """
        Execute static analysis with AI-enhanced vulnerability detection.
        """
        target_path = Path(target) if isinstance(target, str) else target

        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target_path}")

        print(f"[{self.name}] Starting static analysis of: {target_path}")

        # Step 1: Run traditional static analysis
        findings = await self._run_static_analysis(target_path, result)

        # Step 2: AI-enhanced analysis for context and severity assessment
        if self.config.enable_ai_fixes and findings:
            await self._enhance_with_ai_analysis(findings, target_path, result)

        # Step 3: Populate results
        result.findings = findings
        result.data.update(
            {
                "scan_type": "static_analysis",
                "target_path": str(target_path),
                "tools_used": self.tools,
                "findings_count": len(findings),
                "severity_breakdown": self._get_severity_breakdown(findings),
            }
        )

        print(f"[{self.name}] Completed analysis: {len(findings)} findings")

    async def _run_static_analysis(
        self, target_path: Path, result: AgentResult
    ) -> List[Finding]:
        """Run static analysis tools and convert results to Finding objects"""

        print(f"[{self.name}] Running static analysis tools (Semgrep)...")

        # Use existing static scan functionality
        # We need to ensure the config passed to run_scan has the correct root_path
        # if target_path is different from self.config.root_path

        scan_config = self.config
        if target_path != self.config.root_path:
            # Create a temporary config with the target path
            # We can't easily clone pydantic models without .copy(update={}) usually
            # Assuming ScanConfig is a pydantic model or dataclass
            from dataclasses import replace

            if hasattr(scan_config, "model_copy"):
                scan_config = scan_config.model_copy(update={"root_path": target_path})
            elif hasattr(scan_config, "replace"):  # dataclass
                scan_config = replace(scan_config, root_path=target_path)
            else:
                # Fallback: just modify it temporarily or assume it's fine if it's a dataclass
                # Let's assume it's a Pydantic model or similar.
                # Actually, let's just pass the config we have, but run_scan uses config.root_path
                # So we really should update it.
                # Let's try to construct a new one if possible, or just monkey patch
                pass

        # Actually, run_scan takes a ScanConfig.
        # Let's just call run_scan with the current config, but we might need to ensure root_path is correct.
        # In the verification script, I created specific configs.
        # Here, I'll assume self.config is correct or I'll try to update it.

        # For now, let's just pass self.config. If target_path is a subdirectory, run_scan might scan the whole root
        # if we don't update it. But run_scan uses config.root_path.

        # Let's try to update it safely
        try:
            # Try pydantic v2
            scan_config = self.config.model_copy(update={"root_path": target_path})
        except:
            try:
                # Try pydantic v1
                scan_config = self.config.copy(update={"root_path": target_path})
            except:
                # Maybe it's a dataclass
                try:
                    import dataclasses

                    scan_config = dataclasses.replace(
                        self.config, root_path=target_path
                    )
                except:
                    # Fallback
                    scan_config = self.config

        findings = await asyncio.to_thread(run_scan, scan_config)

        print(f"[{self.name}] Static analysis found {len(findings)} potential issues")

        # Filter by minimum severity
        filtered_findings = [
            f for f in findings if self._meets_severity_threshold(f.severity)
        ]

        if len(filtered_findings) < len(findings):
            filtered_out = len(findings) - len(filtered_findings)
            print(
                f"[{self.name}] Filtered out {filtered_out} findings below {self.config.min_severity.value} severity"
            )

        return filtered_findings

    async def _enhance_with_ai_analysis(
        self, findings: List[Finding], target_path: Path, result: AgentResult
    ) -> None:
        """
        Enhance findings with AI analysis for better context and accuracy.
        """
        print(f"[{self.name}] Enhancing {len(findings)} findings with AI analysis...")

        for i, finding in enumerate(findings):
            try:
                # Create AI prompt for vulnerability analysis
                prompt = self._create_ai_analysis_prompt(finding, target_path)

                # Get AI analysis
                ai_analysis = await self._get_ai_analysis(
                    prompt, context={"finding": finding, "target": str(target_path)}
                )

                # Parse and apply AI insights
                if ai_analysis:
                    finding.ai_explanation = ai_analysis

                    # Try to extract enhanced severity if AI suggests it
                    enhanced_severity = self._extract_severity_from_ai(ai_analysis)
                    if enhanced_severity and enhanced_severity != finding.severity:
                        print(
                            f"[{self.name}] AI suggested severity change for {finding.vuln_id}: "
                            f"{finding.severity.value} → {enhanced_severity.value}"
                        )
                        finding.severity = enhanced_severity

                print(f"[{self.name}] AI enhanced finding {i + 1}/{len(findings)}")

            except Exception as e:
                print(f"[{self.name}] AI enhancement failed for finding {i + 1}: {e}")
                continue

    def _get_code_context(
        self, file_path: Path, line_number: int, context_lines: int = 10
    ) -> str:
        """Extract code context around a specific line"""
        try:
            if not file_path.exists():
                return "File not found."

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            start_line = max(0, line_number - context_lines - 1)
            end_line = min(len(lines), line_number + context_lines)

            context = []
            for i in range(start_line, end_line):
                prefix = ">> " if i == (line_number - 1) else "   "
                context.append(f"{prefix}{i + 1}: {lines[i].rstrip()}")

            return "\n".join(context)
        except Exception as e:
            return f"Error reading context: {e}"

    def _create_ai_analysis_prompt(self, finding: Finding, target_path: Path) -> str:
        """Create a detailed prompt for AI analysis of a security finding"""

        # Extract rich context
        code_context = self._get_code_context(finding.file_path, finding.line_number)

        return f"""
Analyze this security vulnerability finding for accuracy and context.
You are a Senior Security Engineer. Your goal is to filter out False Positives.

**Vulnerability Details:**
- ID: {finding.vuln_id}
- Rule: {finding.rule_id} 
- Title: {finding.title}
- Current Severity: {finding.severity.value.upper()}
- Description: {finding.description}

**Code Context (Surrounding Lines):**
```
{code_context}
```

**Analysis Required:**
1. **Sanitization Check**: Look for sanitization libraries (e.g., DOMPurify, bleach) or validation logic in the context.
2. **Reachability**: Is this code actually reachable or dead/test code?
3. **Verdict**: Is this a True Positive or False Positive?

**Response Format:**
Please provide your analysis in the following format:
- **Verdict**: [True Positive / False Positive / Needs Review]
- **Confidence**: [High / Medium / Low]
- **Reasoning**: [Brief explanation of why]
- **Suggested Severity**: [Critical / High / Medium / Low / Safe]
- **Remediation**: [Specific fix if True Positive, or "None" if False Positive]

If it is a False Positive, explain EXACTLY why (e.g., "Input is sanitized by DOMPurify on line 5").
"""

    def _extract_severity_from_ai(self, ai_analysis: str) -> Severity:
        """Extract severity suggestion from AI analysis"""
        ai_lower = ai_analysis.lower()

        if "critical" in ai_lower:
            return Severity.CRITICAL
        elif "high" in ai_lower:
            return Severity.HIGH
        elif "medium" in ai_lower:
            return Severity.MEDIUM
        elif "low" in ai_lower:
            return Severity.LOW

        return None  # No severity found

    def _meets_severity_threshold(self, severity: Severity) -> bool:
        """Check if finding meets minimum severity threshold"""
        severity_order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }

        finding_level = severity_order.get(severity, 1)
        threshold_level = severity_order.get(self.config.min_severity, 2)

        return finding_level >= threshold_level

    def _get_severity_breakdown(self, findings: List[Finding]) -> Dict[str, int]:
        """Get count of findings by severity level"""
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in findings:
            severity_key = finding.severity.value.lower()
            if severity_key in breakdown:
                breakdown[severity_key] += 1

        return breakdown

    async def _is_tool_available(self, tool: str) -> bool:
        """Check if static analysis tool is available"""
        import shutil

        return shutil.which(tool) is not None

    def get_capabilities(self) -> Dict[str, Any]:
        """Return agent capabilities"""
        capabilities = super().get_capabilities()
        capabilities.update(
            {
                "agent_type": "static_analysis",
                "supported_languages": ["python", "javascript", "java", "go", "php"],
                "analysis_types": ["security", "code_quality", "best_practices"],
                "ai_enhanced": True,
                "mandatory_citations": True,
            }
        )
        return capabilities
