"""
Static Analysis Security Agent

Specialized agent for performing comprehensive static code analysis 
with mandatory web search citations for all findings.
"""

import asyncio
from pathlib import Path
from typing import Dict, Any, List, Union

from .base import MultiModelAgent, AgentResult, AgentStatus
from ..utils.schema import ScanConfig, Finding, Severity, VulnSource
from ..core.static_scan import scan_for_static_issues


class StaticAnalysisAgent(MultiModelAgent):
    """
    Specialized agent for static code analysis with AI-enhanced vulnerability detection.
    
    This agent combines traditional static analysis tools (Bandit, Semgrep) with AI models
    for improved vulnerability detection and context-aware security assessment.
    """
    
    # Agent metadata for factory registration
    required_tools = ["bandit"]
    default_tools = ["bandit", "semgrep"]
    dependencies = []
    
    def __init__(
        self, 
        name: str, 
        config: ScanConfig,
        tools: List[str] = None,
        **kwargs
    ):
        super().__init__(
            name=name,
            config=config, 
            tools=tools or self.default_tools,
            **kwargs
        )
        self.agent_type = "static_analysis"
        
    async def _execute_internal(
        self, 
        target: Union[str, Path], 
        context: Dict[str, Any],
        result: AgentResult
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
        result.data.update({
            "scan_type": "static_analysis",
            "target_path": str(target_path),
            "tools_used": self.tools,
            "findings_count": len(findings),
            "severity_breakdown": self._get_severity_breakdown(findings)
        })
        
        print(f"[{self.name}] Completed analysis: {len(findings)} findings")
    
    async def _run_static_analysis(
        self, 
        target_path: Path, 
        result: AgentResult
    ) -> List[Finding]:
        """Run static analysis tools and convert results to Finding objects"""
        
        print(f"[{self.name}] Running static analysis tools...")
        
        # Use existing static scan functionality
        findings = await asyncio.to_thread(
            scan_for_static_issues,
            target_path
        )
        
        print(f"[{self.name}] Static analysis found {len(findings)} potential issues")
        
        # Filter by minimum severity
        filtered_findings = [
            f for f in findings 
            if self._meets_severity_threshold(f.severity)
        ]
        
        if len(filtered_findings) < len(findings):
            filtered_out = len(findings) - len(filtered_findings)
            print(f"[{self.name}] Filtered out {filtered_out} findings below {self.config.min_severity.value} severity")
        
        return filtered_findings
    
    async def _enhance_with_ai_analysis(
        self, 
        findings: List[Finding], 
        target_path: Path,
        result: AgentResult
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
                    prompt, 
                    context={"finding": finding, "target": str(target_path)}
                )
                
                # Parse and apply AI insights
                if ai_analysis:
                    finding.ai_explanation = ai_analysis
                    
                    # Try to extract enhanced severity if AI suggests it
                    enhanced_severity = self._extract_severity_from_ai(ai_analysis)
                    if enhanced_severity and enhanced_severity != finding.severity:
                        print(f"[{self.name}] AI suggested severity change for {finding.vuln_id}: "
                              f"{finding.severity.value} → {enhanced_severity.value}")
                        finding.severity = enhanced_severity
                
                print(f"[{self.name}] AI enhanced finding {i+1}/{len(findings)}")
                
            except Exception as e:
                print(f"[{self.name}] AI enhancement failed for finding {i+1}: {e}")
                continue
    
    def _create_ai_analysis_prompt(self, finding: Finding, target_path: Path) -> str:
        """Create a detailed prompt for AI analysis of a security finding"""
        
        return f"""
Analyze this security vulnerability finding for accuracy and context:

**Vulnerability Details:**
- ID: {finding.vuln_id}
- Rule: {finding.rule_id} 
- Title: {finding.title}
- Current Severity: {finding.severity.value.upper()}
- Description: {finding.description}

**Code Context:**
- File: {finding.file_path}
- Line: {finding.line_number}
- Code: {finding.code_snippet}

**Analysis Required:**
1. Validate if this is a true positive or false positive
2. Assess if the severity level is appropriate 
3. Provide additional context about the vulnerability
4. Suggest specific remediation steps

**Project Context:**
- Target: {target_path}
- File extension suggests: {finding.file_path.suffix}

Please provide:
1. **Accuracy**: True/False positive assessment
2. **Severity**: Confirm or suggest different severity (LOW/MEDIUM/HIGH/CRITICAL)  
3. **Context**: Additional security implications
4. **Remediation**: Specific fix recommendations

Focus on practical, actionable security insights.
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
            Severity.CRITICAL: 4
        }
        
        finding_level = severity_order.get(severity, 1)
        threshold_level = severity_order.get(self.config.min_severity, 2)
        
        return finding_level >= threshold_level
    
    def _get_severity_breakdown(self, findings: List[Finding]) -> Dict[str, int]:
        """Get count of findings by severity level"""
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0, 
            "low": 0
        }
        
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
        capabilities.update({
            "agent_type": "static_analysis",
            "supported_languages": ["python", "javascript", "java", "go", "php"],
            "analysis_types": ["security", "code_quality", "best_practices"],
            "ai_enhanced": True,
            "mandatory_citations": True
        })
        return capabilities