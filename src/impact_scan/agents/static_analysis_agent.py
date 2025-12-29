"""
Static Analysis Security Agent

Specialized agent for performing comprehensive static code analysis
using observable, callable tools.
"""

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Union

from ..tools.ripgrep_tool import RipgrepTool
from ..tools.ai_validator_tool import AIValidatorTool
from ..tools.stackoverflow_tool import StackOverflowTool
from ..tools.ai_fix_generator_tool import AIFixGeneratorTool
from ..utils.schema import Finding, ScanConfig, Severity
from .base import AgentResult, AgentStatus, MultiModelAgent


class StaticAnalysisAgent(MultiModelAgent):
    """
    Specialized agent for static code analysis with AI-enhanced vulnerability detection.

    This agent uses observable tools in sequence:
    1. RipgrepTool - Fast pattern-based scanning
    2. AIValidatorTool - AI-powered false positive filtering
    3. StackOverflowTool - Community solution enrichment
    4. AIFixGeneratorTool - AI-powered fix generation
    """

    # Agent metadata for factory registration
    required_tools = []  # Ripgrep is bundled, no external tools required
    default_tools = []
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
        Execute static analysis using observable tool calls.

        Tool execution sequence:
        1. RipgrepTool - Generate context, rules, and scan
        2. AIValidatorTool - Filter false positives (if enabled)
        3. StackOverflowTool - Enrich with community solutions (if enabled)
        4. AIFixGeneratorTool - Generate AI fixes (if enabled)
        """
        target_path = Path(target) if isinstance(target, str) else target

        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target_path}")

        print(f"[{self.name}] Starting static analysis of: {target_path}")

        # Step 1: Run ripgrep scan (observable tool call)
        ripgrep_tool = RipgrepTool(
            root_path=target_path,
            groq_api_key=os.getenv("GROQ_API_KEY")
        )

        rg_result = await asyncio.to_thread(
            ripgrep_tool.execute,
            generate_context=True,
            generate_rules=True,
            scan=True
        )

        if not rg_result.success:
            result.status = AgentStatus.FAILED
            result.data["error"] = rg_result.error
            print(f"[{self.name}] Ripgrep scan failed: {rg_result.error}")
            return

        findings = rg_result.data.get('findings', [])
        context_file = rg_result.data.get('context_file')

        # Step 2: AI Validation (if enabled and API key available)
        if os.getenv("GROQ_API_KEY") and hasattr(self.config, 'ai_validation') and self.config.ai_validation:
            try:
                ai_validator_tool = AIValidatorTool(
                    root_path=target_path,
                    groq_api_key=os.getenv("GROQ_API_KEY")
                )

                val_result = await asyncio.to_thread(
                    ai_validator_tool.execute,
                    findings=findings,
                    knowledge_graph=context.get('knowledge_graph'),
                    repo_graph=context.get('repo_graph')
                )

                if val_result.success:
                    findings = val_result.data
                else:
                    print(f"[{self.name}] AI validation failed: {val_result.error}. Keeping all findings.")

            except ValueError as e:
                print(f"[{self.name}] Skipping AI validation: {str(e)}")
            except Exception as e:
                print(f"[{self.name}] AI validation error: {str(e)}. Keeping all findings.")

        # Step 3: Stack Overflow enrichment (if enabled)
        stackoverflow_enabled = hasattr(self.config, 'stackoverflow') and self.config.stackoverflow
        if stackoverflow_enabled and findings:
            so_tool = StackOverflowTool(max_answers=3, scrape_delay=4.0)

            for finding in findings:
                try:
                    so_result = await asyncio.to_thread(
                        so_tool.execute,
                        finding=finding
                    )

                    if so_result.success:
                        finding.stackoverflow_fixes = so_result.data

                except Exception as e:
                    print(f"[{self.name}] Stack Overflow lookup failed for {finding.title}: {str(e)}")

        # Step 4: AI Fix Generation (if enabled)
        ai_fix_enabled = (
            hasattr(self.config, 'enable_ai_fixes') and
            self.config.enable_ai_fixes and
            os.getenv("GROQ_API_KEY")
        )

        if ai_fix_enabled and findings:
            try:
                fix_tool = AIFixGeneratorTool(
                    provider="groq",
                    api_key=os.getenv("GROQ_API_KEY")
                )

                for finding in findings:
                    try:
                        fix_result = await asyncio.to_thread(
                            fix_tool.execute,
                            finding=finding,
                            stackoverflow_solutions=finding.stackoverflow_fixes if hasattr(finding, 'stackoverflow_fixes') else None
                        )

                        if fix_result.success:
                            finding.ai_fix = fix_result.data

                    except Exception as e:
                        print(f"[{self.name}] AI fix generation failed for {finding.title}: {str(e)}")

            except ValueError as e:
                print(f"[{self.name}] Skipping AI fix generation: {str(e)}")
            except Exception as e:
                print(f"[{self.name}] AI fix generation error: {str(e)}")

        # Step 5: Populate results
        result.findings = findings
        result.status = AgentStatus.COMPLETED
        result.data.update({
            "scan_type": "static_analysis",
            "target_path": str(target_path),
            "context_file": str(context_file) if context_file else None,
            "tools_used": ["ripgrep", "ai_validator", "stackoverflow", "ai_fix_generator"],
            "findings_count": len(findings),
            "severity_breakdown": self._get_severity_breakdown(findings),
        })

        print(f"[{self.name}] Completed analysis: {len(findings)} findings")


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
