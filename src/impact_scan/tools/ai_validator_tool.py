"""
AI Validator tool for false positive filtering.

Wraps AIValidator as an observable, callable tool.
"""

from pathlib import Path
from typing import List, Optional, Any, Dict
from . import BaseTool
from ..core.ai_validator import AIValidator
from ..core.fix_ai import GroqFixProvider
from ..utils import schema


class AIValidatorTool(BaseTool):
    """
    Tool for AI-powered false positive filtering.

    This tool uses Groq API to validate findings and filter out false positives
    using contextual code analysis and repository knowledge.

    Features:
    - Context-aware validation using knowledge graphs
    - ~91% false positive reduction (based on research)
    - Detailed reasoning for each validation decision
    - Observable logging of validation process
    """

    def __init__(self, root_path: Path, groq_api_key: str):
        """
        Initialize AI Validator tool.

        Args:
            root_path: Root directory of the codebase
            groq_api_key: Groq API key for AI validation

        Raises:
            ValueError: If groq_api_key is not provided
        """
        if not groq_api_key:
            raise ValueError("Groq API key is required for AI validation")

        super().__init__("ai_validator")
        self.root_path = Path(root_path)

        # Create Groq AI provider
        ai_provider = GroqFixProvider(api_key=groq_api_key)

        # Initialize AIValidator with the provider
        self.validator = AIValidator(
            ai_provider=ai_provider,
            root_path=root_path
        )

    def _execute_internal(
        self,
        findings: List[schema.Finding],
        knowledge_graph=None,
        repo_graph=None
    ) -> List[schema.Finding]:
        """
        Validate findings using AI to filter false positives.

        Args:
            findings: List of findings to validate
            knowledge_graph: Optional KnowledgeGraph for context
            repo_graph: Optional RepositoryGraph for context

        Returns:
            Filtered list of true positive findings

        Raises:
            Exception: If AI validation fails
        """
        if not findings:
            self.logger.info("[AI Validator] No findings to validate")
            return []

        self.logger.info(f"[AI Validator] Validating {len(findings)} findings with Groq API...")

        validated = []
        false_positives = []

        for i, finding in enumerate(findings, 1):
            self.logger.debug(
                f"[AI Validator] ({i}/{len(findings)}) Checking {finding.title} "
                f"at {finding.file_path}:{finding.line_number}"
            )

            try:
                validation_result = self.validator.validate_finding(
                    finding=finding,
                    code_snippet=finding.code_snippet,
                    knowledge_graph=knowledge_graph,
                    repo_graph=repo_graph
                )

                if validation_result.get('is_valid', False):
                    validated.append(finding)
                    self.logger.debug(f"[AI Validator] ✓ TRUE POSITIVE: {finding.title}")
                else:
                    false_positives.append(finding)
                    reason = validation_result.get('reason', 'No reason provided')
                    self.logger.debug(f"[AI Validator] ✗ FALSE POSITIVE: {finding.title} - {reason}")

            except Exception as e:
                # If validation fails for a specific finding, log error but continue
                self.logger.warning(
                    f"[AI Validator] Failed to validate {finding.title}: {str(e)}. "
                    "Keeping finding as potential vulnerability."
                )
                validated.append(finding)  # Keep finding if validation fails

        # Calculate and log statistics
        original_count = len(findings)
        validated_count = len(validated)
        filtered_count = len(false_positives)
        reduction_rate = (filtered_count / original_count * 100) if original_count > 0 else 0

        self.logger.info(
            f"[AI Validator] Filtered {filtered_count} false positives "
            f"({reduction_rate:.1f}% reduction)"
        )
        self.logger.info(f"[AI Validator] {validated_count} true positives remain")

        return validated

    def _get_metadata(self) -> Dict[str, Any]:
        """
        Get tool execution metadata.

        Returns:
            Dict with tool name, configuration, and statistics
        """
        return {
            "tool": self.name,
            "root_path": str(self.root_path),
            "provider": "groq",
            "has_knowledge_graph": hasattr(self.validator, 'knowledge_graph')
        }


__all__ = ['AIValidatorTool']
