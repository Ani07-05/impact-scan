"""
AI-powered finding validation to reduce false positives.

This module uses Large Language Models to validate security findings from static analysis,
reducing false positives by providing contextual analysis of the code.

Based on research showing 91% false positive reduction using AI validation
(SAST-Genius framework, arXiv 2509.15433).
"""

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Tuple

from ..utils import schema
from . import fix_ai, repo_graph_integration

if TYPE_CHECKING:  # Only for type hints, do not require gh_repo_kg at runtime
    from gh_repo_kg.api import RepositoryGraph
    from .knowledge_graph import KnowledgeGraph

logger = logging.getLogger(__name__)


class AIValidator:
    """
    Validates security findings using LLM contextual analysis.

    Uses the same AI providers as fix generation (OpenAI, Anthropic, Gemini, Groq)
    to analyze whether a finding is a true positive or false positive.
    """

    # Validation prompt template - concise to minimize token usage
    _VALIDATION_PROMPT = """You are a security expert reviewing a potential vulnerability.
Analyze this finding and determine if it is a TRUE POSITIVE or FALSE POSITIVE.

Vulnerability Report:
- ID: {vuln_id}
- Title: {title}
- Severity: {severity}
- File: {file_path}:{line_number}

Code Context:
{code_snippet}

Repository Context:
{repo_context}

Description:
{description}

Consider:
1. Is the vulnerable pattern actually exploitable in this context?
2. Are there mitigating controls in the surrounding code or other files?
3. Is this a common false positive pattern (e.g., test code, commented code, framework-safe helpers)?
4. Does the wider project context make this safe (e.g., templating auto-escaping, safe URL builders)?

Respond with ONLY ONE of:
TRUE_POSITIVE: [brief reason why this is exploitable]
FALSE_POSITIVE: [brief reason why this is not exploitable]

Do not include any other text."""

    def __init__(
        self,
        ai_provider: fix_ai.AIFixProvider,
        *,
        repo_graph: Optional["RepositoryGraph"] = None,
        knowledge_graph: Optional["KnowledgeGraph"] = None,
        root_path: Optional[Path] = None,
    ):
        """Initialize AI validator with an AI provider and optional graphs.

        Args:
            ai_provider: Instance of AIFixProvider (OpenAI, Anthropic, Gemini, or Groq)
            repo_graph: Optional RepositoryGraph with structural context
            knowledge_graph: Optional KnowledgeGraph with semantic context
            root_path: Root of the scanned project (for future use)
        """
        self.ai_provider = ai_provider
        self.repo_graph = repo_graph
        self.knowledge_graph = knowledge_graph
        self.root_path = root_path
        self._validation_count = 0
        self._true_positive_count = 0
        self._false_positive_count = 0

    def _get_code_context(self, finding: schema.Finding, context_lines: int = 5) -> str:
        """
        Extract code context around the finding for better AI analysis.

        Args:
            finding: The security finding to get context for
            context_lines: Number of lines before/after to include

        Returns:
            Code snippet with line numbers
        """
        try:
            file_path = Path(finding.file_path)
            if not file_path.exists():
                return finding.code_snippet or "Code not available"

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Get line number (default to 0 if not set)
            line_num = getattr(finding, "line_number", 0) or 0

            # Calculate context range
            start = max(0, line_num - context_lines - 1)
            end = min(len(lines), line_num + context_lines)

            # Format with line numbers
            context = []
            for i in range(start, end):
                prefix = ">>> " if i == line_num - 1 else "    "
                context.append(f"{prefix}{i + 1}: {lines[i].rstrip()}")

            return "\n".join(context)

        except Exception as e:
            logger.debug(f"Could not read file context: {e}")
            return finding.code_snippet or "Code not available"

    def _get_repo_context(self, finding: schema.Finding) -> str:
        """Build a short repository/semantic context string for the LLM prompt."""

        parts: List[str] = []

        # KnowledgeGraph classification (file type / risk)
        if self.knowledge_graph is not None:
            file_meta = self.knowledge_graph.files.get(str(finding.file_path))
            if file_meta:
                parts.append(
                    f"File classification: {file_meta.file_type} (risk: {file_meta.risk_level})"
                )

        # RepositoryGraph structure (imports, imported-by, neighbors)
        if self.repo_graph is not None:
            graph_ctx = repo_graph_integration.build_graph_context_for_finding(
                self.repo_graph,
                finding,
            )
            if graph_ctx:
                parts.append(graph_ctx)

        return "\n".join(parts)

    def validate_finding(self, finding: schema.Finding) -> Tuple[bool, str]:
        """
        Validate a single finding using AI analysis.

        Args:
            finding: The security finding to validate

        Returns:
            Tuple of (is_true_positive: bool, reason: str)
        """
        self._validation_count += 1

        # Get code context for better analysis
        code_context = self._get_code_context(finding)
        repo_context = self._get_repo_context(finding)

        # Prepare prompt with finding details
        prompt = self._VALIDATION_PROMPT.format(
            vuln_id=finding.vuln_id,
            title=finding.title,
            severity=finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity),
            file_path=finding.file_path,
            line_number=getattr(finding, "line_number", "unknown"),
            code_snippet=code_context,
            repo_context=repo_context or "No additional repository context available.",
            description=finding.description[:500],  # Limit description length
        )

        try:
            logger.debug(
                f"AI validating finding: {finding.vuln_id} in {finding.file_path}"
            )
            response = self.ai_provider.generate_content(prompt)

            # Parse response
            response = response.strip()

            if response.startswith("TRUE_POSITIVE"):
                reason = (
                    response.split(":", 1)[1].strip()
                    if ":" in response
                    else "AI confirmed vulnerability"
                )
                self._true_positive_count += 1
                logger.info(
                    f"AI validated as TRUE_POSITIVE: {finding.vuln_id} - {reason}"
                )
                return True, reason

            elif response.startswith("FALSE_POSITIVE"):
                reason = (
                    response.split(":", 1)[1].strip()
                    if ":" in response
                    else "AI identified as false positive"
                )
                self._false_positive_count += 1
                logger.info(
                    f"AI validated as FALSE_POSITIVE: {finding.vuln_id} - {reason}"
                )
                return False, reason

            else:
                # Ambiguous response - default to TRUE_POSITIVE to avoid hiding real vulnerabilities
                logger.warning(
                    f"Ambiguous AI response for {finding.vuln_id}: {response[:100]}"
                )
                self._true_positive_count += 1
                return True, "AI validation inconclusive - kept as precaution"

        except Exception as e:
            # Fail-open: Keep finding if AI validation errors
            logger.error(f"AI validation failed for {finding.vuln_id}: {e}")
            self._true_positive_count += 1
            return True, f"Validation error: {str(e)}"

    def validate_findings(
        self, findings: List[schema.Finding], max_findings: Optional[int] = None
    ) -> Tuple[List[schema.Finding], List[schema.Finding]]:
        """
        Validate multiple findings using AI.

        Args:
            findings: List of security findings to validate
            max_findings: Optional limit on number of findings to validate (for cost control)

        Returns:
            Tuple of (true_positives: List[Finding], false_positives: List[Finding])
        """
        if not findings:
            return [], []

        # Limit findings if requested (e.g., for cost control)
        findings_to_validate = findings[:max_findings] if max_findings else findings
        skipped = len(findings) - len(findings_to_validate) if max_findings else 0

        if skipped > 0:
            logger.warning(
                f"Validating only {len(findings_to_validate)} of {len(findings)} findings (limit: {max_findings})"
            )

        logger.info(f"AI validating {len(findings_to_validate)} findings...")

        true_positives = []
        false_positives = []

        for finding in findings_to_validate:
            is_valid, reason = self.validate_finding(finding)

            # Add validation metadata to finding
            if not hasattr(finding, "metadata") or finding.metadata is None:
                finding.metadata = {}

            finding.metadata["ai_validated"] = True
            finding.metadata["ai_validation_reason"] = reason
            finding.metadata["ai_validation_result"] = (
                "TRUE_POSITIVE" if is_valid else "FALSE_POSITIVE"
            )

            if is_valid:
                true_positives.append(finding)
            else:
                false_positives.append(finding)

        # Log summary statistics
        reduction_pct = (
            (len(false_positives) / len(findings_to_validate) * 100)
            if findings_to_validate
            else 0
        )
        logger.info(
            f"AI validation complete: {len(true_positives)} true positives, "
            f"{len(false_positives)} false positives ({reduction_pct:.1f}% reduction)"
        )

        return true_positives, false_positives

    def get_stats(self) -> dict:
        """Get validation statistics."""
        return {
            "total_validated": self._validation_count,
            "true_positives": self._true_positive_count,
            "false_positives": self._false_positive_count,
            "false_positive_rate": (
                self._false_positive_count / self._validation_count * 100
                if self._validation_count > 0
                else 0
            ),
        }


def validate_with_ai(
    findings: List[schema.Finding],
    config: schema.ScanConfig,
    *,
    repo_graph: Optional["RepositoryGraph"] = None,
    knowledge_graph: Optional["KnowledgeGraph"] = None,
) -> List[schema.Finding]:
    """
    Public API for AI validation of security findings.

    This function integrates with the existing entrypoint.py workflow.

    Args:
        findings: List of findings to validate
        config: Scan configuration (must have enable_ai_validation=True)

    Returns:
        Filtered list of findings (false positives removed)

    Raises:
        No exceptions - fails open if AI validation fails
    """
    # Check if AI validation is enabled
    enable_validation = getattr(config, "enable_ai_validation", False)
    if not enable_validation:
        logger.debug("AI validation disabled")
        return findings

    if not findings:
        logger.debug("No findings to validate")
        return findings

    try:
        # Initialize AI provider
        logger.info("Initializing AI provider for validation...")
        api_keys = config.api_keys

        # Get AI provider - either from config or auto-detect
        ai_provider_name = getattr(config, "ai_validation_provider", None)
        if ai_provider_name:
            logger.info(
                f"Using specified AI provider for validation: {ai_provider_name}"
            )

        ai_provider = fix_ai.get_ai_fix_provider(
            api_keys, provider_override=ai_provider_name
        )

        # Create validator with optional graphs
        validator = AIValidator(
            ai_provider,
            repo_graph=repo_graph,
            knowledge_graph=knowledge_graph,
            root_path=Path(config.root_path),
        )

        # Validate findings
        max_findings = getattr(config, "ai_validation_max_findings", None)
        true_positives, false_positives = validator.validate_findings(
            findings, max_findings
        )

        # Log statistics
        stats = validator.get_stats()
        logger.info(f"AI Validation Stats: {stats}")

        # Optionally save false positives for review
        if getattr(config, "save_false_positives", False) and false_positives:
            _save_false_positives(false_positives, config)

        return true_positives

    except fix_ai.AIFixError as e:
        logger.error(f"AI validation initialization failed: {e}")
        logger.warning("Proceeding without AI validation - all findings kept")
        return findings

    except Exception as e:
        logger.error(f"Unexpected error during AI validation: {e}", exc_info=True)
        logger.warning("Proceeding without AI validation - all findings kept")
        return findings


def _save_false_positives(
    false_positives: List[schema.Finding], config: schema.ScanConfig
) -> None:
    """
    Save false positives to a file for later review.

    Args:
        false_positives: List of findings identified as false positives
        config: Scan configuration
    """
    try:
        output_path = config.root_path / "ai_false_positives.json"

        data = {
            "false_positives": [
                {
                    "vuln_id": f.vuln_id,
                    "title": f.title,
                    "severity": f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity),
                    "file_path": str(f.file_path),
                    "line_number": getattr(f, "line_number", None),
                    "ai_reason": f.metadata.get("ai_validation_reason")
                    if f.metadata
                    else None,
                }
                for f in false_positives
            ],
            "total_false_positives": len(false_positives),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(false_positives)} false positives to {output_path}")

    except Exception as e:
        logger.error(f"Failed to save false positives: {e}")
