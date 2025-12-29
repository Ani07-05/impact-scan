"""
Ripgrep tool for code scanning.

Wraps RipgrepScanner as an observable, callable tool.
"""

from pathlib import Path
from typing import Any, Dict, Optional, List
from . import BaseTool
from ..core.ripgrep_scanner import RipgrepScanner
from ..utils import schema


class RipgrepTool(BaseTool):
    """
    Tool for executing ripgrep-based code searches.

    This tool wraps the RipgrepScanner to provide observable execution with
    standardized logging and error handling.

    Features:
    - Generates codebase context (impact-scan.md)
    - Generates security rules (impact-scan.yml)
    - Executes pattern-based vulnerability scanning
    - Returns findings with line numbers and code snippets
    """

    def __init__(self, root_path: Path, groq_api_key: Optional[str] = None):
        """
        Initialize Ripgrep tool.

        Args:
            root_path: Root directory of the codebase to scan
            groq_api_key: Optional Groq API key for AI enhancements
        """
        super().__init__("ripgrep")
        self.root_path = Path(root_path)
        self.scanner = RipgrepScanner(self.root_path, groq_api_key)

    def _execute_internal(
        self,
        generate_context: bool = True,
        generate_rules: bool = True,
        scan: bool = True
    ) -> Dict[str, Any]:
        """
        Execute ripgrep scanning workflow.

        Args:
            generate_context: Generate impact-scan.md codebase context
            generate_rules: Generate impact-scan.yml security rules
            scan: Execute vulnerability scanning

        Returns:
            Dict containing:
                - context_file: Path to impact-scan.md
                - rules_file: Path to impact-scan.yml
                - findings: List[Finding] of discovered vulnerabilities

        Raises:
            Exception: If ripgrep execution fails
        """
        result = {}

        if generate_context:
            self.logger.info("[Ripgrep] Generating codebase context (impact-scan.md)...")
            context_file = self.scanner.generate_codebase_context()
            result['context_file'] = context_file
            self.logger.debug(f"[Ripgrep] Context saved to: {context_file}")

        if generate_rules:
            self.logger.info("[Ripgrep] Generating security rules (impact-scan.yml)...")
            rules_file = self.scanner.generate_scan_rules()
            result['rules_file'] = rules_file
            self.logger.debug(f"[Ripgrep] Rules saved to: {rules_file}")

        if scan:
            self.logger.info("[Ripgrep] Executing pattern-based scan...")

            # Use generated rules if available, otherwise scanner will generate them
            rules_file = result.get('rules_file')
            findings = self.scanner.scan_with_rules(rules_file)

            result['findings'] = findings
            self.logger.info(f"[Ripgrep] Found {len(findings)} potential vulnerabilities")

            # Log severity breakdown
            if findings:
                severity_breakdown = {}
                for finding in findings:
                    severity = finding.severity.value
                    severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

                self.logger.debug(f"[Ripgrep] Severity breakdown: {severity_breakdown}")

        return result

    def _get_metadata(self) -> Dict[str, Any]:
        """
        Get tool execution metadata.

        Returns:
            Dict with tool name, version, and configuration
        """
        return {
            "tool": self.name,
            "root_path": str(self.root_path),
            "ripgrep_available": self.scanner._is_ripgrep_available() if hasattr(self.scanner, '_is_ripgrep_available') else True
        }


__all__ = ['RipgrepTool']
