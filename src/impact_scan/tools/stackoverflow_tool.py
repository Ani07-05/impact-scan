"""
Stack Overflow tool for finding solutions.

Wraps Stack Overflow scraper as an observable, callable tool.
"""

from typing import List, Dict, Any
from . import BaseTool
from ..core.stackoverflow_scraper import search_and_scrape_solutions
from ..utils import schema


class StackOverflowTool(BaseTool):
    """
    Tool for finding Stack Overflow solutions for vulnerabilities.

    This tool searches Stack Overflow for community solutions to security
    vulnerabilities, providing code examples and explanations.

    Features:
    - Hybrid scraping (Parse.bot API + Playwright fallback)
    - Advanced rate limiting with token bucket algorithm
    - Persistent caching to reduce redundant requests
    - Circuit breaker for 429 errors
    - Observable logging of search process
    """

    def __init__(self, max_answers: int = 3, scrape_delay: float = 4.0):
        """
        Initialize Stack Overflow tool.

        Args:
            max_answers: Maximum number of solutions to fetch per vulnerability
            scrape_delay: Delay between requests in seconds (for rate limiting)
        """
        super().__init__("stackoverflow")
        self.max_answers = max_answers
        self.scrape_delay = scrape_delay

    def _execute_internal(
        self,
        finding: schema.Finding
    ) -> List[schema.StackOverflowFix]:
        """
        Search Stack Overflow for solutions to a vulnerability.

        Args:
            finding: The vulnerability finding to search for

        Returns:
            List of StackOverflowFix objects with code snippets and explanations

        Raises:
            Exception: If Stack Overflow search/scraping fails
        """
        # Build search query from vulnerability metadata
        query_parts = [finding.title]

        if finding.vuln_id and finding.vuln_id != "UNKNOWN":
            query_parts.append(finding.vuln_id)

        # Include CWE if available in metadata
        if 'cwe' in finding.metadata:
            query_parts.append(f"CWE-{finding.metadata['cwe']}")

        query = " ".join(query_parts)
        self.logger.info(f"[Stack Overflow] Searching solutions for: {query}")

        # Search and scrape solutions
        solutions = search_and_scrape_solutions(
            finding=finding,
            max_results=self.max_answers,
            scrape_delay=self.scrape_delay
        )

        if solutions:
            self.logger.info(f"[Stack Overflow] Found {len(solutions)} relevant solutions")

            # Log solution details
            for i, solution in enumerate(solutions, 1):
                self.logger.debug(
                    f"[Stack Overflow] Solution {i}: {solution.title} "
                    f"({solution.votes} votes, accepted={solution.accepted})"
                )
        else:
            self.logger.warning(f"[Stack Overflow] No solutions found for: {query}")

        return solutions

    def _get_metadata(self) -> Dict[str, Any]:
        """
        Get tool execution metadata.

        Returns:
            Dict with tool name, configuration, and scraping settings
        """
        return {
            "tool": self.name,
            "max_answers": self.max_answers,
            "scrape_delay": self.scrape_delay,
            "scraping_method": "hybrid"  # Parse.bot + Playwright fallback
        }


__all__ = ['StackOverflowTool']
