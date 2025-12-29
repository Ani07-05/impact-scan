"""
AI Fix Generator tool for code fixes.

Wraps AIFixProvider as an observable, callable tool.
"""

from typing import Optional, List, Dict, Any
from . import BaseTool
from ..core.fix_ai import get_ai_fix_provider, AIFixProvider, AIFixError
from ..utils import schema


class AIFixGeneratorTool(BaseTool):
    """
    Tool for AI-powered fix generation with Stack Overflow context.

    This tool generates code fixes using AI, optionally incorporating
    Stack Overflow community solutions for better accuracy.

    Features:
    - Multi-provider support (Groq, OpenAI, Anthropic, Gemini)
    - Stack Overflow-guided fix generation
    - Unified diff format output
    - Observable logging of generation process
    """

    def __init__(self, provider: str = "groq", api_key: Optional[str] = None):
        """
        Initialize AI Fix Generator tool.

        Args:
            provider: AI provider to use (groq, openai, anthropic, gemini)
            api_key: API key for the provider

        Raises:
            ValueError: If api_key is not provided
            AIFixError: If provider is invalid
        """
        if not api_key:
            raise ValueError(f"API key is required for AI fix generation (provider: {provider})")

        super().__init__("ai_fix_generator")
        self.provider_name = provider

        # Create provider instance with simple signature
        # Note: get_ai_fix_provider expects APIKeys object, so we'll create provider directly
        from ..core.fix_ai import GroqFixProvider, OpenAIFixProvider, AnthropicFixProvider, GeminiFixProvider

        provider_map = {
            'groq': GroqFixProvider,
            'openai': OpenAIFixProvider,
            'anthropic': AnthropicFixProvider,
            'gemini': GeminiFixProvider
        }

        provider_class = provider_map.get(provider)
        if not provider_class:
            raise AIFixError(f"Unknown provider: {provider}")

        self.provider = provider_class(api_key)

    def _execute_internal(
        self,
        finding: schema.Finding,
        stackoverflow_solutions: Optional[List[schema.StackOverflowFix]] = None
    ) -> str:
        """
        Generate AI-powered code fix.

        Args:
            finding: The vulnerability to fix
            stackoverflow_solutions: Optional Stack Overflow context to guide fix

        Returns:
            Generated fix as unified diff/patch

        Raises:
            Exception: If AI fix generation fails
        """
        self.logger.info(f"[AI Fix Generator] Generating fix for: {finding.title}")

        # Attach Stack Overflow context to finding if provided
        if stackoverflow_solutions:
            finding.stackoverflow_fixes = stackoverflow_solutions
            self.logger.debug(
                f"[AI Fix Generator] Using {len(stackoverflow_solutions)} "
                "Stack Overflow solutions as context"
            )

            # Log the top solution being used
            if stackoverflow_solutions:
                top_solution = stackoverflow_solutions[0]
                self.logger.debug(
                    f"[AI Fix Generator] Top solution: {top_solution.title} "
                    f"({top_solution.votes} votes, accepted={top_solution.accepted})"
                )
        else:
            self.logger.debug("[AI Fix Generator] No Stack Overflow context, using pure AI generation")

        # Generate fix using provider
        try:
            fix = self.provider.generate_fix(finding)

            self.logger.info(f"[AI Fix Generator] Generated fix ({len(fix)} characters)")
            self.logger.debug(f"[AI Fix Generator] Fix preview: {fix[:100]}...")

            return fix

        except Exception as e:
            self.logger.error(f"[AI Fix Generator] Failed to generate fix: {str(e)}")
            raise

    def _get_metadata(self) -> Dict[str, Any]:
        """
        Get tool execution metadata.

        Returns:
            Dict with tool name, provider, and configuration
        """
        return {
            "tool": self.name,
            "provider": self.provider_name,
            "fix_format": "unified_diff"
        }


__all__ = ['AIFixGeneratorTool']
