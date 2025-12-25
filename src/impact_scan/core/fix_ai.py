import abc
import logging
from typing import Dict, List, Optional, Type

from ..utils import schema

# Set up logging
logger = logging.getLogger(__name__)


class AIFixError(Exception):
    """Custom exception for AI fix generation failures."""

    pass


class AIFixProvider(abc.ABC):
    """Abstract base class for AI fix suggestion providers."""

    _PROMPT_TEMPLATE = """
You are an expert security engineer. Your task is to fix a vulnerability in the following code snippet.
Provide a fix in the form of a standard unified diff format ONLY.
Do not add any explanations, conversational text, or markdown code fences like ```diff.

Vulnerability Details:
- ID: {vuln_id}
- Title: {title}
- Description: {description}

Vulnerable Code from `{file_path}` at line {line_number}:
{code_snippet}
Respond with the unified diff to fix the vulnerability.
"""

    _SO_GUIDED_PROMPT_TEMPLATE = """
You are an expert security engineer. Your task is to adapt a Stack Overflow solution to fix a specific vulnerability in the user's codebase.

IMPORTANT: Base your fix on the Stack Overflow solution provided below, but adapt it to the user's specific code context.

Vulnerability Details:
- ID: {vuln_id}
- Title: {title}
- Description: {description}

User's Vulnerable Code from `{file_path}` at line {line_number}:
{code_snippet}

Stack Overflow Community Solution:
{stackoverflow_solution}

Your task:
1. Review the Stack Overflow solution carefully
2. Adapt it to fix the user's specific vulnerable code above
3. Provide a fix in standard unified diff format ONLY
4. Do not add explanations, conversational text, or markdown code fences

Respond with the unified diff that applies the Stack Overflow solution to the user's code.
"""

    def _format_stackoverflow_solution(self, finding: schema.Finding) -> Optional[str]:
        """Format Stack Overflow solutions for inclusion in AI prompt."""
        if not finding.stackoverflow_fixes or len(finding.stackoverflow_fixes) == 0:
            return None

        # Use the top-voted/accepted answer
        top_answer = finding.stackoverflow_fixes[0]

        solution_text = f"Answer from Stack Overflow (Votes: {top_answer.votes}"
        if top_answer.accepted:
            solution_text += ", ACCEPTED"
        solution_text += f", by {top_answer.author}):\n\n"

        # Include the answer explanation
        if top_answer.answer_text:
            solution_text += f"{top_answer.answer_text[:500]}\n\n"

        # Include code snippets
        if top_answer.code_snippets:
            solution_text += "Code from Stack Overflow:\n"
            for i, code in enumerate(top_answer.code_snippets[:2], 1):  # Top 2 code blocks
                solution_text += f"\nCode Block {i}:\n{code}\n"

        solution_text += f"\nSource: {top_answer.url}"

        return solution_text

    def generate_fix(self, finding: schema.Finding) -> str:
        """
        Generate fix for a finding, optionally guided by Stack Overflow solutions.
        This method is now in the base class to avoid duplication across providers.
        """
        so_solution = self._format_stackoverflow_solution(finding)

        if so_solution:
            # Use SO-guided template - AI adapts community solution
            prompt_data = finding.model_dump()
            prompt_data['stackoverflow_solution'] = so_solution
            prompt = self._SO_GUIDED_PROMPT_TEMPLATE.format(**prompt_data)
            logger.info(f"Using Stack Overflow-guided AI fix for: {finding.title}")
        else:
            # Fall back to pure AI fix generation
            prompt = self._PROMPT_TEMPLATE.format(**finding.model_dump())
            logger.debug(f"Using pure AI fix generation for: {finding.title}")

        return self.generate_content(prompt)

    @abc.abstractmethod
    def generate_content(self, prompt: str) -> str:
        """Generates content for a given prompt."""
        raise NotImplementedError


class OpenAIFixProvider(AIFixProvider):
    def __init__(self, api_key: str):
        import openai

        self.client = openai.OpenAI(api_key=api_key)
        self.openai_module = openai

    def generate_content(self, prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
            )
            return response.choices[0].message.content.strip()
        except self.openai_module.APIError as e:
            raise AIFixError(f"OpenAI API error: {e}") from e


class AnthropicFixProvider(AIFixProvider):
    def __init__(self, api_key: str):
        import anthropic

        self.client = anthropic.Anthropic(api_key=api_key)
        self.anthropic_module = anthropic

    def generate_content(self, prompt: str) -> str:
        try:
            response = self.client.messages.create(
                model="claude-3-haiku-20240307",
                system="You are an expert security engineer providing code fixes as unified diffs.",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.0,
            )
            return response.content[0].text.strip()
        except self.anthropic_module.APIError as e:
            raise AIFixError(f"Anthropic API error: {e}") from e


class GeminiFixProvider(AIFixProvider):
    def __init__(self, api_key: str):
        from google import genai

        self.client = genai.Client(api_key=api_key)

    def generate_content(self, prompt: str) -> str:
        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash", contents=prompt
            )
            return response.text.strip()
        except Exception as e:
            raise AIFixError(f"Gemini API error: {e}") from e


class GroqFixProvider(AIFixProvider):
    def __init__(self, api_key: str):
        from groq import Groq

        self.client = Groq(api_key=api_key)

    def generate_content(self, prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=2048,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise AIFixError(f"Groq API error: {e}") from e


_PROVIDER_MAP: Dict[str, Type[AIFixProvider]] = {
    "openai": OpenAIFixProvider,
    "anthropic": AnthropicFixProvider,
    "gemini": GeminiFixProvider,
    "groq": GroqFixProvider,
}


def auto_detect_provider(api_keys: schema.APIKeys) -> Optional[AIFixProvider]:
    """
    Auto-detect the first available AI provider based on API keys.

    Priority order: groq -> gemini -> openai -> anthropic

    Args:
        api_keys: API keys for various providers

    Returns:
        Instance of AIFixProvider or None if no API key found
    """
    # Priority order for auto-detection
    priority_order = ["groq", "gemini", "openai", "anthropic"]

    for provider_name in priority_order:
        api_key = getattr(api_keys, provider_name, None)
        if api_key:
            provider_class = _PROVIDER_MAP.get(provider_name)
            if provider_class:
                logger.info(f"Auto-detected AI provider: {provider_name}")
                return provider_class(api_key)

    return None


def get_ai_fix_provider(
    api_keys: schema.APIKeys, provider_override: Optional[str] = None
) -> AIFixProvider:
    """
    Factory function to get the first available AI fix provider.

    Args:
        api_keys: API keys for various providers
        provider_override: Optional provider name to use (groq, gemini, openai, anthropic)

    Returns:
        Instance of AIFixProvider

    Raises:
        AIFixError: If no API key is found or provider override is invalid
    """
    # If provider override specified, try that first
    if provider_override:
        api_key = getattr(api_keys, provider_override, None)
        if not api_key:
            raise AIFixError(
                f"Provider '{provider_override}' specified but no API key found"
            )

        provider_class = _PROVIDER_MAP.get(provider_override)
        if not provider_class:
            raise AIFixError(f"Unknown provider: '{provider_override}'")

        return provider_class(api_key)

    # Otherwise, auto-detect first available provider
    for provider_name, api_key in api_keys.model_dump().items():
        if api_key:
            provider_class = _PROVIDER_MAP.get(provider_name)
            if provider_class:
                return provider_class(api_key)

    raise AIFixError("No AI provider API key found.")


def generate_fixes(findings: List[schema.Finding], config: schema.ScanConfig) -> None:
    """
    Generates AI-powered fix suggestions for a list of findings.
    """
    if not config.enable_ai_fixes:
        return

    try:
        fix_provider = get_ai_fix_provider(config.api_keys)
    except AIFixError as e:
        logger.error(f"Error initializing AI fix provider: {e}")
        return

    logger.info("[AI] Generating AI-powered fixes...")
    for finding in findings:
        try:
            fix_diff = fix_provider.generate_fix(finding)
            finding.ai_fix = fix_diff
            logger.debug(f"Generated fix for {finding.vuln_id}")
        except AIFixError as e:
            logger.warning(f"Could not generate fix for {finding.vuln_id}: {e}")


def get_ai_response(
    prompt: str, config: schema.ScanConfig, provider: str = None
) -> str:
    """
    Get a response from the AI provider for a given prompt.
    """
    try:
        # If provider is specified, try to use it specifically
        if provider:
            api_key = getattr(config.api_keys, provider, None)
            if api_key:
                provider_class = _PROVIDER_MAP.get(provider)
                if provider_class:
                    fix_provider = provider_class(api_key)
                    return fix_provider.generate_content(prompt)

        # Fallback to default provider selection
        fix_provider = get_ai_fix_provider(config.api_keys)
        return fix_provider.generate_content(prompt)
    except Exception as e:
        logger.error(f"Error getting AI response: {e}")
        return ""
