import abc
from pathlib import Path
from typing import List, Dict, Type

import openai
import anthropic
import google.generativeai as genai
from llama_cpp import Llama

from impact_scan.utils import schema


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

    @abc.abstractmethod
    def generate_fix(self, finding: schema.Finding) -> str:
        """Generates a fix suggestion for a given vulnerability finding."""
        raise NotImplementedError


class OpenAIFixProvider(AIFixProvider):
    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)

    def generate_fix(self, finding: schema.Finding) -> str:
        prompt = self._PROMPT_TEMPLATE.format(**finding.model_dump())
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
            )
            return response.choices[0].message.content.strip()
        except openai.APIError as e:
            raise AIFixError(f"OpenAI API error: {e}") from e


class AnthropicFixProvider(AIFixProvider):
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)

    def generate_fix(self, finding: schema.Finding) -> str:
        prompt = self._PROMPT_TEMPLATE.format(**finding.model_dump())
        try:
            response = self.client.messages.create(
                model="claude-3-haiku-20240307",
                system="You are an expert security engineer providing code fixes as unified diffs.",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.0,
            )
            return response.content[0].text.strip()
        except anthropic.APIError as e:
            raise AIFixError(f"Anthropic API error: {e}") from e


class GeminiFixProvider(AIFixProvider):
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')

    def generate_fix(self, finding: schema.Finding) -> str:
        prompt = self._PROMPT_TEMPLATE.format(**finding.model_dump())
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            raise AIFixError(f"Gemini API error: {e}") from e


class LocalLLMFixProvider(AIFixProvider):
    def __init__(self, model_path: Path):
        if not model_path.is_file():
            raise FileNotFoundError(f"Local LLM model not found: {model_path}")
        self.llm = Llama(model_path=str(model_path), verbose=False)

    def generate_fix(self, finding: schema.Finding) -> str:
        prompt = self._PROMPT_TEMPLATE.format(**finding.model_dump())
        try:
            output = self.llm(prompt, max_tokens=1024, stop=["\n\n"], echo=False)
            return output["choices"][0]["text"].strip()
        except Exception as e:
            raise AIFixError(f"Local LLM error: {e}") from e


_PROVIDER_MAP: Dict[str, Type[AIFixProvider]] = {
    "openai": OpenAIFixProvider,
    "anthropic": AnthropicFixProvider,
    "gemini": GeminiFixProvider,
}

def get_ai_fix_provider(api_keys: schema.APIKeys, local_model: Path = None) -> AIFixProvider:
    """
    Factory function to get the first available AI fix provider.
    """
    if local_model:
        try:
            return LocalLLMFixProvider(local_model)
        except FileNotFoundError as e:
            raise AIFixError(str(e)) from e


    for provider_name, api_key in api_keys.model_dump().items():
        if api_key:
            provider_class = _PROVIDER_MAP.get(provider_name)
            if provider_class:
                return provider_class(api_key)

    raise AIFixError("No AI provider API key found or local model specified.")


def generate_fixes(findings: List[schema.Finding], config: schema.ScanConfig) -> None:
    """
    Generates AI-powered fix suggestions for a list of findings.
    """
    if not config.enable_ai_fixes:
        return

    try:
        local_llm_path = getattr(config, "local_llm_path", None)
        fix_provider = get_ai_fix_provider(config.api_keys, local_llm_path)
    except AIFixError as e:
        print(f"Error initializing AI fix provider: {e}")
        return

    print("🤖 Generating AI-powered fixes...")
    for finding in findings:
        try:
            fix_diff = fix_provider.generate_fix(finding)
            finding.ai_fix = fix_diff
        except AIFixError as e:
            print(f"Could not generate fix for {finding.vuln_id}: {e}")
