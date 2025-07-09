import abc
import os
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
            response = self.llm(prompt, max_tokens=512, stop=["\n\n"], echo=False)
            return response["choices"][0]["text"].strip()
        except Exception as e:
            raise AIFixError(f"Local LLM inference error: {e}") from e


def get_fix_provider(config: schema.ScanConfig) -> AIFixProvider:
    """Factory function to instantiate the correct AI fix provider."""
    provider_map: Dict[schema.AIProvider, Type[AIFixProvider]] = {
        schema.AIProvider.OPENAI: OpenAIFixProvider,
        schema.AIProvider.ANTHROPIC: AnthropicFixProvider,
        schema.AIProvider.GEMINI: GeminiFixProvider,
        schema.AIProvider.LOCAL: LocalLLMFixProvider,
    }
    
    provider_class = provider_map.get(config.ai_provider)
    if not provider_class:
        raise ValueError(f"Unsupported AI provider: {config.ai_provider}")

    if config.ai_provider == schema.AIProvider.LOCAL:
        model_path = Path(os.path.expanduser("~/.impact-scan/models/codellama-7b.Q4_K_M.gguf"))
        return LocalLLMFixProvider(model_path=model_path)
    
    # Map provider names to API key names in config
    key_mapping = {
        "openai": "openai",
        "anthropic": "anthropic", 
        "gemini": "google"  # Gemini uses "google" key name
    }
    
    key_name = key_mapping.get(config.ai_provider.value, config.ai_provider.value)
    api_key = config.api_keys.get(key_name)
    if not api_key:
        raise ValueError(f"API key for '{key_name}' not found in config.")
    
    return provider_class(api_key=api_key)


def process_findings_for_fixes(
    findings: List[schema.Finding], config: schema.ScanConfig
) -> None:
    """Iterates through findings and populates 'fix_suggestion' in place."""
    if not config.enable_ai_fixes:
        return

    try:
        provider = get_fix_provider(config)
    except (ValueError, FileNotFoundError) as e:
        print(f"Warning: Could not initialize AI provider. Skipping fixes. Reason: {e}")
        return

    for finding in findings:
        if finding.source == schema.VulnSource.DEPENDENCY:
            continue # AI fixes are for code, not dependencies
        try:
            fix_suggestion = provider.generate_fix(finding)
            finding.fix_suggestion = fix_suggestion
        except AIFixError as e:
            print(f"Warning: Could not generate fix for {finding.vuln_id}: {e}")

