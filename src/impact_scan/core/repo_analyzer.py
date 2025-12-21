"""
Repository Analyzer for impact-scan init command

Analyzes a repository to detect languages, frameworks, and generate
custom security rules tailored to the codebase.
"""

import ast
import logging
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import Counter
from datetime import datetime

from ..utils import schema

logger = logging.getLogger(__name__)


class RepoAnalyzer:
    """Analyzes repository structure and generates custom security rules."""

    LANGUAGE_EXTENSIONS = {
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "go": [".go"],
        "rust": [".rs"],
        "ruby": [".rb"],
        "php": [".php"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".hpp", ".cc", ".hh"],
        "csharp": [".cs"],
    }

    FRAMEWORK_INDICATORS = {
        "python": {
            "fastapi": ["from fastapi", "import fastapi"],
            "flask": ["from flask", "import flask"],
            "django": ["from django", "import django", "django."],
            "sqlalchemy": ["from sqlalchemy", "import sqlalchemy"],
        },
        "javascript": {
            "express": ["require('express')", 'require("express")', "from 'express'"],
            "react": ["from 'react'", 'from "react"', "import React"],
            "nextjs": ["from 'next", "next/"],
            "vue": ["from 'vue'", "import Vue"],
            "expo": ["from 'expo", "import { Expo", "expo-"],
            "react-native": ["from 'react-native'", "import { View"],
        },
        "typescript": {
            "express": ["from 'express'", "import express"],
            "react": ["from 'react'", "import React"],
            "nextjs": ["from 'next'", "next/"],
            "nestjs": ["@nestjs/", "from '@nestjs"],
            "expo": ["from 'expo", "expo-"],
            "react-native": ["from 'react-native'", "import { View"],
        },
    }

    SECURITY_PATTERNS = {
        "python": [
            "eval", "exec", "pickle", "yaml.load", "subprocess",
            "os.system", "commands.", "jwt.decode", "hashlib.md5",
            "hashlib.sha1", "random.random",
        ],
        "javascript": [
            "eval(", "innerHTML", "dangerouslySetInnerHTML",
            "document.write", "setTimeout(", "setInterval(",
            ".html(", "crypto.createHash('md5')",
        ],
        "typescript": [
            "eval(", "innerHTML", "dangerouslySetInnerHTML",
            "any", "as any", "ts-ignore",
        ],
    }

    # Secret detection patterns with regex
    SECRET_PATTERNS = {
        "supabase_key": {
            "pattern": r'(?:supabase|SUPABASE)[_-]?(?:ANON|SERVICE|PUBLIC|SECRET)?[_-]?KEY["\']?\s*[:=]\s*["\']?([a-zA-Z0-9._-]{20,})',
            "severity": "CRITICAL",
            "description": "Supabase API key exposed",
        },
        "supabase_url": {
            "pattern": r'(?:supabase|SUPABASE)[_-]?URL["\']?\s*[:=]\s*["\']?(https?://[a-zA-Z0-9.-]+\.supabase\.co)',
            "severity": "HIGH",
            "description": "Supabase URL exposed (can be combined with leaked key)",
        },
        "firebase_key": {
            "pattern": r'(?:firebase|FIREBASE)[_-]?(?:API)?[_-]?KEY["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            "severity": "CRITICAL",
            "description": "Firebase API key exposed",
        },
        "aws_key": {
            "pattern": r'(?:AWS|aws)[_-]?(?:ACCESS)?[_-]?KEY[_-]?(?:ID)?["\']?\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})',
            "severity": "CRITICAL",
            "description": "AWS Access Key ID exposed",
        },
        "aws_secret": {
            "pattern": r'(?:AWS|aws)[_-]?(?:SECRET)?[_-]?(?:ACCESS)?[_-]?KEY["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
            "severity": "CRITICAL",
            "description": "AWS Secret Access Key exposed",
        },
        "openai_key": {
            "pattern": r'(?:OPENAI|openai)[_-]?(?:API)?[_-]?KEY["\']?\s*[:=]\s*["\']?(sk-[a-zA-Z0-9]{32,})',
            "severity": "CRITICAL",
            "description": "OpenAI API key exposed",
        },
        "stripe_key": {
            "pattern": r'(?:STRIPE|stripe)[_-]?(?:SECRET|PUBLISHABLE)?[_-]?KEY["\']?\s*[:=]\s*["\']?(sk_(?:test|live)_[a-zA-Z0-9]{24,}|pk_(?:test|live)_[a-zA-Z0-9]{24,})',
            "severity": "CRITICAL",
            "description": "Stripe API key exposed",
        },
        "jwt_secret": {
            "pattern": r'(?:JWT|jwt)[_-]?(?:SECRET|KEY)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]{16,})',
            "severity": "CRITICAL",
            "description": "JWT secret key exposed",
        },
        "database_url": {
            "pattern": r'(?:DATABASE|DB|MONGO|POSTGRES|MYSQL)[_-]?(?:URL|URI|CONNECTION)["\']?\s*[:=]\s*["\']?((?:postgres|mysql|mongodb)://[^\s"\']+)',
            "severity": "CRITICAL",
            "description": "Database connection string exposed",
        },
        "generic_api_key": {
            "pattern": r'(?:API|api)[_-]?KEY["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            "severity": "HIGH",
            "description": "Generic API key exposed",
        },
        "private_key": {
            "pattern": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            "severity": "CRITICAL",
            "description": "Private key file detected",
        },
        "github_token": {
            "pattern": r'(?:GITHUB|github)[_-]?(?:TOKEN|PAT)["\']?\s*[:=]\s*["\']?(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})',
            "severity": "CRITICAL",
            "description": "GitHub token exposed",
        },
        "expo_token": {
            "pattern": r'(?:EXPO|expo)[_-]?(?:ACCESS)?[_-]?TOKEN["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            "severity": "HIGH",
            "description": "Expo access token exposed",
        },
    }

    def __init__(self, root_path: Path):
        self.root_path = Path(root_path).resolve()
        self.languages: Counter = Counter()
        self.frameworks: Set[str] = set()
        self.security_hotspots: List[Dict] = []
        self.secrets_found: List[Dict] = []
        self.file_count: Dict[str, int] = {}

    def analyze(self) -> Dict:
        """
        Analyze the repository and return comprehensive analysis.

        Returns:
            Dict with languages, frameworks, file counts, and security hotspots
        """
        logger.info(f"Analyzing repository at {self.root_path}")

        self._scan_files()
        self._detect_frameworks()
        self._scan_for_secrets()

        return {
            "root_path": str(self.root_path),
            "languages": dict(self.languages.most_common()),
            "primary_language": self._get_primary_language(),
            "frameworks": sorted(list(self.frameworks)),
            "file_counts": self.file_count,
            "security_hotspots": self.security_hotspots,
            "secrets_found": self.secrets_found,
            "total_files": sum(self.file_count.values()),
        }

    def _scan_for_secrets(self):
        """Scan all files for exposed secrets and API keys."""
        # File extensions to scan for secrets
        scannable_extensions = [
            ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
            ".php", ".env", ".json", ".yml", ".yaml", ".toml", ".xml",
            ".config", ".conf", ".ini", ".properties",
        ]
        
        for file_path in self.root_path.rglob("*"):
            if self._should_ignore(file_path):
                continue
                
            if not file_path.is_file():
                continue
                
            # Check file extension or specific filenames
            if file_path.suffix.lower() not in scannable_extensions:
                # Also check specific secret-prone files
                if file_path.name.lower() not in [".env", ".env.local", ".env.development", ".env.production", "config.js", "constants.js", "constants.ts"]:
                    continue
            
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.split('\n')
                
                for secret_name, secret_config in self.SECRET_PATTERNS.items():
                    pattern = secret_config["pattern"]
                    matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                    
                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        
                        # Mask the actual secret value
                        secret_value = match.group(1) if match.groups() else match.group(0)
                        masked_value = secret_value[:4] + "..." + secret_value[-4:] if len(secret_value) > 12 else "***"
                        
                        self.secrets_found.append({
                            "type": secret_name,
                            "file": str(file_path.relative_to(self.root_path)),
                            "line": line_num,
                            "severity": secret_config["severity"],
                            "description": secret_config["description"],
                            "masked_value": masked_value,
                            "line_content": line_content.strip()[:100],
                        })
                        
            except Exception as e:
                logger.debug(f"Could not scan {file_path} for secrets: {e}")

    def _scan_files(self):
        """Scan repository files and detect languages."""
        for file_path in self.root_path.rglob("*"):
            # Skip common ignore patterns
            if self._should_ignore(file_path):
                continue

            if file_path.is_file():
                self._analyze_file(file_path)

    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        ignore_patterns = [
            ".git", "__pycache__", "node_modules", "venv", ".venv",
            "dist", "build", ".pytest_cache", ".mypy_cache",
            "target", "vendor", ".idea", ".vscode",
        ]

        for part in path.parts:
            if part in ignore_patterns or part.startswith("."):
                return True

        return False

    def _analyze_file(self, file_path: Path):
        """Analyze a single file."""
        suffix = file_path.suffix.lower()

        # Detect language
        for lang, extensions in self.LANGUAGE_EXTENSIONS.items():
            if suffix in extensions:
                self.languages[lang] += 1
                self.file_count[lang] = self.file_count.get(lang, 0) + 1

                # Scan for security patterns
                self._scan_security_patterns(file_path, lang)
                break

    def _scan_security_patterns(self, file_path: Path, language: str):
        """Scan file for security-relevant patterns."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            patterns = self.SECURITY_PATTERNS.get(language, [])
            for pattern in patterns:
                if pattern in content:
                    self.security_hotspots.append({
                        "file": str(file_path.relative_to(self.root_path)),
                        "language": language,
                        "pattern": pattern,
                    })

        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")

    def _detect_frameworks(self):
        """Detect frameworks used in the codebase."""
        for lang, indicators in self.FRAMEWORK_INDICATORS.items():
            if lang not in self.languages:
                continue

            # Search for framework indicators
            for framework, patterns in indicators.items():
                if self._search_for_patterns(lang, patterns):
                    self.frameworks.add(framework)

    def _search_for_patterns(self, language: str, patterns: List[str]) -> bool:
        """Search for patterns in files of a specific language."""
        extensions = self.LANGUAGE_EXTENSIONS.get(language, [])

        for file_path in self.root_path.rglob("*"):
            if file_path.suffix.lower() not in extensions:
                continue

            if self._should_ignore(file_path):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for pattern in patterns:
                    if pattern in content:
                        return True
            except Exception:
                continue

        return False

    def _get_primary_language(self) -> str:
        """Get the primary language of the repository."""
        if not self.languages:
            return "unknown"

        return self.languages.most_common(1)[0][0]

    async def generate_custom_rules(self, ai_config=None) -> List[Dict]:
        """
        Generate custom security rules based on repository analysis using Groq AI.

        Args:
            ai_config: Required config object with API keys and provider info (expects .api_keys and .ai_provider)

        Returns:
            List of custom rule configurations generated by Groq AI

        Raises:
            RuntimeError: If ai_config is not provided or Groq API key is missing
            Exception: If Groq AI fails to generate rules
        """
        if not ai_config:
            raise RuntimeError("ai_config is required for generating custom rules with Groq AI")

        if getattr(ai_config, 'ai_provider', None) != 'groq':
            raise RuntimeError(f"Invalid AI provider: {getattr(ai_config, 'ai_provider', None)}. Only 'groq' is supported.")

        if not hasattr(ai_config, 'api_keys'):
            raise RuntimeError("ai_config must have api_keys attribute")

        from impact_scan.core import fix_ai
        prompt = self._build_ai_rule_prompt()

        try:
            ai_rules_yaml = await self._call_groq_for_rules(prompt, ai_config)
            import yaml
            ai_rules = yaml.safe_load(ai_rules_yaml)

            if isinstance(ai_rules, list):
                logger.info(f"[AI] Successfully generated {len(ai_rules)} custom rules with Groq")
                return ai_rules
            else:
                logger.error(f"[AI] Groq returned invalid format (expected list, got {type(ai_rules)})")
                raise RuntimeError("Groq AI returned rules in invalid format")

        except Exception as e:
            logger.error(f"[AI] Failed to generate rules with Groq: {e}")
            raise

    def _build_ai_rule_prompt(self) -> str:
        """Builds a prompt for the AI to generate custom security rules."""
        context = {
            "languages": dict(self.languages.most_common()),
            "frameworks": list(self.frameworks),
            "security_hotspots": self.security_hotspots,
            "secrets_found": self.secrets_found,
        }
        import json
        return (
            "You are an expert application security engineer. "
            "Given the following codebase context, generate a YAML list of custom Semgrep-style security rules "
            "(id, name, description, severity, pattern, enabled) tailored to the project. "
            "Only output valid YAML, no explanations.\n\n"
            f"Codebase context:\n{json.dumps(context, indent=2)}\n\nRules (YAML list):"
        )

    async def _call_groq_for_rules(self, prompt: str, ai_config) -> str:
        """Call Groq AI provider to generate rules from prompt."""
        from impact_scan.core import fix_ai
        api_key = getattr(ai_config.api_keys, 'groq', None)
        if not api_key:
            raise RuntimeError("No Groq API key found in config.api_keys.groq")
        provider = fix_ai.GroqFixProvider(api_key)
        # Use the same interface as generate_content, but wrap in asyncio
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, provider.generate_content, prompt)


    def generate_impact_scan_md(self, analysis: Dict = None) -> str:
        """
        Generate the impact-scan.md file content with project context and custom rules.
        
        This file helps Impact Scan understand the codebase and apply targeted security rules.
        """
        if analysis is None:
            analysis = self.analyze()
        
        project_name = self.root_path.name
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        md_content = f"""# Impact Scan Configuration for {project_name}

> Auto-generated by `impact-scan init` on {timestamp}
> This file helps Impact Scan understand your codebase and apply targeted security rules.

## Project Overview

| Property | Value |
|----------|-------|
| **Project Name** | {project_name} |
| **Primary Language** | {analysis.get('primary_language', 'unknown')} |
| **Total Files** | {analysis.get('total_files', 0)} |
| **Frameworks** | {', '.join(analysis.get('frameworks', [])) or 'None detected'} |

### Languages Detected

"""
        # Language breakdown
        languages = analysis.get('languages', {})
        for lang, count in languages.items():
            md_content += f"- **{lang}**: {count} files\n"
        
        md_content += """
## Security Configuration

### Severity Thresholds

```yaml
# Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)
min_severity: MEDIUM

# Enable AI validation for reducing false positives
ai_validation: true
ai_provider: groq  # Options: openai, anthropic, gemini, groq
```

### Secret Detection Rules

The following secret patterns are actively scanned:

"""
        # List secret patterns
        for secret_type, config in self.SECRET_PATTERNS.items():
            md_content += f"- **{secret_type}**: {config['description']} (Severity: {config['severity']})\n"
        
        # Secrets found section
        secrets = analysis.get('secrets_found', [])
        if secrets:
            md_content += f"""
## ⚠️ SECRETS DETECTED ({len(secrets)} found)

> **CRITICAL**: The following secrets were detected in your codebase. These should be removed immediately!

| Type | File | Line | Severity |
|------|------|------|----------|
"""
            for secret in secrets[:20]:  # Limit to 20 for readability
                md_content += f"| {secret['type']} | `{secret['file']}` | {secret['line']} | {secret['severity']} |\n"
            
            if len(secrets) > 20:
                md_content += f"\n*...and {len(secrets) - 20} more secrets detected*\n"
            
            md_content += """
### Remediation Steps

1. **Remove hardcoded secrets** from your codebase
2. **Use environment variables** for all secrets
3. **Add secrets to `.gitignore`** (`.env`, `.env.local`, etc.)
4. **Rotate compromised keys** immediately
5. **Use a secrets manager** in production (e.g., AWS Secrets Manager, HashiCorp Vault)

"""
        
        md_content += """
## Custom Security Rules

### Framework-Specific Rules

"""
        # Add framework-specific rules
        frameworks = analysis.get('frameworks', [])
        
        if 'expo' in frameworks or 'react-native' in frameworks:
            md_content += """
#### React Native / Expo Security

```yaml
rules:
  - id: expo-secure-store
    description: "Use SecureStore for sensitive data, not AsyncStorage"
    pattern: "AsyncStorage.setItem.*(?:token|password|key|secret)"
    severity: HIGH
    
  - id: expo-api-keys
    description: "Don't hardcode API keys in React Native"
    pattern: "(?:apiKey|API_KEY|supabaseKey)\\s*[:=]\\s*['\"][^'\"]{10,}"
    severity: CRITICAL
    
  - id: expo-deep-linking
    description: "Validate deep link parameters"
    pattern: "Linking\\.addEventListener"
    severity: MEDIUM
```

"""
        
        if 'react' in frameworks or 'nextjs' in frameworks:
            md_content += """
#### React / Next.js Security

```yaml
rules:
  - id: react-dangerously-set-html
    description: "Avoid dangerouslySetInnerHTML - can lead to XSS"
    pattern: "dangerouslySetInnerHTML"
    severity: HIGH
    
  - id: nextjs-api-validation
    description: "Validate API route inputs"
    pattern: "req\\.body|req\\.query"
    severity: MEDIUM
    
  - id: nextjs-env-client-exposure
    description: "Don't expose server secrets to client"
    pattern: "NEXT_PUBLIC_.*(?:SECRET|KEY|PASSWORD)"
    severity: HIGH
```

"""
        
        if 'supabase' in str(frameworks).lower() or any('supabase' in str(s.get('type', '')).lower() for s in secrets):
            md_content += """
#### Supabase Security

```yaml
rules:
  - id: supabase-anon-key-exposure
    description: "Supabase anon key should only be in env files"
    pattern: "supabaseKey\\s*[:=]\\s*['\"]eyJ"
    severity: CRITICAL
    
  - id: supabase-rls-bypass
    description: "Ensure RLS policies are enabled"
    pattern: "\\.from\\(['\"].*['\"]\\)\\.select\\("
    severity: MEDIUM
    message: "Verify Row Level Security is enabled for this table"
    
  - id: supabase-service-key
    description: "Never expose service role key in client code"
    pattern: "service_role|SERVICE_ROLE"
    severity: CRITICAL
```

"""
        
        md_content += """
### Ignore Rules

Files and patterns to exclude from scanning:

```yaml
ignore:
  # Directories
  - node_modules/
  - .git/
  - dist/
  - build/
  - coverage/
  
  # Test files (optional - enable if too noisy)
  # - "**/*.test.js"
  # - "**/*.spec.ts"
  
  # Generated files
  - "*.min.js"
  - "*.bundle.js"
```

## Scan Commands

```bash
# Quick scan with defaults
impact-scan scan

# Full scan with AI validation
impact-scan scan --profile comprehensive --ai

# Scan specific directory
impact-scan scan ./src

# Output to different formats
impact-scan scan --output html --output sarif
```

## Integration

### Pre-commit Hook

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: impact-scan
        name: Security Scan
        entry: impact-scan scan --min-severity HIGH
        language: system
        pass_filenames: false
```

### GitHub Actions

Run `impact-scan init-github-action` to generate a workflow file.

---

*Generated by [Impact Scan](https://github.com/Ani07-05/impact-scan)*
"""
        
        return md_content

    def save_impact_scan_md(self, output_path: Path = None) -> Path:
        """
        Generate and save the impact-scan.md file.
        
        Args:
            output_path: Where to save the file (default: repo root / impact-scan.md)
            
        Returns:
            Path to the saved file
        """
        if output_path is None:
            output_path = self.root_path / "impact-scan.md"
        
        analysis = self.analyze()
        content = self.generate_impact_scan_md(analysis)
        
        output_path.write_text(content, encoding="utf-8")
        
        return output_path
