"""
Groq-powered repository analyzer for generating codebase-specific security rules.

Analyzes a repository to understand:
1. Architecture and design patterns
2. Authentication/authorization mechanisms
3. Data handling and storage
4. API endpoints and integrations
5. Specific security concerns
6. Technology stack and versions

Generates:
1. impact-scan.md - Detailed codebase analysis
2. custom-rules.yml - Tailored Semgrep-compatible security rules
"""

import json
import logging
import re
from pathlib import Path
from typing import Optional

from impact_scan.utils.api_key_manager import APIKeyManager
from . import groq_system_prompt

logger = logging.getLogger(__name__)


class GroqRepoAnalyzer:
    def __init__(self, repo_path: Path, api_key: Optional[str] = None):
        self.repo_path = Path(repo_path).resolve()
        self.api_key = api_key or APIKeyManager.get_api_key("groq")
        
        if not self.api_key:
            raise ValueError(
                "Groq API key not found. Set GROQ_API_KEY environment variable"
            )
        
        # Import Groq client
        try:
            from groq import Groq
            self.client = Groq(api_key=self.api_key)
        except ImportError:
            raise ImportError("Install groq: pip install groq")
    
    def collect_codebase_info(self) -> dict:
        """Analyze repo structure and collect codebase information."""
        import subprocess
        
        info = {
            "repo_path": str(self.repo_path),
            "file_structure": self._get_file_structure(),
            "tech_stack": self._detect_tech_stack(),
            "key_files": self._find_key_files(),
            "dependency_info": self._get_dependency_info(),
            "code_samples": self._extract_code_samples(),
        }
        
        return info
    
    def _get_file_structure(self, max_depth: int = 3) -> dict:
        """Get directory structure of repo."""
        from pathlib import Path
        
        def _build_tree(path: Path, depth: int = 0) -> dict:
            if depth > max_depth:
                return {}
            
            try:
                items = {}
                for item in sorted(path.iterdir()):
                    if item.name.startswith('.'):
                        continue
                    if item.is_dir():
                        items[item.name] = _build_tree(item, depth + 1)
                    else:
                        items[item.name] = "file"
                return items
            except PermissionError:
                return {}
        
        return _build_tree(self.repo_path)
    
    def _detect_tech_stack(self) -> dict:
        """Detect programming languages and frameworks."""
        tech_indicators = {
            "python": ["*.py", "requirements.txt", "setup.py", "pyproject.toml"],
            "javascript": ["*.js", "*.jsx", "package.json", "npm-shrinkwrap.json"],
            "typescript": ["*.ts", "*.tsx", "tsconfig.json"],
            "java": ["*.java", "pom.xml", "build.gradle"],
            "go": ["*.go", "go.mod", "go.sum"],
            "rust": ["*.rs", "Cargo.toml"],
            "php": ["*.php", "composer.json"],
            "csharp": ["*.cs", "*.csproj"],
        }
        
        detected = {}
        
        for lang, patterns in tech_indicators.items():
            for pattern in patterns:
                if pattern.startswith("*."):
                    # Check for file extensions
                    ext = pattern[1:]
                    count = len(list(self.repo_path.rglob(f"*{ext}")))
                    if count > 0:
                        detected[lang] = detected.get(lang, 0) + count
                else:
                    # Check for specific files
                    if (self.repo_path / pattern).exists():
                        detected[lang] = detected.get(lang, 0) + 1
        
        return detected
    
    def _find_key_files(self) -> dict:
        """Find important security-related files."""
        key_file_patterns = {
            "auth": ["auth", "login", "oauth", "jwt", "passport"],
            "database": ["db", "model", "schema", "migration"],
            "api": ["routes", "controller", "endpoint", "handler"],
            "config": ["config", "env", "settings"],
            "security": ["security", "crypto", "encryption", "hash"],
        }
        
        found = {category: [] for category in key_file_patterns}
        
        for py_file in self.repo_path.rglob("*.py"):
            filename_lower = py_file.stem.lower()
            for category, keywords in key_file_patterns.items():
                if any(kw in filename_lower for kw in keywords):
                    found[category].append(str(py_file.relative_to(self.repo_path)))
        
        # Also check JS/TS files
        for js_file in self.repo_path.rglob("*.[jt]s"):
            filename_lower = js_file.stem.lower()
            for category, keywords in key_file_patterns.items():
                if any(kw in filename_lower for kw in keywords):
                    found[category].append(str(js_file.relative_to(self.repo_path)))
        
        return {k: v for k, v in found.items() if v}
    
    def _get_dependency_info(self) -> dict:
        """Extract dependency information."""
        deps = {}
        
        # Python
        if (self.repo_path / "requirements.txt").exists():
            with open(self.repo_path / "requirements.txt") as f:
                deps["python_pip"] = f.read().strip().split('\n')[:10]  # First 10
        
        if (self.repo_path / "pyproject.toml").exists():
            with open(self.repo_path / "pyproject.toml") as f:
                content = f.read()
                if "flask" in content.lower():
                    deps["framework"] = "Flask"
                elif "django" in content.lower():
                    deps["framework"] = "Django"
                elif "fastapi" in content.lower():
                    deps["framework"] = "FastAPI"
        
        # JavaScript/Node
        if (self.repo_path / "package.json").exists():
            import json
            with open(self.repo_path / "package.json") as f:
                pkg = json.load(f)
                deps["node_packages"] = list(
                    pkg.get("dependencies", {}).keys()
                )[:10]
                deps["node_devpackages"] = list(
                    pkg.get("devDependencies", {}).keys()
                )[:5]
        
        return deps
    
    def _extract_code_samples(self, limit: int = 5) -> dict:
        """Extract relevant code snippets for analysis."""
        samples = {
            "auth_handlers": [],
            "api_routes": [],
            "database_models": [],
            "security_configs": [],
        }
        
        # Look for auth-related code
        for py_file in list(self.repo_path.rglob("*auth*.py"))[:limit]:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Get first 1000 chars of relevant functions
                    for match in re.finditer(r'def (login|authenticate|verify|validate).*?(?=\n    def |\nclass |\Z)',
                                             content, re.DOTALL):
                        samples["auth_handlers"].append({
                            "file": str(py_file.relative_to(self.repo_path)),
                            "snippet": match.group(0)[:500]
                        })
            except Exception as e:
                logger.debug(f"Could not read {py_file}: {e}")
        
        return samples
    
    def analyze_with_groq(self, codebase_info: dict) -> str:
        """Use Groq to analyze codebase and generate security rules."""
        
        # Prepare context
        user_context = f"""
Analyze this codebase structure and identify security vulnerabilities and patterns:

## Technology Stack
{json.dumps(codebase_info['tech_stack'], indent=2)}

## Key Security-Related Files
{json.dumps(codebase_info['key_files'], indent=2)}

## Dependencies
{json.dumps(codebase_info['dependency_info'], indent=2)}

## Directory Structure
{json.dumps(codebase_info['file_structure'], indent=2)}

## Code Samples
{json.dumps(codebase_info['code_samples'], indent=2)}

Analyze this codebase for:
1. Authentication/authorization vulnerabilities
2. OAuth/OpenID Connect issues
3. Data protection weaknesses
4. API security problems
5. Session management vulnerabilities
6. Framework-specific security issues
7. Dependency security concerns
8. Configuration weaknesses

Provide detailed analysis with specific file references and code patterns.
"""
        
        logger.info("Sending codebase analysis to Groq...")
        
        message = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",  # Fast, efficient model
            max_tokens=4096,
            system=groq_system_prompt.CODEBASE_ANALYSIS_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": user_context
                }
            ]
        )
        
        return message.choices[0].message.content
    
    def generate_custom_rules(self, analysis: str) -> str:
        """Generate custom Semgrep rules based on analysis."""
        
        user_prompt = f"""
Based on this codebase security analysis:

{analysis}

---

Generate Semgrep YAML rules for this specific codebase.

For each identified vulnerability:
1. Create a specific rule ID (e.g., app-oauth-pkce-missing, app-plaintext-password)
2. Design Semgrep patterns that accurately match vulnerable code
3. Provide detailed message with vulnerability explanation and concrete fix
4. Assign appropriate severity (CRITICAL, ERROR, WARNING)
5. Include accurate CWE/OWASP mappings

Generate 5-15 high-priority rules. Focus on CRITICAL and ERROR severity findings first.

Output must be valid YAML that can be used directly with Semgrep.
"""
        
        logger.info("Generating custom rules with Groq...")
        
        message = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=4096,
            system=groq_system_prompt.CUSTOM_RULES_GENERATION_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        )
        
        return message.choices[0].message.content
    
    def run_full_analysis(self, output_dir: Optional[Path] = None) -> tuple[str, str]:
        """
        Run complete analysis and generate files.
        
        Returns:
            Tuple of (analysis_md, rules_yaml)
        """
        output_dir = Path(output_dir or self.repo_path)
        
        logger.info(f"Collecting codebase information from {self.repo_path}...")
        codebase_info = self.collect_codebase_info()
        
        logger.info("Running Groq analysis...")
        analysis = self.analyze_with_groq(codebase_info)
        
        logger.info("Generating custom security rules...")
        rules = self.generate_custom_rules(analysis)
        
        # Save analysis
        analysis_file = output_dir / "impact-scan.md"
        self._save_analysis_md(analysis_file, codebase_info, analysis)
        logger.info(f"✓ Analysis saved to {analysis_file}")
        
        # Save rules
        rules_file = output_dir / ".impact-scan/custom-rules.yml"
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rules_file, 'w') as f:
            f.write(rules)
        logger.info(f"✓ Custom rules saved to {rules_file}")
        
        return analysis, rules
    
    def _save_analysis_md(self, filepath: Path, info: dict, analysis: str):
        """Save analysis as markdown."""
        content = f"""# Impact-Scan Repository Analysis

**Generated:** {__import__('datetime').datetime.now().isoformat()}

## Codebase Overview

### Technology Stack
```json
{json.dumps(info['tech_stack'], indent=2)}
```

### Key Security-Related Files
```json
{json.dumps(info['key_files'], indent=2)}
```

### Dependencies
```json
{json.dumps(info['dependency_info'], indent=2)}
```

## Security Analysis

{analysis}

---

This analysis was generated automatically using Groq AI analysis.
Run `impact-scan scan` to apply custom security rules based on this analysis.
"""
        
        with open(filepath, 'w') as f:
            f.write(content)
