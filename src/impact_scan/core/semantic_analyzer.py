"""
Framework Semantics Analyzer (Phase 1 - AI-Native SAST)

Detects framework-specific security issues that SAST tools miss:
- Missing required parameters (SessionMiddleware max_age)
- Insecure default values (SameSite=Lax for session cookies)
- Framework-specific misconfigurations

Based on 2025 research:
- SAST-Genius (arXiv:2509.15433)
- IRIS Framework (arXiv:2405.17238)
- Abstract Syntax Tree (AST) semantic analysis
"""

import ast
import logging
from pathlib import Path
from typing import Dict, List, Optional

from ..utils import schema
from . import fix_ai

logger = logging.getLogger(__name__)


class FrameworkSemanticAnalyzer:
    """
    Analyzes framework-specific semantic patterns using AST + LLM.

    Detects:
    - Missing required parameters (SessionMiddleware max_age)
    - Insecure default values (SameSite=Lax for session cookies)
    - Framework-specific misconfigurations
    """

    # Framework knowledge base
    FRAMEWORK_PATTERNS = {
        "fastapi": {
            "SessionMiddleware": {
                "required_params": {
                    "max_age": {
                        "severity": "HIGH",
                        "cwe": "CWE-613",
                        "description": "Session should expire after inactivity",
                        "fix": "Add max_age=1800 (30 minutes) parameter",
                    }
                },
                "dangerous_combinations": {
                    "https_only_false": {
                        "severity": "MEDIUM",
                        "cwe": "CWE-614",
                        "description": "Session cookies should be HTTPS-only",
                        "fix": "Set https_only=True parameter",
                    }
                },
            },
            "CORSMiddleware": {
                "dangerous_patterns": {
                    "wildcard_with_credentials": {
                        "pattern": {"allow_origins": ["*"], "allow_credentials": True},
                        "severity": "HIGH",
                        "cwe": "CWE-942",
                        "description": "CORS wildcard with credentials enabled",
                        "fix": "Specify exact origins or disable credentials",
                    }
                }
            },
            "set_cookie": {
                "auth_context": {
                    "required_flags": {
                        "secure": {
                            "severity": "MEDIUM",
                            "cwe": "CWE-614",
                            "description": "Session cookies should have secure flag",
                            "fix": "Add secure=True parameter",
                        },
                        "httponly": {
                            "severity": "MEDIUM",
                            "cwe": "CWE-1004",
                            "description": "Session cookies should have httponly flag",
                            "fix": "Add httponly=True parameter",
                        },
                        "samesite": {
                            "expected": "strict",
                            "severity": "MEDIUM",
                            "cwe": "CWE-1275",
                            "description": "Session cookies should use SameSite=Strict",
                            "fix": "Set samesite='strict' parameter",
                        },
                    }
                }
            },
        },
        "flask": {
            "session_config": {
                "required_config": {
                    "SESSION_COOKIE_SECURE": {
                        "expected": True,
                        "severity": "MEDIUM",
                        "cwe": "CWE-614",
                    },
                    "SESSION_COOKIE_HTTPONLY": {
                        "expected": True,
                        "severity": "MEDIUM",
                        "cwe": "CWE-1004",
                    },
                    "SESSION_COOKIE_SAMESITE": {
                        "expected": "Strict",
                        "severity": "MEDIUM",
                        "cwe": "CWE-1275",
                    },
                }
            }
        },
    }

    def __init__(self, ai_provider: Optional[fix_ai.AIFixProvider] = None):
        """
        Initialize semantic analyzer.

        Args:
            ai_provider: Optional AI provider for LLM reasoning (if None, only pattern matching)
        """
        self.ai_provider = ai_provider

    def analyze_file(
        self, file_path: Path, framework: str = "fastapi"
    ) -> List[schema.Finding]:
        """
        Analyze a Python file for framework semantic vulnerabilities.

        Args:
            file_path: Path to Python file
            framework: Framework name (fastapi, flask, django)

        Returns:
            List of semantic vulnerability findings
        """
        if not file_path.exists() or file_path.suffix != ".py":
            return []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source_code = f.read()

            tree = ast.parse(source_code, filename=str(file_path))
            findings = []

            # Analyze middleware configurations
            findings.extend(self._analyze_middleware(tree, file_path, framework))

            # Analyze cookie settings
            findings.extend(
                self._analyze_cookies(tree, file_path, source_code, framework)
            )

            return findings

        except (SyntaxError, UnicodeDecodeError) as e:
            logger.debug(f"Could not parse {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}", exc_info=True)
            return []

    def _analyze_middleware(
        self, tree: ast.AST, file_path: Path, framework: str
    ) -> List[schema.Finding]:
        """Analyze middleware configurations for missing parameters."""
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Check for add_middleware calls
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_middleware"
            ):
                # Extract middleware class name
                if node.args and isinstance(node.args[0], ast.Name):
                    middleware_name = node.args[0].id

                    # Extract keyword arguments
                    kwargs = {kw.arg: kw.value for kw in node.keywords}

                    # Check against framework patterns
                    finding = self._check_middleware_config(
                        middleware_name, kwargs, file_path, node.lineno, framework
                    )

                    if finding:
                        findings.append(finding)

        return findings

    def _check_middleware_config(
        self,
        middleware_name: str,
        kwargs: Dict[str, ast.AST],
        file_path: Path,
        line_number: int,
        framework: str,
    ) -> Optional[schema.Finding]:
        """Check middleware configuration against security requirements."""
        patterns = self.FRAMEWORK_PATTERNS.get(framework, {})
        middleware_patterns = patterns.get(middleware_name, {})

        if not middleware_patterns:
            return None

        # Check for missing required parameters
        required_params = middleware_patterns.get("required_params", {})
        for param_name, config in required_params.items():
            if param_name not in kwargs:
                # Use LLM to confirm this is a security issue
                if self.ai_provider:
                    is_vuln, reason = self._llm_validate_missing_param(
                        middleware_name, param_name, kwargs, file_path
                    )

                    if not is_vuln:
                        logger.debug(
                            f"LLM validated missing {param_name} is OK: {reason}"
                        )
                        continue

                return schema.Finding(
                    file_path=file_path,
                    line_number=line_number,
                    vuln_id=f"semantic-missing-param-{middleware_name.lower()}-{param_name}",
                    rule_id=f"semantic:{framework}:{middleware_name}:{param_name}",
                    title=f"Missing Security Parameter: {param_name} in {middleware_name}",
                    severity=schema.Severity[config["severity"]],
                    source=schema.VulnSource.STATIC_ANALYSIS,
                    code_snippet=f"app.add_middleware({middleware_name}, ...)",
                    description=f"{config['description']}. {config['fix']}",
                    cwe=config["cwe"],
                    fix_suggestion=config["fix"],
                    metadata={"semantic_analysis": True, "framework": framework},
                )

        return None

    def _analyze_cookies(
        self, tree: ast.AST, file_path: Path, source_code: str, framework: str
    ) -> List[schema.Finding]:
        """Analyze cookie settings for security flags."""
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Check for set_cookie calls
            if isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie":
                # Extract keyword arguments
                kwargs = {kw.arg: kw.value for kw in node.keywords}

                # Get cookie name (key parameter)
                cookie_name = self._get_cookie_name(node, kwargs)

                # Determine if this is a session/auth cookie
                is_auth_cookie = self._is_auth_cookie(
                    cookie_name, kwargs, file_path, source_code
                )

                if is_auth_cookie:
                    finding = self._check_cookie_security(
                        kwargs, file_path, node.lineno, cookie_name, framework
                    )

                    if finding:
                        findings.append(finding)

        return findings

    def _get_cookie_name(self, node: ast.Call, kwargs: Dict) -> str:
        """Extract cookie name from set_cookie call."""
        if "key" in kwargs:
            key_node = kwargs["key"]
            if isinstance(key_node, ast.Constant):
                return key_node.value
        return "unknown"

    def _is_auth_cookie(
        self, cookie_name: str, kwargs: Dict, file_path: Path, source_code: str
    ) -> bool:
        """
        Determine if a cookie is security-sensitive (session/auth).

        Uses heuristics + optional LLM reasoning.
        """
        # Heuristic: check cookie name
        auth_keywords = ["session", "auth", "token", "login", "user", "jwt", "csrf"]
        cookie_lower = cookie_name.lower()

        if any(keyword in cookie_lower for keyword in auth_keywords):
            return True

        # Check file context
        if "auth" in str(file_path).lower() or "login" in str(file_path).lower():
            return True

        return False

    def _check_cookie_security(
        self,
        kwargs: Dict[str, ast.AST],
        file_path: Path,
        line_number: int,
        cookie_name: str,
        framework: str,
    ) -> Optional[schema.Finding]:
        """Check cookie configuration for missing security flags."""
        patterns = self.FRAMEWORK_PATTERNS.get(framework, {})
        cookie_patterns = patterns.get("set_cookie", {}).get("auth_context", {})

        if not cookie_patterns:
            return None

        required_flags = cookie_patterns.get("required_flags", {})
        missing_flags = []

        for flag_name, config in required_flags.items():
            if flag_name not in kwargs:
                missing_flags.append((flag_name, config))
            elif flag_name == "samesite":
                # Check if value is correct
                value_node = kwargs[flag_name]
                if isinstance(value_node, ast.Constant):
                    if value_node.value.lower() != config["expected"]:
                        missing_flags.append((flag_name, config))

        if missing_flags:
            # Create finding for the most severe missing flag
            flag_name, config = max(
                missing_flags, key=lambda x: schema.Severity[x[1]["severity"]].value
            )

            return schema.Finding(
                file_path=file_path,
                line_number=line_number,
                vuln_id=f"semantic-cookie-{flag_name}-{cookie_name}",
                rule_id=f"semantic:{framework}:cookie:{flag_name}",
                title=f"Missing Cookie Security Flag: {flag_name}",
                severity=schema.Severity[config["severity"]],
                source=schema.VulnSource.STATIC_ANALYSIS,
                code_snippet=f"response.set_cookie(key='{cookie_name}', ...)",
                description=f"{config['description']}. {config['fix']}",
                cwe=config["cwe"],
                fix_suggestion=config["fix"],
                metadata={
                    "semantic_analysis": True,
                    "framework": framework,
                    "cookie_name": cookie_name,
                    "missing_flags": [f[0] for f in missing_flags],
                },
            )

        return None

    def _llm_validate_missing_param(
        self,
        middleware_name: str,
        param_name: str,
        existing_params: Dict,
        file_path: Path,
    ) -> tuple[bool, str]:
        """
        Use LLM to validate if missing parameter is a security issue.

        Returns:
            (is_vulnerability: bool, reason: str)
        """
        if not self.ai_provider:
            return True, "No LLM available for validation"

        prompt = f"""Analyze this FastAPI middleware configuration for security issues:

Middleware: {middleware_name}
Missing Parameter: {param_name}
Existing Parameters: {list(existing_params.keys())}
File: {file_path.name}

Is this missing parameter a security vulnerability? Consider:
1. Default behavior when parameter is missing
2. Security implications of the default
3. OWASP session management best practices (30 min timeout recommended)
4. Context: Is this a development/test file or production code?

Respond with ONLY ONE of:
TRUE_POSITIVE: [brief reason why this is a security issue]
FALSE_POSITIVE: [brief reason why this is acceptable]

Do not include any other text."""

        try:
            response = self.ai_provider.generate_content(prompt)
            response = response.strip()

            if response.startswith("TRUE_POSITIVE"):
                reason = (
                    response.split(":", 1)[1].strip()
                    if ":" in response
                    else "LLM confirmed vulnerability"
                )
                return True, reason
            elif response.startswith("FALSE_POSITIVE"):
                reason = (
                    response.split(":", 1)[1].strip()
                    if ":" in response
                    else "LLM confirmed safe"
                )
                return False, reason
            else:
                # Ambiguous response - default to TRUE_POSITIVE to avoid false negatives
                logger.warning(f"Ambiguous LLM response: {response[:100]}")
                return True, "Ambiguous LLM validation - kept as precaution"

        except Exception as e:
            logger.error(f"LLM validation failed: {e}")
            # Fail-safe: treat as vulnerability
            return True, f"LLM validation error: {e}"


def analyze_framework_semantics(
    file_paths: List[Path],
    framework: str = "fastapi",
    ai_provider: Optional[fix_ai.AIFixProvider] = None,
) -> List[schema.Finding]:
    """
    Public API for framework semantic analysis.

    Args:
        file_paths: List of Python files to analyze
        framework: Framework name (fastapi, flask, django)
        ai_provider: Optional AI provider for LLM validation

    Returns:
        List of semantic vulnerability findings
    """
    analyzer = FrameworkSemanticAnalyzer(ai_provider)
    all_findings = []

    for file_path in file_paths:
        findings = analyzer.analyze_file(file_path, framework)
        all_findings.extend(findings)

    logger.info(
        f"Semantic analysis found {len(all_findings)} issues across {len(file_paths)} files"
    )

    return all_findings
