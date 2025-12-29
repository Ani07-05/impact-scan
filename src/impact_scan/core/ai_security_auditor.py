"""
AI-Powered Security Auditor - Discovers vulnerabilities missed by static analysis rules.

This module performs deep security analysis using LLMs to identify:
- Session management vulnerabilities (fixation, weak secrets)
- Missing security configurations (cookie flags, HTTPS enforcement)
- Business logic flaws (authentication bypass, race conditions)
- Framework-specific security issues
- Deployment security misconfigurations

Unlike ai_validator.py (which validates existing findings), this module actively
discovers NEW vulnerabilities by analyzing code patterns, control flow, and configurations.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from ..utils import schema
from . import fix_ai

logger = logging.getLogger(__name__)


class AISecurityAuditor:
    """
    Discovers security vulnerabilities using deep AI code analysis.

    Complements static analysis by finding:
    - Configuration vulnerabilities (missing security flags)
    - Logic vulnerabilities (session fixation, race conditions)
    - Framework-specific issues (CORS misconfig, middleware order)
    - Deployment issues (HTTPS enforcement, secret management)
    """

    # Security audit prompt templates for different file types

    _GENERAL_AUDIT_PROMPT = """<role>You are a senior security engineer with 15+ years of experience in application security, specializing in finding logic vulnerabilities and configuration issues that automated tools miss.</role>

<task>Perform a deep security audit of the following code to identify vulnerabilities that pattern-based scanners cannot detect.</task>

<context>
File: {file_path}
Language: {language}
</context>

<code>
{code}
</code>

<analysis_framework>
Think step-by-step through these security dimensions:

1. **Session Management & State**
   - Is session creation timing secure? (created before/after auth?)
   - Can sessions be fixed, hijacked, or predicted?
   - Are session secrets validated for cryptographic strength?
   - Is session storage encrypted and protected?

2. **Cookie Security Flags**
   - Are Secure, HttpOnly, SameSite flags present?
   - Do cookie names/values leak sensitive information?
   - Is cookie domain scope properly restricted?

3. **Authentication & Authorization Logic**
   - Are OAuth/OIDC flows verified cryptographically (ID token validation)?
   - Are there race conditions or timing attacks?
   - Can authentication be bypassed through logic flaws?
   - Is token storage secure (not localStorage)?

4. **Security Configuration**
   - Is HTTPS enforced in production?
   - Are CORS policies properly scoped (not wildcard "*")?
   - Are security headers present (CSP, HSTS, X-Frame-Options)?
   - Is CSRF protection implemented with state tokens?
   - Are rate limits configured?

5. **Secret Management**
   - Are secrets loaded from environment without validation?
   - Are default/weak secrets used?
   - Are secrets exposed in error messages or logs?

6. **Production Readiness**
   - Is debug mode disabled in production?
   - Are development endpoints exposed?
   - Is verbose error handling revealing internals?
</analysis_framework>

<output_requirements>
For each vulnerability found:
1. Identify the EXACT line number
2. Explain the security impact and attack vector
3. Provide a SPECIFIC, ACTIONABLE fix with working code
4. Use CWE identifiers where applicable

Return ONLY a JSON object (no markdown, no backticks):
{{
  "vulnerabilities": [
    {{
      "cwe_id": "CWE-XXX",
      "severity": "HIGH|MEDIUM|LOW",
      "title": "Descriptive title (max 60 chars)",
      "line_number": <exact_line>,
      "description": "Clear explanation of the vulnerability",
      "attack_scenario": "Step-by-step attack path an adversary would take",
      "fix": "Specific fix instructions with framework-native code examples. ONLY use imports/modules that exist in the framework. Include environment checks where needed."
    }}
  ]
}}
</output_requirements>

<constraints>
- Focus on LOGIC and CONFIGURATION issues (not syntax)
- Only report vulnerabilities you are HIGHLY confident about
- Prioritize HIGH severity issues that are exploitable
- Provide fixes using ONLY standard framework features (no fictional imports)
- Consider production deployment context
</constraints>

<false_positive_filters>
CRITICAL: Do NOT report the following as vulnerabilities:

1. **Test Code Usage**: If the file path contains "test", "tests", "_test", "conftest", "spec", or "mock":
   - MD5/SHA1 used for test assertions or file comparison is SAFE
   - Hardcoded credentials in test fixtures are SAFE (unless loaded in production)
   - SQL without sanitization in test mocks is SAFE

2. **Non-Security Cryptography**: Check if crypto functions are used for security:
   - `hashlib.md5(..., usedforsecurity=False)` or `used_for_security=False` is SAFE
   - MD5/SHA1 for checksums, ETags, cache keys, file fingerprints is SAFE
   - Only flag MD5/SHA1 if used for passwords, tokens, signatures, or authentication

3. **Library/Framework Internal Code**: If analyzing a library (not a web application):
   - **Path Traversal**: Libraries don't handle HTTP requests. The calling application is responsible for path validation. NOT a vulnerability in libraries.
   - **XSS**: Only relevant for HTML output. PDF/image/data libraries are NOT vulnerable to XSS.
   - **File Upload**: Libraries don't handle uploads. Only web applications do. NOT a vulnerability in libraries.
   - Input validation may be delegated to the calling application
   - Test utilities and example code should not be flagged

4. **Tutorial/Example/Demo Code**: If path contains "tutorial", "example", "demo", "sample", "docs":
   - Simplified code for teaching purposes is SAFE
   - Hardcoded values in demos are SAFE (they're examples, not production)
   - These are NOT production security issues

5. **Context Matters**: Always read surrounding code to understand intent:
   - Check variable names: `test_password`, `example_key`, `demo_secret` are likely safe
   - Check comments: "for testing only", "non-cryptographic hash", "checksum"
   - Check file purpose: Is this production code or development/test/example code?
   - Check output format: PDF libraries can't have XSS, image libraries can't have SQL injection

If unsure whether something is a real vulnerability, DO NOT REPORT IT. False positives waste developer time.
</false_positive_filters>"""

    _AUTH_ROUTE_AUDIT_PROMPT = """<role>You are a principal security architect specializing in OAuth2/OIDC implementations and session management vulnerabilities, with deep expertise in authentication bypass techniques.</role>

<task>Audit this authentication code for critical security flaws that could lead to unauthorized access or session hijacking.</task>

<context>
File: {file_path} (Authentication/Authorization Route)
Language: {language}
</context>

<code>
{code}
</code>

<critical_security_checks>
Analyze each of these high-risk areas:

**1. OAuth2/OIDC Flow Integrity**
- ❌ Is access_token used for user info WITHOUT ID token verification?
- ❌ Is the ID token signature validated using the provider's public key?
- ❌ Are token claims (iss, aud, exp, nonce) verified?
- ❌ Is PKCE (Proof Key for Code Exchange) used for public clients?
- ❌ Is the state parameter validated to prevent CSRF?

**2. Session Creation Timing (SESSION FIXATION)**
- ❌ Is the session created BEFORE authentication completes?
- ❌ Is the session ID regenerated AFTER successful authentication?
- ❌ Can an attacker predict or control the session ID?

**3. Cookie Security Posture**
- ❌ Missing Secure flag (allows transmission over HTTP)?
- ❌ Missing HttpOnly flag (vulnerable to XSS theft)?
- ❌ Missing or weak SameSite flag (CSRF vulnerable)?
- ❌ Overly broad cookie domain?

**4. Token & Secret Management**
- ❌ Are tokens stored in localStorage (vulnerable to XSS)?
- ❌ Are session secrets loaded without strength validation?
- ❌ Are secrets hardcoded or use weak defaults?
- ❌ Are secrets exposed in URLs or error messages?

**5. Production Security Controls**
- ❌ Is HTTPS enforcement missing or bypassable?
- ❌ Are rate limits missing on login/token endpoints?
- ❌ Is session timeout configured properly?
- ❌ Are refresh tokens stored securely?

**6. Authorization Logic Flaws**
- ❌ Can users access resources without proper authentication?
- ❌ Are there race conditions in token validation?
- ❌ Is logout properly implemented (client + server)?
</critical_security_checks>

<output_format>
Return ONLY a JSON object (no markdown, no code blocks):
{{
  "vulnerabilities": [
    {{
      "cwe_id": "CWE-XXX",
      "severity": "HIGH|MEDIUM|LOW",
      "title": "Precise vulnerability name",
      "line_number": <exact_line>,
      "description": "Technical explanation of the flaw",
      "attack_scenario": "Realistic step-by-step exploit path",
      "fix": "Production-ready code fix using ONLY real framework APIs. Include:\\n- Environment-aware logic (dev vs prod)\\n- Inline comments explaining WHY\\n- Complete working example\\n\\nExample:\\nif os.getenv('ENVIRONMENT') == 'production':\\n    # Enforce HTTPS at application level OR use reverse proxy\\n    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['yourdomain.com'])\\n\\n# Better: Configure nginx/traefik for HTTPS termination"
    }}
  ]
}}
</output_format>

<quality_standards>
- Report ONLY high-confidence vulnerabilities
- Provide fixes using REAL framework features (verify imports exist!)
- Focus on authentication-specific issues
- Prioritize exploitable flaws over theoretical risks
</quality_standards>

<false_positive_filters>
CRITICAL: Do NOT report the following as vulnerabilities:

1. **Test Code**: If file path contains "test", "tests", "_test", "conftest", "spec", or "mock":
   - Hardcoded test credentials are SAFE
   - Insecure test sessions are SAFE
   - Mock authentication is SAFE

2. **Non-Security Cryptography**:
   - `hashlib.md5(..., usedforsecurity=False)` is SAFE
   - MD5/SHA1 for checksums, cache keys, ETags is SAFE
   - Only flag if used for passwords, tokens, or signatures

3. **Library Code**: If this is a library (not a web application):
   - Session/auth vulnerabilities only apply to web applications, not libraries
   - Libraries delegate security to the calling application

4. **Tutorial/Example Code**: If path contains "tutorial", "example", "demo":
   - Teaching examples with weak auth are SAFE (not production)

5. **Context Matters**: Check variable names and comments before reporting:
   - `test_secret`, `demo_token`, `example_password` are likely safe
   - Comments like "for testing only" or "development mode" indicate non-production code

If unsure, DO NOT REPORT IT. False positives waste time.
</false_positive_filters>"""

    _CONFIG_AUDIT_PROMPT = """<role>You are a DevSecOps principal engineer specializing in production security hardening, with expertise in OWASP Top 10 and cloud-native security patterns.</role>

<task>Audit this application configuration for security misconfigurations that could be exploited in production deployments.</task>

<context>
File: {file_path} (Application Configuration)
Language: {language}
</context>

<code>
{code}
</code>

<configuration_security_framework>
Systematically evaluate these production security controls:

**1. CORS Configuration (CWE-346)**
- ❌ Wildcard origins ["*"] with credentials enabled?
- ❌ Missing origin validation for authenticated endpoints?
- ❌ Overly permissive allowed_methods or allowed_headers?

**2. Secret Management (CWE-798, CWE-259)**
- ❌ Secrets loaded without cryptographic strength validation (< 32 bytes)?
- ❌ Default/hardcoded secrets still present?
- ❌ Secrets exposed in environment or error messages?
- ❌ No secret rotation mechanism?

**3. Transport Security (CWE-319, CWE-523)**
- ❌ Missing HTTPS enforcement middleware or headers?
- ❌ Insecure redirect from HTTP→HTTPS?
- ❌ Missing HSTS (HTTP Strict Transport Security) headers?

**4. Security Headers (Multiple CWEs)**
- ❌ Missing Content-Security-Policy (CSP)?
- ❌ Missing X-Frame-Options (clickjacking)?
- ❌ Missing X-Content-Type-Options: nosniff?
- ❌ Permissive Referrer-Policy?

**5. Middleware Ordering & Composition**
- ❌ Security middleware loaded AFTER routing (too late)?
- ❌ Authentication middleware bypass possible?
- ❌ CSRF middleware missing for state-changing endpoints?

**6. Production Readiness**
- ❌ Debug mode enabled (leaks stack traces)?
- ❌ Verbose error handling exposing internals?
- ❌ Development endpoints/routes exposed?
- ❌ Missing rate limiting on APIs?

**7. Session Configuration**
- ❌ Session timeout too long or missing?
- ❌ Session not regenerated after auth?
- ❌ Client-side session storage (insecure)?
</configuration_security_framework>

<output_format>
Return ONLY a JSON object (no markdown):
{{
  "vulnerabilities": [
    {{
      "cwe_id": "CWE-XXX",
      "severity": "HIGH|MEDIUM|LOW",
      "title": "Specific misconfiguration name",
      "line_number": <exact_line>,
      "description": "Technical explanation of the security risk",
      "attack_scenario": "How an attacker exploits this misconfiguration",
      "fix": "Complete secure configuration with code examples. Use ONLY real framework features:\\n\\n# Example Secure CORS:\\napp.add_middleware(\\n    CORSMiddleware,\\n    allow_origins=[\\n        'http://localhost:3000',  # Dev\\n        'https://yourdomain.com'  # Prod (replace with actual domain)\\n    ],\\n    allow_credentials=True,\\n    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\\n    allow_headers=['Content-Type', 'Authorization'],\\n    max_age=3600\\n)\\n\\n# NEVER use wildcard '*' with credentials!"
    }}
  ]
}}
</output_format>

<quality_criteria>
- Report ONLY exploitable misconfigurations
- Provide production-ready fixes using real framework APIs
- Include environment-aware examples (dev vs prod)
- Prioritize HIGH severity issues (HTTPS, CORS, secrets)
- Add inline comments explaining security rationale
</quality_criteria>

<false_positive_filters>
CRITICAL: Do NOT report the following as vulnerabilities:

1. **Test/Development Configuration**: If file contains "test", "dev", "example", "demo":
   - Debug mode enabled is SAFE in test/dev configs
   - Weak secrets in test configs are SAFE
   - Permissive CORS in local development is SAFE

2. **Non-Security Cryptography**:
   - `hashlib.md5(..., usedforsecurity=False)` is SAFE
   - MD5/SHA1 for checksums, ETags, cache keys is SAFE
   - Only flag if used for passwords, tokens, or signatures

3. **Library Code**: If analyzing a library/framework (not a web application):
   - Security configuration is the responsibility of the consuming application
   - CORS/HTTPS/headers only matter for web servers, not libraries
   - Example code should not be flagged

4. **Tutorial/Example Code**: If path contains "tutorial", "example", "demo":
   - Simplified configs for teaching are SAFE (not production)

If unsure, DO NOT REPORT IT. False positives waste time.
</false_positive_filters>"""

    def __init__(self, ai_provider: fix_ai.AIFixProvider, config: schema.ScanConfig):
        """
        Initialize AI Security Auditor with an AI provider.

        Args:
            ai_provider: Instance of AIFixProvider (OpenAI, Anthropic, Gemini, or Groq)
            config: Scan configuration
        """
        self.ai_provider = ai_provider
        self.config = config
        self._audit_count = 0
        self._vulnerabilities_found = 0

    def _select_prompt_template(self, file_path: Path) -> str:
        """
        Select the appropriate audit prompt based on file type and content.

        Args:
            file_path: Path to the file being audited

        Returns:
            The appropriate prompt template
        """
        file_name = file_path.name.lower()
        file_content_preview = ""

        try:
            # Read first 500 characters to detect file purpose
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                file_content_preview = f.read(500).lower()
        except Exception:
            pass

        # Authentication/Authorization routes
        if any(
            keyword in file_name or keyword in file_content_preview
            for keyword in ["auth", "login", "oauth", "session", "jwt", "token"]
        ):
            logger.debug(f"Using AUTH_ROUTE audit prompt for {file_path}")
            return self._AUTH_ROUTE_AUDIT_PROMPT

        # Main config files
        if any(
            keyword in file_name
            for keyword in [
                "main.py",
                "app.py",
                "server.py",
                "config.py",
                "settings.py",
                "index.js",
                "server.js",
                "app.js",
            ]
        ):
            logger.debug(f"Using CONFIG audit prompt for {file_path}")
            return self._CONFIG_AUDIT_PROMPT

        # Default to general audit
        return self._GENERAL_AUDIT_PROMPT

    def _get_file_language(self, file_path: Path) -> str:
        """Detect programming language from file extension."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".php": "php",
            ".rb": "ruby",
            ".go": "go",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
        }
        return ext_map.get(file_path.suffix.lower(), "unknown")

    def _read_file_content(
        self, file_path: Path, max_lines: int = 500
    ) -> Optional[str]:
        """
        Read file content with safety limits.

        Args:
            file_path: Path to file
            max_lines: Maximum lines to read (prevents token overflow)

        Returns:
            File content or None if unreadable
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        lines.append(f"\n... (file truncated after {max_lines} lines)")
                        break
                    lines.append(line)
                return "".join(lines)
        except Exception as e:
            logger.debug(f"Could not read file {file_path}: {e}")
            return None

    def _parse_ai_response(
        self, response: str, file_path: Path
    ) -> List[schema.Finding]:
        """
        Parse AI audit response and convert to Finding objects.

        Args:
            response: JSON response from AI
            file_path: Path to the audited file

        Returns:
            List of Finding objects
        """
        findings = []

        try:
            # Clean response (remove markdown code fences if present)
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]
            response = response.strip()

            # Parse JSON
            audit_result = json.loads(response)

            # Extract vulnerabilities
            vulnerabilities = audit_result.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                # Map severity string to Severity enum
                severity_str = vuln.get("severity", "MEDIUM").upper()
                severity_map = {
                    "CRITICAL": schema.Severity.CRITICAL,
                    "HIGH": schema.Severity.HIGH,
                    "MEDIUM": schema.Severity.MEDIUM,
                    "LOW": schema.Severity.LOW,
                }
                severity = severity_map.get(severity_str, schema.Severity.MEDIUM)

                # Extract actual code snippet from file
                line_number = vuln.get("line_number", 0)
                code_snippet = self._extract_code_at_line(file_path, line_number)

                # Create Finding object
                finding = schema.Finding(
                    vuln_id=f"ai-audit-{vuln.get('cwe_id', 'LOGIC')}",
                    rule_id=f"ai-security-audit.{vuln.get('cwe_id', 'logic-vulnerability')}",
                    title=vuln.get("title", "AI-Detected Security Issue"),
                    description=f"{vuln.get('description', 'Security vulnerability detected by AI audit.')}\n\n"
                    f"**Attack Scenario:** {vuln.get('attack_scenario', 'Not specified')}\n\n"
                    f"**Fix:** {vuln.get('fix', 'Review code and apply security best practices')}",
                    severity=severity,
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=code_snippet,
                    source=schema.VulnSource.AI_DETECTION,
                    fix_suggestion=vuln.get("fix"),
                )

                findings.append(finding)
                self._vulnerabilities_found += 1

                logger.info(
                    f"AI discovered {severity_str} vulnerability: {finding.title} "
                    f"in {file_path}:{finding.line_number}"
                )

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse AI audit response as JSON: {e}")
            logger.debug(f"Raw response: {response[:500]}")
        except Exception as e:
            logger.error(f"Error processing AI audit response: {e}")

        return findings

    def audit_file(self, file_path: Path) -> List[schema.Finding]:
        """
        Perform AI security audit on a single file.

        Args:
            file_path: Path to file to audit

        Returns:
            List of discovered vulnerabilities
        """
        self._audit_count += 1

        # Read file content
        code = self._read_file_content(file_path)
        if not code:
            logger.debug(f"Skipping AI audit for {file_path} (unreadable)")
            return []

        # Detect language
        language = self._get_file_language(file_path)

        # Select appropriate prompt
        prompt_template = self._select_prompt_template(file_path)

        # Fill in prompt
        prompt = prompt_template.format(
            file_path=str(file_path), language=language, code=code
        )

        try:
            logger.info(f"Running AI security audit on {file_path}...")

            # Generate AI analysis
            response = self.ai_provider.generate_content(prompt)

            # Parse response into findings
            findings = self._parse_ai_response(response, file_path)

            if findings:
                logger.info(
                    f"AI audit found {len(findings)} vulnerabilities in {file_path}"
                )
            else:
                logger.debug(f"AI audit: {file_path} appears secure")

            return findings

        except Exception as e:
            logger.error(f"AI audit failed for {file_path}: {e}")
            return []

    def _extract_code_at_line(
        self, file_path: Path, line_number: int, context: int = 3
    ) -> str:
        """
        Extract actual code snippet from file at specified line with context.

        Args:
            file_path: Path to source file
            line_number: Target line number (1-indexed)
            context: Number of lines to include before/after

        Returns:
            Code snippet with context, or placeholder if extraction fails
        """
        try:
            if not file_path.exists() or line_number <= 0:
                return f"AI-detected vulnerability at line {line_number}"

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Get context lines (convert to 0-indexed)
            start = max(0, line_number - context - 1)
            end = min(len(lines), line_number + context)

            # Format with line numbers and highlight target line
            code_lines = []
            for i in range(start, end):
                line_num = i + 1
                prefix = ">>> " if line_num == line_number else "    "
                code_lines.append(f"{prefix}{lines[i].rstrip()}")

            return "\n".join(code_lines)
        except Exception as e:
            logger.debug(f"Failed to extract code from {file_path}:{line_number}: {e}")
            return f"AI-detected vulnerability at line {line_number}\n# Error: Unable to read source file"

    def audit_directory(
        self, target_path: Path, file_patterns: List[str] = None, max_files: int = 20
    ) -> List[schema.Finding]:
        """
        Perform AI security audit on multiple files in a directory.

        Args:
            target_path: Root directory to audit
            file_patterns: File patterns to include (e.g., ['*.py', '*.js'])
            max_files: Maximum files to audit (cost control)

        Returns:
            List of all discovered vulnerabilities
        """
        if file_patterns is None:
            # Default patterns for security-critical files
            # Prioritize auth, config, and entry point files
            file_patterns = [
                # Authentication & authorization
                "**/auth/*.py",
                "**/auth/*.js",
                "**/auth/*.ts",
                "**/authentication/*.py",
                "**/authentication/*.js",
                # Entry points
                "**/main.py",
                "**/app.py",
                "**/server.py",
                "**/index.js",
                "**/server.js",
                "**/app.js",
                # Configuration
                "**/config.py",
                "**/settings.py",
                "**/config.js",
                "**/config.ts",
                # Routes & endpoints
                "**/routes/*.py",
                "**/routes/*.js",
                "**/views/*.py",
                "**/api/*.py",
                "**/api/*.js",
                # Middleware & handlers
                "**/middleware/*.py",
                "**/middleware/*.js",
                "**/handlers/*.py",
                # For libraries: scan main module files
                "*.py",  # Top-level Python files
                "**/*.py",  # All Python files (recursive)
                "**/*.js",  # All JavaScript files (recursive)
            ]

        all_findings = []
        files_audited = 0

        # Collect files to audit
        files_to_audit = []
        for pattern in file_patterns:
            try:
                if "**" in pattern:
                    # Recursive glob - use rglob
                    sub_pattern = pattern.replace("**/", "")
                    matched_files = list(target_path.rglob(sub_pattern))
                    files_to_audit.extend(matched_files)
                else:
                    # Non-recursive glob
                    matched_files = list(target_path.glob(pattern))
                    files_to_audit.extend(matched_files)
            except (OSError, ValueError) as e:
                logger.debug(f"Pattern {pattern} failed to match: {e}")
                continue

        # Remove duplicates, filter out non-files, and skip test files
        files_to_audit = list(
            set(
                f
                for f in files_to_audit
                if f.is_file()
                and not any(
                    skip in str(f).lower()
                    for skip in [
                        "test_", "_test", "tests/", "/test/", "/tests/",
                        "conftest.py", "test.py", "_spec.py",
                        ".pyc", "__pycache__",
                        "/examples/", "/example/", "/demo/",
                        "/tutorial/", "/tutorials/"
                    ]
                )
            )
        )

        # Sort by priority (auth files first)
        files_to_audit.sort(
            key=lambda f: (
                0
                if any(kw in f.name.lower() for kw in ["auth", "login", "oauth"])
                else 1
                if any(
                    kw in f.name.lower() for kw in ["main", "app", "server", "config"]
                )
                else 2
            )
        )

        # Limit files for cost control
        files_to_audit = files_to_audit[:max_files]

        logger.info(
            f"AI Security Auditor: Will audit {len(files_to_audit)} files in {target_path}"
        )

        for file_path in files_to_audit:
            findings = self.audit_file(file_path)
            all_findings.extend(findings)
            files_audited += 1

            # Cost control: stop if too many findings
            if len(all_findings) >= 50:
                logger.warning(
                    f"Stopping AI audit: Found {len(all_findings)} vulnerabilities already"
                )
                break

        logger.info(
            f"AI Security Audit complete: {files_audited} files audited, "
            f"{len(all_findings)} vulnerabilities discovered"
        )

        return all_findings

    def get_stats(self) -> Dict[str, int]:
        """Get audit statistics."""
        return {
            "files_audited": self._audit_count,
            "vulnerabilities_found": self._vulnerabilities_found,
        }


def audit_with_ai(
    target_path: Path, config: schema.ScanConfig, max_files: int = 20
) -> List[schema.Finding]:
    """
    Public API: Perform AI security audit on a codebase.

    This complements static analysis by discovering logic and configuration
    vulnerabilities that rule-based tools miss.

    Args:
        target_path: Directory to audit
        config: Scan configuration with AI provider settings
        max_files: Maximum files to audit (cost control)

    Returns:
        List of discovered vulnerabilities

    Raises:
        Exception: If AI provider initialization fails
    """
    # Get AI provider
    try:
        # Convert AIProvider enum to string if needed
        provider_name = config.ai_provider.value if config.ai_provider else None
        ai_provider = fix_ai.get_ai_fix_provider(config.api_keys, provider_name)
    except fix_ai.AIFixError as e:
        logger.error(f"Failed to initialize AI provider: {e}")
        logger.warning("AI security audit skipped (no AI provider available)")
        return []

    # Create auditor
    auditor = AISecurityAuditor(ai_provider, config)

    # Run audit
    findings = auditor.audit_directory(target_path, max_files=max_files)

    # Log stats
    stats = auditor.get_stats()
    logger.info(f"AI Security Audit Stats: {stats}")

    return findings
