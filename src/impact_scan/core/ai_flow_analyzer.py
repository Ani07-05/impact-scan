"""
AI-Powered Code Flow Analyzer

Revolutionary approach: Instead of pattern matching, use AI to understand
code logic, data flow, and find vulnerabilities that static analyzers miss.

This is the secret weapon that makes impact-scan unique.
"""

import logging
import os
from pathlib import Path
from typing import List, Dict, Optional
import json

from ..utils import schema

logger = logging.getLogger(__name__)


class AIFlowAnalyzer:
    """
    AI-powered vulnerability detector that understands code context.

    Instead of regex patterns, this analyzer:
    1. Reads actual code files
    2. Asks AI to trace authentication flows
    3. Finds logic bugs, missing checks, bypass opportunities
    4. Provides detailed attack scenarios
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            logger.warning("No Groq API key found - AI flow analysis will be skipped")

    def analyze_all_files(self, root_path: Path, max_files: int = 50) -> List[schema.Finding]:
        """
        Analyze ALL code files using AI to find security vulnerabilities.

        This finds ALL types of vulnerabilities:
        - Authentication/authorization issues
        - SQL injection, XSS, command injection
        - Logic bugs and race conditions
        - Insecure configurations
        - Data exposure and privacy issues
        """
        if not self.api_key:
            return []

        findings = []

        # Find all code files (Python, JS, TS)
        code_files = self._find_all_code_files(root_path)

        if not code_files:
            logger.info("No code files found")
            return findings

        logger.info(f"Found {len(code_files)} code files, analyzing up to {max_files}")

        # Analyze each file with AI
        import time

        for idx, file_path in enumerate(code_files[:max_files], 1):
            try:
                file_findings = self._analyze_file_with_ai(file_path, root_path)
                findings.extend(file_findings)

                # Add delay between requests to avoid rate limiting
                # Groq free tier limits vary - use conservative 5s delay
                if idx < len(code_files[:max_files]):  # Don't sleep after last file
                    time.sleep(5.0)  # 5s delay = max 12 requests/minute (very conservative)

            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
                # Still sleep on error to avoid hammering the API
                if idx < len(code_files[:max_files]):
                    time.sleep(5.0)

        return findings

    def analyze_auth_flow(self, root_path: Path) -> List[schema.Finding]:
        """
        Analyze authentication and authorization flows using AI.

        Legacy method - use analyze_all_files() for comprehensive scanning.
        """
        # Just call analyze_all_files with lower limit for backward compatibility
        return self.analyze_all_files(root_path, max_files=20)

    def _find_all_code_files(self, root_path: Path) -> List[Path]:
        """Find all Python, JavaScript, and TypeScript files."""
        code_files = []

        # Find Python files
        for py_file in root_path.rglob("*.py"):
            if self._should_skip(py_file):
                continue
            code_files.append(py_file)

        # Find JavaScript/TypeScript files
        for js_file in root_path.rglob("*.js"):
            if self._should_skip(js_file):
                continue
            code_files.append(js_file)

        for ts_file in root_path.rglob("*.ts"):
            if self._should_skip(ts_file):
                continue
            code_files.append(ts_file)

        for tsx_file in root_path.rglob("*.tsx"):
            if self._should_skip(tsx_file):
                continue
            code_files.append(tsx_file)

        # Remove duplicates
        unique_files = list(set(code_files))

        # Sort by size (analyze smaller files first for faster results)
        unique_files.sort(key=lambda f: f.stat().st_size if f.exists() else 0)

        return unique_files

    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        skip_patterns = ['node_modules', '.venv', 'venv', '.git', 'dist', 'build', '__pycache__', '.next', 'coverage']
        return any(part in file_path.parts for part in skip_patterns)

    def _find_auth_files(self, root_path: Path) -> List[Path]:
        """Find files likely to contain authentication logic."""
        auth_patterns = [
            "*auth*", "*login*", "*session*", "*jwt*", "*oauth*",
            "*permission*", "*access*", "*security*", "*middleware*",
            "*route*", "*api*", "*handler*"
        ]

        auth_files = []

        for pattern in auth_patterns:
            # Python files
            auth_files.extend(root_path.rglob(f"**/{pattern}.py"))
            # JavaScript/TypeScript files
            auth_files.extend(root_path.rglob(f"**/{pattern}.js"))
            auth_files.extend(root_path.rglob(f"**/{pattern}.ts"))

        # Remove duplicates and filter out common ignore patterns
        unique_files = []
        seen = set()

        for f in auth_files:
            if f in seen:
                continue
            if any(part in f.parts for part in ['node_modules', '.venv', 'venv', '.git', 'dist', 'build']):
                continue
            seen.add(f)
            unique_files.append(f)

        return unique_files[:20]  # Limit to 20 files

    def _analyze_file_with_ai(self, file_path: Path, root_path: Path) -> List[schema.Finding]:
        """Use Groq AI to analyze a file for vulnerabilities."""
        try:
            source_code = file_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")
            return []

        # Truncate if too large (Groq has token limits)
        if len(source_code) > 10000:
            source_code = source_code[:10000] + "\n\n... (truncated)"

        prompt = f"""You are an elite security researcher and penetration tester with deep expertise in application security.

MISSION: Perform a COMPREHENSIVE security analysis of the code below. Think like an attacker - your goal is to find EVERY possible way to exploit this code.

File: {file_path.name}
Language: {file_path.suffix}

Code:
```
{source_code}
```

ANALYSIS FRAMEWORK - Follow this systematic approach:

1. AUTHENTICATION & AUTHORIZATION ANALYSIS
   - Identify all endpoints/functions that handle sensitive operations
   - Check: Is authentication required? Can it be bypassed?
   - Check: Are there hardcoded credentials or weak authentication logic?
   - Check: Can users access resources belonging to other users?
   - Look for: Missing decorators, unauthenticated routes, broken access control

2. INPUT VALIDATION & INJECTION ATTACKS
   - Trace ALL user inputs (parameters, headers, cookies, body)
   - For each input, ask: Where does this data flow? What operations use it?
   - SQL Injection: Is input used in database queries without parameterization?
   - Command Injection: Is input passed to system commands (os.system, subprocess)?
   - XSS: Is input rendered in HTML without sanitization?
   - Path Traversal: Is input used in file operations without validation?

3. BUSINESS LOGIC VULNERABILITIES
   - Can workflow steps be skipped or reordered?
   - Are there race conditions in critical operations?
   - Can numeric values overflow or underflow?
   - Are there TOCTOU (time-of-check-time-of-use) bugs?

4. SENSITIVE DATA EXPOSURE
   - Are secrets/API keys hardcoded in the code?
   - Is sensitive data logged or exposed in error messages?
   - Are cryptographic operations done correctly?
   - Can attackers enumerate valid users or resources?

5. FRAMEWORK-SPECIFIC ISSUES
   - Are security middleware/decorators missing?
   - Are framework defaults insecure?
   - Are CORS policies too permissive?

CRITICAL INSTRUCTIONS:
- THINK DEEPLY: Don't just pattern match. Understand the code flow.
- TRACE DATA: Follow user input from entry point to dangerous operations.
- BE SPECIFIC: Provide exact line numbers and attack payloads.
- EXPLOIT SCENARIOS: Explain step-by-step how to exploit each vulnerability.

OUTPUT FORMAT (MUST BE VALID JSON):
{{
  "vulnerabilities": [
    {{
      "line": <exact line number where vulnerability occurs>,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "<concise vulnerability name>",
      "description": "<detailed technical explanation of the security flaw>",
      "exploit": "<step-by-step attack scenario with example payloads/requests>",
      "fix": "<specific code changes or security controls needed>"
    }}
  ]
}}

SEVERITY GUIDELINES:
- CRITICAL: Direct system compromise, auth bypass, RCE, data breach
- HIGH: SQL injection, XSS, unauthorized data access, privilege escalation
- MEDIUM: Information disclosure, CSRF, weak crypto, logic flaws
- LOW: Security misconfigurations, information leaks, best practice violations

EXAMPLE HIGH-QUALITY FINDING:
{{
  "line": 67,
  "severity": "CRITICAL",
  "title": "SQL Injection via Unsanitized User Input",
  "description": "The search_query parameter from user input is directly concatenated into the SQL query string without any sanitization or parameterization, allowing arbitrary SQL commands to be executed.",
  "exploit": "1. Send POST request with search_query=' OR '1'='1' --\n2. Query becomes: SELECT * FROM users WHERE name='' OR '1'='1' --'\n3. Bypasses WHERE clause, returns all users including admins\n4. Use UNION SELECT to exfiltrate other tables: search_query=' UNION SELECT password FROM admin_users--",
  "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (search_query,)) instead of string concatenation"
}}

NOW ANALYZE THE CODE. Think step-by-step:
1. What is the purpose of this code?
2. What user inputs does it accept?
3. Where do those inputs flow in the code?
4. What dangerous operations (DB, files, commands) are performed?
5. What security checks are present or MISSING?

Return ONLY valid JSON. If no vulnerabilities: {{"vulnerabilities": []}}
"""

        try:
            response = self._call_groq(prompt)
            vulnerabilities = self._parse_ai_response(response)

            findings = []
            for vuln in vulnerabilities:
                finding = schema.Finding(
                    file_path=file_path,
                    line_number=vuln.get('line', 1),
                    vuln_id=f"AI-FLOW-{len(findings):03d}",
                    rule_id=f"AI-FLOW-{len(findings):03d}",
                    title=vuln.get('title', 'AI-Detected Vulnerability'),
                    description=vuln.get('description', '') + "\n\nExploit: " + vuln.get('exploit', ''),
                    severity=self._parse_severity(vuln.get('severity', 'MEDIUM')),
                    source=schema.VulnSource.AI_DETECTION,
                    code_snippet=self._get_code_snippet(source_code, vuln.get('line', 1)),
                    fix_suggestion=vuln.get('fix', 'Review the code and apply appropriate security controls'),
                )
                findings.append(finding)

            return findings

        except Exception as e:
            logger.error(f"AI analysis failed for {file_path}: {e}")
            return []

    def _call_groq(self, prompt: str, retry_count: int = 3) -> str:
        """Call Groq API with retry logic for rate limiting."""
        import httpx
        import time

        for attempt in range(retry_count):
            try:
                response = httpx.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security expert. Always return valid JSON with properly escaped strings."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        "temperature": 0.1,
                        "max_tokens": 2000,
                        "response_format": {"type": "json_object"}
                    },
                    timeout=30.0,
                )

                response.raise_for_status()
                result = response.json()
                return result['choices'][0]['message']['content']

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limit
                    if attempt < retry_count - 1:
                        wait_time = (attempt + 1) * 2  # Exponential backoff: 2s, 4s, 6s
                        logger.warning(f"Rate limited by Groq API. Retrying in {wait_time}s... (attempt {attempt + 1}/{retry_count})")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error(f"Rate limit exceeded after {retry_count} attempts")
                        raise
                else:
                    logger.error(f"Groq API HTTP error: {e}")
                    raise
            except Exception as e:
                logger.error(f"Groq API call failed: {e}")
                raise

        raise Exception("Failed to call Groq API after all retries")

    def _parse_ai_response(self, response: str) -> List[Dict]:
        """Parse AI response into structured vulnerabilities."""
        try:
            # With response_format=json_object, the response should already be valid JSON
            # Just parse it directly
            data = json.loads(response)
            return data.get('vulnerabilities', [])

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")

            # Fallback: try to extract JSON manually
            try:
                start = response.find('{')
                end = response.rfind('}') + 1

                if start != -1 and end > 0:
                    json_str = response[start:end]
                    data = json.loads(json_str)
                    return data.get('vulnerabilities', [])
            except:
                pass

            logger.debug(f"Raw response: {response[:500]}...")
            return []

    def _parse_severity(self, severity_str: str) -> schema.Severity:
        """Parse severity string to Severity enum."""
        severity_map = {
            'CRITICAL': schema.Severity.CRITICAL,
            'HIGH': schema.Severity.HIGH,
            'MEDIUM': schema.Severity.MEDIUM,
            'LOW': schema.Severity.LOW,
        }
        return severity_map.get(severity_str.upper(), schema.Severity.MEDIUM)

    def _get_code_snippet(self, source: str, line_number: int) -> str:
        """Extract code snippet around line number."""
        lines = source.splitlines()
        if 0 < line_number <= len(lines):
            return lines[line_number - 1].strip()
        return ""
