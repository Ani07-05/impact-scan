"""
AST-Based Security Scanner

Pure Python AST analysis for security vulnerabilities without external tools.
Bypasses Semgrep and uses native Python ast module for pattern detection.
"""

import ast
import logging
from pathlib import Path
from typing import List, Optional, Set, Tuple

from ..utils import schema

logger = logging.getLogger(__name__)


class ASTSecurityScanner:
    """
    AST-based security vulnerability scanner.

    Detects security issues by parsing Python source code into Abstract Syntax Trees
    and analyzing patterns that indicate vulnerabilities.
    """

    def __init__(self):
        self.findings: List[schema.Finding] = []

    def scan_python_file(self, file_path: Path, root_path: Path) -> List[schema.Finding]:
        """
        Scan a single Python file for security vulnerabilities.

        Args:
            file_path: Path to the Python file
            root_path: Root path of the project

        Returns:
            List of security findings
        """
        findings = []

        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))

            # Run different vulnerability checks
            findings.extend(self._check_sql_injection(tree, file_path, root_path, source))
            findings.extend(self._check_command_injection(tree, file_path, root_path, source))
            findings.extend(self._check_insecure_deserialization(tree, file_path, root_path, source))
            findings.extend(self._check_weak_crypto(tree, file_path, root_path, source))
            findings.extend(self._check_hardcoded_secrets(tree, file_path, root_path, source))
            findings.extend(self._check_eval_exec(tree, file_path, root_path, source))
            findings.extend(self._check_jwt_issues(tree, file_path, root_path, source))

        except SyntaxError as e:
            logger.debug(f"Syntax error parsing {file_path}: {e}")
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")

        return findings

    def _check_sql_injection(
        self, tree: ast.AST, file_path: Path, root_path: Path, source: str
    ) -> List[schema.Finding]:
        """Detect SQL injection vulnerabilities."""
        findings = []

        for node in ast.walk(tree):
            # Check for string formatting in SQL queries
            if isinstance(node, ast.Call):
                if self._is_sql_query_call(node):
                    # Check if using string formatting
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['format', 'execute', 'executemany']:
                            # Check if argument involves string concatenation or f-strings
                            for arg in node.args:
                                if self._is_dynamic_string(arg):
                                    findings.append(self._create_finding(
                                        file_path=file_path,
                                        root_path=root_path,
                                        line_number=node.lineno,
                                        vuln_id="AST-SQL-001",
                                        title="SQL Injection via String Formatting",
                                        description="SQL query constructed using string formatting or concatenation. Use parameterized queries instead.",
                                        severity=schema.Severity.HIGH,
                                        cwe="CWE-89",
                                        code_snippet=self._get_code_snippet(source, node.lineno),
                                        fix_suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                                    ))

        return findings

    def _check_command_injection(
        self, tree: ast.AST, file_path: Path, root_path: Path, source: str
    ) -> List[schema.Finding]:
        """Detect command injection vulnerabilities."""
        findings = []

        dangerous_functions = {
            'os.system', 'os.popen', 'subprocess.call', 'subprocess.run',
            'subprocess.Popen', 'commands.getoutput', 'eval', 'exec'
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)

                if func_name in dangerous_functions:
                    # Check if command involves user input
                    if node.args and self._is_dynamic_string(node.args[0]):
                        findings.append(self._create_finding(
                            file_path=file_path,
                            root_path=root_path,
                            line_number=node.lineno,
                            vuln_id="AST-CMD-001",
                            title="Command Injection Risk",
                            description=f"Command execution using {func_name} with dynamic input. This can lead to command injection.",
                            severity=schema.Severity.CRITICAL,
                            cwe="CWE-78",
                            code_snippet=self._get_code_snippet(source, node.lineno),
                            fix_suggestion="Use subprocess.run() with shell=False and pass arguments as a list.",
                        ))

        return findings

    def _check_insecure_deserialization(
        self, tree: ast.AST, file_path: Path, root_path: Path, source: str
    ) -> List[schema.Finding]:
        """Detect insecure deserialization (pickle, yaml.load)."""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)

                # Check for pickle.loads, pickle.load
                if func_name in ['pickle.loads', 'pickle.load']:
                    findings.append(self._create_finding(
                        file_path=file_path,
                        root_path=root_path,
                        line_number=node.lineno,
                        vuln_id="AST-DESER-001",
                        title="Insecure Deserialization - Pickle",
                        description="pickle.load() can execute arbitrary code. Never unpickle data from untrusted sources.",
                        severity=schema.Severity.CRITICAL,
                        cwe="CWE-502",
                        code_snippet=self._get_code_snippet(source, node.lineno),
                        fix_suggestion="Use JSON or other safe serialization formats. If pickle is required, validate and sign the data.",
                    ))

                # Check for yaml.load without Loader
                if func_name == 'yaml.load':
                    has_safe_loader = False
                    for keyword in node.keywords:
                        if keyword.arg == 'Loader' and self._is_safe_yaml_loader(keyword.value):
                            has_safe_loader = True

                    if not has_safe_loader:
                        findings.append(self._create_finding(
                            file_path=file_path,
                            root_path=root_path,
                            line_number=node.lineno,
                            vuln_id="AST-DESER-002",
                            title="Insecure YAML Deserialization",
                            description="yaml.load() without SafeLoader can execute arbitrary Python code.",
                            severity=schema.Severity.HIGH,
                            cwe="CWE-502",
                            code_snippet=self._get_code_snippet(source, node.lineno),
                            fix_suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                        ))

        return findings

    def _check_weak_crypto(
        self, tree: ast.AST, file_path: Path, root_path: Path, source: str
    ) -> List[schema.Finding]:
        """Detect weak cryptographic algorithms."""
        findings = []

        weak_algorithms = ['md5', 'sha1', 'des', 'rc4']

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)

                # Check hashlib usage
                if func_name in ['hashlib.md5', 'hashlib.sha1']:
                    findings.append(self._create_finding(
                        file_path=file_path,
                        root_path=root_path,
                        line_number=node.lineno,
                        vuln_id="AST-CRYPTO-001",
                        title="Weak Cryptographic Hash",
                        description=f"{func_name} is cryptographically broken. Use SHA-256 or stronger.",
                        severity=schema.Severity.MEDIUM,
                        cwe="CWE-327",
                        code_snippet=self._get_code_snippet(source, node.lineno),
                        fix_suggestion="Use hashlib.sha256() or hashlib.sha3_256() for secure hashing.",
                    ))

                # Check for weak random
                if func_name == 'random.random':
                    findings.append(self._create_finding(
                        file_path=file_path,
                        root_path=root_path,
                        line_number=node.lineno,
                        vuln_id="AST-CRYPTO-002",
                        title="Weak Random Number Generator",
                        description="random.random() is not cryptographically secure.",
                        severity=schema.Severity.LOW,
                        cwe="CWE-338",
                        code_snippet=self._get_code_snippet(source, node.lineno),
                        fix_suggestion="Use secrets.token_bytes() or os.urandom() for cryptographic purposes.",
                    ))

        return findings

    def _check_hardcoded_secrets(
        self, tree: ast.AST, file_path: Path, root_path: Path, source: str
    ) -> List[schema.Finding]:
        """Detect hardcoded secrets and credentials."""
        findings = []

        secret_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
            'token', 'auth', 'credential', 'private_key'
        ]

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()

                        # Check if variable name suggests it's a secret
                        if any(pattern in var_name for pattern in secret_patterns):
                            # Check if value is a hardcoded string
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                if len(node.value.value) > 8:  # Likely a real secret
                                    findings.append(self._create_finding(
                                        file_path=file_path,
                                        root_path=root_path,
                                        line_number=node.lineno,
                                        vuln_id="AST-SECRET-001",
                                        title="Hardcoded Secret",
                                        description=f"Potential hardcoded secret in variable '{target.id}'",
                                        severity=schema.Severity.HIGH,
                                        cwe="CWE-798",
                                        code_snippet=self._get_code_snippet(source, node.lineno, mask_secrets=True),
                                        fix_suggestion="Use environment variables or a secrets management system.",
                                    ))

        return findings

    def _check_eval_exec(
        self, tree: ast.AST, file_path: Path, root_path: Path, source: str
    ) -> List[schema.Finding]:
        """Detect dangerous eval/exec usage."""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)

                if func_name in ['eval', 'exec', 'compile']:
                    findings.append(self._create_finding(
                        file_path=file_path,
                        root_path=root_path,
                        line_number=node.lineno,
                        vuln_id="AST-CODE-001",
                        title="Code Injection via eval/exec",
                        description=f"Use of {func_name}() can execute arbitrary code.",
                        severity=schema.Severity.CRITICAL,
                        cwe="CWE-95",
                        code_snippet=self._get_code_snippet(source, node.lineno),
                        fix_suggestion="Avoid eval/exec. Use safer alternatives like ast.literal_eval() for parsing literals.",
                    ))

        return findings

    def _check_jwt_issues(
        self, tree: ast.AST, file_path: Path, root_path: Path, source: str
    ) -> List[schema.Finding]:
        """Detect JWT security issues."""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)

                if func_name == 'jwt.decode':
                    # Check for verify=False or verify_signature=False
                    for keyword in node.keywords:
                        if keyword.arg in ['verify', 'verify_signature']:
                            if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                                findings.append(self._create_finding(
                                    file_path=file_path,
                                    root_path=root_path,
                                    line_number=node.lineno,
                                    vuln_id="AST-JWT-001",
                                    title="JWT Signature Not Verified",
                                    description="JWT token decoded without signature verification.",
                                    severity=schema.Severity.CRITICAL,
                                    cwe="CWE-347",
                                    code_snippet=self._get_code_snippet(source, node.lineno),
                                    fix_suggestion="Remove verify=False or set verify_signature=True",
                                ))

        return findings

    # Helper methods

    def _is_sql_query_call(self, node: ast.Call) -> bool:
        """Check if a call is likely a SQL query execution."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in ['execute', 'executemany', 'raw']
        return False

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Check if a string is dynamically constructed or comes from a variable."""
        # Variables, f-strings, concatenation, or function calls are all dynamic
        return isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call, ast.Name, ast.Attribute))

    def _get_function_name(self, node: ast.AST) -> str:
        """Get the full name of a function being called."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_function_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return ""

    def _is_safe_yaml_loader(self, node: ast.AST) -> bool:
        """Check if YAML loader is safe."""
        if isinstance(node, ast.Attribute):
            return node.attr in ['SafeLoader', 'BaseLoader']
        return False

    def _get_code_snippet(self, source: str, line_number: int, mask_secrets: bool = False) -> str:
        """Extract code snippet around the line number."""
        lines = source.splitlines()
        if 0 < line_number <= len(lines):
            snippet = lines[line_number - 1].strip()
            if mask_secrets:
                # Simple masking for demonstration
                snippet = snippet[:40] + "..." if len(snippet) > 40 else snippet
            return snippet
        return ""

    def _create_finding(
        self,
        file_path: Path,
        root_path: Path,
        line_number: int,
        vuln_id: str,
        title: str,
        description: str,
        severity: schema.Severity,
        cwe: str,
        code_snippet: str,
        fix_suggestion: str,
    ) -> schema.Finding:
        """Create a Finding object."""
        return schema.Finding(
            file_path=file_path,
            line_number=line_number,
            vuln_id=vuln_id,
            title=title,
            description=description,
            severity=severity,
            source=schema.VulnSource.STATIC_ANALYSIS,  # AST analysis is static analysis
            cwe=cwe,
            code_snippet=code_snippet,
            fix_suggestion=fix_suggestion,
            rule_id=vuln_id,
        )


def scan_directory_with_ast(root_path: Path) -> List[schema.Finding]:
    """
    Scan a directory for Python security vulnerabilities using AST analysis.

    Args:
        root_path: Root directory to scan

    Returns:
        List of security findings
    """
    scanner = ASTSecurityScanner()
    findings = []

    for py_file in root_path.rglob("*.py"):
        # Skip common directories
        if any(part in py_file.parts for part in ['.venv', 'venv', 'node_modules', '.git', '__pycache__']):
            continue

        file_findings = scanner.scan_python_file(py_file, root_path)
        findings.extend(file_findings)

    logger.info(f"AST scan complete: {len(findings)} findings in {root_path}")
    return findings
