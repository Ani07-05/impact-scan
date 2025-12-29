"""
Ripgrep-based security scanner for Impact-Scan.

This module replaces semgrep/bandit with a ripgrep-based approach:
1. Use ripgrep to scan codebase and generate impact-scan.md (codebase context)
2. Generate impact-scan.yml (rule-based scanning patterns)
3. Use Groq AI for validation and fix suggestions with Stack Overflow citations
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from groq import Groq

from ..utils import schema

# Set up logging
logger = logging.getLogger(__name__)

# Ripgrep timeout
RIPGREP_TIMEOUT_SECONDS = 300  # 5 minutes


def _find_bundled_ripgrep() -> Optional[str]:
    """
    Find bundled ripgrep binary in the executable bundle.

    When PyInstaller creates a bundle, it extracts files to a temporary directory.
    This function looks for the bundled ripgrep binary in that location.

    Returns:
        Path to bundled ripgrep binary, or None if not found
    """
    # Check if we're running as a PyInstaller bundle
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Running in a PyInstaller bundle
        bundle_dir = Path(sys._MEIPASS)

        # Look for ripgrep in the impact_scan_tools subdirectory
        rg_name = 'rg.exe' if sys.platform == 'win32' else 'rg'
        bundled_rg = bundle_dir / 'impact_scan_tools' / rg_name

        if bundled_rg.exists():
            logger.debug(f"Found bundled ripgrep at: {bundled_rg}")
            return str(bundled_rg)

        # Also check in the root of the bundle (fallback)
        bundled_rg_root = bundle_dir / rg_name
        if bundled_rg_root.exists():
            logger.debug(f"Found bundled ripgrep at: {bundled_rg_root}")
            return str(bundled_rg_root)

    return None


def _get_ripgrep_path() -> str:
    """
    Get the path to ripgrep binary.

    Priority:
    1. Bundled ripgrep (if running as executable)
    2. System ripgrep (from PATH)

    Returns:
        Path to ripgrep binary

    Raises:
        RuntimeError: If ripgrep is not found
    """
    # First, check for bundled ripgrep
    bundled_rg = _find_bundled_ripgrep()
    if bundled_rg:
        logger.info(f"Using bundled ripgrep: {bundled_rg}")
        return bundled_rg

    # Fall back to system ripgrep
    system_rg = shutil.which("rg")
    if system_rg:
        logger.debug(f"Using system ripgrep: {system_rg}")
        return system_rg

    # Not found anywhere
    raise RuntimeError(
        "ripgrep (rg) not found. Please install it:\n"
        "  - Windows: choco install ripgrep\n"
        "  - macOS: brew install ripgrep\n"
        "  - Linux: sudo apt install ripgrep\n"
        "  - Or download from: https://github.com/BurntSushi/ripgrep/releases"
    )


class RipgrepScanner:
    """Ripgrep-based security scanner with AI validation."""

    def __init__(self, root_path: Path, groq_api_key: Optional[str] = None):
        """
        Initialize the ripgrep scanner.

        Args:
            root_path: Root directory to scan
            groq_api_key: Groq API key for AI validation
        """
        self.root_path = root_path.resolve()
        self.groq_api_key = groq_api_key or os.getenv("GROQ_API_KEY")
        self.groq_client = None

        if self.groq_api_key:
            self.groq_client = Groq(api_key=self.groq_api_key)

        # Get ripgrep path (bundled or system)
        self.rg_path = _get_ripgrep_path()

    def generate_codebase_context(self) -> str:
        """
        Generate impact-scan.md: codebase context for AI analysis.

        Returns:
            Path to the generated markdown file
        """
        logger.info("Generating codebase context with ripgrep...")

        context_md = self.root_path / "impact-scan.md"

        # Gather codebase statistics
        file_stats = self._get_file_statistics()
        project_type = self._classify_project()
        frameworks = self._detect_frameworks()
        dependencies = self._extract_dependencies()
        entry_points = self._find_entry_points()

        # Build markdown content
        content = f"""# Impact-Scan Codebase Context

## Project Overview
- **Type**: {project_type}
- **Root Path**: {self.root_path}
- **Total Files**: {file_stats['total_files']}
- **Total Lines**: {file_stats['total_lines']}

## File Distribution
{self._format_file_distribution(file_stats['by_extension'])}

## Detected Frameworks & Libraries
{self._format_frameworks(frameworks)}

## Dependencies
{self._format_dependencies(dependencies)}

## Entry Points
{self._format_entry_points(entry_points)}

## Security-Relevant Patterns Detected
{self._detect_security_patterns()}

## Knowledge Graph Building Hints
This codebase appears to be a **{project_type}** project.
Key relationships to model:
- Files to frameworks/libraries
- Entry points to routes/handlers
- Dependencies to vulnerabilities
- Security patterns to CWE categories
"""

        # Write to file
        context_md.write_text(content, encoding='utf-8')
        logger.info(f"Generated codebase context: {context_md}")

        return str(context_md)

    def generate_scan_rules(self, project_context: Optional[str] = None) -> str:
        """
        Generate impact-scan.yml: rule-based scanning patterns for this codebase.

        Args:
            project_context: Optional project classification context

        Returns:
            Path to the generated YAML file
        """
        logger.info("Generating scan rules based on codebase...")

        rules_yml = self.root_path / "impact-scan.yml"

        # Build rule-based patterns
        rules = {
            "version": "1.0",
            "project_type": project_context or self._classify_project(),
            "rules": []
        }

        # Add language-specific security patterns
        rules["rules"].extend(self._get_generic_security_patterns())

        # Add framework-specific patterns
        frameworks = self._detect_frameworks()
        if "Flask" in frameworks or "Django" in frameworks:
            rules["rules"].extend(self._get_python_web_patterns())
        if "Express" in frameworks or "React" in frameworks:
            rules["rules"].extend(self._get_javascript_patterns())

        # Write to file
        with open(rules_yml, 'w', encoding='utf-8') as f:
            yaml.dump(rules, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Generated scan rules: {rules_yml}")
        return str(rules_yml)

    def scan_with_rules(self, rules_path: str) -> List[schema.Finding]:
        """
        Scan codebase using the generated rules.

        Args:
            rules_path: Path to impact-scan.yml

        Returns:
            List of findings
        """
        logger.info("Scanning codebase with ripgrep rules...")

        with open(rules_path, 'r', encoding='utf-8') as f:
            rules_data = yaml.safe_load(f)

        findings = []

        for rule in rules_data.get("rules", []):
            rule_findings = self._scan_with_rule(rule)
            findings.extend(rule_findings)

        logger.info(f"Found {len(findings)} potential issues")
        return findings

    def _scan_with_rule(self, rule: Dict) -> List[schema.Finding]:
        """Scan using a single rule pattern."""
        pattern = rule.get("pattern")
        if not pattern:
            return []

        try:
            # Run ripgrep with the pattern
            cmd = [
                self.rg_path,
                "--json",
                "--ignore-case" if rule.get("case_insensitive", False) else "--case-sensitive",
                "--type-add", "code:*.{py,js,ts,jsx,tsx,java,go,rs,php,rb}",
                "--type", "code",
                pattern
            ]

            proc = subprocess.run(
                cmd,
                cwd=self.root_path,
                capture_output=True,
                text=True,
                timeout=RIPGREP_TIMEOUT_SECONDS,
                encoding='utf-8',
                errors='replace'
            )

            if proc.returncode not in [0, 1]:
                logger.warning(f"Ripgrep failed for pattern '{pattern}': {proc.stderr}")
                return []

            # Parse ripgrep JSON output
            findings = []
            for line in proc.stdout.strip().split('\n'):
                if not line:
                    continue

                try:
                    match_data = json.loads(line)
                    if match_data.get("type") == "match":
                        finding = self._create_finding_from_match(match_data, rule)
                        if finding:
                            findings.append(finding)
                except json.JSONDecodeError:
                    continue

            return findings

        except subprocess.TimeoutExpired:
            logger.error(f"Ripgrep timed out for pattern: {pattern}")
            return []
        except Exception as e:
            logger.error(f"Error scanning with pattern '{pattern}': {e}")
            return []

    def _create_finding_from_match(self, match_data: Dict, rule: Dict) -> Optional[schema.Finding]:
        """Create a Finding object from ripgrep match data."""
        try:
            data = match_data.get("data", {})
            path_data = data.get("path", {})
            file_path = Path(self.root_path) / path_data.get("text", "")

            line_number = data.get("line_number", 1)
            line_text = data.get("lines", {}).get("text", "")

            # Map severity
            severity_str = rule.get("severity", "MEDIUM").upper()
            severity_map = {
                "CRITICAL": schema.Severity.CRITICAL,
                "HIGH": schema.Severity.HIGH,
                "MEDIUM": schema.Severity.MEDIUM,
                "LOW": schema.Severity.LOW,
            }
            severity = severity_map.get(severity_str, schema.Severity.MEDIUM)

            finding = schema.Finding(
                file_path=file_path,
                line_number=line_number,
                vuln_id=rule.get("id", "CUSTOM-001"),
                rule_id=rule.get("id", "CUSTOM-001"),
                title=rule.get("title", "Security Issue"),
                severity=severity,
                citations=[],
                source=schema.VulnSource.STATIC_ANALYSIS,
                code_snippet=line_text.strip(),
                description=rule.get("description", "Potential security issue detected"),
                metadata={
                    "cwe": rule.get("cwe"),
                    "owasp": rule.get("owasp"),
                    "pattern": rule.get("pattern"),
                },
            )

            return finding

        except Exception as e:
            logger.error(f"Error creating finding from match: {e}")
            return None

    def validate_with_ai(self, findings: List[schema.Finding]) -> List[schema.Finding]:
        """
        Validate findings using Groq AI and add fix suggestions.

        Args:
            findings: List of findings to validate

        Returns:
            Validated findings with AI-generated fix suggestions
        """
        if not self.groq_client:
            logger.warning("Groq API key not available, skipping AI validation")
            return findings

        logger.info(f"Validating {len(findings)} findings with Groq AI...")

        validated_findings = []

        for finding in findings:
            try:
                # Validate and enhance with AI
                enhanced_finding = self._validate_single_finding(finding)
                if enhanced_finding:
                    validated_findings.append(enhanced_finding)
            except Exception as e:
                logger.error(f"Error validating finding: {e}")
                # Keep original finding if validation fails
                validated_findings.append(finding)

        logger.info(f"AI validation complete: {len(validated_findings)} valid findings")
        return validated_findings

    def _validate_single_finding(self, finding: schema.Finding) -> Optional[schema.Finding]:
        """Validate a single finding with Groq AI."""
        prompt = f"""You are a security expert. Analyze this potential vulnerability:

File: {finding.file_path}
Line: {finding.line_number}
Code: {finding.code_snippet}
Issue: {finding.description}

Tasks:
1. Confirm if this is a real vulnerability (true/false)
2. If real, provide a fix suggestion
3. Find relevant Stack Overflow solutions (provide URLs if possible)

Respond in JSON format:
{{
    "is_valid": true/false,
    "confidence": 0.0-1.0,
    "fix_suggestion": "detailed fix steps",
    "stackoverflow_links": ["url1", "url2"],
    "reasoning": "explanation"
}}
"""

        try:
            response = self.groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=2000
            )

            result_text = response.choices[0].message.content

            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = {"is_valid": True, "confidence": 0.5}

            # Only return if AI confirms it's valid
            if result.get("is_valid", False):
                # Enhance finding with AI insights
                finding.fix_suggestion = result.get("fix_suggestion", finding.fix_suggestion)
                finding.citations = result.get("stackoverflow_links", [])
                finding.metadata["ai_confidence"] = result.get("confidence", 0.5)
                finding.metadata["ai_reasoning"] = result.get("reasoning", "")

                return finding
            else:
                logger.info(f"AI filtered out false positive: {finding.title}")
                return None

        except Exception as e:
            logger.error(f"AI validation error: {e}")
            return finding

    # Helper methods for codebase analysis

    def _get_file_statistics(self) -> Dict:
        """Get file statistics using ripgrep."""
        try:
            cmd = [self.rg_path, "--files", "--stats"]
            proc = subprocess.run(
                cmd,
                cwd=self.root_path,
                capture_output=True,
                text=True,
                timeout=30
            )

            files = proc.stdout.strip().split('\n')
            files = [f for f in files if f and not f.startswith(' ')]

            # Count by extension
            by_extension = {}
            for file in files:
                ext = Path(file).suffix or 'no_extension'
                by_extension[ext] = by_extension.get(ext, 0) + 1

            # Count total lines
            total_lines = self._count_total_lines()

            return {
                "total_files": len(files),
                "total_lines": total_lines,
                "by_extension": by_extension
            }
        except Exception as e:
            logger.error(f"Error getting file statistics: {e}")
            return {"total_files": 0, "total_lines": 0, "by_extension": {}}

    def _count_total_lines(self) -> int:
        """Count total lines of code."""
        try:
            cmd = [self.rg_path, "--count", "--files-with-matches", ".*"]
            proc = subprocess.run(
                cmd,
                cwd=self.root_path,
                capture_output=True,
                text=True,
                timeout=30
            )

            # This is a rough estimate
            return len(proc.stdout.strip().split('\n')) * 50  # Estimate
        except:
            return 0

    def _classify_project(self) -> str:
        """Classify project type based on files present."""
        indicators = {
            "Python Web App": ["requirements.txt", "app.py", "manage.py"],
            "Node.js App": ["package.json", "node_modules"],
            "React App": ["package.json", "src/App.jsx", "src/App.tsx"],
            "Django App": ["manage.py", "settings.py"],
            "Flask App": ["app.py", "requirements.txt"],
            "Go App": ["go.mod", "main.go"],
            "Rust App": ["Cargo.toml", "src/main.rs"],
            "Java App": ["pom.xml", "build.gradle"],
        }

        for proj_type, files in indicators.items():
            for file in files:
                if (self.root_path / file).exists():
                    return proj_type

        return "Unknown Project"

    def _detect_frameworks(self) -> List[str]:
        """Detect frameworks/libraries used."""
        frameworks = []

        # Check for Python frameworks
        if (self.root_path / "requirements.txt").exists():
            content = (self.root_path / "requirements.txt").read_text()
            if "flask" in content.lower():
                frameworks.append("Flask")
            if "django" in content.lower():
                frameworks.append("Django")
            if "fastapi" in content.lower():
                frameworks.append("FastAPI")

        # Check for JS frameworks
        if (self.root_path / "package.json").exists():
            try:
                content = json.loads((self.root_path / "package.json").read_text())
                deps = {**content.get("dependencies", {}), **content.get("devDependencies", {})}

                if "react" in deps:
                    frameworks.append("React")
                if "vue" in deps:
                    frameworks.append("Vue")
                if "express" in deps:
                    frameworks.append("Express")
                if "next" in deps:
                    frameworks.append("Next.js")
            except:
                pass

        return frameworks

    def _extract_dependencies(self) -> List[str]:
        """Extract dependencies from package files."""
        deps = []

        # Python
        if (self.root_path / "requirements.txt").exists():
            content = (self.root_path / "requirements.txt").read_text()
            deps.extend([line.split('==')[0].strip() for line in content.split('\n') if line and not line.startswith('#')])

        # Node.js
        if (self.root_path / "package.json").exists():
            try:
                content = json.loads((self.root_path / "package.json").read_text())
                deps.extend(content.get("dependencies", {}).keys())
            except:
                pass

        return deps[:20]  # Limit to top 20

    def _find_entry_points(self) -> List[str]:
        """Find application entry points."""
        entry_points = []

        common_entry_files = [
            "main.py", "app.py", "index.js", "server.js", "main.go",
            "main.rs", "Main.java", "manage.py"
        ]

        for entry_file in common_entry_files:
            if (self.root_path / entry_file).exists():
                entry_points.append(entry_file)

        return entry_points

    def _detect_security_patterns(self) -> str:
        """Detect common security patterns in the codebase."""
        patterns = []

        # Check for authentication
        if self._search_pattern(r'(auth|login|signin|password)'):
            patterns.append("- Authentication/Authorization logic detected")

        # Check for database operations
        if self._search_pattern(r'(SELECT|INSERT|UPDATE|DELETE|execute|query)'):
            patterns.append("- Database operations detected")

        # Check for file operations
        if self._search_pattern(r'(open|read|write|upload)'):
            patterns.append("- File I/O operations detected")

        # Check for network operations
        if self._search_pattern(r'(requests|fetch|axios|urllib)'):
            patterns.append("- Network/HTTP operations detected")

        return '\n'.join(patterns) if patterns else "- No obvious security-critical patterns detected"

    def _search_pattern(self, pattern: str) -> bool:
        """Check if a pattern exists in the codebase."""
        try:
            cmd = [self.rg_path, "--quiet", "--ignore-case", pattern]
            proc = subprocess.run(
                cmd,
                cwd=self.root_path,
                capture_output=True,
                timeout=10
            )
            return proc.returncode == 0
        except:
            return False

    def _format_file_distribution(self, by_extension: Dict) -> str:
        """Format file distribution as markdown table."""
        lines = ["| Extension | Count |", "|-----------|-------|"]
        for ext, count in sorted(by_extension.items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"| {ext} | {count} |")
        return '\n'.join(lines)

    def _format_frameworks(self, frameworks: List[str]) -> str:
        """Format frameworks as bullet list."""
        if not frameworks:
            return "- No frameworks detected"
        return '\n'.join(f"- {fw}" for fw in frameworks)

    def _format_dependencies(self, deps: List[str]) -> str:
        """Format dependencies as bullet list."""
        if not deps:
            return "- No dependencies found"
        return '\n'.join(f"- {dep}" for dep in deps)

    def _format_entry_points(self, entry_points: List[str]) -> str:
        """Format entry points as bullet list."""
        if not entry_points:
            return "- No entry points found"
        return '\n'.join(f"- {ep}" for ep in entry_points)

    def _get_generic_security_patterns(self) -> List[Dict]:
        """Get generic security patterns for all codebases."""
        return [
            {
                "id": "hardcoded-secret",
                "pattern": r'(password|api_key|secret|token)\s*=\s*["\'][^"\']{8,}["\']',
                "title": "Hardcoded Secret",
                "severity": "HIGH",
                "description": "Hardcoded credentials detected",
                "cwe": "CWE-798",
                "owasp": "A07:2021"
            },
            {
                "id": "sql-injection",
                "pattern": r'(execute|query|SELECT|INSERT|UPDATE|DELETE)\s*\(\s*["\'].*%s.*["\']',
                "title": "SQL Injection Risk",
                "severity": "CRITICAL",
                "description": "Potential SQL injection vulnerability",
                "cwe": "CWE-89",
                "owasp": "A03:2021"
            },
            {
                "id": "command-injection",
                "pattern": r'(exec|eval|system|popen|subprocess)\s*\(',
                "title": "Command Injection Risk",
                "severity": "HIGH",
                "description": "Potential command injection vulnerability",
                "cwe": "CWE-78",
                "owasp": "A03:2021"
            },
            {
                "id": "path-traversal",
                "pattern": r'(open|read|write)\s*\(.*\.\./.*\)',
                "title": "Path Traversal Risk",
                "severity": "MEDIUM",
                "description": "Potential path traversal vulnerability",
                "cwe": "CWE-22",
                "owasp": "A01:2021"
            },
        ]

    def _get_python_web_patterns(self) -> List[Dict]:
        """Get Python web framework specific patterns."""
        return [
            {
                "id": "flask-debug-mode",
                "pattern": r'app\.run\s*\(.*debug\s*=\s*True',
                "title": "Flask Debug Mode Enabled",
                "severity": "HIGH",
                "description": "Flask running with debug mode in production",
                "cwe": "CWE-489",
                "owasp": "A05:2021"
            },
            {
                "id": "django-secret-key",
                "pattern": r'SECRET_KEY\s*=\s*["\'][^"\']+["\']',
                "title": "Django Secret Key Exposed",
                "severity": "CRITICAL",
                "description": "Django SECRET_KEY hardcoded",
                "cwe": "CWE-798",
                "owasp": "A02:2021"
            },
        ]

    def _get_javascript_patterns(self) -> List[Dict]:
        """Get JavaScript/Node.js specific patterns."""
        return [
            {
                "id": "eval-usage",
                "pattern": r'\beval\s*\(',
                "title": "Dangerous eval() Usage",
                "severity": "HIGH",
                "description": "Use of eval() can lead to code injection",
                "cwe": "CWE-95",
                "owasp": "A03:2021"
            },
            {
                "id": "cors-wildcard",
                "pattern": r'Access-Control-Allow-Origin.*\*',
                "title": "CORS Wildcard",
                "severity": "MEDIUM",
                "description": "CORS allows all origins",
                "cwe": "CWE-942",
                "owasp": "A05:2021"
            },
        ]


def run_ripgrep_scan(root_path: Path, groq_api_key: Optional[str] = None) -> List[schema.Finding]:
    """
    Main entry point for ripgrep-based scanning.

    Args:
        root_path: Root directory to scan
        groq_api_key: Optional Groq API key for AI validation

    Returns:
        List of validated findings
    """
    logger.info("Starting ripgrep-based security scan...")

    scanner = RipgrepScanner(root_path, groq_api_key)

    # Step 1: Generate codebase context
    context_file = scanner.generate_codebase_context()
    logger.info(f"Generated codebase context: {context_file}")

    # Step 2: Generate scan rules
    rules_file = scanner.generate_scan_rules()
    logger.info(f"Generated scan rules: {rules_file}")

    # Step 3: Scan with rules
    findings = scanner.scan_with_rules(rules_file)
    logger.info(f"Found {len(findings)} potential issues")

    # Step 4: Validate with AI and add Stack Overflow citations
    if groq_api_key:
        findings = scanner.validate_with_ai(findings)
        logger.info(f"AI validation complete: {len(findings)} validated findings")

    return findings
