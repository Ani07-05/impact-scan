"""
Markdown Report Generator for GitHub PR Comments and Documentation

Generates clean, GitHub-friendly Markdown reports with:
- Severity badges
- Collapsible sections
- Code blocks with syntax highlighting
- Vulnerability tables
- Quick action items
"""

from datetime import datetime
from pathlib import Path
from typing import List

from ..utils import schema


class MarkdownReportGenerator:
    """Generate GitHub-friendly Markdown reports"""

    def __init__(self):
        self.shields_io_base = "https://img.shields.io/badge"

    def generate_markdown(self, result: schema.ScanResult) -> str:
        """
        Generate complete Markdown report

        Args:
            result: ScanResult from Impact-Scan

        Returns:
            Markdown formatted string
        """

        # Extract all findings
        findings_by_severity = result.findings_by_severity

        # Build report sections
        report = []

        # Header with badges
        report.append(self._generate_header(result))

        # Executive Summary
        report.append(self._generate_summary(findings_by_severity, result))

        # Critical & High findings (always expanded)
        critical_findings = findings_by_severity.get(schema.Severity.CRITICAL, [])
        high_findings = findings_by_severity.get(schema.Severity.HIGH, [])

        if critical_findings:
            report.append(
                self._generate_findings_section(
                    "[CRITICAL] Critical Vulnerabilities",
                    critical_findings,
                    expanded=True,
                )
            )

        if high_findings:
            report.append(
                self._generate_findings_section(
                    "[HIGH] High Severity Issues", high_findings, expanded=True
                )
            )

        # Medium & Low findings (collapsible)
        medium_findings = findings_by_severity.get(schema.Severity.MEDIUM, [])
        low_findings = findings_by_severity.get(schema.Severity.LOW, [])

        if medium_findings:
            report.append(
                self._generate_findings_section(
                    "[MEDIUM] Medium Severity Issues", medium_findings, expanded=False
                )
            )

        if low_findings:
            report.append(
                self._generate_findings_section(
                    "[LOW] Low Severity Issues", low_findings, expanded=False
                )
            )

        # Footer
        report.append(self._generate_footer())

        return "\n\n".join(report)

    def _generate_header(self, result: schema.ScanResult) -> str:
        """Generate header with badges and metadata"""
        total_findings = sum(
            len(findings) for findings in result.findings_by_severity.values()
        )

        critical_count = len(
            result.findings_by_severity.get(schema.Severity.CRITICAL, [])
        )
        high_count = len(result.findings_by_severity.get(schema.Severity.HIGH, []))
        medium_count = len(result.findings_by_severity.get(schema.Severity.MEDIUM, []))
        low_count = len(result.findings_by_severity.get(schema.Severity.LOW, []))

        timestamp = datetime.fromtimestamp(result.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        header = f"""# 🛡️ Impact-Scan Security Report

![Total Findings]({self.shields_io_base}/findings-{total_findings}-blue)
![Critical]({self.shields_io_base}/critical-{critical_count}-red)
![High]({self.shields_io_base}/high-{high_count}-orange)
![Medium]({self.shields_io_base}/medium-{medium_count}-yellow)
![Low]({self.shields_io_base}/low-{low_count}-green)

**Project:** `{result.config.root_path.name}`  
**Scan Date:** {timestamp}  
**Scan Profile:** {getattr(result.config, "profile", "default")}
"""
        return header

    def _generate_summary(self, findings_by_severity: dict, result: schema.ScanResult = None) -> str:
        """Generate executive summary"""
        total = sum(len(findings) for findings in findings_by_severity.values())

        if total == 0:
            summary = """## ✅ Executive Summary

**No security vulnerabilities detected!** Your code passed all security checks."""

            # Add scan coverage details when available
            if result:
                scanned_files = getattr(result, 'scanned_files', 0)
                scan_duration = getattr(result, 'scan_duration', 0)
                if scanned_files > 0:
                    summary += f"\n\n### Scan Coverage\n\n"
                    summary += f"- **{scanned_files} files** analyzed in {scan_duration:.1f}s\n"

                    # Show entry points if any were detected
                    entry_points = getattr(result, 'entry_points', [])
                    if entry_points:
                        frameworks = set(ep.framework for ep in entry_points[:3])
                        summary += f"- **Frameworks detected:** {', '.join(frameworks)}\n"

                    # Add check types performed
                    summary += f"\n### Security Checks Performed\n\n"
                    summary += "- ✓ Static code analysis (1500+ Semgrep rules)\n"
                    summary += "- ✓ Dependency vulnerability scanning\n"
                    summary += "- ✓ AI-powered logical flaw detection\n"
                    if getattr(result.config, 'enable_ai_validation', False):
                        summary += "- ✓ AI validation for false positive reduction\n"

            summary += "\n\n**Keep up the good security practices!**"
            return summary

        critical_count = len(findings_by_severity.get(schema.Severity.CRITICAL, []))
        high_count = len(findings_by_severity.get(schema.Severity.HIGH, []))

        risk_level = (
            "**CRITICAL**"
            if critical_count > 0
            else "**HIGH**"
            if high_count > 0
            else "**MEDIUM**"
        )

        summary = f"""## Executive Summary

**Overall Risk Level:** {risk_level}

| Severity | Count | Status |
|----------|-------|--------|
| Critical | {len(findings_by_severity.get(schema.Severity.CRITICAL, []))} | {"Requires immediate action" if critical_count > 0 else "None found"} |
| High | {len(findings_by_severity.get(schema.Severity.HIGH, []))} | {"Fix before deployment" if high_count > 0 else "None found"} |
| Medium | {len(findings_by_severity.get(schema.Severity.MEDIUM, []))} | {"Plan remediation" if len(findings_by_severity.get(schema.Severity.MEDIUM, [])) > 0 else "None found"} |
| Low | {len(findings_by_severity.get(schema.Severity.LOW, []))} | Address when convenient |

### 🎯 Quick Actions

"""

        if critical_count > 0 or high_count > 0:
            summary += f"1. **URGENT:** Fix {critical_count + high_count} critical/high severity vulnerabilities immediately\n"

        ai_fixes = sum(
            1
            for findings in findings_by_severity.values()
            for f in findings
            if f.ai_fix
        )
        if ai_fixes > 0:
            summary += f"2. **{ai_fixes} AI-generated fixes available** - Review and apply suggested patches\n"

        summary += "3. **Review the detailed findings below** for exploitation proof-of-concepts and remediation guidance\n"

        return summary

    def _generate_findings_section(
        self, title: str, findings: List[schema.Finding], expanded: bool = True
    ) -> str:
        """Generate findings section with optional collapsible"""

        if not findings:
            return ""

        section = []

        if expanded:
            section.append(f"## {title}\n")
        else:
            section.append(
                f"<details>\n<summary><h2>{title} ({len(findings)} issues)</h2></summary>\n"
            )

        for i, finding in enumerate(findings, 1):
            section.append(self._format_finding(finding, i))

        if not expanded:
            section.append("</details>")

        return "\n".join(section)

    def _format_finding(self, finding: schema.Finding, index: int) -> str:
        """Format individual finding as Markdown"""

        # Severity prefix
        severity_prefix = {
            schema.Severity.CRITICAL: "[CRITICAL]",
            schema.Severity.HIGH: "[HIGH]",
            schema.Severity.MEDIUM: "[MEDIUM]",
            schema.Severity.LOW: "[LOW]",
        }.get(finding.severity, "[INFO]")

        md = f"""### {severity_prefix} {index}. {finding.title}

**File:** `{finding.file_path}:{finding.line_number}`  
**Rule ID:** `{finding.rule_id}`  
**Severity:** {finding.severity.value.upper()}  
**Source:** {finding.source.value}

"""

        # Description
        md += f"#### Description\n\n{finding.description}\n\n"

        # Vulnerable code
        if finding.code_snippet:
            language = self._detect_language(str(finding.file_path))
            md += f"#### Vulnerable Code\n\n```{language}\n{finding.code_snippet[:500]}\n```\n\n"

        # AI Fix
        if finding.ai_fix:
            md += f"#### AI-Generated Fix\n\n```{language}\n{finding.ai_fix[:800]}\n```\n\n"

        # AI Explanation
        if finding.ai_explanation:
            md += f"#### AI Analysis\n\n{finding.ai_explanation[:1000]}\n\n"

        # Stack Overflow references
        if finding.stackoverflow_fixes:
            md += "#### Stack Overflow Solutions\n\n"
            for so_fix in finding.stackoverflow_fixes[:3]:
                accepted = "[ACCEPTED] " if so_fix.accepted else ""
                md += f"- {accepted}[{so_fix.title}]({so_fix.url}) (↑ {so_fix.votes} votes, by {so_fix.author})\n"
            md += "\n"

        # Citations
        if finding.citations:
            md += "#### References\n\n"
            for citation in finding.citations[:3]:
                md += f"- {citation}\n"
            md += "\n"

        md += "---\n"

        return md

    def _detect_language(self, file_path: str) -> str:
        """Detect language for syntax highlighting"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
            ".rs": "rust",
            ".sh": "bash",
            ".sql": "sql",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".html": "html",
            ".css": "css",
        }

        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, "text")

    def _generate_footer(self) -> str:
        """Generate report footer"""
        return f"""---

## About Impact-Scan

**Impact-Scan** is an AI-powered security scanner combining:
- Static analysis (1500+ Semgrep rules)
- AI-powered logical flaw detection (Groq + Claude)
- Automatic fix generation
- Code quality metrics

**Scan powered by:**
- Semgrep (SAST)
- Groq AI (Logical review)
- Radon (Code quality)
- Stack Overflow Intelligence

[Documentation](https://github.com/Ani07-05/impact-scan) | [Report Issues](https://github.com/Ani07-05/impact-scan/issues)

---

*Generated by [Impact-Scan](https://github.com/Ani07-05/impact-scan) on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""


def save_markdown_report(result: schema.ScanResult, output_path: Path) -> None:
    """
    Generate and save Markdown report

    Args:
        result: ScanResult from Impact-Scan
        output_path: Where to save Markdown file
    """
    generator = MarkdownReportGenerator()
    markdown_content = generator.generate_markdown(result)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)
