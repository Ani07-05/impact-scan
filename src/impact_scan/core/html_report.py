"""
Professional HTML Report Generator for Impact Scan Security Assessment

This module generates highly professional, dark-themed security reports with syntax highlighting,
bold fonts, and comprehensive sectioning. Designed for large Python codebases with full
support for all scanner results, AI fixes, and citations.
"""

from datetime import datetime
from html import escape
from pathlib import Path

try:
    import markdown

    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import DiffLexer, get_lexer_by_name
from pygments.util import ClassNotFound

from ..utils import schema


class SecurityReportGenerator:
    def __init__(self):
        self.report_data = {}
        self.formatter = HtmlFormatter(
            style="monokai", cssclass="highlight", noclasses=False
        )
        self.PYGMENTS_STYLE = self.formatter.get_style_defs(".highlight")

    def _generate_html_header(self, result: schema.ScanResult) -> str:
        """Generates the HTML header section of the report."""
        summary = result.findings_by_severity
        project_name = str(result.config.root_path)
        timestamp = datetime.fromtimestamp(result.timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        critical_count = len(summary.get(schema.Severity.CRITICAL, []))
        high_count = len(summary.get(schema.Severity.HIGH, []))
        medium_count = len(summary.get(schema.Severity.MEDIUM, []))
        low_count = len(summary.get(schema.Severity.LOW, []))

        return f"""
        <div class="report-header">
            <h1>Security Scan Report</h1>
            <p class="report-subtitle">Project: {escape(project_name)}</p>
            <div class="report-meta">
                Generated on: {timestamp}
            </div>
        </div>
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Executive Summary</h2>
            </div>
            <div class="section-content">
                <div class="metrics-grid">
                    <div class="metric-item critical">
                        <div class="metric-number">{critical_count}</div>
                        <div class="metric-label">Critical</div>
                    </div>
                    <div class="metric-item high">
                        <div class="metric-number">{high_count}</div>
                        <div class="metric-label">High</div>
                    </div>
                    <div class="metric-item medium">
                        <div class="metric-number">{medium_count}</div>
                        <div class="metric-label">Medium</div>
                    </div>
                    <div class="metric-item low">
                        <div class="metric-number">{low_count}</div>
                        <div class="metric-label">Low</div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _get_severity_icon(self, severity: schema.Severity) -> str:
        """Returns the appropriate icon for the severity level."""
        return {
            schema.Severity.CRITICAL: '<i class="fas fa-skull-crossbones"></i>',
            schema.Severity.HIGH: '<i class="fas fa-exclamation-triangle"></i>',
            schema.Severity.MEDIUM: '<i class="fas fa-exclamation-circle"></i>',
            schema.Severity.LOW: '<i class="fas fa-info-circle"></i>',
        }.get(severity, '<i class="fas fa-question-circle"></i>')

    def _get_language_from_filename(self, filename: str) -> str:
        """Gets the highlight.js language class from a filename."""
        ext = filename.split(".")[-1].lower()
        lang_map = {
            "py": "python",
            "js": "javascript",
            "java": "java",
            "html": "xml",
            "css": "css",
            "ts": "typescript",
            "go": "go",
            "php": "php",
            "rb": "ruby",
            "sh": "bash",
            "sql": "sql",
            "yaml": "yaml",
            "yml": "yaml",
            "json": "json",
            "diff": "diff",
            "patch": "diff",
        }
        return lang_map.get(ext, "plaintext")

    def _highlight_code(self, code: str, language: str) -> str:
        """Highlights a code snippet using Pygments."""
        if not code:
            return ""
        try:
            if language.lower() == "diff":
                lexer = DiffLexer()
            else:
                lexer = get_lexer_by_name(language, stripall=True)

            highlighted_code = highlight(code, lexer, self.formatter)
            return f'<div class="code-container">{highlighted_code}</div>'
        except ClassNotFound:
            return f'<div class="code-container"><pre><code>{escape(code)}</code></pre></div>'

    def _generate_finding_card(self, finding: schema.Finding, index: int) -> str:
        """Generates the HTML for a single finding card."""
        file_path_str = str(finding.file_path)
        snippet_lang = self._get_language_from_filename(file_path_str)
        highlighted_snippet = self._highlight_code(finding.code_snippet, snippet_lang)

        fix_suggestion = (
            finding.ai_fix
            or finding.web_fix
            or finding.fix_suggestion
            or finding.metadata.get("fix_suggestion", "")
        )
        fix_suggestion_lang = (
            "diff"
            if fix_suggestion and fix_suggestion.strip().startswith("--- a/")
            else "python"
        )
        highlighted_fix = (
            self._highlight_code(fix_suggestion, fix_suggestion_lang)
            if fix_suggestion
            else ""
        )

        # Merge AI explanation with Gemini Stack Overflow analysis
        ai_explanation_html = ""
        combined_explanation = ""

        # Add main AI explanation if exists
        if finding.ai_explanation:
            combined_explanation = finding.ai_explanation
        # Fallback: Use description if no AI explanation
        elif finding.description:
            combined_explanation = f"**Vulnerability:** {finding.description}\n\n"
            # Add basic severity info
            combined_explanation += (
                f"**Severity:** {finding.severity.value.upper()}\n\n"
            )
            # Suggest enabling AI features
            if not finding.ai_fix:
                combined_explanation += "*Enable AI-powered fix generation with `--ai gemini` for detailed remediation guidance.*"

        # Add Gemini SO analysis if exists
        if (
            finding.stackoverflow_fixes
            and finding.stackoverflow_fixes[0].gemini_analysis
        ):
            if combined_explanation:
                combined_explanation += (
                    "\n\n---\n\n**Why the Stack Overflow Fix Works:**\n\n"
                )
            combined_explanation += finding.stackoverflow_fixes[0].gemini_analysis

        # Convert to HTML
        if combined_explanation:
            if HAS_MARKDOWN:
                # Enable extensions for proper bold/italic rendering and code blocks
                ai_explanation_html = markdown.markdown(
                    combined_explanation, extensions=["extra", "nl2br", "sane_lists"]
                )
            else:
                ai_explanation_html = escape(combined_explanation).replace("\n", "<br>")

        citations_html = ""
        if finding.citations:
            citations_list = "".join(
                f'<div class="citation-link"><a href="{escape(c)}" target="_blank">{escape(c)}</a></div>'
                for c in finding.citations
            )
            citations_html = f"""
            <div class="citations-container">
                <h4><i class="fas fa-book"></i> Citations & References</h4>
                {citations_list}
            </div>
            """

        # Stack Overflow Fixes Section
        stackoverflow_html = ""
        if finding.stackoverflow_fixes:
            # Get the top-voted answer (first in sorted list)
            primary_fix = finding.stackoverflow_fixes[0]

            # Build PRIMARY answer card (full details)
            # Generate code blocks HTML for primary answer
            code_blocks_html = ""
            for code_block in primary_fix.code_snippets:
                highlighted_so_code = self._highlight_code(
                    code_block.code, code_block.language
                )
                code_blocks_html += f"""
                <div class="so-code-block">
                    <div class="code-lang-tag">{escape(code_block.language)}</div>
                    {highlighted_so_code}
                </div>
                """

            # Generate comments HTML for primary answer
            comments_html = ""
            if primary_fix.comments:
                comments_list = "".join(
                    f"<li>{escape(comment)}</li>"
                    for comment in primary_fix.comments[:3]
                )
                comments_html = f"""
                <div class="so-comments">
                    <strong><i class="fas fa-comments"></i> Key Comments:</strong>
                    <ul>{comments_list}</ul>
                </div>
                """

            # Build primary SO answer card
            accepted_badge = (
                '<span class="so-accepted"><i class="fas fa-check-circle"></i> Accepted</span>'
                if primary_fix.accepted
                else ""
            )
            primary_card_html = f"""
            <div class="so-answer-card so-primary-answer">
                <div class="so-header">
                    <div class="so-title-row">
                        <a href="{escape(primary_fix.url)}" target="_blank" class="so-link">
                            <i class="fab fa-stack-overflow"></i> {escape(primary_fix.title)}
                        </a>
                    </div>
                    <div class="so-meta-row">
                        <span class="so-votes" title="Stack Overflow Votes">
                            <i class="fas fa-arrow-up"></i> {primary_fix.votes}
                        </span>
                        {accepted_badge}
                        <span class="so-author">
                            <i class="fas fa-user"></i> {escape(primary_fix.author)}
                            <span class="so-reputation">({primary_fix.author_reputation:,} rep)</span>
                        </span>
                        <span class="so-date">
                            <i class="fas fa-calendar"></i> {escape(primary_fix.post_date)}
                        </span>
                    </div>
                </div>
                <div class="so-body">
                    <div class="so-explanation">
                        <strong>Answer Explanation:</strong>
                        <p>{escape(primary_fix.explanation)}</p>
                    </div>
                    {code_blocks_html}
                    {comments_html}
                </div>
            </div>
            """

            # Build ADDITIONAL references (compact citation links)
            additional_refs_html = ""
            if len(finding.stackoverflow_fixes) > 1:
                additional_links = []
                for so_fix in finding.stackoverflow_fixes[1:]:
                    accepted_icon = (
                        '<i class="fas fa-check-circle" style="color: #5fa134;"></i>'
                        if so_fix.accepted
                        else ""
                    )
                    additional_links.append(f"""
                    <li class="so-citation-item">
                        <a href="{escape(so_fix.url)}" target="_blank" class="so-citation-link">
                            <i class="fab fa-stack-overflow"></i> {escape(so_fix.title)}
                        </a>
                        <span class="so-citation-meta">
                            <span class="so-citation-votes">↑ {so_fix.votes}</span>
                            {accepted_icon}
                        </span>
                    </li>
                    """)

                additional_refs_html = f"""
                <div class="so-additional-references">
                    <h5><i class="fas fa-link"></i> Additional Stack Overflow References</h5>
                    <ul class="so-citations-list">
                        {"".join(additional_links)}
                    </ul>
                </div>
                """

            stackoverflow_html = f"""
            <div class="stackoverflow-fixes-container">
                <h4><i class="fab fa-stack-overflow"></i> Top Stack Overflow Solution</h4>
                {primary_card_html}
                {additional_refs_html}
            </div>
            """

        return f"""
        <div class="finding-card" id="finding-{index}">
            <div class="card-header {finding.severity.value.lower()}">
                <h3>{self._get_severity_icon(finding.severity)} {escape(finding.title)}</h3>
            </div>
            <div class="card-body">
                <div class="finding-location">
                    <i class="fas fa-file-code"></i> <strong>File:</strong> {escape(file_path_str)}
                </div>
                <div class="grid-container">
                    <div class="grid-item">
                        <h4><i class="fas fa-exclamation-triangle"></i> Vulnerable Code</h4>
                        {highlighted_snippet}
                    </div>
                    <div class="grid-item">
                        <h4><i class="fas fa-shield-alt"></i> Secure Code Fix</h4>
                        {highlighted_fix if highlighted_fix else "<p>No fix suggestion available.</p>"}
                    </div>
                </div>

                <h4><i class="fas fa-lightbulb"></i> Vulnerability Explanation & Fix Analysis</h4>
                <div class="ai-explanation">
                    {ai_explanation_html}
                </div>
                {stackoverflow_html}
                {citations_html}
            </div>
            <div class="card-footer">
                <strong>Rule ID:</strong> {escape(finding.rule_id)} | <strong>Source:</strong> {escape(finding.source.value)}
            </div>
        </div>
        """

    def _generate_dependency_section(self, result: schema.ScanResult) -> str:
        """Generate dependency vulnerability section with upgrade recommendations"""
        # Filter DependencyFindings from all findings
        dep_findings = [
            f for f in result.findings if isinstance(f, schema.DependencyFinding)
        ]

        if not dep_findings:
            return ""

        # Group by ecosystem
        by_ecosystem = {}
        for finding in dep_findings:
            eco = finding.ecosystem
            if eco not in by_ecosystem:
                by_ecosystem[eco] = []
            by_ecosystem[eco].append(finding)

        html = """
        <div class="section">
            <div class="section-header">
                <h2 class="section-title"><i class="fas fa-box"></i> Dependency Vulnerabilities</h2>
            </div>
            <div class="section-content">
        """

        for ecosystem, findings in by_ecosystem.items():
            critical_deps = [
                f for f in findings if f.severity == schema.Severity.CRITICAL
            ]
            high_deps = [f for f in findings if f.severity == schema.Severity.HIGH]
            medium_deps = [f for f in findings if f.severity == schema.Severity.MEDIUM]

            html += f"""
            <h3 style="color: #FFFFFF; margin-top: 20px;"><i class="fas fa-code-branch"></i> {ecosystem.upper()} Dependencies</h3>
            <table class="dependency-table">
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Severity</th>
                        <th>CVE</th>
                        <th>CVSS</th>
                        <th>Fix Available</th>
                        <th>Upgrade Command</th>
                    </tr>
                </thead>
                <tbody>
            """

            for finding in findings:
                severity_badge = f'<span class="severity-badge {finding.severity.value.lower()}">{finding.severity.value}</span>'
                cvss = f"{finding.cvss_score:.1f}" if finding.cvss_score else "N/A"

                # Get upgrade recommendation
                fix_available = "No"
                upgrade_cmd = "N/A"
                if finding.upgrade_recommendation:
                    rec = finding.upgrade_recommendation
                    fix_available = f'<span style="color: #22c55e;">Yes ({rec.recommended_version})</span>'

                    # Generate upgrade command
                    if ecosystem.lower() == "python":
                        upgrade_cmd = f"pip install {finding.package_name}=={rec.recommended_version}"
                    elif ecosystem.lower() == "javascript":
                        upgrade_cmd = f"npm install {finding.package_name}@{rec.recommended_version}"
                    else:
                        upgrade_cmd = f"Upgrade to {rec.recommended_version}"

                html += f"""
                <tr>
                    <td><strong>{escape(finding.package_name)}</strong></td>
                    <td><code>{escape(finding.package_version)}</code></td>
                    <td>{severity_badge}</td>
                    <td><code>{escape(finding.vuln_id)}</code></td>
                    <td>{cvss}</td>
                    <td>{fix_available}</td>
                    <td><code style="font-size: 0.85em;">{escape(upgrade_cmd)}</code></td>
                </tr>
                """

            html += """
                </tbody>
            </table>
            """

        html += """
            </div>
        </div>
        """

        return html

    def generate_html(self, result: schema.ScanResult) -> str:
        """Generates the complete HTML report."""

        header_html = self._generate_html_header(result)

        findings_by_severity = result.findings_by_severity

        findings_html = ""
        for severity in [
            schema.Severity.CRITICAL,
            schema.Severity.HIGH,
            schema.Severity.MEDIUM,
            schema.Severity.LOW,
        ]:
            if severity in findings_by_severity and findings_by_severity[severity]:
                findings_html += '<div class="severity-section">'
                findings_html += f'<h2 class="severity-title {severity.value.lower()}">{self._get_severity_icon(severity)} {severity.value.upper()} ({len(findings_by_severity[severity])})</h2>'
                findings_html += '<div class="findings-grid">'
                for i, finding in enumerate(findings_by_severity[severity]):
                    findings_html += self._generate_finding_card(finding, i)
                findings_html += "</div></div>"

        # Add dependency vulnerabilities section
        dependency_html = self._generate_dependency_section(result)

        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Impact Scan Security Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code&display=swap" rel="stylesheet">
    <style>
        {self.PYGMENTS_STYLE}
        body {{
            font-family: 'Inter', 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background-color: #000000;
            color: #FFFFFF;
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 1400px;
            margin: auto;
            background: #000000;
            padding: 20px;
            border: 1px solid #333;
        }}
        .report-header {{
            text-align: center;
            padding: 40px 20px;
            background-color: #000000;
            border-bottom: 1px solid #333;
        }}
        .report-header h1 {{
            font-size: 2.8em;
            font-weight: 700;
            color: #FFFFFF;
            margin: 0;
        }}
        .report-subtitle {{
            font-size: 1.2em;
            color: #FFFFFF;
            margin-top: 10px;
        }}
        .report-meta {{
            font-size: 0.9em;
            color: #FFFFFF;
        }}
        .section {{
            margin-bottom: 20px;
        }}
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 20px;
            background-color: #000000;
            border-bottom: 1px solid #333;
        }}
        .section-title {{
            font-size: 1.8em;
            color: #FFFFFF;
            margin: 0;
        }}
        .section-content {{
            padding: 20px;
            background-color: #000000;
        }}
        .metrics-grid {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
            flex-wrap: wrap;
        }}
        .metric-item {{
            background-color: #000000;
            padding: 15px 25px;
            text-align: center;
            min-width: 120px;
            border-left: 5px solid;
        }}
        .metric-item .metric-number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .metric-item .metric-label {{
            font-size: 1em;
            color: #FFFFFF;
        }}
        .metric-item.critical {{ border-color: #d73a49; }}
        .metric-item.high {{ border-color: #cb2431; }}
        .metric-item.medium {{ border-color: #f1e05a; }}
        .metric-item.low {{ border-color: #0366d6; }}
        .metric-item .critical {{ color: #d73a49; }}
        .metric-item .high {{ color: #cb2431; }}
        .metric-item .medium {{ color: #f1e05a; }}
        .metric-item .low {{ color: #0366d6; }}

        .severity-section {{
            margin-bottom: 30px;
        }}
        .severity-title {{
            padding: 10px 15px;
            color: #FFFFFF;
            margin-bottom: 20px;
            font-size: 1.5em;
        }}
        .severity-title.critical {{ background-color: #d73a49; }}
        .severity-title.high {{ background-color: #cb2431; }}
        .severity-title.medium {{ background-color: #b08800; }}
        .severity-title.low {{ background-color: #0366d6; }}

        .findings-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
        }}
        .finding-card {{
            background-color: #000000;
            border: 1px solid #333;
            margin-bottom: 25px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            transition: box-shadow 0.3s ease;
            overflow: hidden;
        }}
        .finding-card:hover {{
            box-shadow: 0 6px 12px rgba(0,0,0,0.3);
        }}
        .card-header {{
            padding: 15px 20px;
            border-bottom: 1px solid #333;
        }}
        .card-header h3 {{
            margin: 0;
            font-size: 1.4em;
            font-weight: 600;
            display: flex;
            align-items: center;
        }}
        .card-header .fas {{
            margin-right: 12px;
            font-size: 1.2em;
        }}
        .card-header.critical {{ background-color: rgba(215, 58, 73, 0.1); border-left: 5px solid #d73a49; }}
        .card-header.high {{ background-color: rgba(203, 36, 49, 0.1); border-left: 5px solid #cb2431; }}
        .card-header.medium {{ background-color: rgba(241, 224, 90, 0.1); border-left: 5px solid #f1e05a; }}
        .card-header.low {{ background-color: rgba(3, 102, 214, 0.1); border-left: 5px solid #0366d6; }}

        .card-body {{
            padding: 20px;
        }}
        .card-body h4 {{
            color: #FFFFFF;
            margin-top: 1em;
            margin-bottom: 0.5em;
            border-bottom: 1px solid #333;
            padding-bottom: 5px;
        }}
        .card-body p, .card-body ul {{
            margin-bottom: 1em;
        }}
        .card-body ul {{
            padding-left: 20px;
        }}
        .card-body a {{
            color: #58a6ff;
            text-decoration: none;
        }}
        .card-body a:hover {{
            text-decoration: underline;
        }}
        .finding-location {{
            background-color: #000000;
            padding: 8px 12px;
            margin-bottom: 1em;
            font-family: 'Fira Code', monospace;
            border: 1px solid #333;
        }}
        .citations-container {{
            margin-top: 15px;
            padding: 10px;
            background-color: #000000;
            border: 1px solid #333;
        }}
        .citation-link {{
            margin-bottom: 5px;
        }}
        .citation-link a {{
            color: #58a6ff;
            text-decoration: none;
        }}
        .citation-link a:hover {{
            text-decoration: underline;
        }}

        /* Stack Overflow Fixes Section */
        .stackoverflow-fixes-container {{
            margin-top: 20px;
            padding: 15px;
            background-color: #0d0d0d;
            border: 2px solid #F48024;
            border-radius: 8px;
        }}
        .stackoverflow-fixes-container h4 {{
            color: #F48024;
            font-size: 1.3em;
            margin-top: 0;
            margin-bottom: 15px;
            border-bottom: 2px solid #F48024;
            padding-bottom: 8px;
        }}
        .so-fixes-grid {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        .so-answer-card {{
            background-color: #000000;
            border: 1px solid #444;
            border-left: 4px solid #F48024;
            border-radius: 6px;
            padding: 15px;
            transition: all 0.3s ease;
        }}
        .so-answer-card:hover {{
            border-left-color: #F48024;
            box-shadow: 0 4px 12px rgba(244, 128, 36, 0.2);
            transform: translateY(-2px);
        }}
        .so-header {{
            margin-bottom: 12px;
        }}
        .so-title-row {{
            margin-bottom: 8px;
        }}
        .so-link {{
            color: #F48024;
            font-size: 1.15em;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        .so-link:hover {{
            color: #ff9147;
            text-decoration: underline;
        }}
        .so-meta-row {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 0.9em;
            color: #999;
            align-items: center;
        }}
        .so-votes {{
            color: #F48024;
            font-weight: 600;
            font-size: 1em;
        }}
        .so-accepted {{
            color: #5eba7d;
            font-weight: 600;
            padding: 2px 8px;
            background-color: rgba(94, 186, 125, 0.1);
            border-radius: 4px;
        }}
        .so-author {{
            color: #BBB;
        }}
        .so-reputation {{
            color: #888;
            font-size: 0.9em;
        }}
        .so-date {{
            color: #888;
        }}
        .so-body {{
            margin-top: 12px;
        }}
        .so-explanation {{
            background-color: #0a0a0a;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 12px;
            border-left: 3px solid #555;
        }}
        .so-explanation p {{
            margin: 0;
            color: #DDD;
            line-height: 1.6;
        }}
        .so-code-block {{
            margin: 12px 0;
            position: relative;
        }}
        .code-lang-tag {{
            background-color: #F48024;
            color: #000;
            padding: 3px 10px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-block;
            border-radius: 3px 3px 0 0;
            font-family: 'Fira Code', monospace;
        }}
        .gemini-validation {{
            background-color: #0d1117;
            border: 1px solid #30363d;
            border-left: 3px solid #58a6ff;
            padding: 12px;
            margin-top: 12px;
            border-radius: 4px;
        }}
        .gemini-validation strong {{
            color: #58a6ff;
            display: block;
            margin-bottom: 8px;
        }}
        .gemini-analysis-content {{
            color: #DDD;
            line-height: 1.6;
        }}
        .so-comments {{
            background-color: #0a0a0a;
            padding: 10px;
            margin-top: 12px;
            border-radius: 4px;
            border-left: 3px solid #666;
        }}
        .so-comments strong {{
            color: #BBB;
            display: block;
            margin-bottom: 8px;
        }}
        .so-comments ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .so-comments li {{
            color: #AAA;
            margin-bottom: 6px;
            line-height: 1.5;
        }}

        /* Primary SO Answer - Enhanced prominence */
        .so-primary-answer {{
            border-left-width: 5px;
            border-left-color: #F48024;
            box-shadow: 0 2px 8px rgba(244, 128, 36, 0.15);
        }}

        /* Additional Stack Overflow References */
        .so-additional-references {{
            margin-top: 20px;
            padding: 15px;
            background-color: #0a0a0a;
            border-radius: 6px;
            border: 1px solid #333;
        }}
        .so-additional-references h5 {{
            color: #BBB;
            font-size: 1.05em;
            margin-top: 0;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .so-additional-references h5 i {{
            color: #F48024;
        }}
        .so-citations-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .so-citation-item {{
            padding: 8px 0;
            border-bottom: 1px solid #222;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .so-citation-item:last-child {{
            border-bottom: none;
        }}
        .so-citation-link {{
            color: #F48024;
            text-decoration: none;
            font-size: 0.95em;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            flex: 1;
        }}
        .so-citation-link:hover {{
            color: #ff9147;
            text-decoration: underline;
        }}
        .so-citation-meta {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.85em;
            color: #888;
        }}
        .so-citation-votes {{
            color: #F48024;
            font-weight: 600;
        }}

        .grid-container {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 15px;
        }}
        .grid-item h4 {{
            font-size: 1.2em;
            color: #FFFFFF;
            margin-top: 0;
            margin-bottom: 10px;
            border-bottom: 2px solid #333;
            padding-bottom: 5px;
        }}
        .code-container {{
            background-color: #000000;
            padding: 15px;
            overflow-x: auto;
            max-height: 400px;
            border: 1px solid #333;
        }}
        .highlight pre {{
            margin: 0;
            font-family: 'Fira Code', 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .report-footer {{
            text-align: center;
            padding: 20px;
            margin-top: 40px;
            color: #FFFFFF;
            font-size: 0.9em;
        }}
        /* Diff styles */
        .highlight .gd {{
            background-color: rgba(215, 58, 73, 0.2);
            display: block;
        }}
        .highlight .gi {{
            background-color: rgba(46, 160, 67, 0.2);
            display: block;
        }}
        .highlight .gu {{
            color: #FFFFFF;
            font-weight: bold;
        }}
        .card-footer {{
            padding: 10px 20px;
            font-size: 0.9em;
            color: #FFFFFF;
            background-color: #000000;
            border-top: 1px solid #333;
        }}
        
        /* Interactive Controls */
        .controls-bar {{
            background-color: #0d0d0d;
            padding: 20px;
            margin-bottom: 30px;
            border: 1px solid #333;
            border-radius: 8px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
        }}
        .search-box input {{
            width: 100%;
            padding: 10px 15px;
            background-color: #1a1a1a;
            border: 1px solid #444;
            border-radius: 4px;
            color: #fff;
            font-size: 14px;
        }}
        .search-box input:focus {{
            outline: none;
            border-color: #58a6ff;
        }}
        .filter-buttons {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 8px 16px;
            border: 2px solid;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
            background-color: transparent;
            color: #fff;
        }}
        .filter-btn.critical {{ border-color: #d73a49; }}
        .filter-btn.high {{ border-color: #cb2431; }}
        .filter-btn.medium {{ border-color: #f1e05a; }}
        .filter-btn.low {{ border-color: #0366d6; }}
        .filter-btn.active {{
            opacity: 1;
        }}
        .filter-btn.inactive {{
            opacity: 0.3;
        }}
        .export-buttons {{
            display: flex;
            gap: 10px;
        }}
        .export-btn {{
            padding: 8px 16px;
            background-color: #238636;
            border: none;
            border-radius: 4px;
            color: #fff;
            cursor: pointer;
            font-weight: 600;
            transition: background-color 0.2s;
        }}
        .export-btn:hover {{
            background-color: #2ea043;
        }}
        .copy-btn {{
            position: absolute;
            top: 10px;
            right: 10px;
            padding: 6px 12px;
            background-color: #238636;
            border: none;
            border-radius: 4px;
            color: #fff;
            cursor: pointer;
            font-size: 12px;
            opacity: 0;
            transition: opacity 0.2s;
        }}
        .code-container {{
            position: relative;
        }}
        .code-container:hover .copy-btn {{
            opacity: 1;
        }}
        .copy-btn:hover {{
            background-color: #2ea043;
        }}
        .stats-item {{
            cursor: pointer;
            transition: transform 0.2s;
        }}
        .stats-item:hover {{
            transform: scale(1.05);
        }}
        
        /* Dependency table styling */
        .dependency-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background-color: #000000;
            border: 1px solid #333;
        }}
        .dependency-table th {{
            background-color: #1a1a1a;
            color: #FFFFFF;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #333;
        }}
        .dependency-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #222;
            color: #FFFFFF;
        }}
        .dependency-table tbody tr:hover {{
            background-color: #1a1a1a;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .severity-badge.critical {{
            background-color: #d73a49;
            color: #fff;
        }}
        .severity-badge.high {{
            background-color: #cb2431;
            color: #fff;
        }}
        .severity-badge.medium {{
            background-color: #b08800;
            color: #000;
        }}
        .severity-badge.low {{
            background-color: #0366d6;
            color: #fff;
        }}
    </style>
</head>
<body>
    <div class="container">
        {header_html}
        
        {dependency_html}
        
        <!-- Interactive Controls -->
        <div class="controls-bar">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Search findings (file, title, description)...">
            </div>
            <div class="filter-buttons">
                <button class="filter-btn critical active" data-severity="critical" title="Toggle CRITICAL findings">
                    <i class="fas fa-bomb"></i> CRITICAL
                </button>
                <button class="filter-btn high active" data-severity="high" title="Toggle HIGH findings">
                    <i class="fas fa-exclamation-circle"></i> HIGH
                </button>
                <button class="filter-btn medium active" data-severity="medium" title="Toggle MEDIUM findings">
                    <i class="fas fa-exclamation-triangle"></i> MEDIUM
                </button>
                <button class="filter-btn low active" data-severity="low" title="Toggle LOW findings">
                    <i class="fas fa-info-circle"></i> LOW
                </button>
            </div>
            <div class="export-buttons">
                <button class="export-btn" onclick="exportToJSON()" title="Export as JSON">
                    <i class="fas fa-download"></i> JSON
                </button>
                <button class="export-btn" onclick="window.print()" title="Print or save as PDF">
                    <i class="fas fa-print"></i> PDF
                </button>
            </div>
        </div>
        
        {findings_html}
        <div class="report-footer">
            <p>&copy; {{datetime.now().year}} Impact Scan. All rights reserved.</p>
        </div>
    </div>
    
    <script>
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        const findingCards = document.querySelectorAll('.finding-card');
        
        searchInput.addEventListener('input', function() {{
            const searchTerm = this.value.toLowerCase();
            findingCards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                if (text.includes(searchTerm)) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
            updateVisibleCount();
        }});
        
        // Severity filtering
        const filterBtns = document.querySelectorAll('.filter-btn');
        filterBtns.forEach(btn => {{
            btn.addEventListener('click', function() {{
                this.classList.toggle('active');
                this.classList.toggle('inactive');
                filterFindings();
            }});
        }});
        
        function filterFindings() {{
            const activeSeverities = Array.from(filterBtns)
                .filter(btn => btn.classList.contains('active'))
                .map(btn => btn.dataset.severity);
            
            findingCards.forEach(card => {{
                const header = card.querySelector('.card-header');
                const isVisible = activeSeverities.some(sev => header.classList.contains(sev));
                card.style.display = isVisible ? 'block' : 'none';
            }});
            updateVisibleCount();
        }}
        
        function updateVisibleCount() {{
            const visible = Array.from(findingCards).filter(card => card.style.display !== 'none').length;
            const total = findingCards.length;
            document.title = `Impact Scan Report ({{visible}}/{{total}} findings)`;
        }}
        
        // Copy code to clipboard
        function setupCopyButtons() {{
            const codeContainers = document.querySelectorAll('.code-container');
            codeContainers.forEach(container => {{
                const btn = document.createElement('button');
                btn.className = 'copy-btn';
                btn.innerHTML = '<i class="fas fa-copy"></i> Copy';
                btn.onclick = function() {{
                    const code = container.querySelector('pre').textContent;
                    navigator.clipboard.writeText(code).then(() => {{
                        btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                        setTimeout(() => {{
                            btn.innerHTML = '<i class="fas fa-copy"></i> Copy';
                        }}, 2000);
                    }});
                }};
                container.appendChild(btn);
            }});
        }}
        
        // Export to JSON
        function exportToJSON() {{
            const findings = Array.from(findingCards).map(card => {{
                const header = card.querySelector('.card-header h3');
                const location = card.querySelector('.finding-location');
                const description = card.querySelector('.card-body');
                
                return {{
                    title: header ? header.textContent.trim() : '',
                    location: location ? location.textContent.trim() : '',
                    severity: Array.from(card.querySelector('.card-header').classList).find(c => 
                        ['critical', 'high', 'medium', 'low'].includes(c)
                    )
                }};
            }});
            
            const dataStr = JSON.stringify(findings, null, 2);
            const dataBlob = new Blob([dataStr], {{type: 'application/json'}});
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'impact-scan-findings.json';
            link.click();
        }}
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {{
            setupCopyButtons();
        }});
    </script>
</body>
</html>
        """


def save_report(result: schema.ScanResult, output_path):
    """Generates and saves the HTML report.

    Args:
        result: The scan result to generate a report from
        output_path: Path or string where the report should be saved
    """
    generator = SecurityReportGenerator()
    html_content = generator.generate_html(result)

    # Convert to Path object if string is provided
    if isinstance(output_path, str):
        output_path = Path(output_path)

    output_path.write_text(html_content, encoding="utf-8")
