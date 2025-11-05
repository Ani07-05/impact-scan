"""
Professional HTML Report Generator for Impact Scan Security Assessment

This module generates highly professional, dark-themed security reports with syntax highlighting,
bold fonts, and comprehensive sectioning. Designed for large Python codebases with full
support for all scanner results, AI fixes, and citations.
"""
from datetime import datetime
from pathlib import Path
from html import escape

try:
    import markdown
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

from pygments import highlight
from pygments.lexers import get_lexer_by_name, DiffLexer
from pygments.formatters import HtmlFormatter
from pygments.util import ClassNotFound

from impact_scan.utils import schema

class SecurityReportGenerator:
    def __init__(self):
        self.report_data = {}
        self.formatter = HtmlFormatter(style='monokai', cssclass="highlight", noclasses=False)
        self.PYGMENTS_STYLE = self.formatter.get_style_defs('.highlight')

    def _generate_html_header(self, result: schema.ScanResult) -> str:
        """Generates the HTML header section of the report."""
        summary = result.findings_by_severity
        project_name = str(result.config.root_path)
        timestamp = datetime.fromtimestamp(result.timestamp).strftime('%Y-%m-%d %H:%M:%S')

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
            schema.Severity.LOW: '<i class="fas fa-info-circle"></i>'
        }.get(severity, '<i class="fas fa-question-circle"></i>')

    def _get_language_from_filename(self, filename: str) -> str:
        """Gets the highlight.js language class from a filename."""
        ext = filename.split('.')[-1].lower()
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
            "patch": "diff"
        }
        return lang_map.get(ext, "plaintext")

    def _highlight_code(self, code: str, language: str) -> str:
        """Highlights a code snippet using Pygments."""
        if not code:
            return ""
        try:
            if language.lower() == 'diff':
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
        
        fix_suggestion = finding.ai_fix or finding.web_fix or finding.fix_suggestion or finding.metadata.get('fix_suggestion', '')
        fix_suggestion_lang = "diff" if fix_suggestion and fix_suggestion.strip().startswith("--- a/") else "python"
        highlighted_fix = self._highlight_code(fix_suggestion, fix_suggestion_lang) if fix_suggestion else ""

        if finding.ai_explanation:
            if HAS_MARKDOWN:
                ai_explanation_html = markdown.markdown(finding.ai_explanation)
            else:
                ai_explanation_html = escape(finding.ai_explanation).replace('\n', '<br>')
        else:
            ai_explanation_html = ""
        
        citations_html = ""
        if finding.citations:
            citations_list = "".join(f'<div class="citation-link"><a href="{escape(c)}" target="_blank">{escape(c)}</a></div>' for c in finding.citations)
            citations_html = f"""
            <div class="citations-container">
                <h4><i class="fas fa-book"></i> Citations & References</h4>
                {citations_list}
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
                        {highlighted_fix if highlighted_fix else '<p>No fix suggestion available.</p>'}
                    </div>
                </div>

                <h4><i class="fas fa-lightbulb"></i> AI-Powered Explanation</h4>
                <div class="ai-explanation">
                    {ai_explanation_html}
                </div>
                {citations_html}
            </div>
            <div class="card-footer">
                <strong>Rule ID:</strong> {escape(finding.rule_id)} | <strong>Source:</strong> {escape(finding.source.value)}
            </div>
        </div>
        """


    def generate_html(self, result: schema.ScanResult) -> str:
        """Generates the complete HTML report."""
        
        header_html = self._generate_html_header(result)
        
        findings_by_severity = result.findings_by_severity
        
        findings_html = ""
        for severity in [schema.Severity.CRITICAL, schema.Severity.HIGH, schema.Severity.MEDIUM, schema.Severity.LOW]:
            if severity in findings_by_severity and findings_by_severity[severity]:
                findings_html += '<div class="severity-section">'
                findings_html += f'<h2 class="severity-title {severity.value.lower()}">{self._get_severity_icon(severity)} {severity.value.upper()} ({len(findings_by_severity[severity])})</h2>'
                findings_html += '<div class="findings-grid">'
                for i, finding in enumerate(findings_by_severity[severity]):
                    findings_html += self._generate_finding_card(finding, i)
                findings_html += '</div></div>'

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
    </style>
</head>
<body>
    <div class="container">
        {header_html}
        {findings_html}
        <div class="report-footer">
            <p>&copy; {datetime.now().year} Impact Scan. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """

def save_report(result: schema.ScanResult, output_path: Path):
    """Generates and saves the HTML report."""
    generator = SecurityReportGenerator()
    html_content = generator.generate_html(result)
    output_path.write_text(html_content, encoding="utf-8")
