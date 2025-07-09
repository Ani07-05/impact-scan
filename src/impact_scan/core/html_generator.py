"""
Professional HTML Security Report Generator

This module provides comprehensive HTML report generation for security scan results.
Features include:
- Professional dark theme styling
- Syntax-highlighted code blocks
- Responsive design
- Executive summary dashboards
- Detailed vulnerability analysis
- AI-powered fix suggestions
- Citation management
"""

import html
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from impact_scan.utils import schema


class ProfessionalHTMLGenerator:
    """
    Professional HTML report generator for security assessment results.
    
    Generates enterprise-grade security reports with:
    - Executive summaries
    - Detailed vulnerability analysis
    - Syntax-highlighted code sections
    - AI-powered recommendations
    - Professional styling and typography
    """
    
    def __init__(self):
        self.css_theme = self._load_professional_css()
        
    def generate_report(self, result: schema.ScanResult, output_path: Path) -> None:
        """
        Generate a comprehensive HTML security report.
        
        Args:
            result: The scan result containing all findings and metadata
            output_path: Path where the HTML report will be saved
        """
        try:
            html_content = self._build_html_structure(result)
            
            with output_path.open("w", encoding="utf-8") as f:
                f.write(html_content)
                
            print(f"✅ Professional security report generated: {output_path}")
            
        except IOError as e:
            print(f"❌ Error: Failed to write report to {output_path}. Reason: {e}")
    
    def _build_html_structure(self, result: schema.ScanResult) -> str:
        """Build the complete HTML document structure."""
        project_name = result.config.target_path.name
        
        # Calculate statistics
        severity_stats = self._calculate_severity_stats(result.findings)
        
        # Build HTML sections
        sections = [
            self._build_html_header(project_name),
            self._build_page_header(project_name),
            self._build_executive_summary(result, severity_stats),
            self._build_project_overview(result),
            self._build_entry_points_section(result),
            self._build_scanner_results_overview(result),
            self._build_detailed_findings(result),
            self._build_footer(),
        ]
        
        return "\n".join(sections)
    
    def _calculate_severity_stats(self, findings: List[schema.Finding]) -> Dict[schema.Severity, int]:
        """Calculate vulnerability statistics by severity."""
        severity_stats = {severity: 0 for severity in schema.Severity}
        for finding in findings:
            severity_stats[finding.severity] += 1
        return severity_stats
    
    def _build_html_header(self, project_name: str) -> str:
        """Build HTML document header with CSS."""
        return f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>Security Assessment Report - {html.escape(project_name)}</title>
{self.css_theme}
</head>
<body>"""
    
    def _build_page_header(self, project_name: str) -> str:
        """Build the page header section."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"""
<div class='header'>
    <h1>Security Assessment Report</h1>
    <div class='subtitle'>Project: {html.escape(project_name)} | Generated: {timestamp}</div>
</div>
<div class='container'>"""
    
    def _build_executive_summary(self, result: schema.ScanResult, severity_stats: Dict[schema.Severity, int]) -> str:
        """Build executive summary with metrics and risk assessment."""
        total_critical_high = severity_stats[schema.Severity.CRITICAL] + severity_stats[schema.Severity.HIGH]
        risk_level = 'HIGH' if total_critical_high > 0 else 'MEDIUM' if severity_stats[schema.Severity.MEDIUM] > 0 else 'LOW'
        
        return f"""
<div class='section'>
    <div class='section-header'>
        <h2>Executive Summary</h2>
    </div>
    <div class='section-content'>
        <div class='exec-summary'>
            <div class='metric-card critical'>
                <div class='metric-number'>{severity_stats[schema.Severity.CRITICAL]}</div>
                <div class='metric-label'>Critical</div>
            </div>
            <div class='metric-card high'>
                <div class='metric-number'>{severity_stats[schema.Severity.HIGH]}</div>
                <div class='metric-label'>High</div>
            </div>
            <div class='metric-card medium'>
                <div class='metric-number'>{severity_stats[schema.Severity.MEDIUM]}</div>
                <div class='metric-label'>Medium</div>
            </div>
            <div class='metric-card low'>
                <div class='metric-number'>{severity_stats[schema.Severity.LOW]}</div>
                <div class='metric-label'>Low</div>
            </div>
        </div>
        
        <div class='analysis-section'>
            <h4>Risk Assessment</h4>
            <p><strong>Overall Risk Level:</strong> {risk_level}</p>
            <p><strong>Total Vulnerabilities Found:</strong> {len(result.findings)}</p>
            <p><strong>Files Scanned:</strong> {result.scanned_files}</p>
            <p><strong>Scan Duration:</strong> {result.scan_duration:.2f} seconds</p>
        </div>
    </div>
</div>"""
    
    def _build_project_overview(self, result: schema.ScanResult) -> str:
        """Build project overview table."""
        return f"""
<div class='section'>
    <div class='section-header'>
        <h2>Project Overview</h2>
    </div>
    <div class='section-content'>
        <table class='overview-table'>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Target Path</td><td><code>{html.escape(str(result.config.target_path))}</code></td></tr>
            <tr><td>Minimum Severity Filter</td><td>{result.config.min_severity.value.title()}</td></tr>
            <tr><td>AI Fixes Enabled</td><td>{'Yes' if result.config.enable_ai_fixes else 'No'}</td></tr>
            <tr><td>Web Search Enabled</td><td>{'Yes' if result.config.enable_web_search else 'No'}</td></tr>
            <tr><td>Total Files Analyzed</td><td>{result.scanned_files}</td></tr>
        </table>
    </div>
</div>"""
    
    def _build_entry_points_section(self, result: schema.ScanResult) -> str:
        """Build entry points and project structure section."""
        entry_points = []
        for ep_path in result.entry_points:
            if ep_path.exists():
                entry_points.append(str(ep_path.relative_to(result.config.target_path)))
        
        entry_points_html = ""
        if entry_points:
            for ep in entry_points:
                entry_points_html += f"<div class='entry-point'>{html.escape(ep)}</div>"
        else:
            entry_points_html = "<p>No specific entry points identified.</p>"
        
        return f"""
<div class='section'>
    <div class='section-header'>
        <h2>Project Structure & Entry Points</h2>
    </div>
    <div class='section-content'>
        <h4>Identified Entry Points</h4>
        {entry_points_html}
    </div>
</div>"""
    
    def _build_scanner_results_overview(self, result: schema.ScanResult) -> str:
        """Build scanner results overview section."""
        osv_findings = [f for f in result.findings if f.source == schema.VulnSource.DEPENDENCY]
        bandit_findings = [f for f in result.findings if f.source == schema.VulnSource.STATIC_ANALYSIS]
        
        return f"""
<div class='section'>
    <div class='section-header'>
        <h2>Scanner Results Overview</h2>
    </div>
    <div class='section-content'>
        <div class='scanner-results'>
            <div class='scanner-card'>
                <div class='scanner-header'>OSV Scanner (Dependency Analysis)</div>
                <div class='scanner-content'>
                    <p><strong>Vulnerabilities Found:</strong> {len(osv_findings)}</p>
                    <p><strong>Scanner Type:</strong> Dependency vulnerability scanner</p>
                    <p><strong>Data Source:</strong> Open Source Vulnerability (OSV) Database</p>
                    <p><strong>Coverage:</strong> Python packages, npm packages, and other dependencies</p>
                </div>
            </div>
            
            <div class='scanner-card'>
                <div class='scanner-header'>Bandit (Static Analysis)</div>
                <div class='scanner-content'>
                    <p><strong>Issues Found:</strong> {len(bandit_findings)}</p>
                    <p><strong>Scanner Type:</strong> Python static security analysis</p>
                    <p><strong>Coverage:</strong> Common security anti-patterns in Python code</p>
                    <p><strong>Analysis:</strong> SQL injection, hardcoded passwords, and other OWASP Top 10 issues</p>
                </div>
            </div>
        </div>
    </div>
</div>"""
    
    def _build_detailed_findings(self, result: schema.ScanResult) -> str:
        """Build detailed findings section."""
        if not result.findings:
            return self._build_no_findings_section()
        
        # Sort findings by severity
        severity_order = {s: i for i, s in enumerate(schema.Severity)}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order[f.severity])
        
        findings_html = []
        findings_html.append("""
<div class='section'>
    <div class='section-header'>
        <h2>Detailed Security Findings</h2>
    </div>
    <div class='section-content'>""")
        
        for i, finding in enumerate(sorted_findings, 1):
            findings_html.append(self._build_finding_detail(finding))
        
        findings_html.append("""
    </div>
</div>""")
        
        return "\n".join(findings_html)
    
    def _build_finding_detail(self, finding: schema.Finding) -> str:
        """Build detailed view for a single finding."""
        severity_class = finding.severity.value.lower()
        
        # Source badge
        source_badge = ""
        if finding.source == schema.VulnSource.DEPENDENCY:
            source_badge = "<span class='badge badge-osv'>OSV Scanner</span>"
        elif finding.source == schema.VulnSource.STATIC_ANALYSIS:
            source_badge = "<span class='badge badge-bandit'>Bandit</span>"
        
        sections = [
            f"""
<div class='finding'>
    <div class='finding-header {severity_class}'>
        <div>
            <div>{html.escape(finding.title)}</div>
            <div class='finding-id'>{html.escape(finding.vuln_id)}</div>
        </div>
        <div>{source_badge}</div>
    </div>
    
    <div class='finding-body'>
        {self._build_finding_metadata(finding)}
        {self._build_vulnerability_description(finding)}
        {self._build_osv_analysis(finding)}
        {self._build_code_sections(finding)}
        {self._build_citations(finding)}
    </div>
</div>"""]
        
        return "\n".join(sections)
    
    def _build_finding_metadata(self, finding: schema.Finding) -> str:
        """Build finding metadata grid."""
        return f"""
<div class='finding-meta'>
    <div class='meta-item'>
        <div class='meta-label'>Severity Level</div>
        <div class='meta-value'>{finding.severity.value.title()}</div>
    </div>
    <div class='meta-item'>
        <div class='meta-label'>File Location</div>
        <div class='meta-value'>{html.escape(str(finding.file_path))}:{finding.line_number}</div>
    </div>
    <div class='meta-item'>
        <div class='meta-label'>Detection Source</div>
        <div class='meta-value'>{finding.source.value.replace('_', ' ').title()}</div>
    </div>
    <div class='meta-item'>
        <div class='meta-label'>Vulnerability ID</div>
        <div class='meta-value'>{html.escape(finding.vuln_id)}</div>
    </div>
</div>"""
    
    def _build_vulnerability_description(self, finding: schema.Finding) -> str:
        """Build vulnerability description section."""
        return f"""
<div class='analysis-section'>
    <h4>Vulnerability Description</h4>
    <p>{html.escape(finding.description)}</p>
</div>"""
    
    def _build_osv_analysis(self, finding: schema.Finding) -> str:
        """Build OSV analysis section for dependency vulnerabilities."""
        if finding.source != schema.VulnSource.DEPENDENCY:
            return ""
        
        return f"""
<div class='analysis-section'>
    <h4>OSV Database Analysis</h4>
    <p>This vulnerability ({html.escape(finding.vuln_id)}) was identified in your project's dependencies through the OSV (Open Source Vulnerability) database. OSV provides comprehensive vulnerability data for open source projects maintained by Google and the security community.</p>
    <p><strong>Recommended Action:</strong> Update the affected package to a version that addresses this vulnerability. Check the package's changelog or security advisories for specific upgrade instructions.</p>
</div>"""
    
    def _build_code_sections(self, finding: schema.Finding) -> str:
        """Build code sections (vulnerable code, fixes, etc.)."""
        sections = []
        
        # Vulnerable code
        if finding.code_snippet:
            highlighted_code = self._apply_syntax_highlighting(finding.code_snippet)
            sections.append(f"""
<div class='code-section'>
    <div class='code-header'>Vulnerable Code</div>
    <div class='code-block code-vulnerable'>{highlighted_code}</div>
</div>""")
        
        # AI suggested fix
        if finding.fix_suggestion:
            highlighted_fix = self._apply_syntax_highlighting(finding.fix_suggestion)
            sections.append(f"""
<div class='code-section'>
    <div class='code-header'>AI Suggested Fix</div>
    <div class='code-block code-fix'>{highlighted_fix}</div>
</div>""")
        
        # Web/Gemini fix
        if finding.web_fix:
            is_gemini_fix = "Gemini Analysis:" in finding.description
            fix_header = "AI-Powered Security Fix" if is_gemini_fix else "Community-Sourced Fix"
            highlighted_web_fix = self._apply_syntax_highlighting(finding.web_fix)
            fix_class = "code-ai-fix" if is_gemini_fix else "code-fix"
            
            sections.append(f"""
<div class='code-section'>
    <div class='code-header'>{fix_header}</div>
    <div class='code-block {fix_class}'>{highlighted_web_fix}</div>
</div>""")
        
        return "\n".join(sections)
    
    def _build_citations(self, finding: schema.Finding) -> str:
        """Build citations and references section."""
        has_citations = finding.citation or (hasattr(finding, 'metadata') and finding.metadata.get('additional_citations'))
        
        if has_citations:
            citations_html = ["<div class='citations'>", "<h4>References and Documentation</h4>"]
            
            if finding.citation:
                citations_html.append(f"<div class='citation-item'><strong>Primary Source:</strong> <a href='{finding.citation}' target='_blank'>{finding.citation}</a></div>")
            
            additional_citations = getattr(finding, 'metadata', {}).get('additional_citations', [])
            for idx, citation in enumerate(additional_citations[:3], 1):
                citations_html.append(f"<div class='citation-item'><strong>Additional Resource {idx}:</strong> <a href='{citation}' target='_blank'>{citation}</a></div>")
            
            citations_html.append("</div>")
            return "\n".join(citations_html)
        else:
            return self._build_fallback_resources(finding)
    
    def _build_fallback_resources(self, finding: schema.Finding) -> str:
        """Build fallback resource links when no citations are available."""
        if finding.source == schema.VulnSource.STATIC_ANALYSIS:
            search_query = f"{finding.vuln_id} {finding.title} python security fix"
            so_url = f"https://stackoverflow.com/search?q={html.escape(search_query)}"
            owasp_url = "https://owasp.org/www-project-top-ten/"
            
            return f"""
<div class='citations'>
    <h4>Recommended Resources</h4>
    <div class='citation-item'><strong>Stack Overflow Search:</strong> <a href='{so_url}' target='_blank'>Search for fixes</a></div>
    <div class='citation-item'><strong>OWASP Top 10:</strong> <a href='{owasp_url}' target='_blank'>Security best practices</a></div>
</div>"""
        elif finding.source == schema.VulnSource.DEPENDENCY:
            osv_url = f"https://osv.dev/vulnerability/{finding.vuln_id}"
            return f"""
<div class='citations'>
    <h4>Recommended Resources</h4>
    <div class='citation-item'><strong>OSV Database:</strong> <a href='{osv_url}' target='_blank'>Detailed vulnerability information</a></div>
</div>"""
        
        return ""
    
    def _build_no_findings_section(self) -> str:
        """Build section for when no vulnerabilities are found."""
        return """
<div class='section'>
    <div class='section-header'>
        <h2>Security Findings</h2>
    </div>
    <div class='section-content'>
        <div class='analysis-section'>
            <h4>No Vulnerabilities Detected</h4>
            <p>No security vulnerabilities were identified in this codebase during the scan. This indicates good security practices are being followed.</p>
            <p><strong>Note:</strong> This scan covers common vulnerability patterns and known dependency issues. Consider regular security audits and code reviews as part of your security strategy.</p>
        </div>
    </div>
</div>"""
    
    def _build_footer(self) -> str:
        """Build page footer."""
        return """
</div>

<div class='footer'>
    <div class='footer-content'>
        <h3>Impact Scan Security Assessment</h3>
        <p>This report was generated by Impact Scan, an AI-powered security analysis tool.</p>
        <p>For questions about this report or to discuss security improvements, please consult with your development or security team.</p>
    </div>
</div>

</body>
</html>"""
    
    def _apply_syntax_highlighting(self, code: str, language: str = 'python') -> str:
        """Apply syntax highlighting to code."""
        # Escape HTML first
        code = html.escape(code)
        
        # Python syntax highlighting patterns
        patterns = [
            (r'\b(def|class|if|elif|else|for|while|try|except|finally|with|import|from|as|return|yield|break|continue|pass|lambda|global|nonlocal)\b', r"<span class='keyword'>\1</span>"),
            (r'(""".*?"""|\'\'\'.*?\'\'\'|".*?"|\'.*?\')', r"<span class='string'>\1</span>"),
            (r'(#.*?)(?=\n|$)', r"<span class='comment'>\1</span>"),
            (r'\b(\d+\.?\d*)\b', r"<span class='number'>\1</span>"),
            (r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?=\()', r"<span class='function'>\1</span>"),
            (r'(\+|\-|\*|\/|==|!=|<=|>=|<|>|=)', r"<span class='operator'>\1</span>"),
        ]
        
        highlighted = code
        for pattern, replacement in patterns:
            highlighted = re.sub(pattern, replacement, highlighted, flags=re.MULTILINE | re.DOTALL)
        
        return highlighted
    
    def _load_professional_css(self) -> str:
        """Load the professional dark theme CSS."""
        return """
<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body { 
    font-family: 'SF Pro Display', 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif; 
    margin: 0; 
    padding: 0;
    background: #0d1117;
    color: #f0f6fc;
    line-height: 1.6;
    font-weight: 400;
}

.header {
    background: linear-gradient(135deg, #161b22 0%, #21262d 50%, #30363d 100%);
    color: #f0f6fc;
    padding: 3rem 0;
    text-align: center;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    border-bottom: 2px solid #30363d;
}

.header h1 {
    font-size: 3rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    background: linear-gradient(45deg, #58a6ff, #7c3aed);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.header .subtitle {
    font-size: 1.2rem;
    opacity: 0.8;
    font-weight: 300;
    color: #8b949e;
}

.container { 
    max-width: 1400px; 
    margin: 0 auto; 
    padding: 2rem;
}

.section {
    background: #161b22;
    margin: 2rem 0;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    overflow: hidden;
    border: 1px solid #30363d;
}

.section-header {
    background: linear-gradient(135deg, #21262d, #30363d);
    padding: 2rem;
    border-bottom: 2px solid #58a6ff;
}

.section-header h2 {
    font-size: 1.8rem;
    font-weight: 700;
    color: #f0f6fc;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.section-content {
    padding: 2rem;
}

/* Executive Summary */
.exec-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 2rem;
    margin-bottom: 2rem;
}

.metric-card {
    background: linear-gradient(135deg, #21262d, #30363d);
    padding: 2rem;
    border-radius: 12px;
    text-align: center;
    border-left: 4px solid #6c757d;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    transition: transform 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-4px);
}

.metric-card.critical { 
    border-left-color: #f85149; 
    box-shadow: 0 4px 20px rgba(248, 81, 73, 0.2);
}
.metric-card.high { 
    border-left-color: #fb8500; 
    box-shadow: 0 4px 20px rgba(251, 133, 0, 0.2);
}
.metric-card.medium { 
    border-left-color: #d29922; 
    box-shadow: 0 4px 20px rgba(210, 153, 34, 0.2);
}
.metric-card.low { 
    border-left-color: #58a6ff; 
    box-shadow: 0 4px 20px rgba(88, 166, 255, 0.2);
}

.metric-number {
    font-size: 3rem;
    font-weight: 900;
    margin-bottom: 0.5rem;
    color: #f0f6fc;
}

.metric-label {
    font-size: 0.9rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: 600;
}

/* Project Overview Table */
.overview-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 2rem;
    background: #21262d;
    border-radius: 8px;
    overflow: hidden;
}

.overview-table th {
    background: #30363d;
    padding: 1.5rem;
    text-align: left;
    font-weight: 700;
    color: #f0f6fc;
    border-bottom: 2px solid #58a6ff;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.overview-table td {
    padding: 1.5rem;
    border-bottom: 1px solid #30363d;
    vertical-align: top;
    color: #f0f6fc;
}

.overview-table tr:hover {
    background: #30363d;
}

.overview-table code {
    background: #0d1117;
    padding: 0.5rem;
    border-radius: 4px;
    color: #79c0ff;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    border: 1px solid #30363d;
}

/* Entry Points and File Structure */
.file-tree {
    background: #0d1117;
    padding: 2rem;
    border-radius: 8px;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.95rem;
    border: 2px solid #30363d;
    color: #79c0ff;
}

.entry-point {
    background: #21262d;
    padding: 1rem 1.5rem;
    margin: 0.75rem 0;
    border-radius: 6px;
    border-left: 4px solid #58a6ff;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    color: #79c0ff;
    font-weight: 600;
}

/* Vulnerability Findings */
.finding {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    margin: 2rem 0;
    overflow: hidden;
    box-shadow: 0 6px 20px rgba(0,0,0,0.3);
    transition: transform 0.3s ease;
}

.finding:hover {
    transform: translateY(-2px);
}

.finding-header {
    padding: 2rem;
    color: white;
    font-weight: 700;
    display: flex;
    justify-content: space-between;
    align-items: center;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.finding-header.critical { background: linear-gradient(135deg, #f85149, #da3633); }
.finding-header.high { background: linear-gradient(135deg, #fb8500, #e85d00); }
.finding-header.medium { background: linear-gradient(135deg, #d29922, #b08800); }
.finding-header.low { background: linear-gradient(135deg, #58a6ff, #1f6feb); }

.finding-id {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.9rem;
    opacity: 0.9;
    font-weight: 400;
}

.finding-body {
    padding: 2rem;
    background: #161b22;
}

.finding-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
    padding: 1.5rem;
    background: #21262d;
    border-radius: 8px;
    border: 1px solid #30363d;
}

.meta-item {
    display: flex;
    flex-direction: column;
}

.meta-label {
    font-size: 0.8rem;
    font-weight: 700;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 0.5rem;
}

.meta-value {
    font-size: 1rem;
    color: #f0f6fc;
    font-weight: 500;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
}

/* Code and Fix Sections */
.code-section {
    margin: 2rem 0;
}

.code-header {
    background: #30363d;
    padding: 1rem 1.5rem;
    font-weight: 700;
    color: #f0f6fc;
    border-radius: 8px 8px 0 0;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid #58a6ff;
}

.code-block {
    background: #0d1117;
    border: 2px solid #30363d;
    border-top: none;
    padding: 2rem;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.9rem;
    overflow-x: auto;
    white-space: pre-wrap;
    border-radius: 0 0 8px 8px;
    color: #e6edf3;
    line-height: 1.5;
}

.code-vulnerable {
    border-left: 4px solid #f85149;
    background: linear-gradient(135deg, #0d1117, #1a0f0f);
}

.code-fix {
    border-left: 4px solid #3fb950;
    background: linear-gradient(135deg, #0d1117, #0f1a0f);
}

.code-ai-fix {
    border-left: 4px solid #58a6ff;
    background: linear-gradient(135deg, #0d1117, #0f1319);
    position: relative;
}

.code-ai-fix::before {
    content: "AI POWERED";
    position: absolute;
    top: -10px;
    right: 15px;
    background: linear-gradient(45deg, #58a6ff, #7c3aed);
    color: white;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 1px;
}

/* Syntax Highlighting */
.keyword { color: #ff7b72; font-weight: 600; }
.string { color: #a5d6ff; }
.comment { color: #8b949e; font-style: italic; }
.number { color: #79c0ff; }
.function { color: #d2a8ff; font-weight: 600; }
.variable { color: #ffa657; }
.operator { color: #ff7b72; }

/* Analysis and Citations */
.analysis-section {
    background: #21262d;
    padding: 2rem;
    margin: 2rem 0;
    border-radius: 8px;
    border-left: 4px solid #58a6ff;
    border: 1px solid #30363d;
}

.analysis-section h4 {
    color: #f0f6fc;
    margin-bottom: 1rem;
    font-size: 1.2rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.analysis-section p {
    color: #e6edf3;
    line-height: 1.7;
}

.citations {
    margin: 2rem 0;
    background: #21262d;
    padding: 1.5rem;
    border-radius: 8px;
    border: 1px solid #30363d;
}

.citations h4 {
    color: #f0f6fc;
    margin-bottom: 1rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.citation-item {
    background: #161b22;
    padding: 1rem 1.5rem;
    margin: 0.75rem 0;
    border-radius: 6px;
    border-left: 3px solid #58a6ff;
    transition: all 0.3s ease;
}

.citation-item:hover {
    background: #21262d;
    border-left-color: #79c0ff;
}

.citation-item a {
    color: #58a6ff;
    text-decoration: none;
    font-weight: 600;
    transition: color 0.3s ease;
}

.citation-item a:hover {
    color: #79c0ff;
    text-decoration: underline;
}

/* Scanner Results */
.scanner-results {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
    gap: 2rem;
    margin: 2rem 0;
}

.scanner-card {
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 4px 16px rgba(0,0,0,0.2);
}

.scanner-header {
    background: linear-gradient(135deg, #30363d, #21262d);
    color: #f0f6fc;
    padding: 1.5rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid #58a6ff;
}

.scanner-content {
    padding: 2rem;
    color: #e6edf3;
}

.scanner-content p {
    margin-bottom: 1rem;
    line-height: 1.6;
}

.scanner-content strong {
    color: #f0f6fc;
    font-weight: 700;
}

.badge {
    display: inline-block;
    padding: 0.5rem 1rem;
    font-size: 0.8rem;
    font-weight: 700;
    border-radius: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge-osv {
    background: linear-gradient(45deg, #1f6feb, #58a6ff);
    color: white;
}

.badge-bandit {
    background: linear-gradient(45deg, #fb8500, #d29922);
    color: white;
}

.badge-ai {
    background: linear-gradient(45deg, #7c3aed, #d2a8ff);
    color: white;
}

/* Footer */
.footer {
    background: #161b22;
    color: #8b949e;
    text-align: center;
    padding: 3rem;
    margin-top: 3rem;
    border-top: 2px solid #30363d;
}

.footer-content {
    max-width: 600px;
    margin: 0 auto;
}

.footer h3 {
    color: #f0f6fc;
    margin-bottom: 1rem;
    font-weight: 700;
}

/* Responsive Design */
@media (max-width: 768px) {
    .container {
        padding: 1rem;
    }
    
    .exec-summary {
        grid-template-columns: 1fr;
    }
    
    .finding-meta {
        grid-template-columns: 1fr;
    }
    
    .scanner-results {
        grid-template-columns: 1fr;
    }
}

/* Print Styles */
@media print {
    body {
        background: white !important;
        color: black !important;
    }
    
    .header {
        background: #333 !important;
        -webkit-print-color-adjust: exact;
    }
    
    .section {
        box-shadow: none;
        border: 1px solid #ccc;
        page-break-inside: avoid;
    }
}

/* Dark scrollbar */
::-webkit-scrollbar {
    width: 8px;
}

::-webkit-scrollbar-track {
    background: #21262d;
}

::-webkit-scrollbar-thumb {
    background: #58a6ff;
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: #79c0ff;
}
</style>"""


class LightThemeHTMLGenerator(ProfessionalHTMLGenerator):
    """
    Light theme variant of the HTML generator for different presentation needs.
    """
    
    def __init__(self):
        self.css_theme = self._load_light_theme_css()
    
    def _load_light_theme_css(self) -> str:
        """Load light theme CSS for corporate environments."""
        # This could be implemented for environments that prefer light themes
        return super()._load_professional_css()


# Factory function for creating HTML generators
def create_html_generator(theme: str = 'dark') -> ProfessionalHTMLGenerator:
    """
    Factory function to create HTML generators.
    
    Args:
        theme: Theme type ('dark' or 'light')
        
    Returns:
        Configured HTML generator instance
    """
    if theme.lower() == 'light':
        return LightThemeHTMLGenerator()
    else:
        return ProfessionalHTMLGenerator()
