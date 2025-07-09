"""
Professional HTML Report Generator for Impact Scan Security Assessment

This module generates highly professional, dark-themed security reports with syntax highlighting,
bold fonts, and comprehensive sectioning. Designed for large Python codebases with full
support for all scanner results, AI fixes, and citations.
"""

import html
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from impact_scan.utils import schema

class SecurityReportGenerator:
    def __init__(self):
        self.report_data = {}
        
    def generate_css(self) -> str:
        return """
        <style>
        /* Professional Security Report Styles */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        
        :root {
            --primary-black: #000000;
            --secondary-black: #1a1a1a;
            --tertiary-black: #2d2d2d;
            --quaternary-black: #404040;
            --dark-surface: #0d1117;
            --darker-surface: #161b22;
            --darkest-surface: #21262d;
            --light-gray: #30363d;
            --medium-gray: #21262d;
            --dark-gray: #8b949e;
            --white: #f0f6fc;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #7d8590;
            --accent-red: #f85149;
            --accent-orange: #ff8c42;
            --accent-yellow: #f0c000;
            --accent-green: #3fb950;
            --accent-blue: #58a6ff;
            --accent-purple: #bc8cff;
            --web-fix-bg: #0f2027;
            --web-fix-border: #3fb950;
            --ai-suggestion-bg: #1a1d29;
            --ai-suggestion-border: #58a6ff;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--dark-surface);
            font-size: 14px;
        }
        
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background: var(--dark-surface);
            min-height: 100vh;
        }
        
        /* Header */
        .report-header {
            background: var(--primary-black);
            color: var(--white);
            padding: 60px 40px;
            text-align: center;
            border-bottom: 4px solid var(--accent-blue);
        }
        
        .report-title {
            font-size: 48px;
            font-weight: 800;
            letter-spacing: -1px;
            margin-bottom: 16px;
            text-transform: uppercase;
        }
        
        .report-subtitle {
            font-size: 18px;
            font-weight: 400;
            opacity: 0.9;
            letter-spacing: 0.5px;
        }
        
        .report-meta {
            margin-top: 24px;
            font-size: 14px;
            opacity: 0.8;
            font-weight: 300;
        }
        
        /* Content */
        .report-content {
            padding: 0;
        }
        
        .section {
            border-bottom: 1px solid var(--border-color);
            background: var(--darker-surface);
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .section-header {
            background: var(--darkest-surface);
            padding: 24px 40px;
            border-bottom: 2px solid var(--border-color);
        }
        
        .section-title {
            font-size: 24px;
            font-weight: 700;
            color: var(--white);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .section-content {
            padding: 40px;
        }
        
        /* Executive Summary */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 2px;
            background: var(--border-color);
            border: 2px solid var(--border-color);
            margin-bottom: 40px;
        }
        
        .metric-item {
            background: var(--darkest-surface);
            padding: 32px 24px;
            text-align: center;
            border: none;
        }
        
        .metric-item.critical {
            border-left: 6px solid var(--accent-red);
        }
        
        .metric-item.high {
            border-left: 6px solid var(--accent-orange);
        }
        
        .metric-item.medium {
            border-left: 6px solid var(--accent-yellow);
        }
        
        .metric-item.low {
            border-left: 6px solid var(--accent-green);
        }
        
        .metric-number {
            font-size: 48px;
            font-weight: 800;
            color: var(--white);
            margin-bottom: 8px;
            line-height: 1;
        }
        
        .metric-label {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            border: 2px solid var(--border-color);
            background: var(--darkest-surface);
            margin-bottom: 32px;
        }
        
        .data-table th,
        .data-table td {
            padding: 16px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }
        
        .data-table th {
            background: var(--primary-black);
            color: var(--white);
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .data-table td {
            font-size: 14px;
            color: var(--text-primary);
        }
        
        .data-table td:first-child {
            font-weight: 600;
            background: var(--darker-surface);
        }
        
        .data-table code {
            background: var(--quaternary-black);
            padding: 4px 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--accent-green);
            border: 1px solid var(--border-color);
        }
        
        /* Findings */
        .finding {
            border: 2px solid var(--border-color);
            margin-bottom: 32px;
            background: var(--darkest-surface);
        }
        
        .finding-header {
            padding: 24px 32px;
            color: var(--white);
            font-weight: 700;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .finding-header.critical {
            background: var(--accent-red);
        }
        
        .finding-header.high {
            background: var(--accent-orange);
        }
        
        .finding-header.medium {
            background: var(--accent-yellow);
            color: var(--primary-black);
        }
        
        .finding-header.low {
            background: var(--accent-green);
        }
        
        .finding-title {
            font-size: 18px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .finding-id {
            font-size: 14px;
            font-weight: 600;
            background: rgba(0, 0, 0, 0.4);
            padding: 6px 12px;
            font-family: 'JetBrains Mono', monospace;
        }
        
        .finding-body {
            padding: 32px;
            background: var(--darkest-surface);
        }
        
        .finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2px;
            background: var(--border-color);
            border: 2px solid var(--border-color);
            margin-bottom: 32px;
        }
        
        .meta-item {
            background: var(--darker-surface);
            padding: 16px 20px;
        }
        
        .meta-label {
            font-size: 11px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }
        
        .meta-value {
            font-size: 14px;
            font-weight: 600;
            color: var(--white);
            font-family: 'JetBrains Mono', monospace;
        }
        
        /* Code Blocks */
        .code-section {
            margin: 24px 0;
            border: 2px solid var(--border-color);
            background: var(--darkest-surface);
        }
        
        .code-header {
            background: var(--primary-black);
            color: var(--white);
            padding: 12px 20px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .code-block {
            padding: 24px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            line-height: 1.6;
            background: var(--quaternary-black);
            color: var(--white);
            white-space: pre-wrap;
            overflow-x: auto;
        }
        
        .code-vulnerable {
            border-left: 6px solid var(--accent-red);
        }
        
        .code-fix {
            border-left: 6px solid var(--accent-green);
        }
        
        /* Web Fix Sections - Enhanced Styling */
        .web-fix-section {
            margin: 24px 0;
            border: 3px solid var(--web-fix-border);
            background: var(--web-fix-bg);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(63, 185, 80, 0.15);
        }
        
        .web-fix-header {
            background: linear-gradient(135deg, var(--web-fix-border), var(--accent-green));
            color: var(--white);
            padding: 16px 24px;
            font-weight: 700;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .web-fix-header::before {
            content: "🌐";
            font-size: 18px;
        }
        
        .web-fix-content {
            padding: 24px;
            background: var(--web-fix-bg);
            color: var(--white);
            font-size: 14px;
            line-height: 1.7;
        }
        
        .web-fix-content h4 {
            color: var(--accent-green);
            font-weight: 700;
            margin-bottom: 12px;
            font-size: 16px;
        }
        
        .web-fix-content p {
            margin-bottom: 16px;
        }
        
        .web-fix-content strong {
            color: var(--accent-green);
            font-weight: 700;
        }
        
        .web-fix-content code {
            background: var(--quaternary-black);
            color: var(--accent-green);
            padding: 3px 6px;
            border-radius: 3px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }
        
        /* AI Suggestion Sections - Enhanced Styling */
        .ai-suggestion-section {
            margin: 24px 0;
            border: 3px solid var(--ai-suggestion-border);
            background: var(--ai-suggestion-bg);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(88, 166, 255, 0.15);
        }
        
        .ai-suggestion-header {
            background: linear-gradient(135deg, var(--ai-suggestion-border), var(--accent-purple));
            color: var(--white);
            padding: 16px 24px;
            font-weight: 700;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .ai-suggestion-header::before {
            content: "🤖";
            font-size: 18px;
        }
        
        .ai-suggestion-content {
            padding: 24px;
            background: var(--ai-suggestion-bg);
            color: var(--white);
            font-size: 14px;
            line-height: 1.7;
        }
        
        .ai-suggestion-content h4 {
            color: var(--accent-blue);
            font-weight: 700;
            margin-bottom: 12px;
            font-size: 16px;
        }
        
        .ai-suggestion-content p {
            margin-bottom: 16px;
        }
        
        .ai-suggestion-content strong {
            color: var(--accent-blue);
            font-weight: 700;
        }
        
        .ai-suggestion-content code {
            background: var(--quaternary-black);
            color: var(--accent-blue);
            padding: 3px 6px;
            border-radius: 3px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }
        
        /* Analysis Section */
        .analysis-section {
            background: var(--darker-surface);
            padding: 24px;
            border: 2px solid var(--border-color);
            margin-bottom: 24px;
        }
        
        .analysis-title {
            font-size: 16px;
            font-weight: 700;
            color: var(--white);
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .analysis-content {
            font-size: 14px;
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .analysis-content strong {
            font-weight: 700;
            color: var(--white);
        }
        
        /* Scanner Results */
        .scanner-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2px;
            background: var(--border-color);
            border: 2px solid var(--border-color);
        }
        
        .scanner-item {
            background: var(--darkest-surface);
            border: none;
        }
        
        .scanner-header {
            background: var(--primary-black);
            color: var(--white);
            padding: 16px 20px;
            font-weight: 700;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .scanner-content {
            padding: 24px 20px;
        }
        
        .scanner-content p {
            margin-bottom: 12px;
            font-size: 14px;
            color: var(--text-primary);
        }
        
        .scanner-content strong {
            font-weight: 700;
            color: var(--white);
        }
        
        /* Entry Points */
        .entry-points {
            background: var(--darker-surface);
            border: 2px solid var(--border-color);
            padding: 24px;
        }
        
        .entry-point {
            background: var(--darkest-surface);
            border: 1px solid var(--border-color);
            border-left: 6px solid var(--accent-blue);
            padding: 12px 16px;
            margin-bottom: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
            font-size: 14px;
            color: var(--white);
        }
        
        /* Citations */
        .citations {
            background: var(--darker-surface);
            border: 2px solid var(--border-color);
            padding: 24px;
            margin-top: 24px;
        }
        
        .citations-title {
            font-size: 16px;
            font-weight: 700;
            color: var(--white);
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .citation-item {
            margin-bottom: 12px;
            padding: 12px;
            background: var(--darkest-surface);
            border: 1px solid var(--border-color);
            font-size: 13px;
        }
        
        .citation-item strong {
            font-weight: 700;
            color: var(--white);
        }
        
        .citation-item a {
            color: var(--accent-blue);
            text-decoration: underline;
            font-weight: 500;
            word-break: break-all;
        }
        
        .citation-item a:hover {
            color: var(--accent-purple);
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: 700;
            background: var(--accent-blue);
            color: var(--white);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Footer */
        .report-footer {
            background: var(--primary-black);
            color: var(--white);
            text-align: center;
            padding: 40px;
            margin-top: 0;
        }
        
        .footer-title {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .footer-content {
            font-size: 14px;
            opacity: 0.8;
            line-height: 1.6;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .report-header {
                padding: 40px 20px;
            }
            
            .report-title {
                font-size: 32px;
            }
            
            .section-content {
                padding: 20px;
            }
            
            .metrics-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .finding-body {
                padding: 20px;
            }
            
            .finding-meta {
                grid-template-columns: 1fr;
            }
            
            .scanner-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Print Styles */
        @media print {
            body {
                background: white !important;
                color: black !important;
            }
            
            .report-container {
                background: white !important;
            }
            
            .section {
                background: white !important;
                break-inside: avoid;
                page-break-inside: avoid;
            }
            
            .finding {
                background: white !important;
                break-inside: avoid;
                page-break-inside: avoid;
            }
            
            .web-fix-section,
            .ai-suggestion-section {
                background: white !important;
                border-color: #333 !important;
            }
        }
        </style>
        """
    
    def generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate complete HTML security report"""
        
        # Extract data
        project_name = data.get('project_name', 'Unknown Project')
        timestamp = data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        summary = data.get('summary', {})
        project_info = data.get('project_info', {})
        entry_points = data.get('entry_points', [])
        scanner_results = data.get('scanner_results', {})
        findings = data.get('findings', [])
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {project_name}</title>
            {self.generate_css()}
        </head>
        <body>
            <div class="report-container">
                {self._generate_header(project_name, timestamp)}
                <div class="report-content">
                    {self._generate_executive_summary(summary)}
                    {self._generate_project_overview(project_info)}
                    {self._generate_entry_points(entry_points)}
                    {self._generate_scanner_results(scanner_results)}
                    {self._generate_findings(findings)}
                </div>
                {self._generate_footer()}
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_header(self, project_name: str, timestamp: str) -> str:
        return f"""
        <div class="report-header">
            <h1 class="report-title">Security Assessment Report</h1>
            <div class="report-subtitle">Comprehensive Security Analysis</div>
            <div class="report-meta">
                Project: {project_name} | Generated: {timestamp}
            </div>
        </div>
        """
    
    def _generate_executive_summary(self, summary: Dict[str, Any]) -> str:
        metrics = summary.get('metrics', {})
        analysis = summary.get('analysis', {})
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Executive Summary</h2>
            </div>
            <div class="section-content">
                <div class="metrics-grid">
                    <div class="metric-item critical">
                        <div class="metric-number">{metrics.get('critical', 0)}</div>
                        <div class="metric-label">Critical</div>
                    </div>
                    <div class="metric-item high">
                        <div class="metric-number">{metrics.get('high', 0)}</div>
                        <div class="metric-label">High</div>
                    </div>
                    <div class="metric-item medium">
                        <div class="metric-number">{metrics.get('medium', 0)}</div>
                        <div class="metric-label">Medium</div>
                    </div>
                    <div class="metric-item low">
                        <div class="metric-number">{metrics.get('low', 0)}</div>
                        <div class="metric-label">Low</div>
                    </div>
                </div>
                
                <div class="analysis-section">
                    <h4 class="analysis-title">Risk Assessment</h4>
                    <div class="analysis-content">
                        <p><strong>Overall Risk Level:</strong> {analysis.get('risk_level', 'Unknown')}</p>
                        <p><strong>Total Vulnerabilities Found:</strong> {analysis.get('total_vulnerabilities', 0)}</p>
                        <p><strong>Files Scanned:</strong> {analysis.get('files_scanned', 0)}</p>
                        <p><strong>Scan Duration:</strong> {analysis.get('scan_duration', 'Unknown')}</p>
                        <p><strong>AI Fixes Generated:</strong> {analysis.get('ai_fixes', 0)}</p>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_project_overview(self, project_info: Dict[str, Any]) -> str:
        rows = ""
        for key, value in project_info.items():
            formatted_key = key.replace('_', ' ').title()
            if isinstance(value, bool):
                value = "Yes" if value else "No"
            elif isinstance(value, str) and value.startswith('/'):
                value = f"<code>{value}</code>"
            rows += f"""
            <tr>
                <td>{formatted_key}</td>
                <td>{value}</td>
            </tr>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Project Overview</h2>
            </div>
            <div class="section-content">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def _generate_entry_points(self, entry_points: List[str]) -> str:
        entry_point_items = ""
        for entry_point in entry_points:
            entry_point_items += f'<div class="entry-point">{entry_point}</div>'
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Project Structure & Entry Points</h2>
            </div>
            <div class="section-content">
                <h4 class="analysis-title">Identified Entry Points</h4>
                <div class="entry-points">
                    {entry_point_items}
                </div>
            </div>
        </div>
        """
    
    def _generate_scanner_results(self, scanner_results: Dict[str, Any]) -> str:
        scanner_items = ""
        
        for scanner_name, results in scanner_results.items():
            scanner_items += f"""
            <div class="scanner-item">
                <div class="scanner-header">{scanner_name}</div>
                <div class="scanner-content">
                    <p><strong>Issues Found:</strong> {results.get('issues_found', 0)}</p>
                    <p><strong>Scanner Type:</strong> {results.get('scanner_type', 'Unknown')}</p>
                    <p><strong>Coverage:</strong> {results.get('coverage', 'Not specified')}</p>
                    <p><strong>Analysis:</strong> {results.get('analysis', 'No additional analysis')}</p>
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Scanner Results Overview</h2>
            </div>
            <div class="section-content">
                <div class="scanner-grid">
                    {scanner_items}
                </div>
            </div>
        </div>
        """
    
    def _generate_findings(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return """
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">Detailed Security Findings</h2>
                </div>
                <div class="section-content">
                    <div class="analysis-section">
                        <div class="analysis-content">
                            <p><strong>No security findings detected.</strong></p>
                            <p>The security scan completed successfully with no vulnerabilities identified above the configured severity threshold.</p>
                        </div>
                    </div>
                </div>
            </div>
            """
        
        findings_html = ""
        for finding in findings:
            findings_html += self._generate_single_finding(finding)
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Detailed Security Findings</h2>
            </div>
            <div class="section-content">
                {findings_html}
            </div>
        </div>
        """
    
    def _generate_single_finding(self, finding: Dict[str, Any]) -> str:
        severity = finding.get('severity', 'unknown').lower()
        title = finding.get('title', 'Unknown Vulnerability')
        finding_id = finding.get('id', 'N/A')
        source = finding.get('source', 'Unknown')
        
        # Generate metadata
        meta_items = ""
        metadata = finding.get('metadata', {})
        for key, value in metadata.items():
            formatted_key = key.replace('_', ' ').title()
            meta_items += f"""
            <div class="meta-item">
                <div class="meta-label">{formatted_key}</div>
                <div class="meta-value">{value}</div>
            </div>
            """
        
        # Generate description
        description = finding.get('description', 'No description available.')
        
        # Generate code sections
        code_sections = ""
        if 'vulnerable_code' in finding:
            code_sections += f"""
            <div class="code-section code-vulnerable">
                <div class="code-header">Vulnerable Code</div>
                <div class="code-block">{finding['vulnerable_code']}</div>
            </div>
            """
        
        if 'fix_code' in finding:
            code_sections += f"""
            <div class="code-section code-fix">
                <div class="code-header">Security Fix</div>
                <div class="code-block">{finding['fix_code']}</div>
            </div>
            """
        
        # Generate web fix section with enhanced styling
        web_fix_section = ""
        if hasattr(finding, 'web_fix') and finding.web_fix:
            web_fix_section = f"""
            <div class="web-fix-section">
                <div class="web-fix-header">
                    🌐 AI-Powered Web Search Fix Suggestion
                </div>
                <div class="web-fix-content">
                    <h4>🔧 Recommended Solution</h4>
                    <div class="web-fix-text">{html.escape(finding.web_fix)}</div>
                </div>
            </div>
            """
        elif 'web_fix' in finding and finding['web_fix']:
            web_fix_section = f"""
            <div class="web-fix-section">
                <div class="web-fix-header">
                    🌐 AI-Powered Web Search Fix Suggestion
                </div>
                <div class="web-fix-content">
                    <h4>🔧 Recommended Solution</h4>
                    <div class="web-fix-text">{html.escape(finding['web_fix'])}</div>
                </div>
            </div>
            """
        
        # Generate AI suggestion section with enhanced styling
        ai_suggestion_section = ""
        if hasattr(finding, 'ai_fix') and finding.ai_fix:
            ai_suggestion_section = f"""
            <div class="ai-suggestion-section">
                <div class="ai-suggestion-header">
                    Generative AI Fix Suggestion
                </div>
                <div class="ai-suggestion-content">
                    <h4>AI-Generated Solution</h4>
                    <p>{html.escape(finding.ai_fix)}</p>
                </div>
            </div>
            """
        elif 'ai_fix' in finding and finding['ai_fix']:
            ai_suggestion_section = f"""
            <div class="ai-suggestion-section">
                <div class="ai-suggestion-header">
                    Generative AI Fix Suggestion
                </div>
                <div class="ai-suggestion-content">
                    <h4>AI-Generated Solution</h4>
                    <p>{html.escape(finding['ai_fix'])}</p>
                </div>
            </div>
            """
        
        # Generate citations
        citations_html = ""
        if 'citations' in finding:
            citation_items = ""
            for i, citation in enumerate(finding['citations'], 1):
                citation_items += f"""
                <div class="citation-item">
                    <strong>Reference {i}:</strong> <a href="{citation}" target="_blank">{citation}</a>
                </div>
                """
            
            citations_html = f"""
            <div class="citations">
                <h4 class="citations-title">References and Documentation</h4>
                {citation_items}
            </div>
            """
        
        return f"""
        <div class="finding">
            <div class="finding-header {severity}">
                <div>
                    <div class="finding-title">{title}</div>
                </div>
                <div>
                    <span class="badge">{source}</span>
                    <span class="finding-id">{finding_id}</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-meta">
                    {meta_items}
                </div>
                
                <div class="analysis-section">
                    <h4 class="analysis-title">Vulnerability Description</h4>
                    <div class="analysis-content">
                        <p>{description}</p>
                    </div>
                </div>
                
                {code_sections}
                {web_fix_section}
                {ai_suggestion_section}
                {citations_html}
            </div>
        </div>
        """
    
    def _generate_footer(self) -> str:
        return """
        <div class="report-footer">
            <h3 class="footer-title">Impact Scan Security Assessment</h3>
            <div class="footer-content">
                <p>This report was generated by Impact Scan, an AI-powered security analysis tool.</p>
                <p>For questions about this report or to discuss security improvements, please consult with your development or security team.</p>
            </div>
        </div>
        """

class HTMLReportGenerator:
    """
    Professional HTML report generator for Impact Scan security assessments.
    
    Features:
    - Dark theme with professional styling
    - Syntax highlighting for code blocks
    - Bold fonts and modern typography
    - Responsive design
    - Comprehensive sectioning
    - AI-powered fix suggestions display
    - Citation and reference management
    """
    
    def __init__(self):
        self.css = self._generate_enhanced_dark_theme_css()
    
    def _generate_enhanced_dark_theme_css(self) -> str:
        """Generate enhanced dark theme CSS with better web fix highlighting."""
        return """
        <style>
        /* Enhanced Dark Theme CSS Variables */
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --bg-card: #1c2128;
            --bg-code: #0d1117;
            --bg-accent: #1f2937;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border-primary: #30363d;
            --border-secondary: #21262d;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-orange: #ff8700;
            --accent-red: #f85149;
            --accent-purple: #a5a5ff;
            --shadow-primary: rgba(0, 0, 0, 0.8);
            --shadow-secondary: rgba(0, 0, 0, 0.5);
            --gradient-primary: linear-gradient(135deg, #0d1117 0%, #21262d 50%, #30363d 100%);
            --gradient-danger: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            --gradient-warning: linear-gradient(135deg, #d97706 0%, #92400e 100%);
            --gradient-success: linear-gradient(135deg, #059669 0%, #047857 100%);
        }

        /* Reset and Base Styles */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            font-weight: 400;
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Typography */
        h1, h2, h3, h4, h5, h6 {
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 1rem;
            line-height: 1.2;
        }

        h1 { font-size: 2.5rem; }
        h2 { font-size: 2rem; font-weight: 700; }
        h3 { font-size: 1.5rem; font-weight: 600; }
        h4 { font-size: 1.25rem; font-weight: 600; }

        p {
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }

        /* Header */
        .header {
            background: var(--gradient-primary);
            padding: 3rem 2rem;
            text-align: center;
            border-bottom: 2px solid var(--border-primary);
            box-shadow: 0 4px 20px var(--shadow-primary);
        }

        .header h1 {
            color: white;
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            background: linear-gradient(45deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .subtitle {
            color: rgba(255, 255, 255, 0.9);
            font-size: 1.1rem;
            font-weight: 500;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }

        /* Container */
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 2rem;
            background: var(--bg-primary);
        }

        /* Sections */
        .section {
            background: var(--bg-secondary);
            border-radius: 12px;
            margin-bottom: 2rem;
            overflow: hidden;
            border: 1px solid var(--border-primary);
            box-shadow: 0 4px 12px var(--shadow-secondary);
        }

        .section-header {
            background: var(--bg-tertiary);
            padding: 1.5rem 2rem;
            border-bottom: 2px solid var(--border-primary);
        }

        .section-header h2 {
            color: var(--accent-blue);
            font-weight: 700;
            font-size: 1.8rem;
            margin: 0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .section-content {
            padding: 2rem;
            background: var(--bg-secondary);
        }

        /* Executive Summary */
        .exec-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .metric-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            border: 1px solid var(--border-secondary);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            box-shadow: 0 4px 12px var(--shadow-secondary);
        }

        .metric-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 20px var(--shadow-primary);
        }

        .metric-card.critical {
            border-left: 4px solid var(--accent-red);
            background: linear-gradient(135deg, var(--bg-card) 0%, rgba(248, 81, 73, 0.1) 100%);
        }

        .metric-card.high {
            border-left: 4px solid var(--accent-orange);
            background: linear-gradient(135deg, var(--bg-card) 0%, rgba(255, 135, 0, 0.1) 100%);
        }

        .metric-card.medium {
            border-left: 4px solid var(--accent-yellow);
            background: linear-gradient(135deg, var(--bg-card) 0%, rgba(210, 153, 34, 0.1) 100%);
        }

        .metric-card.low {
            border-left: 4px solid var(--accent-green);
            background: linear-gradient(135deg, var(--bg-card) 0%, rgba(63, 185, 80, 0.1) 100%);
        }

        .metric-number {
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }

        .metric-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Findings */
        .finding { 
            background: var(--bg-card);
            border: 1px solid var(--border-secondary);
            border-radius: 12px; 
            margin-bottom: 2rem; 
            overflow: hidden; 
            box-shadow: 0 6px 20px var(--shadow-secondary);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .finding:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px var(--shadow-primary);
        }

        .finding-header { 
            padding: 1.5rem 2rem; 
            color: #fff; 
            font-weight: 700; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            position: relative;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .finding-header::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: rgba(255, 255, 255, 0.3);
        }

        .critical { background: var(--gradient-danger); }
        .high { background: var(--gradient-warning); }
        .medium { background: linear-gradient(135deg, #eab308 0%, #ca8a04 100%); }
        .low { background: var(--gradient-success); }

        .finding-id {
            font-size: 0.9em;
            opacity: 0.9;
            font-weight: 500;
            background: rgba(255, 255, 255, 0.1);
            padding: 0.25rem 0.75rem;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            font-family: 'JetBrains Mono', monospace;
        }

        .finding-body { 
            padding: 2rem;
            background: var(--bg-secondary);
        }

        /* Enhanced Web Fix Sections */
        .web-fix-section {
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, rgba(88, 166, 255, 0.08) 100%);
            border: 2px solid var(--accent-blue);
            border-radius: 12px;
            margin: 2rem 0;
            overflow: hidden;
            box-shadow: 0 8px 25px rgba(88, 166, 255, 0.15);
            position: relative;
            transition: all 0.3s ease;
        }

        .web-fix-section:hover {
            box-shadow: 0 12px 35px rgba(88, 166, 255, 0.25);
            transform: translateY(-2px);
        }

        .web-fix-section::before {
            content: "🌐 WEB SEARCH FIX";
            position: absolute;
            top: -12px;
            left: 20px;
            background: linear-gradient(45deg, var(--accent-blue), var(--accent-purple));
            color: white;
            padding: 6px 15px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 12px rgba(88, 166, 255, 0.3);
            z-index: 10;
        }

        .web-fix-header {
            background: linear-gradient(135deg, var(--accent-blue), rgba(88, 166, 255, 0.9));
            color: white;
            padding: 1.5rem 2rem;
            font-weight: 700;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid rgba(255, 255, 255, 0.3);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .web-fix-content {
            padding: 2rem;
            background: var(--bg-card);
        }

        .web-fix-text {
            background: linear-gradient(135deg, var(--bg-code) 0%, rgba(88, 166, 255, 0.08) 100%);
            border-left: 4px solid var(--accent-blue);
            padding: 1.5rem;
            border-radius: 8px;
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            line-height: 1.7;
            font-size: 1rem;
            box-shadow: inset 0 0 15px rgba(88, 166, 255, 0.1);
            position: relative;
        }

        .web-fix-text::before {
            content: "💡";
            position: absolute;
            top: -8px;
            left: 15px;
            background: var(--accent-blue);
            color: white;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            box-shadow: 0 2px 8px rgba(88, 166, 255, 0.4);
        }

        /* Enhanced AI Fix Sections */
        .ai-suggestion-section {
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, rgba(163, 120, 255, 0.05) 100%);
            border: 2px solid var(--accent-purple);
            border-radius: 12px;
            margin: 2rem 0;
            overflow: hidden;
            box-shadow: 0 8px 25px rgba(163, 120, 255, 0.15);
            position: relative;
        }

        .ai-suggestion-section::before {
            content: "🤖 AI-POWERED FIX";
            position: absolute;
            top: -12px;
            left: 20px;
            background: linear-gradient(45deg, var(--accent-purple), #7c3aed);
            color: white;
            padding: 6px 15px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 12px rgba(163, 120, 255, 0.3);
        }

        .ai-suggestion-header {
            background: linear-gradient(135deg, var(--accent-purple), rgba(163, 120, 255, 0.8));
            color: white;
            padding: 1.5rem 2rem;
            font-weight: 700;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid rgba(255, 255, 255, 0.3);
        }

        .ai-suggestion-content {
            padding: 2rem;
            background: var(--bg-card);
        }

        /* Enhanced Code Sections */
        .code-section {
            margin: 1.5rem 0;
            border-radius: 12px;
            overflow: hidden;
            border: 2px solid var(--border-secondary);
            background: var(--bg-code);
            box-shadow: 0 4px 15px var(--shadow-secondary);
        }

        .code-header {
            background: var(--bg-tertiary);
            padding: 1rem 1.5rem;
            font-weight: 700;
            font-size: 0.9rem;
            color: var(--accent-blue);
            border-bottom: 2px solid var(--border-primary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .code-block {
            padding: 2rem;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.95rem;
            line-height: 1.6;
            white-space: pre-wrap;
            overflow-x: auto;
            background: var(--bg-code);
            color: var(--text-primary);
            border-left: 4px solid transparent;
        }

        .code-vulnerable {
            border-left-color: var(--accent-red);
            background: linear-gradient(135deg, var(--bg-code) 0%, rgba(248, 81, 73, 0.08) 100%);
        }

        .code-fix {
            border-left-color: var(--accent-green);
            background: linear-gradient(135deg, var(--bg-code) 0%, rgba(63, 185, 80, 0.08) 100%);
        }

        .code-ai-fix {
            border-left-color: var(--accent-purple);
            background: linear-gradient(135deg, var(--bg-code) 0%, rgba(163, 120, 255, 0.08) 100%);
        }

        .code-web-fix {
            border-left-color: var(--accent-blue);
            background: linear-gradient(135deg, var(--bg-code) 0%, rgba(88, 166, 255, 0.08) 100%);
        }

        /* Enhanced Syntax Highlighting */
        .syntax-keyword { color: #ff7b72; font-weight: 600; }
        .syntax-string { color: #a5d6ff; }
        .syntax-comment { color: #8b949e; font-style: italic; }
        .syntax-number { color: #79c0ff; }
        .syntax-function { color: #d2a8ff; font-weight: 600; }
        .syntax-variable { color: #ffa657; }
        .syntax-operator { color: #ff7b72; }

        /* Citations */
        .citations {
            background: var(--bg-tertiary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-top: 1.5rem;
            border: 2px solid var(--border-secondary);
            border-left: 4px solid var(--accent-blue);
            box-shadow: 0 4px 15px var(--shadow-secondary);
        }

        .citations h4 {
            color: var(--accent-blue);
            font-weight: 700;
            margin-bottom: 1rem;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .citation-item {
            margin-bottom: 0.75rem;
            padding: 1rem;
            background: var(--bg-card);
            border-radius: 8px;
            border: 1px solid var(--border-secondary);
            transition: all 0.3s ease;
        }

        .citation-item:hover {
            background: var(--bg-tertiary);
            border-color: var(--accent-blue);
            transform: translateX(5px);
        }

        .citation-item strong {
            color: var(--text-primary);
            font-weight: 700;
        }

        .citation-item a {
            color: var(--accent-blue);
            text-decoration: none;
            font-weight: 500;
            word-break: break-all;
            transition: color 0.3s ease;
        }

        .citation-item a:hover {
            text-decoration: underline;
            color: var(--accent-purple);
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 0.5rem 1rem;
            font-size: 0.8rem;
            font-weight: 700;
            border-radius: 20px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        }

        .badge-osv {
            background: linear-gradient(45deg, var(--accent-blue), rgba(88, 166, 255, 0.8));
            color: white;
            border: 1px solid var(--accent-blue);
        }

        .badge-bandit {
            background: linear-gradient(45deg, var(--accent-yellow), rgba(210, 153, 34, 0.8));
            color: white;
            border: 1px solid var(--accent-yellow);
        }

        .badge-ai {
            background: linear-gradient(45deg, var(--accent-purple), #7c3aed);
            color: white;
            border: 1px solid var(--accent-purple);
        }

        .badge-web {
            background: linear-gradient(45deg, var(--accent-blue), var(--accent-purple));
            color: white;
            border: 1px solid var(--accent-blue);
        }

        /* Footer */
        .footer { 
            background: var(--bg-secondary);
            color: var(--text-secondary);
            text-align: center; 
            padding: 3rem 2rem;
            margin-top: 3rem;
            border-top: 2px solid var(--border-primary);
        }

        .footer-content h3 {
            color: var(--accent-blue);
            font-weight: 700;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }

        .footer p {
            margin-bottom: 0.5rem;
            color: var(--text-muted);
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header {
                padding: 2rem 1rem;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .section-content {
                padding: 1rem;
            }
            
            .finding-body {
                padding: 1rem;
            }
            
            .exec-summary {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        /* Print styles */
        @media print {
            body {
                background: white !important;
                color: black !important;
            }
            
            .header {
                background: #2563eb !important;
                -webkit-print-color-adjust: exact;
            }
            
            .section {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            
            .finding {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            
            .web-fix-section,
            .ai-suggestion-section {
                background: white !important;
                border-color: #333 !important;
            }
        }
        </style>
        """
    
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
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Calculate statistics
        severity_stats = self._calculate_severity_stats(result.findings)
        total_critical_high = severity_stats.get(schema.Severity.CRITICAL, 0) + severity_stats.get(schema.Severity.HIGH, 0)
        entry_points = [str(ep) for ep in result.entry_points]
        
        # Build HTML sections
        sections = [
            self._build_html_header(project_name),
            self._build_page_header(project_name, timestamp),
            self._build_executive_summary(result, severity_stats, total_critical_high),
            self._build_project_overview(result),
            self._build_entry_points_section(entry_points),
            self._build_scanner_results_overview(result),
            self._build_detailed_findings(result),
            self._build_footer(),
            "</body></html>"
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
{self.css}
</head>
<body>"""
    
    def _build_page_header(self, project_name: str, timestamp: str) -> str:
        """Build the page header section."""
        return f"""<div class='header'>
<h1>Security Assessment Report</h1>
<div class='subtitle'>Project: {html.escape(project_name)} | Generated: {timestamp}</div>
</div>
<div class='container'>"""
    
    def _build_executive_summary(self, result: schema.ScanResult, severity_stats: Dict[schema.Severity, int], total_critical_high: int) -> str:
        """Build the executive summary section."""
        risk_level = self._determine_risk_level(severity_stats)
        
        return f"""<div class='section'>
<div class='section-header'>
<h2>Executive Summary</h2>
</div>
<div class='section-content'>
<div class='exec-summary'>
<div class='metric-card critical'>
<div class='metric-number'>{severity_stats.get(schema.Severity.CRITICAL, 0)}</div>
<div class='metric-label'>Critical</div>
</div>
<div class='metric-card high'>
<div class='metric-number'>{severity_stats.get(schema.Severity.HIGH, 0)}</div>
<div class='metric-label'>High</div>
</div>
<div class='metric-card medium'>
<div class='metric-number'>{severity_stats.get(schema.Severity.MEDIUM, 0)}</div>
<div class='metric-label'>Medium</div>
</div>
<div class='metric-card low'>
<div class='metric-number'>{severity_stats.get(schema.Severity.LOW, 0)}</div>
<div class='metric-label'>Low</div>
</div>
</div>

<div class='analysis-section'>
<h4>Risk Assessment</h4>
<p><strong>Overall Risk Level:</strong> {risk_level}</p>
<p><strong>Total Vulnerabilities Found:</strong> {result.total_findings}</p>
<p><strong>Files Scanned:</strong> {result.scanned_files}</p>
<p><strong>Scan Duration:</strong> {result.scan_duration:.2f} seconds</p>
<p><strong>High-Risk Issues (Critical + High):</strong> {total_critical_high}</p>
</div>
</div>
</div>"""
    
    def _determine_risk_level(self, severity_stats: Dict[schema.Severity, int]) -> str:
        """Determine overall risk level based on findings."""
        if severity_stats.get(schema.Severity.CRITICAL, 0) > 0:
            return "CRITICAL"
        elif severity_stats.get(schema.Severity.HIGH, 0) > 0:
            return "HIGH" 
        elif severity_stats.get(schema.Severity.MEDIUM, 0) > 0:
            return "MEDIUM"
        elif severity_stats.get(schema.Severity.LOW, 0) > 0:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _build_project_overview(self, result: schema.ScanResult) -> str:
        """Build the project overview section."""
        config = result.config
        
        return f"""<div class='section'>
<div class='section-header'>
<h2>Project Overview</h2>
</div>
<div class='section-content'>
<table class='overview-table'>
<tr><td>Target Path</td><td><code>{config.target_path}</code></td></tr>
<tr><td>Minimum Severity Filter</td><td>{config.min_severity.value.title()}</td></tr>
<tr><td>AI Fixes Enabled</td><td>{'Yes' if config.enable_ai_fixes else 'No'}</td></tr>
<tr><td>Web Search Enabled</td><td>{'Yes' if config.enable_web_search else 'No'}</td></tr>
<tr><td>AI Provider</td><td>{config.ai_provider.value if config.ai_provider else 'None'}</td></tr>
<tr><td>Total Files Analyzed</td><td>{result.scanned_files}</td></tr>
<tr><td>Scan Timestamp</td><td>{datetime.fromtimestamp(result.timestamp).strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
</table>
</div>
</div>"""
    
    def _build_entry_points_section(self, entry_points: List[str]) -> str:
        """Build the entry points section."""
        entry_point_items = ""
        for entry_point in entry_points:
            entry_point_items += f"<div class='entry-point'>{html.escape(entry_point)}</div>"
        
        if not entry_point_items:
            entry_point_items = "<div class='entry-point'>No entry points detected</div>"
        
        return f"""<div class='section'>
<div class='section-header'>
<h2>Project Structure & Entry Points</h2>
</div>
<div class='section-content'>
<h4>Identified Entry Points</h4>
{entry_point_items}
</div>
</div>"""
    
    def _build_scanner_results_overview(self, result: schema.ScanResult) -> str:
        """Build the scanner results overview section."""
        osv_count = len([f for f in result.findings if f.source == schema.VulnSource.DEPENDENCY])
        bandit_count = len([f for f in result.findings if f.source == schema.VulnSource.STATIC_ANALYSIS])
        
        return f"""<div class='section'>
<div class='section-header'>
<h2>Scanner Results Overview</h2>
</div>
<div class='section-content'>
<div class='scanner-results'>
<div class='scanner-card'>
<div class='scanner-header'>OSV Scanner (Dependency Analysis)</div>
<div class='scanner-content'>
<p><strong>Issues Found:</strong> {osv_count}</p>
<p><strong>Scanner Type:</strong> Dependency vulnerability scanner</p>
<p><strong>Coverage:</strong> Python packages, npm packages, and other dependencies</p>
<p><strong>Analysis:</strong> Open Source Vulnerability (OSV) Database analysis</p>
</div>
</div>
<div class='scanner-card'>
<div class='scanner-header'>Bandit (Static Analysis)</div>
<div class='scanner-content'>
<p><strong>Issues Found:</strong> {bandit_count}</p>
<p><strong>Scanner Type:</strong> Python static security analysis</p>
<p><strong>Coverage:</strong> Common security anti-patterns in Python code</p>
<p><strong>Analysis:</strong> SQL injection, hardcoded passwords, and other OWASP Top 10 issues</p>
</div>
</div>
</div>
</div>
</div>"""
    
    def _build_detailed_findings(self, result: schema.ScanResult) -> str:
        """Build the detailed findings section."""
        if not result.findings:
            return f"""<div class='section'>
<div class='section-header'>
<h2>Detailed Security Findings</h2>
</div>
<div class='section-content'>
<div class='no-findings'>
🛡️ No security findings detected above the configured severity threshold.
</div>
</div>
</div>"""
        
        findings_html = ""
        for finding in result.findings:
            findings_html += self._build_single_finding(finding)
        
        return f"""<div class='section'>
<div class='section-header'>
<h2>Detailed Security Findings</h2>
</div>
<div class='section-content'>
{findings_html}
</div>
</div>"""
    
    def _build_single_finding(self, finding: schema.Finding) -> str:
        """Build HTML for a single finding."""
        severity_class = finding.severity.value.lower()
        
        # Build metadata
        meta_items = f"""
<div class='meta-item'>
<div class='meta-label'>Severity Level</div>
<div class='meta-value'>{finding.severity.value.title()}</div>
</div>
<div class='meta-item'>
<div class='meta-label'>File Location</div>
<div class='meta-value'>{finding.file_path}:{finding.line_number}</div>
</div>
<div class='meta-item'>
<div class='meta-label'>Detection Source</div>
<div class='meta-value'>{finding.source.value.replace('_', ' ').title()}</div>
</div>
<div class='meta-item'>
<div class='meta-label'>Vulnerability ID</div>
<div class='meta-value'>{finding.vuln_id}</div>
</div>"""
        
        # Build code sections
        code_sections = ""
        if finding.code_snippet:
            code_sections += f"""
<div class='code-section'>
<div class='code-header'>Vulnerable Code</div>
<div class='code-block code-vulnerable'>{self._apply_syntax_highlighting(finding.code_snippet)}</div>
</div>"""
        
        if finding.fix_suggestion:
            code_sections += f"""
<div class='code-section'>
<div class='code-header'>AI-Powered Security Fix</div>
<div class='code-block code-ai-fix'>{self._apply_syntax_highlighting(finding.fix_suggestion)}</div>
</div>"""
        
        # Build web fix section if available
        web_fix_section = ""
        if finding.web_fix:
            web_fix_section = self._build_web_fix_section(finding.web_fix)
        
        # Build citations (excluding web fix since it has its own section)
        citations_html = ""
        if finding.citation:
            citations_html = self._build_citations_section(finding)
        
        return f"""
<div class='finding'>
<div class='finding-header {severity_class}'>
<div class='finding-title'>{html.escape(finding.title)}</div>
<div>
<span class='badge-{finding.source.value.lower()}'>{finding.source.value.replace('_', ' ').title()}</span>
<span class='finding-id'>{finding.vuln_id}</span>
</div>
</div>
<div class='finding-body'>
<div class='finding-meta'>
{meta_items}
</div>

<div class='analysis-section'>
<h4>Vulnerability Description</h4>
<p>{html.escape(finding.description)}</p>
</div>

{code_sections}
{web_fix_section}
{citations_html}
</div>
</div>"""
    
    def _build_web_fix_section(self, web_fix: str) -> str:
        """Build a dedicated web fix section with enhanced styling."""
        return f"""
<div class='web-fix-section'>
    <div class='web-fix-header'>
        🌐 Web Search Fix Recommendation
    </div>
    <div class='web-fix-content'>
        <div class='web-fix-text'>{html.escape(web_fix)}</div>
    </div>
</div>"""

    def _build_citations_section(self, finding: schema.Finding) -> str:
        """Build the citations section for a finding (excluding web fix)."""
        citations = []
        
        if finding.citation:
            citations.append(f"<strong>Reference:</strong> <a href='{finding.citation}' target='_blank'>{finding.citation}</a>")
        
        if citations:
            citation_items = "".join(f"<div class='citation-item'>{citation}</div>" for citation in citations)
            return f"""
<div class='citations'>
<h4>References and Documentation</h4>
{citation_items}
</div>"""
        
        return ""
    
    def _build_footer(self) -> str:
        """Build the footer section."""
        return """</div>
<div class='footer'>
<div class='footer-content'>
<h3>🚀 Impact Scan Security Assessment</h3>
<p>This report was generated by Impact Scan, an AI-powered security analysis tool.</p>
<p>For questions about this report or to discuss security improvements, please consult with your development or security team.</p>
</div>
</div>"""
    
    def _apply_syntax_highlighting(self, code: str) -> str:
        """Apply basic syntax highlighting to code snippets."""
        escaped_code = html.escape(code)
        
        # Simple Python syntax highlighting patterns
        import re
        
        # Keywords
        keywords = r'\b(def|class|if|else|elif|for|while|try|except|finally|import|from|return|yield|lambda|with|as|pass|break|continue|and|or|not|in|is|True|False|None)\b'
        escaped_code = re.sub(keywords, r'<span class="syntax-keyword">\1</span>', escaped_code)
        
        # Strings
        escaped_code = re.sub(r'(["\'])([^"\']*)\1', r'<span class="syntax-string">\1\2\1</span>', escaped_code)
        
        # Comments
        escaped_code = re.sub(r'(#.*)', r'<span class="syntax-comment">\1</span>', escaped_code)
        
        # Numbers
        escaped_code = re.sub(r'\b(\d+\.?\d*)\b', r'<span class="syntax-number">\1</span>', escaped_code)
        
        # Function definitions and calls
        escaped_code = re.sub(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', r'<span class="syntax-function">\1</span>(', escaped_code)
        
        return escaped_code


def export_to_html(result: schema.ScanResult, output_path: Path) -> None:
    """
    Exports the scan results to a professional HTML security report using the new HTML generator.
    
    This function serves as the main entry point for HTML report generation,
    maintaining compatibility with the existing renderer interface.
    """
    generator = HTMLReportGenerator()
    generator.generate_report(result, output_path)

# Example usage and data structure
def create_sample_report():
    """Create a sample security report"""
    
    sample_data = {
        "project_name": "vuln_flask_app",
        "timestamp": "2025-07-09 22:53:20",
        "summary": {
            "metrics": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0
            },
            "analysis": {
                "risk_level": "MEDIUM",
                "total_vulnerabilities": 1,
                "files_scanned": 2,
                "scan_duration": "11.06 seconds",
                "ai_fixes": 1
            }
        },
        "project_info": {
            "target_path": "/home/user/Projects/vuln_flask_app",
            "minimum_severity_filter": "Medium",
            "ai_fixes_enabled": True,
            "web_search_enabled": True,
            "total_files_analyzed": 2
        },
        "entry_points": ["app.py"],
        "scanner_results": {
            "OSV Scanner (Dependency Analysis)": {
                "issues_found": 0,
                "scanner_type": "Dependency vulnerability scanner",
                "coverage": "Python packages, npm packages, and other dependencies",
                "analysis": "Open Source Vulnerability (OSV) Database analysis"
            },
            "Bandit (Static Analysis)": {
                "issues_found": 1,
                "scanner_type": "Python static security analysis",
                "coverage": "Common security anti-patterns in Python code",
                "analysis": "SQL injection, hardcoded passwords, and other OWASP Top 10 issues"
            }
        },
        "findings": [
            {
                "title": "hardcoded_sql_expressions",
                "id": "B608",
                "severity": "medium",
                "source": "Bandit",
                "metadata": {
                    "severity_level": "Medium",
                    "file_location": "/home/user/Projects/vuln_flask_app/app.py:13",
                    "detection_source": "Static Analysis",
                    "vulnerability_id": "B608"
                },
                "description": "Possible SQL injection vector through string-based query construction. The vulnerable code uses an f-string to directly embed the user_id variable into the SQL query. This is dangerous because if user_id comes from an untrusted source, an attacker could inject malicious SQL code.",
                "vulnerable_code": '''12     # VULNERABILITY: Direct f-string formatting leads to SQL Injection
13     query = f"SELECT * FROM users WHERE id = {user_id}"
14     ''',
                "fix_code": '''import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()
    
    # Secure way using parameterized query
    try:
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.close()
        return None''',
                "citations": [
                    "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders"
                ]
            }
        ]
    }
    
    generator = SecurityReportGenerator()
    html_report = generator.generate_html_report(sample_data)
    
    # Save to file
    with open('security_report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    print("Security report generated successfully: security_report.html")
    return html_report

if __name__ == "__main__":
    create_sample_report()
