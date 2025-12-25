"""
Rich Findings Table Widget
Enhanced DataTable with rich content rendering, sorting, filtering.
Beautiful cyberpunk styling with detail panel.
"""

from typing import Optional

from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax
from textual import on
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Select, Static, RichLog

from impact_scan.utils.schema import ScanResult, Severity, Finding

# Vibrant color palette
COLORS = {
    "critical": "#FF5555",
    "high": "#FFB86C",
    "medium": "#F1FA8C",
    "low": "#8BE9FD",
    "pink": "#FF6EC7",
    "cyan": "#00D4FF",
    "green": "#50FA7B",
    "purple": "#BD93F9",
    "muted": "#7D8590",
    "text": "#E6EDF3",
}

# Severity labels with icons
SEVERITY_LABELS = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "🔵 LOW",
}


class FindingDetailPanel(Container):
    """Panel showing detailed information about selected finding."""

    DEFAULT_CSS = """
    FindingDetailPanel {
        height: 100%;
        background: #161B22;
        border: solid #30363D;
        padding: 1;
    }

    FindingDetailPanel .detail-header {
        height: 3;
        background: #1C2128;
        border: solid #30363D;
        padding: 0 1;
        content-align: left middle;
        margin: 0 0 1 0;
    }

    FindingDetailPanel .detail-content {
        height: 1fr;
        padding: 0;
    }

    FindingDetailPanel .detail-section {
        height: auto;
        margin: 0 0 1 0;
    }

    FindingDetailPanel .detail-label {
        color: #7D8590;
        height: 1;
    }

    FindingDetailPanel .detail-value {
        color: #E6EDF3;
        height: auto;
        padding: 0 0 0 1;
    }

    FindingDetailPanel .code-block {
        height: auto;
        max-height: 10;
        background: #0D1117;
        border: solid #30363D;
        padding: 1;
        margin: 0 0 1 0;
    }

    FindingDetailPanel .fix-block {
        height: auto;
        max-height: 10;
        background: #0D1117;
        border: solid #238636;
        padding: 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.current_finding: Optional[Finding] = None

    def compose(self) -> ComposeResult:
        yield Static(f"[{COLORS['pink']}]◆ Finding Details[/]", classes="detail-header", id="detail-header")
        with Vertical(classes="detail-content"):
            yield RichLog(id="detail-log", highlight=True, markup=True)

    def show_finding(self, finding: Finding) -> None:
        """Display finding details."""
        self.current_finding = finding
        log = self.query_one("#detail-log", RichLog)
        log.clear()

        severity = finding.severity.value.lower()
        sev_color = COLORS.get(severity, COLORS["muted"])

        # Header
        log.write(f"[bold {sev_color}]{SEVERITY_LABELS.get(severity, severity.upper())}[/]")
        log.write("")

        # Title
        log.write(f"[{COLORS['cyan']}]Title:[/] [bold]{finding.title}[/]")
        log.write("")

        # File location
        log.write(f"[{COLORS['cyan']}]File:[/] [{COLORS['green']}]{finding.file_path}[/]")
        if finding.line_number:
            log.write(f"[{COLORS['cyan']}]Line:[/] [{COLORS['purple']}]{finding.line_number}[/]")
        log.write("")

        # Description
        if finding.description:
            log.write(f"[{COLORS['cyan']}]Description:[/]")
            log.write(f"[{COLORS['muted']}]{finding.description}[/]")
            log.write("")

        # Vulnerable code
        if finding.code_snippet:
            log.write(f"[{COLORS['critical']}]⚠ Vulnerable Code:[/]")
            log.write(f"[on #1C1C1C]{finding.code_snippet}[/]")
            log.write("")

        # Basic Fix suggestion
        if finding.fix_suggestion:
            log.write(f"[{COLORS['green']}]✓ Suggested Fix:[/]")
            log.write(f"[on #0D2818]{finding.fix_suggestion}[/]")
            log.write("")

        # AI-Generated Fix (more detailed)
        if finding.ai_fix:
            # Check if AI fix was guided by Stack Overflow
            if finding.stackoverflow_fixes:
                log.write(f"[{COLORS['cyan']}]◆ AI-Adapted Fix (Based on Stack Overflow):[/]")
                log.write(f"[{COLORS['muted']}]AI interpreted the top Stack Overflow solution for your code[/]")
            else:
                log.write(f"[{COLORS['cyan']}]◆ AI-Generated Fix:[/]")
            log.write(f"[on #0D1821]{finding.ai_fix}[/]")
            log.write("")

        # AI Explanation
        if finding.ai_explanation:
            log.write(f"[{COLORS['purple']}]◆ AI Analysis:[/]")
            log.write(f"[on #1A0D21]{finding.ai_explanation}[/]")
            log.write("")

        # Rule ID
        if finding.rule_id:
            log.write(f"[{COLORS['cyan']}]Rule:[/] [{COLORS['purple']}]{finding.rule_id}[/]")

        # CWE/CVE
        if finding.cwe_id:
            log.write(f"[{COLORS['cyan']}]CWE:[/] [{COLORS['high']}]{finding.cwe_id}[/]")
        
        # Web Citations
        citations = []
        if finding.metadata:
            # Check for web citations in metadata
            web_info = finding.metadata.get('web_citations', [])
            if web_info:
                citations = web_info
            # Also check for stackoverflow references
            so_refs = finding.metadata.get('stackoverflow_references', [])
            if so_refs:
                citations.extend(so_refs)
            # Check for CVE references
            cve_refs = finding.metadata.get('cve_references', [])
            if cve_refs:
                citations.extend(cve_refs)
        
        # Add OWASP, CWE links based on finding info
        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace('CWE-', '').split(':')[0].strip()
            if cwe_num.isdigit():
                citations.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")
        
        if finding.rule_id and 'owasp' in finding.rule_id.lower():
            citations.append("https://owasp.org/Top10/")
        
        if citations:
            log.write("")
            log.write(f"[{COLORS['pink']}]◆ Web Citations:[/]")
            for i, citation in enumerate(citations[:5], 1):  # Limit to 5
                if isinstance(citation, dict):
                    title = citation.get('title', 'Reference')
                    url = citation.get('url', '')
                    log.write(f"  [{COLORS['cyan']}]{i}.[/] [{COLORS['text']}]{title}[/]")
                    if url:
                        log.write(f"     [{COLORS['muted']}]{url}[/]")
                else:
                    log.write(f"  [{COLORS['cyan']}]{i}.[/] [{COLORS['muted']}]{citation}[/]")

        # Stack Overflow Solutions
        if finding.stackoverflow_fixes:
            log.write("")
            log.write(f"[{COLORS['green']}]◆ Stack Overflow Solutions:[/]")

            for i, so_answer in enumerate(finding.stackoverflow_fixes[:3], 1):  # Limit to top 3
                log.write("")

                # Answer header with votes and acceptance
                header_parts = [f"  [{COLORS['cyan']}]{i}.[/]"]

                if so_answer.accepted:
                    header_parts.append(f"[{COLORS['green']}]✓ ACCEPTED[/]")

                if so_answer.votes > 0:
                    header_parts.append(f"[{COLORS['purple']}]↑ {so_answer.votes} votes[/]")

                log.write(" ".join(header_parts))

                # Title
                if so_answer.title:
                    log.write(f"     [{COLORS['text']}]{so_answer.title}[/]")

                # Author info
                if so_answer.author and so_answer.author_reputation:
                    log.write(
                        f"     [{COLORS['muted']}]by {so_answer.author} "
                        f"(rep: {so_answer.author_reputation:,})[/]"
                    )

                # Explanation (first 200 chars)
                if so_answer.explanation:
                    explanation = so_answer.explanation.strip()
                    if len(explanation) > 200:
                        explanation = explanation[:200] + "..."
                    log.write(f"     [{COLORS['muted']}]{explanation}[/]")

                # Code snippets
                if so_answer.code_snippets:
                    log.write(f"     [{COLORS['yellow']}]Code Example:[/]")
                    # Show first code snippet
                    code_block = so_answer.code_snippets[0]
                    code = code_block.code.strip()
                    # Limit code to 5 lines
                    code_lines = code.split('\n')[:5]
                    code_preview = '\n'.join(code_lines)
                    if len(code_block.code.split('\n')) > 5:
                        code_preview += "\n     ..."
                    log.write(f"[on #1C1C1C]     {code_preview}[/]")

                # Link
                if so_answer.url:
                    log.write(f"     [{COLORS['cyan']}]View on Stack Overflow:[/] [{COLORS['muted']}]{so_answer.url}[/]")

    def clear(self) -> None:
        """Clear the detail panel."""
        self.current_finding = None
        log = self.query_one("#detail-log", RichLog)
        log.clear()
        log.write(f"[{COLORS['muted']}]Select a finding to view details[/]")


class RichFindingsTable(Container):
    """Enhanced findings table with metrics, filtering, and detail panel."""

    DEFAULT_CSS = """
    RichFindingsTable {
        height: 100%;
        background: #0D1117;
        layout: horizontal;
    }

    RichFindingsTable .table-section {
        width: 2fr;
        height: 100%;
        background: #0D1117;
    }

    RichFindingsTable .detail-section {
        width: 1fr;
        min-width: 40;
        height: 100%;
        background: #161B22;
        border-left: solid #30363D;
    }

    RichFindingsTable .metrics-row {
        height: 4;
        layout: horizontal;
        padding: 1;
        background: #161B22;
        border: solid #30363D;
    }

    RichFindingsTable .metric-box {
        width: 1fr;
        height: 3;
        text-align: center;
        content-align: center middle;
        text-style: bold;
        border: solid #30363D;
        margin: 0 1 0 0;
    }

    RichFindingsTable .metric-critical { 
        border: solid #FF5555; 
        color: #FF5555; 
        background: #FF5555 15%;
    }
    RichFindingsTable .metric-high { 
        border: solid #FFB86C; 
        color: #FFB86C; 
        background: #FFB86C 15%; 
    }
    RichFindingsTable .metric-medium { 
        border: solid #F1FA8C; 
        color: #F1FA8C; 
        background: #F1FA8C 10%; 
    }
    RichFindingsTable .metric-low { 
        border: solid #8BE9FD; 
        color: #8BE9FD; 
        background: #8BE9FD 15%; 
    }
    RichFindingsTable .metric-score { 
        border: solid #50FA7B; 
        color: #50FA7B; 
        background: #50FA7B 15%; 
        margin: 0; 
    }

    RichFindingsTable .summary-bar {
        height: 2;
        padding: 0 1;
        background: #161B22;
        content-align: left middle;
        color: #7D8590;
    }

    RichFindingsTable .filter-bar {
        height: 3;
        padding: 0 1;
        align: left middle;
        background: #1C2128;
    }

    RichFindingsTable .filter-input {
        width: 24;
        margin-right: 1;
        background: #0D1117;
        border: solid #30363D;
    }

    RichFindingsTable .filter-input:focus {
        border: solid #00D4FF;
    }

    RichFindingsTable .filter-select {
        width: 14;
        margin-right: 1;
        background: #0D1117;
        border: solid #30363D;
    }

    RichFindingsTable .table-container {
        height: 1fr;
        background: #0D1117;
        border: solid #30363D;
        margin: 1 0;
    }

    RichFindingsTable DataTable {
        height: 100%;
        background: #0D1117;
    }

    RichFindingsTable DataTable > .datatable--cursor {
        background: #1C2128;
    }

    RichFindingsTable DataTable > .datatable--header {
        background: #161B22;
        color: #00D4FF;
        text-style: bold;
    }

    RichFindingsTable .stats-bar {
        height: 2;
        background: #161B22;
        color: #7D8590;
        padding: 0 1;
        content-align: left middle;
        border: solid #30363D;
    }

    RichFindingsTable .export-bar {
        height: 4;
        padding: 1;
        align: center middle;
        background: #1C2128;
        border: solid #30363D;
        layout: horizontal;
    }

    RichFindingsTable .export-btn {
        min-width: 12;
        margin: 0 1;
        text-style: bold;
    }

    RichFindingsTable #export-html-btn {
        background: #238636;
        color: white;
    }

    RichFindingsTable #export-sarif-btn {
        background: #1F6FEB;
        color: white;
    }

    RichFindingsTable #export-pdf-btn {
        background: #DA3633;
        color: white;
    }

    RichFindingsTable .clear-btn {
        min-width: 8;
        background: #30363D;
    }
    """

    def __init__(self, **kwargs) -> None:
        """Initialize the rich findings table."""
        super().__init__(**kwargs)
        self.scan_result: Optional[ScanResult] = None
        self.severity_filter = "all"
        self.search_query = ""
        self.findings_list: list = []

    def compose(self) -> ComposeResult:
        """Compose the findings table with detail panel."""
        # Left: Table section
        with Vertical(classes="table-section"):
            # Metrics row at top
            with Horizontal(classes="metrics-row"):
                yield Static("0", classes="metric-box metric-critical", id="metric-critical")
                yield Static("0", classes="metric-box metric-high", id="metric-high")
                yield Static("0", classes="metric-box metric-medium", id="metric-medium")
                yield Static("0", classes="metric-box metric-low", id="metric-low")
                yield Static("--", classes="metric-box metric-score", id="metric-score")

            yield Static(f"[{COLORS['muted']}]Ready to scan...[/]", classes="summary-bar", id="summary-bar")

            with Horizontal(classes="filter-bar"):
                yield Input(
                    placeholder="Search findings...",
                    classes="filter-input",
                    id="search-input"
                )
                yield Select(
                    [
                        ("All", "all"),
                        ("Critical", "critical"),
                        ("High", "high"),
                        ("Medium", "medium"),
                        ("Low", "low"),
                    ],
                    value="all",
                    classes="filter-select",
                    id="severity-filter"
                )
                yield Button("Clear", classes="clear-btn", id="clear-filters")

            with Container(classes="table-container"):
                table = DataTable(
                    id="rich-findings-table",
                    zebra_stripes=True,
                    cursor_type="row",
                    show_cursor=True,
                )
                # Add columns
                table.add_column("●", width=3)
                table.add_column("Severity", width=10)
                table.add_column("Type", width=20)
                table.add_column("File", width=35)
                table.add_column("Line", width=6)
                table.add_column("Description", width=50)
                yield table

            yield Static(f"[{COLORS['muted']}]No findings yet[/]", classes="stats-bar", id="stats-bar")

            with Horizontal(classes="export-bar"):
                yield Button("📄 HTML", variant="success", classes="export-btn", id="export-html-btn")
                yield Button("📋 SARIF", variant="primary", classes="export-btn", id="export-sarif-btn")
                yield Button("📑 PDF", variant="warning", classes="export-btn", id="export-pdf-btn")

        # Right: Detail panel
        with Container(classes="detail-section"):
            yield FindingDetailPanel(id="finding-detail")

    def on_mount(self) -> None:
        """Initialize the detail panel."""
        detail = self.query_one("#finding-detail", FindingDetailPanel)
        detail.clear()

    @on(DataTable.RowSelected, "#rich-findings-table")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Show finding details when row is selected."""
        if event.row_key and self.findings_list:
            try:
                row_index = event.cursor_row
                if 0 <= row_index < len(self.findings_list):
                    finding = self.findings_list[row_index]
                    detail = self.query_one("#finding-detail", FindingDetailPanel)
                    detail.show_finding(finding)
            except Exception:
                pass

    def get_severity_icon(self, severity: str) -> Text:
        """Get colored dot indicator for severity level."""
        colors = {
            "critical": COLORS["critical"],
            "high": COLORS["high"],
            "medium": COLORS["medium"],
            "low": COLORS["low"],
        }
        color = colors.get(severity.lower(), COLORS["muted"])
        return Text("●", style=f"bold {color}")

    def get_severity_style(self, severity: str) -> str:
        """Get style for severity level."""
        colors = {
            "critical": f"bold {COLORS['critical']}",
            "high": f"bold {COLORS['high']}",
            "medium": f"bold {COLORS['medium']}",
            "low": COLORS["low"],
        }
        return colors.get(severity.lower(), COLORS["text"])

    def update_metrics(self, scan_result: ScanResult) -> None:
        """Update the metrics row with scan results."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in scan_result.findings:
            sev = finding.severity.value.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Update metric boxes
        self.query_one("#metric-critical", Static).update(str(severity_counts["critical"]))
        self.query_one("#metric-high", Static).update(str(severity_counts["high"]))
        self.query_one("#metric-medium", Static).update(str(severity_counts["medium"]))
        self.query_one("#metric-low", Static).update(str(severity_counts["low"]))

        # Calculate security score
        total = len(scan_result.findings)
        if total == 0:
            score = 100
        else:
            penalty = (severity_counts["critical"] * 25 + 
                      severity_counts["high"] * 10 + 
                      severity_counts["medium"] * 3 + 
                      severity_counts["low"] * 1)
            score = max(0, 100 - penalty)
        self.query_one("#metric-score", Static).update(f"{score:.0f}%")

        # Update summary bar
        summary = self.query_one("#summary-bar", Static)
        if total > 0:
            risk = "CRITICAL" if severity_counts["critical"] > 0 else (
                "HIGH" if severity_counts["high"] > 0 else (
                    "MEDIUM" if severity_counts["medium"] > 0 else "LOW"
                )
            )
            risk_color = COLORS.get(risk.lower(), COLORS["muted"])
            summary.update(
                f"[{risk_color}]● {risk} RISK[/]  [{COLORS['muted']}]│[/]  "
                f"[{COLORS['text']}]{total}[/] [{COLORS['muted']}]issues found[/]  [{COLORS['muted']}]│[/]  "
                f"[{COLORS['green']}]Score: {score:.0f}%[/]"
            )
        else:
            summary.update(f"[{COLORS['green']}]● No issues found[/]")

    def update_findings(self, scan_result: ScanResult) -> None:
        """Update findings table with vibrant colors."""
        self.scan_result = scan_result
        self._render_findings()

    def _render_findings(self) -> None:
        """Render findings with current filters."""
        if not self.scan_result:
            return

        table = self.query_one("#rich-findings-table", DataTable)
        table.clear()
        self.findings_list = []

        # Apply filters
        filtered_findings = []
        for finding in self.scan_result.findings:
            if self.severity_filter != "all":
                if finding.severity.value.lower() != self.severity_filter:
                    continue

            if self.search_query:
                search_text = f"{finding.title} {finding.description} {finding.file_path}".lower()
                if self.search_query.lower() not in search_text:
                    continue

            filtered_findings.append(finding)

        self.findings_list = filtered_findings[:500]

        # Add findings to table
        for finding in self.findings_list:
            severity = finding.severity.value.lower()
            icon = self.get_severity_icon(severity)
            severity_style = self.get_severity_style(severity)

            severity_text = Text(finding.severity.value.upper(), style=severity_style)

            file_path_str = str(finding.file_path)
            if len(file_path_str) > 33:
                file_text = Text(f"...{file_path_str[-30:]}", style=COLORS["cyan"])
            else:
                file_text = Text(file_path_str, style=COLORS["cyan"])

            description = finding.description or finding.title or "No description"
            if len(description) > 48:
                desc_text = Text(description[:45] + "...", style=COLORS["muted"])
            else:
                desc_text = Text(description, style=COLORS["muted"])

            vuln_type = finding.vuln_id or finding.rule_id or "N/A"
            type_text = Text(vuln_type[:18] if len(vuln_type) > 18 else vuln_type, 
                           style=COLORS["purple"] if vuln_type != "N/A" else COLORS["muted"])

            line_num = str(finding.line_number) if finding.line_number else "-"
            line_text = Text(line_num, style=COLORS["green"] if line_num != "-" else COLORS["muted"])

            table.add_row(icon, severity_text, type_text, file_text, line_text, desc_text)

        # Update stats bar
        stats_bar = self.query_one("#stats-bar", Static)
        total = len(self.scan_result.findings)
        shown = len(self.findings_list)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.scan_result.findings:
            sev = f.severity.value.lower()
            if sev in counts:
                counts[sev] += 1

        if filtered_findings != self.scan_result.findings:
            stats_bar.update(
                f"[{COLORS['muted']}]Filtered:[/] [{COLORS['text']}]{shown}[/][{COLORS['muted']}]/{total}[/]  "
                f"[{COLORS['critical']}]●{counts['critical']}[/] "
                f"[{COLORS['high']}]●{counts['high']}[/] "
                f"[{COLORS['medium']}]●{counts['medium']}[/] "
                f"[{COLORS['low']}]●{counts['low']}[/]"
            )
        else:
            stats_bar.update(
                f"[{COLORS['text']}]{total}[/] [{COLORS['muted']}]findings[/]  "
                f"[{COLORS['critical']}]●{counts['critical']}[/] "
                f"[{COLORS['high']}]●{counts['high']}[/] "
                f"[{COLORS['medium']}]●{counts['medium']}[/] "
                f"[{COLORS['low']}]●{counts['low']}[/]  "
                f"[{COLORS['muted']}]│ Click row for details[/]"
            )

    @on(Input.Changed, "#search-input")
    def on_search_changed(self, event: Input.Changed) -> None:
        """Handle search input changes."""
        self.search_query = event.value
        self._render_findings()

    @on(Select.Changed, "#severity-filter")
    def on_severity_changed(self, event: Select.Changed) -> None:
        """Handle severity filter changes."""
        self.severity_filter = str(event.value)
        self._render_findings()

    @on(Button.Pressed, "#clear-filters")
    def on_clear_filters(self) -> None:
        """Clear all filters."""
        self.search_query = ""
        self.severity_filter = "all"
        self.query_one("#search-input", Input).value = ""
        self.query_one("#severity-filter", Select).value = "all"
        self._render_findings()

    def clear_findings(self) -> None:
        """Clear the findings table."""
        self.scan_result = None
        self.findings_list = []
        table = self.query_one("#rich-findings-table", DataTable)
        table.clear()
        self.query_one("#stats-bar", Static).update(f"[{COLORS['muted']}]No findings[/]")
        self.query_one("#finding-detail", FindingDetailPanel).clear()
