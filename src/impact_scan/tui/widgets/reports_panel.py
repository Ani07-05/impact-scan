"""
Reports Panel Widget
Centralized report generation and export interface.
"""

import time
import webbrowser
from pathlib import Path
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Static

from impact_scan.core import aggregator
from impact_scan.core.html_report import save_report
from impact_scan.core.markdown_report import MarkdownReportGenerator
from impact_scan.utils.schema import ScanResult

# Colors
COLORS = {
    "cyan": "#00D4FF",
    "green": "#50FA7B",
    "orange": "#FFB86C",
    "purple": "#BD93F9",
    "yellow": "#F1FA8C",
    "red": "#FF5555",
    "muted": "#7D8590",
}


class ReportsPanel(Container):
    """Report generation and export panel."""

    DEFAULT_CSS = """
    ReportsPanel {
        height: 100%;
        width: 100%;
        background: #0D1117;
        padding: 2;
    }

    ReportsPanel .reports-header {
        height: 5;
        background: #161B22;
        border: solid #30363D;
        padding: 1;
        margin: 0 0 2 0;
        content-align: center middle;
    }

    ReportsPanel .header-title {
        text-align: center;
        text-style: bold;
        color: #00D4FF;
    }

    ReportsPanel .header-subtitle {
        text-align: center;
        color: #7D8590;
    }

    ReportsPanel .stats-section {
        height: auto;
        background: #161B22;
        border: solid #30363D;
        padding: 2;
        margin: 0 0 2 0;
    }

    ReportsPanel .stats-title {
        color: #00D4FF;
        text-style: bold;
        margin: 0 0 1 0;
    }

    ReportsPanel .stats-grid {
        height: auto;
        layout: horizontal;
        margin: 1 0 0 0;
    }

    ReportsPanel .stat-box {
        width: 1fr;
        height: 5;
        background: #0D1117;
        border: solid #30363D;
        padding: 1;
        margin: 0 1 0 0;
        content-align: center middle;
        text-align: center;
    }

    ReportsPanel .stat-value {
        text-style: bold;
        color: #E6EDF3;
    }

    ReportsPanel .stat-label {
        color: #7D8590;
    }

    ReportsPanel .export-section {
        height: auto;
        background: #161B22;
        border: solid #30363D;
        padding: 2;
        margin: 0 0 2 0;
    }

    ReportsPanel .export-title {
        color: #00D4FF;
        text-style: bold;
        margin: 0 0 1 0;
    }

    ReportsPanel .export-buttons {
        height: auto;
        layout: horizontal;
        margin: 1 0 0 0;
    }

    ReportsPanel .export-btn {
        width: 1fr;
        height: 4;
        margin: 0 1 0 0;
        text-style: bold;
    }

    ReportsPanel .status-section {
        height: auto;
        background: #161B22;
        border: solid #30363D;
        padding: 2;
    }

    ReportsPanel .status-title {
        color: #00D4FF;
        text-style: bold;
        margin: 0 0 1 0;
    }

    ReportsPanel .status-log {
        height: 1fr;
        background: #0D1117;
        border: solid #30363D;
        padding: 1;
        color: #7D8590;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.scan_result: Optional[ScanResult] = None
        self.messages = []

    def compose(self) -> ComposeResult:
        """Compose the reports panel."""
        # Header
        with Container(classes="reports-header"):
            yield Static("Report Generation", classes="header-title")
            yield Static(
                "Export your scan results in multiple formats",
                classes="header-subtitle",
            )

        # Statistics
        with Container(classes="stats-section"):
            yield Static("◈ Scan Statistics", classes="stats-title")

            with Horizontal(classes="stats-grid"):
                with Container(classes="stat-box"):
                    yield Static("--", classes="stat-value", id="report-total")
                    yield Static("Total Findings", classes="stat-label")

                with Container(classes="stat-box"):
                    yield Static("--", classes="stat-value", id="report-critical")
                    yield Static("Critical", classes="stat-label")

                with Container(classes="stat-box"):
                    yield Static("--", classes="stat-value", id="report-high")
                    yield Static("High", classes="stat-label")

                with Container(classes="stat-box"):
                    yield Static("--", classes="stat-value", id="report-medium")
                    yield Static("Medium", classes="stat-label")

        # Export Buttons
        with Container(classes="export-section"):
            yield Static("◈ Generate Reports", classes="export-title")

            with Horizontal(classes="export-buttons"):
                yield Button(
                    "HTML Report",
                    variant="success",
                    classes="export-btn",
                    id="export-html-btn",
                )
                yield Button(
                    "SARIF Report",
                    variant="primary",
                    classes="export-btn",
                    id="export-sarif-btn",
                )
                yield Button(
                    "Markdown Report",
                    variant="default",
                    classes="export-btn",
                    id="export-md-btn",
                )

        # Status Log
        with Container(classes="status-section"):
            yield Static("◈ Export Status", classes="status-title")
            yield Static(
                f"[{COLORS['muted']}]No reports generated yet. Run a scan first.[/]",
                classes="status-log",
                id="report-status",
            )

    def set_scan_result(self, scan_result: ScanResult) -> None:
        """Set the scan result and update the panel."""
        self.update_statistics(scan_result)

    def update_statistics(self, scan_result: ScanResult) -> None:
        """Update statistics from scan result."""
        self.scan_result = scan_result

        if not scan_result or not scan_result.findings:
            self._show_no_data()
            return

        # Calculate stats
        total = len(scan_result.findings)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in scan_result.findings:
            severity = finding.severity.value.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Update UI
        try:
            self.query_one("#report-total", Static).update(str(total))
            self.query_one("#report-critical", Static).update(
                f"[{COLORS['red']}]{severity_counts['critical']}[/]"
            )
            self.query_one("#report-high", Static).update(
                f"[{COLORS['orange']}]{severity_counts['high']}[/]"
            )
            self.query_one("#report-medium", Static).update(
                f"[{COLORS['yellow']}]{severity_counts['medium']}[/]"
            )

            self.log_message("Statistics updated", "green")
        except Exception:
            pass

    def _show_no_data(self) -> None:
        """Show placeholder when no data available."""
        try:
            self.query_one("#report-total", Static).update("--")
            self.query_one("#report-critical", Static).update("--")
            self.query_one("#report-high", Static).update("--")
            self.query_one("#report-medium", Static).update("--")
        except Exception:
            pass

    def log_message(self, message: str, style: str = "cyan") -> None:
        """Add a log message to the status."""
        import time

        ts = time.strftime("%H:%M:%S")
        color = COLORS.get(style, COLORS["cyan"])
        self.messages.append(f"[{COLORS['muted']}]{ts}[/] [{color}]{message}[/]")

        # Keep last 10 messages
        if len(self.messages) > 10:
            self.messages = self.messages[-10:]

        try:
            content = "\n".join(self.messages) if self.messages else f"[{COLORS['muted']}]Ready...[/]"
            status_widget = self.query_one("#report-status", Static)
            status_widget.update(content)
        except Exception:
            pass

    def export_html(self) -> Optional[Path]:
        """Export HTML report."""
        if not self.scan_result:
            self.log_message("No scan results available", "red")
            return None

        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_report_{timestamp}.html"

            self.log_message("Generating HTML report...", "yellow")
            save_report(self.scan_result, str(output_file))

            self.log_message(f"Saved: {output_file.name}", "green")
            self.log_message("Opening in browser...", "cyan")

            # Open in browser
            webbrowser.open(f"file://{output_file.absolute()}")

            return output_file
        except Exception as e:
            self.log_message(f"HTML export failed: {e}", "red")
            return None

    def export_sarif(self) -> Optional[Path]:
        """Export SARIF report."""
        if not self.scan_result:
            self.log_message("No scan results available", "red")
            return None

        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_sarif_{timestamp}.json"

            self.log_message("Generating SARIF report...", "yellow")
            aggregator.save_to_sarif(self.scan_result, output_file)

            self.log_message(f"Saved: {output_file.name}", "green")
            return output_file
        except Exception as e:
            self.log_message(f"SARIF export failed: {e}", "red")
            return None

    def export_markdown(self) -> Optional[Path]:
        """Export Markdown report."""
        if not self.scan_result:
            self.log_message("No scan results available", "red")
            return None

        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_report_{timestamp}.md"

            self.log_message("Generating Markdown report...", "yellow")
            generator = MarkdownReportGenerator()
            markdown_content = generator.generate_markdown(self.scan_result)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(markdown_content)

            self.log_message(f"Saved: {output_file.name}", "green")
            return output_file
        except Exception as e:
            self.log_message(f"Markdown export failed: {e}", "red")
            return None
