"""
Export Panel Widget
Export configuration and preview (placeholder).
"""

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import Static


class ExportPanel(Container):
    """Export configuration and preview panel."""

    DEFAULT_CSS = """
    ExportPanel {
        height: 100%;
        align: center middle;
    }

    ExportPanel .placeholder {
        width: 60;
        height: 20;
        border: heavy $primary;
        padding: 2;
        text-align: center;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the export panel."""
        with Vertical(classes="placeholder"):
            yield Static("Export Center", classes="panel-header")
            yield Static("")
            yield Static("Multiple export formats with live preview")
            yield Static("")
            yield Static("Formats:")
            yield Static("• HTML Report (enhanced)")
            yield Static("• SARIF (existing)")
            yield Static("• Markdown (for GitHub/GitLab)")
            yield Static("• PDF Report (via ReportLab)")
            yield Static("• CSV (for spreadsheet analysis)")
            yield Static("• JSON (raw data)")
            yield Static("")
            yield Static("[Coming Soon in Phase 5]", classes="text-muted")
