"""
History Panel Widget
Displays scan history and comparison features (placeholder).
"""

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import Static


class HistoryPanel(Container):
    """Scan history and comparison panel."""

    DEFAULT_CSS = """
    HistoryPanel {
        height: 100%;
        align: center middle;
    }

    HistoryPanel .placeholder {
        width: 60;
        height: 20;
        border: heavy $primary;
        padding: 2;
        text-align: center;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the history panel."""
        with Vertical(classes="placeholder"):
            yield Static("Scan History", classes="panel-header")
            yield Static("")
            yield Static("Track all scans and compare results over time")
            yield Static("")
            yield Static("Features:")
            yield Static("• View past scan results")
            yield Static("• Compare findings between scans")
            yield Static("• Trend analysis with sparklines")
            yield Static("• Score delta over time")
            yield Static("")
            yield Static("[Coming Soon in Phase 4]", classes="text-muted")
