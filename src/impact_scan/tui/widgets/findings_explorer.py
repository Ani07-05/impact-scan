"""
Findings Explorer Widget
Clean findings view with table.
"""

from textual.app import ComposeResult
from textual.containers import Container

from .rich_findings_table import RichFindingsTable


class FindingsExplorer(Container):
    """Findings explorer - streamlined table view."""

    DEFAULT_CSS = """
    FindingsExplorer {
        height: 100%;
        width: 100%;
        background: #0D1117;
        padding: 0;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the findings explorer."""
        yield RichFindingsTable(id="findings-table")
