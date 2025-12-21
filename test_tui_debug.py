#!/usr/bin/env python3
"""Debug script to test TUI rendering."""

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import Static, Footer

from src.impact_scan.tui.widgets.config_panel import ConfigPanel
from src.impact_scan.tui.widgets.overview_panel import ScanInfo, CodebaseTree, ProgressLog


class DebugApp(App):
    """Debug app to test widgets."""

    CSS = """
    Screen {
        background: #0D1117;
    }

    .left-column {
        width: 50;
        height: 100%;
        background: #161B22;
        border-right: solid #30363D;
        padding: 1;
    }

    .right-column {
        width: 1fr;
        height: 100%;
        background: #0D1117;
        padding: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("Debug TUI Test", id="header")
        
        with Container():
            # Left column
            with Vertical(classes="left-column"):
                yield ConfigPanel()
                yield ScanInfo()
            
            # Right column
            with Vertical(classes="right-column"):
                yield CodebaseTree()
                yield ProgressLog()
        
        yield Footer()


if __name__ == "__main__":
    app = DebugApp()
    app.run()
