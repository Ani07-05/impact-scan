"""
Progress Panel Widget
Extracted progress/activity section from the main TUI.
"""

import time

from textual.app import ComposeResult
from textual.containers import Container
from textual.widgets import Log, ProgressBar, Static

# Color palette
COLORS = {
    "pink": "#FF6EC7",
    "cyan": "#00D4FF",
    "green": "#50FA7B",
    "muted": "#7D8590",
}


class ProgressPanel(Container):
    """Minimal progress and activity panel."""

    DEFAULT_CSS = """
    ProgressPanel {
        height: 1fr;
        background: #161B22;
        padding: 1;
        border: solid #30363D;
    }

    ProgressPanel .progress-bar-container {
        height: 3;
        margin: 0 0 1 0;
        background: #0D1117;
        border: solid #30363D;
        padding: 0 1;
    }

    ProgressPanel ProgressBar > .bar--bar {
        background: #00D4FF;
    }

    ProgressPanel ProgressBar > .bar--complete {
        background: #50FA7B;
    }

    ProgressPanel .status-line {
        height: 2;
        margin: 0 0 1 0;
        text-align: center;
        color: #50FA7B;
        content-align: center middle;
    }

    ProgressPanel .activity-log {
        height: 1fr;
        background: #0D1117;
        border: solid #30363D;
        padding: 1;
        scrollbar-size: 1 1;
    }

    ProgressPanel Log {
        background: #0D1117;
        color: #8BE9FD;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the progress panel."""
        with Container(classes="progress-bar-container"):
            yield ProgressBar(total=100, show_eta=False, id="scan-progress")

        yield Static(f"[{COLORS['green']}]Ready[/]", classes="status-line", id="status-text")

        yield Log(
            highlight=True,
            classes="activity-log",
            id="scan-log",
            auto_scroll=True,
        )

    def log_message(self, message: str) -> None:
        """Add timestamped message to log with color."""
        log_widget = self.query_one("#scan-log", Log)
        timestamp = time.strftime("%H:%M:%S")
        log_widget.write(f"[{COLORS['muted']}]{timestamp}[/] [{COLORS['cyan']}]{message}[/]")

    def update_status(self, status: str) -> None:
        """Update status text with color."""
        self.query_one("#status-text", Static).update(f"[{COLORS['green']}]{status}[/]")

    def update_progress(self, progress: float) -> None:
        """Update progress bar."""
        self.query_one("#scan-progress", ProgressBar).update(progress=progress)

    def reset_progress(self) -> None:
        """Reset progress bar to 0."""
        self.query_one("#scan-progress", ProgressBar).update(total=100, progress=0)

    def clear_log(self) -> None:
        """Clear the activity log."""
        log_widget = self.query_one("#scan-log", Log)
        log_widget.clear()
        self.log_message("Log cleared")
