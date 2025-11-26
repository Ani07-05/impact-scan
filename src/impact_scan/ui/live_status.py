"""
Live status display inspired by Claude Code agent UI.

Shows clean, animated status with timer - not spam logs.
"""

import time
from contextlib import contextmanager
from typing import Optional
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.table import Table


class ClaudeStyleStatus:
    """
    Claude Code-style live status display.

    Shows:
    - Animated progress bar (purple/cyan)
    - Current phase with big text
    - Elapsed timer
    - ESC to interrupt hint
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.start_time = time.time()
        self.current_phase = "Initializing"
        self.details = ""
        self.live = None

    def _build_display(self) -> Panel:
        """Build the live display panel."""
        # Calculate elapsed time
        elapsed = int(time.time() - self.start_time)
        mins = elapsed // 60
        secs = elapsed % 60

        # Create main text
        main_text = Text()
        main_text.append(f"{self.current_phase}", style="bold cyan")
        if self.details:
            main_text.append(f"  {self.details}", style="dim white")

        # Create info row
        info = Table.grid(expand=True)
        info.add_column(justify="left")
        info.add_column(justify="right")

        timer_text = Text()
        timer_text.append(f"{mins}:{secs:02d}", style="dim cyan")

        hint_text = Text()
        hint_text.append("esc ", style="dim white")
        hint_text.append("interrupt", style="dim white")

        info.add_row(timer_text, hint_text)

        # Build panel
        content = Group(
            main_text,
            Text(""),  # Blank line
            info
        )

        return Panel(
            content,
            border_style="cyan dim",
            padding=(1, 2),
            title="[dim]IMPACT SCAN[/dim]",
            title_align="left"
        )

    def update(self, phase: str, details: str = ""):
        """Update the current phase and details."""
        self.current_phase = phase
        self.details = details
        # Force refresh the live display
        if self.live:
            self.live.update(self._build_display())

    def __enter__(self):
        """Start live display."""
        self.live = Live(
            self._build_display(),
            console=self.console,
            refresh_per_second=2,  # Update timer every 0.5 seconds
            transient=True  # Remove after completion to avoid overlap
        )
        self.live.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop live display."""
        if self.live:
            self.live.__exit__(exc_type, exc_val, exc_tb)

    def get_renderable(self):
        """Get current renderable for Live display."""
        return self._build_display()


@contextmanager
def live_scan_status(phase: str = "Starting scan", console: Optional[Console] = None):
    """
    Context manager for Claude-style live status.

    Usage:
        with live_scan_status("Scanning files") as status:
            # Do work
            status.update("Analyzing results", "Found 10 issues")
    """
    status = ClaudeStyleStatus(console)
    status.update(phase)

    with status:
        yield status
