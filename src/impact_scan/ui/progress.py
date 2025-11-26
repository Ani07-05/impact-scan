"""
Progress tracking and animation for scan phases.

Provides Rich Progress bars and spinners for all scanning operations,
replacing static "Running..." messages with live, animated feedback.
"""

from contextlib import contextmanager
from typing import Optional
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.console import Console


class ScanProgressTracker:
    """
    Manages progress tracking for all scan phases.

    Features:
    - Spinners for indeterminate tasks (Semgrep, project classification)
    - Progress bars with counts for deterministic tasks (AI validation, fix generation)
    - Elapsed time tracking for all phases
    - ETA for progress bar tasks
    - Clean, minimal display
    """

    def __init__(self, console: Optional[Console] = None):
        """
        Initialize progress tracker.

        Args:
            console: Rich Console instance (creates new if None)
        """
        self.console = console or Console()
        self.progress = None

    def __enter__(self):
        """Start progress display."""
        self.progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style="cyan", finished_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            transient=False,  # Keep completed tasks visible
            expand=False,
        )
        self.progress.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop progress display."""
        if self.progress:
            self.progress.__exit__(exc_type, exc_val, exc_tb)

    def add_spinner_task(self, description: str) -> int:
        """
        Add a spinner task (indeterminate progress).

        Args:
            description: Task description (e.g., "Running Semgrep scan...")

        Returns:
            Task ID for updating
        """
        if self.progress:
            return self.progress.add_task(description, total=None)
        return -1

    def add_progress_task(self, description: str, total: int) -> int:
        """
        Add a progress bar task (determinate progress).

        Args:
            description: Task description (e.g., "AI validation")
            total: Total number of items to process

        Returns:
            Task ID for updating
        """
        if self.progress:
            return self.progress.add_task(description, total=total)
        return -1

    def update(self, task_id: int, advance: int = 1, description: Optional[str] = None):
        """
        Update task progress.

        Args:
            task_id: Task ID to update
            advance: Number of items completed (default 1)
            description: Optional new description
        """
        if self.progress and task_id >= 0:
            kwargs = {"advance": advance}
            if description:
                kwargs["description"] = description
            self.progress.update(task_id, **kwargs)

    def complete_task(self, task_id: int, description: Optional[str] = None):
        """
        Mark task as complete.

        Args:
            task_id: Task ID to complete
            description: Optional completion message
        """
        if self.progress and task_id >= 0:
            if description:
                self.progress.update(task_id, description=description)
            # For spinner tasks, mark as completed by setting total=1, completed=1
            task = self.progress.tasks[task_id]
            if task.total is None:
                self.progress.update(task_id, total=1, completed=1)
            else:
                # For progress bar tasks, complete any remaining
                self.progress.update(task_id, completed=task.total)


@contextmanager
def spinner_task(tracker: Optional[ScanProgressTracker], description: str):
    """
    Context manager for spinner tasks.

    Usage:
        with spinner_task(tracker, "Running Semgrep...") as task_id:
            # Do work
            pass
        # Auto-completes on exit

    Args:
        tracker: ScanProgressTracker instance (can be None for disabled mode)
        description: Task description

    Yields:
        Task ID
    """
    if tracker and tracker.progress:
        task_id = tracker.add_spinner_task(description)
        try:
            yield task_id
        finally:
            tracker.complete_task(task_id, f"[green]{description.replace('...', ' complete')}")
    else:
        yield -1


@contextmanager
def progress_task(tracker: Optional[ScanProgressTracker], description: str, total: int):
    """
    Context manager for progress bar tasks.

    Usage:
        with progress_task(tracker, "AI validation", 50) as task_id:
            for i in range(50):
                # Do work
                tracker.update(task_id)
        # Auto-completes on exit

    Args:
        tracker: ScanProgressTracker instance (can be None for disabled mode)
        description: Task description
        total: Total items to process

    Yields:
        Task ID
    """
    if tracker and tracker.progress:
        task_id = tracker.add_progress_task(description, total)
        try:
            yield task_id
        finally:
            tracker.complete_task(task_id, f"[green]{description} complete")
    else:
        yield -1
