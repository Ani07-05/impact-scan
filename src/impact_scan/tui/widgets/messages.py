"""
Custom Message Types
Message-passing for component communication in the TUI.
"""

from textual.message import Message

from impact_scan.utils.schema import Finding, ScanConfig, ScanResult


class ScanStarted(Message):
    """Posted when a scan starts."""

    def __init__(self, config: ScanConfig) -> None:
        """Initialize message."""
        self.config = config
        super().__init__()


class ScanProgress(Message):
    """Posted for scan progress updates."""

    def __init__(self, progress: float, phase: str, message: str) -> None:
        """Initialize message."""
        self.progress = progress
        self.phase = phase
        self.message = message
        super().__init__()


class ScanCompleted(Message):
    """Posted when a scan completes."""

    def __init__(self, results: ScanResult) -> None:
        """Initialize message."""
        self.results = results
        super().__init__()


class FindingSelected(Message):
    """Posted when user selects a finding."""

    def __init__(self, finding: Finding, index: int) -> None:
        """Initialize message."""
        self.finding = finding
        self.index = index
        super().__init__()
