"""
Centralized Application State
Reactive state management for the Impact-Scan TUI.
"""

from typing import Optional

from textual.reactive import reactive

from impact_scan.utils.schema import ScanConfig, ScanResult


class AppState:
    """Centralized reactive application state."""

    # Scan state
    scan_running = reactive(False)
    scan_progress = reactive(0.0)
    scan_status = reactive("Ready")
    current_phase = reactive("")  # "analyzing", "scanning", "ai_fixes", "reporting"

    # UI state
    active_view = reactive("overview")  # "overview", "findings", "history", "export"
    selected_finding_idx = reactive(None)

    # Data state
    current_config: Optional[ScanConfig] = None
    current_results: Optional[ScanResult] = None
    scan_history: list[ScanResult] = reactive([])

    # Filters
    severity_filter = reactive({"critical", "high", "medium", "low"})
    source_filter = reactive({"dependency", "static_analysis", "ai_detection"})
    search_query = reactive("")

    def __init__(self):
        """Initialize application state."""
        self.current_config = None
        self.current_results = None

    def reset_scan_state(self) -> None:
        """Reset scan-related state."""
        self.scan_running = False
        self.scan_progress = 0.0
        self.scan_status = "Ready"
        self.current_phase = ""

    def update_progress(self, progress: float, phase: str, status: str) -> None:
        """Update scan progress."""
        self.scan_progress = progress
        self.current_phase = phase
        self.scan_status = status
