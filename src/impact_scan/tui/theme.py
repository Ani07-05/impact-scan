"""
Impact-Scan TUI Theme - Professional Dark Theme
No emojis, clean design inspired by modern dev tools.
"""

# Impact-Scan Dark Theme Colors
IMPACT_DARK_THEME = {
    "primary": "#00A8E8",  # Bright blue
    "secondary": "#6C757D",  # Gray
    "accent": "#00D9FF",  # Cyan
    "error": "#FF4757",  # Red
    "warning": "#FFA502",  # Orange
    "success": "#2ED573",  # Green
    "background": "#1E1E2E",  # Dark slate
    "surface": "#2A2A3E",  # Card background
    "foreground": "#E0E0E0",  # Text color
}

# Severity color mapping (for text styling, no emojis!)
SEVERITY_COLORS = {
    "critical": "red",
    "high": "yellow",
    "medium": "blue",
    "low": "cyan",
}

# Main CSS for the application
MAIN_CSS = """
/* Clean, professional theme with enhanced visuals */
Screen {
    background: $background;
    color: $text;
}

Header {
    background: $primary;
    color: white;
    text-style: bold;
    dock: top;
    height: 3;
    content-align: center middle;
}

Footer {
    background: $surface;
    color: $text-muted;
    dock: bottom;
    height: 1;
}

/* Layout */
.layout {
    height: 1fr;
}

.left-panel {
    width: 45;
    border-right: wide $primary;
    background: $surface;
    padding: 1;
}

.right-panel {
    width: 1fr;
    background: $background;
    padding: 1;
}

/* Configuration Panel */
.config-panel {
    height: auto;
    padding: 2;
    border: round $primary;
    background: $surface-lighten-1;
    margin: 0 0 1 0;
}

.panel-header {
    text-style: bold;
    color: $primary;
    margin: 0 0 1 0;
    text-align: center;
}

.config-section {
    margin: 0 0 2 0;
}

.config-row {
    height: 3;
    margin: 0 0 1 0;
}

.config-label {
    width: 14;
    color: $accent;
    text-align: right;
    margin-right: 2;
    text-style: bold;
}

.config-input {
    width: 1fr;
    border: tall $primary;
}

.config-select {
    width: 1fr;
    border: tall $primary;
}

.mini-btn {
    width: 4;
    margin-left: 1;
    min-width: 4;
}

.scan-button {
    width: 1fr;
    height: 3;
    margin: 2 0 0 0;
    text-style: bold;
}

/* Progress Panel */
.progress-panel {
    height: 1fr;
    padding: 2;
    border: round $primary;
    background: $surface-lighten-1;
}

.progress-bar-container {
    height: 3;
    margin: 0 0 2 0;
}

.status-line {
    height: 3;
    margin: 0 0 1 0;
    text-align: center;
    color: $accent;
    text-style: bold;
}

.activity-log {
    height: 1fr;
    border: round $primary;
    background: $background;
    padding: 1;
    scrollbar-size: 1 1;
}

/* Metrics Panel */
.metrics-panel {
    height: 16;
    padding: 2;
    border: round $primary;
    background: $surface-lighten-1;
    margin: 0 0 1 0;
}

.metrics-grid {
    grid-size: 3 2;
    grid-gutter: 2;
    height: 1fr;
    margin: 1 0 0 0;
}

.metric {
    border: heavy $primary;
    padding: 1;
    text-align: center;
    background: $background;
    height: 5;
}

.metric-value {
    text-style: bold;
    color: $text;
    content-align: center middle;
}

.metric-label {
    color: $text-muted;
    text-style: italic;
}

/* Severity colors with glow effect */
.metric-critical {
    border: heavy $error;
    background: $error 10%;
}

.metric-critical .metric-value {
    color: $error;
    text-style: bold;
}

.metric-high {
    border: heavy $warning;
    background: $warning 10%;
}

.metric-high .metric-value {
    color: $warning;
    text-style: bold;
}

.metric-medium {
    border: heavy yellow;
    background: yellow 10%;
}

.metric-medium .metric-value {
    color: yellow;
    text-style: bold;
}

.metric-low {
    border: heavy cyan;
    background: cyan 10%;
}

.metric-low .metric-value {
    color: cyan;
    text-style: bold;
}

/* Findings Panel */
.findings-panel {
    height: 1fr;
    padding: 2;
    border: round $primary;
    background: $surface-lighten-1;
}

.findings-table {
    height: 1fr;
    border: round $primary;
    background: $background;
    scrollbar-size: 1 1;
}

.export-bar {
    height: 4;
    margin: 1 0 0 0;
    align: center middle;
}

.export-btn {
    margin: 0 2 0 0;
    min-width: 16;
    text-style: bold;
}
"""

# Modal screen CSS patterns
MODAL_CSS = """
/* Path Browser Modal */
PathBrowserModal {
    align: center middle;
    background: $background 50%;
}

.browser-container {
    width: 100;
    height: 40;
    background: $surface;
    border: solid $primary;
}

.browser-header {
    dock: top;
    height: 3;
    background: $surface-lighten-1;
    color: $text;
    padding: 1;
    border-bottom: solid $primary;
}

.browser-shortcuts {
    dock: top;
    height: 5;
    background: $surface;
    padding: 1;
    border-bottom: solid $primary-darken-1;
    align: center middle;
}

.shortcut-btn {
    min-width: 12;
    max-width: 20;
    height: 3;
    margin: 0 1 0 0;
    background: $surface-lighten-1;
    color: $text;
    border: solid $primary-darken-1;
    content-align: center middle;
}

.shortcut-btn:hover {
    background: $primary-darken-1;
    color: white;
}

.browser-content {
    height: 1fr;
    padding: 1;
}

.path-tree {
    height: 1fr;
    border: solid $primary-darken-1;
}

.browser-actions {
    dock: bottom;
    height: 5;
    background: $surface;
    padding: 1;
    border-top: solid $primary;
    align: center middle;
}

.action-btn {
    min-width: 16;
    height: 3;
    margin: 0 1;
    content-align: center middle;
    text-align: center;
}

/* API Keys Modal */
APIKeysModal {
    align: center middle;
    background: $background 50%;
}

.keys-container {
    width: 90;
    height: 35;
    background: $surface;
    border: solid $primary;
}

.keys-header {
    dock: top;
    height: 3;
    background: $surface-lighten-1;
    color: $text;
    padding: 1;
    border-bottom: solid $primary;
    text-align: center;
    text-style: bold;
}

.keys-content {
    height: 1fr;
    padding: 2;
    overflow-y: auto;
}

.keys-actions {
    dock: bottom;
    height: 5;
    background: $surface;
    padding: 1;
    border-top: solid $primary;
    align: center middle;
}

.keys-actions .action-btn {
    min-width: 16;
    height: 3;
    margin: 0 1;
    content-align: center middle;
    text-align: center;
}

.key-row {
    height: 4;
    margin: 0 0 1 0;
    align: left middle;
}

.key-label {
    width: 15;
    text-align: right;
    margin-right: 2;
    color: $text-muted;
    content-align: right middle;
}

.key-input {
    width: 1fr;
    margin-right: 2;
    height: 3;
}

.key-status {
    width: 12;
    text-align: center;
    content-align: center middle;
}
"""


def get_severity_color(severity: str) -> str:
    """
    Get color for severity level.

    Args:
        severity: Severity level (critical, high, medium, low)

    Returns:
        Color name for Rich styling
    """
    return SEVERITY_COLORS.get(severity.lower(), "white")


def format_severity(severity: str) -> str:
    """
    Format severity with color (no emojis!).

    Args:
        severity: Severity level

    Returns:
        Formatted string with Rich markup
    """
    color = get_severity_color(severity)
    return f"[{color}]{severity.upper()}[/{color}]"
