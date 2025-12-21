"""
Configuration Panel Widget
Extracted configuration section from the main TUI.
Vibrant cyberpunk styling.
"""

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, Checkbox, Label, Select, Static

# Vibrant color palette
COLORS = {
    "pink": "#FF6EC7",
    "cyan": "#00D4FF",
    "purple": "#BD93F9",
    "green": "#50FA7B",
    "muted": "#7D8590",
}


class ConfigPanel(Container):
    """Configuration panel widget."""

    # Store scan path internally
    _scan_path: str = ""

    DEFAULT_CSS = """
    ConfigPanel {
        height: auto;
        min-height: 25;
        background: #161B22;
        padding: 1;
        border: round #30363D;
        margin: 0 0 1 0;
    }

    ConfigPanel .config-row {
        height: 3;
        margin: 0 0 1 0;
    }

    ConfigPanel .config-label {
        width: 10;
        color: #8B949E;
        text-align: right;
        margin-right: 1;
        content-align: right middle;
        text-style: bold;
    }

    ConfigPanel .config-input {
        width: 1fr;
        background: #0D1117;
        border: round #30363D;
        color: #E6EDF3;
        padding: 0 1;
    }

    ConfigPanel .config-input:focus {
        border: round #1F6FEB;
    }

    ConfigPanel .config-select {
        width: 1fr;
        background: #0D1117;
        border: round #30363D;
        padding: 0 1;
    }

    ConfigPanel .config-select:focus {
        border: round #1F6FEB;
    }

    ConfigPanel .mini-btn {
        width: 5;
        height: 3;
        margin-left: 1;
        min-width: 5;
        background: #21262D;
        color: #FFA657;
        border: round #373E47;
        text-style: bold;
    }

    ConfigPanel .mini-btn:hover {
        background: #30363D;
        color: #FFA657;
        border: round #FFA657;
    }

    ConfigPanel .mini-btn:focus {
        background: #21262D;
        color: #FFA657;
        border: round #FFA657;
    }

    ConfigPanel .browse-button {
        width: 100%;
        height: 3;
        margin: 0 0 1 0;
        background: #1F6FEB;
        color: white;
        text-style: bold;
        border: round #388BFD;
    }

    ConfigPanel .browse-button:hover {
        background: #388BFD;
        border: round #58A6FF;
    }

    ConfigPanel .browse-button:focus {
        background: #1F6FEB;
        border: round #58A6FF;
    }

    ConfigPanel .ai-row {
        height: auto;
        margin: 0 0 1 0;
        padding: 0 1;
    }

    ConfigPanel Checkbox {
        background: transparent;
        padding: 0;
        width: 100%;
    }

    ConfigPanel .scan-button {
        width: 100%;
        height: 3;
        margin: 1 0 0 0;
        text-style: bold;
        background: #238636;
        color: white;
        border: round #2EA043;
    }

    ConfigPanel .scan-button:hover {
        background: #2EA043;
        border: round #3FB950;
    }

    ConfigPanel .scan-button:focus {
        background: #238636;
        border: round #3FB950;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the config panel."""
        # Browse button only - no text input
        yield Button(
            "Select Folder to Scan",
            variant="primary",
            id="browse-btn",
            classes="browse-button",
        )

        with Horizontal(classes="config-row"):
            yield Label("Profile:", classes="config-label")
            yield Select(
                options=[
                    ("Comprehensive", "comprehensive"),
                    ("Standard", "standard"),
                    ("Quick", "quick"),
                    ("CI/CD", "ci"),
                ],
                value="comprehensive",
                id="profile-select",
                classes="config-select",
            )

        with Horizontal(classes="config-row"):
            yield Label("AI:", classes="config-label")
            yield Select(
                options=[
                    ("Groq", "groq"),
                    ("Gemini", "gemini"),
                    ("OpenAI", "openai"),
                    ("Anthropic", "anthropic"),
                    ("None", "none"),
                ],
                value="groq",
                id="ai-select",
                classes="config-select",
            )
            yield Button(
                "🔑",
                variant="default",
                id="keys-btn",
                classes="mini-btn",
            )

        with Horizontal(classes="ai-row"):
            yield Checkbox("AI Validation (reduce false positives)", id="ai-validation-check", value=True)

        yield Button(
            "▶ Start Scan",
            variant="success",
            id="start-scan-btn",
            classes="scan-button",
        )

    def on_mount(self) -> None:
        """Initialize configuration panel."""
        self._scan_path = str(Path.cwd())

    def get_scan_path(self) -> str:
        """Get the scan path value."""
        return self._scan_path

    def get_path(self) -> str:
        """Get the scan path value (alias for get_scan_path)."""
        return self._scan_path

    def set_scan_path(self, path: str) -> None:
        """Set the scan path value."""
        self._scan_path = path
        # Update browse button text
        try:
            btn = self.query_one("#browse-btn", Button)
            name = Path(path).name or path
            btn.label = f"{name}"
        except Exception:
            pass

    def get_profile(self) -> str:
        """Get the selected profile."""
        return self.query_one("#profile-select", Select).value

    def get_ai_provider(self) -> str:
        """Get the selected AI provider."""
        return self.query_one("#ai-select", Select).value

    def get_ai_validation(self) -> bool:
        """Get the AI validation setting."""
        return self.query_one("#ai-validation-check", Checkbox).value
