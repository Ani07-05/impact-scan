#!/usr/bin/env python3
"""
Impact Scan - Ultra-Modern Hybrid TUI (2025 Edition)

A revolutionary terminal interface combining the best of both implementations:
- Modern web-inspired design with gradients and animations
- Reliable scan execution with immediate visual feedback
- Full AI provider support (OpenAI, Anthropic, Gemini)
- Enhanced progress tracking and real-time logging
- Professional card-based layout
- Command palette for power users

Built with Textual framework using cutting-edge design patterns.
"""

import asyncio
import logging
import os
import subprocess
import time
import webbrowser
from pathlib import Path
from typing import Optional, List, Dict, Any

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import Provider, Hit
from textual.containers import Container, Grid, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button, DataTable, DirectoryTree, Footer, Header, Input, Label,
    LoadingIndicator, Log, Markdown, ProgressBar, Rule,
    Select, Static, Switch, Collapsible
)

from rich.text import Text

from impact_scan.utils import schema, profiles
from impact_scan.core import entrypoint, aggregator, fix_ai
from impact_scan.core.html_report import save_report


# ============================================================================
# COMMAND PALETTE PROVIDER
# ============================================================================

class ModernCommandProvider(Provider):
    """Advanced command provider for rapid navigation."""

    async def search(self, query: str) -> list[Hit]:
        """Provide contextual commands based on query."""
        matcher = self.matcher(query)

        commands = [
            ("scan-start", "🚀 Start Security Scan", "Begin comprehensive security analysis"),
            ("browse-path", "📁 Browse Scan Path", "Select target directory"),
            ("api-keys", "🔑 Manage API Keys", "Configure AI providers (OpenAI, Claude, Gemini)"),
            ("export-html", "📄 Export HTML Report", "Generate detailed HTML report"),
            ("export-sarif", "📊 Export SARIF", "Export in SARIF format"),
            ("clear-log", "🧽 Clear Log", "Clear the log display"),
            ("help", "❓ Show Help", "Display help and shortcuts"),
            ("quit", "🚪 Exit", "Close Impact Scan"),
        ]

        hits = []
        for command_id, title, description in commands:
            if match := matcher.match(title + " " + description):
                hits.append(
                    Hit(
                        match.score,
                        matcher.highlight(title),
                        command_id,
                        help=matcher.highlight(description)
                    )
                )
        return hits

    async def action(self, hit: Hit) -> None:
        """Execute selected command."""
        app = self.app
        command_map = {
            "scan-start": app.action_start_scan,
            "browse-path": app.action_browse_path,
            "api-keys": app.action_manage_keys,
            "export-html": app.action_export_html,
            "export-sarif": app.action_export_sarif,
            "clear-log": app.action_clear_log,
            "help": app.action_help,
            "quit": app.action_quit,
        }

        if action := command_map.get(hit.command):
            action()


# ============================================================================
# MODAL SCREENS
# ============================================================================

class PathBrowserModal(ModalScreen):
    """Ultra-modern path browser with enhanced UX."""

    DEFAULT_CSS = """
    PathBrowserModal {
        align: center middle;
        background: $background 50%;
    }

    .browser-container {
        width: 85%;
        max-width: 120;
        height: 85%;
        max-height: 45;
        background: $surface;
        border: thick $accent;
        border-title-color: white;
        border-title-style: bold;
    }

    .browser-header {
        dock: top;
        height: 5;
        background: $primary;
        color: white;
        text-align: center;
        text-style: bold;
        padding: 1;
    }

    .current-path-display {
        height: 3;
        background: $surface-lighten-2;
        border: round $primary;
        padding: 0 1;
        margin: 1;
        color: $text;
        text-style: bold;
    }

    .browser-content {
        height: 1fr;
        padding: 1;
        background: $surface-lighten-1;
    }

    .path-tree {
        height: 1fr;
        border: round $primary-lighten-1;
        background: $surface;
    }

    .browser-actions {
        dock: bottom;
        height: 6;
        background: $surface-darken-1;
        padding: 1;
    }

    .action-button {
        min-width: 12;
        height: 3;
        margin: 0 1;
        text-style: bold;
    }

    .action-button:hover {
        text-style: bold italic;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
        Binding("enter", "select_path", "Select"),
    ]

    def __init__(self, current_path: Path = None) -> None:
        super().__init__()
        self.current_path = current_path or Path.cwd()
        self.selected_path = self.current_path

    def compose(self) -> ComposeResult:
        with Container(classes="browser-container"):
            with Container(classes="browser-header"):
                yield Static("📁 Select Scan Target Directory", id="browser-title")
                yield Static("Navigate and press Enter to select", classes="browser-subtitle")

            with Vertical(classes="browser-content"):
                yield Static(f"📂 Current: {self.current_path}",
                           classes="current-path-display", id="current-path-display")
                yield DirectoryTree(str(self.current_path), classes="path-tree", id="path-tree")

            with Horizontal(classes="browser-actions"):
                yield Button("✅ Select Path", variant="success", classes="action-button", id="select-path")
                yield Button("🏠 Home", variant="primary", classes="action-button", id="go-home")
                yield Button("❌ Cancel", variant="default", classes="action-button", id="cancel-path")

    @on(DirectoryTree.DirectorySelected)
    def on_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        """Handle directory selection."""
        self.selected_path = Path(event.path)
        self.query_one("#current-path-display").update(f"📂 Selected: {self.selected_path}")

    @on(Button.Pressed, "#select-path")
    def select_path(self) -> None:
        self.dismiss(str(self.selected_path))

    @on(Button.Pressed, "#go-home")
    def go_home(self) -> None:
        home_path = Path.home()
        tree = self.query_one("#path-tree", DirectoryTree)
        tree.path = str(home_path)
        tree.reload()
        self.selected_path = home_path
        self.query_one("#current-path-display").update(f"📂 Current: {home_path}")

    @on(Button.Pressed, "#cancel-path")
    def cancel_path(self) -> None:
        self.dismiss(None)

    def action_dismiss(self) -> None:
        self.dismiss(None)

    def action_select_path(self) -> None:
        self.dismiss(str(self.selected_path))


class APIKeysModal(ModalScreen):
    """Ultra-modern API key management with full Gemini support."""

    DEFAULT_CSS = """
    APIKeysModal {
        align: center middle;
        background: $background 50%;
    }

    .keys-container {
        width: 75%;
        max-width: 100;
        height: 80%;
        max-height: 40;
        background: $surface;
        border: thick $accent;
        border-title-color: white;
        border-title-style: bold;
    }

    .keys-header {
        dock: top;
        height: 6;
        background: $accent;
        color: white;
        text-align: center;
        text-style: bold;
        padding: 1;
    }

    .keys-content {
        height: 1fr;
        padding: 2;
        background: $surface-lighten-1;
    }

    .keys-actions {
        dock: bottom;
        height: 6;
        background: $surface-darken-1;
        padding: 1;
    }

    .key-section {
        height: auto;
        margin: 0 0 2 0;
        padding: 1;
        background: $surface-lighten-2;
        border: round $primary;
    }

    .key-row {
        height: 4;
        margin: 0 0 1 0;
        align: center middle;
    }

    .key-label {
        width: 20;
        text-align: right;
        margin-right: 1;
        color: $primary;
        text-style: bold;
    }

    .key-input {
        width: 1fr;
        margin-right: 1;
        background: $surface;
        border: solid $primary;
    }

    .key-input:focus {
        border: thick $accent;
    }

    .key-status {
        width: 15;
        text-align: center;
        text-style: bold;
        padding: 0 1;
        border: round $surface-darken-1;
    }

    .action-button {
        min-width: 15;
        height: 3;
        margin: 0 1;
        text-style: bold;
    }

    .action-button:hover {
        text-style: bold italic;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(classes="keys-container"):
            with Container(classes="keys-header"):
                yield Static("🔑 AI Provider Authentication", id="keys-title")
                yield Static("Configure API keys for AI-powered security analysis", classes="keys-subtitle")

            with ScrollableContainer(classes="keys-content"):
                # OpenAI Section
                with Container(classes="key-section"):
                    yield Label("🧠 OpenAI (GPT-4)", classes="section-label")
                    with Horizontal(classes="key-row"):
                        yield Label("🧠 OpenAI Key:", classes="key-label")
                        yield Input(
                            placeholder="sk-proj-...",
                            password=True,
                            classes="key-input",
                            value=os.getenv("OPENAI_API_KEY", ""),
                            id="openai-key"
                        )
                        yield Static(self._get_key_status("OPENAI_API_KEY"),
                                   classes="key-status", id="openai-status")

                # Anthropic Section
                with Container(classes="key-section"):
                    yield Label("🔮 Anthropic (Claude)", classes="section-label")
                    with Horizontal(classes="key-row"):
                        yield Label("🔮 Anthropic Key:", classes="key-label")
                        yield Input(
                            placeholder="sk-ant-...",
                            password=True,
                            classes="key-input",
                            value=os.getenv("ANTHROPIC_API_KEY", ""),
                            id="anthropic-key"
                        )
                        yield Static(self._get_key_status("ANTHROPIC_API_KEY"),
                                   classes="key-status", id="anthropic-status")

                # Gemini Section - PROMINENTLY DISPLAYED
                with Container(classes="key-section"):
                    yield Label("💎 Google Gemini (RECOMMENDED)", classes="section-label")
                    with Horizontal(classes="key-row"):
                        yield Label("💎 Gemini Key:", classes="key-label")
                        yield Input(
                            placeholder="AIza...",
                            password=True,
                            classes="key-input",
                            value=os.getenv("GOOGLE_API_KEY", ""),
                            id="gemini-key"
                        )
                        yield Static(self._get_key_status("GOOGLE_API_KEY"),
                                   classes="key-status", id="gemini-status")

                # Information Panel
                with Collapsible(title="ℹ️ API Key Setup Guide", collapsed=True):
                    yield Markdown("""
**Where to obtain API keys:**

• **OpenAI GPT-4**: [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
• **Anthropic Claude**: [console.anthropic.com](https://console.anthropic.com)
• **Google Gemini** ⭐: [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

**Gemini is RECOMMENDED** - Free tier, excellent performance!

**Security Notes:**
• Keys stored only as environment variables
• Never share your API keys
• All providers offer free tiers
                    """)

            with Horizontal(classes="keys-actions"):
                yield Button("💾 Save & Apply", variant="success",
                           classes="action-button", id="save-keys")
                yield Button("🧽 Clear All", variant="warning",
                           classes="action-button", id="clear-keys")
                yield Button("❌ Cancel", variant="default",
                           classes="action-button", id="cancel-keys")

    def _get_key_status(self, env_var: str) -> str:
        """Get visual status indicator for API key."""
        key = os.getenv(env_var)
        if key and len(key) > 10:
            return "[green]✅ Active[/green]"
        return "[red]❌ Missing[/red]"

    @on(Button.Pressed, "#save-keys")
    def save_keys(self) -> None:
        """Save API keys with validation."""
        keys = {
            "OPENAI_API_KEY": self.query_one("#openai-key", Input).value.strip(),
            "ANTHROPIC_API_KEY": self.query_one("#anthropic-key", Input).value.strip(),
            "GOOGLE_API_KEY": self.query_one("#gemini-key", Input).value.strip(),
        }

        saved_count = 0
        for env_var, key_value in keys.items():
            if key_value:
                os.environ[env_var] = key_value
                saved_count += 1

        # Update status indicators
        status_mapping = {
            "OPENAI_API_KEY": "#openai-status",
            "ANTHROPIC_API_KEY": "#anthropic-status",
            "GOOGLE_API_KEY": "#gemini-status"
        }

        for env_var, status_id in status_mapping.items():
            status = self._get_key_status(env_var)
            self.query_one(status_id).update(status)

        self.dismiss({"action": "saved", "count": saved_count})

    @on(Button.Pressed, "#clear-keys")
    def clear_keys(self) -> None:
        """Clear all API keys."""
        env_vars = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]
        for env_var in env_vars:
            if env_var in os.environ:
                del os.environ[env_var]

        self.query_one("#openai-key", Input).value = ""
        self.query_one("#anthropic-key", Input).value = ""
        self.query_one("#gemini-key", Input).value = ""

        self.query_one("#openai-status").update("[red]❌ Missing[/red]")
        self.query_one("#anthropic-status").update("[red]❌ Missing[/red]")
        self.query_one("#gemini-status").update("[red]❌ Missing[/red]")

        self.dismiss({"action": "cleared", "count": 3})

    @on(Button.Pressed, "#cancel-keys")
    def cancel(self) -> None:
        self.dismiss({"action": "cancelled"})


# ============================================================================
# MAIN TUI APPLICATION
# ============================================================================

class ModernHybridTUI(App):
    """Revolutionary modern hybrid TUI for Impact Scan."""

    CSS = """
    /* ========== MODERN THEME ========== */
    Screen {
        background: $background;
        color: $text;
    }

    Header {
        background: $primary;
        color: white;
        text-style: bold;
    }

    Footer {
        background: $surface-darken-1;
    }

    /* ========== LAYOUT ========== */
    .left-column {
        width: 45%;
        margin-right: 1;
    }

    .right-column {
        width: 55%;
    }

    /* ========== MODERN CARDS ========== */
    .modern-card {
        background: $surface;
        border: solid $primary;
        margin: 0 0 1 0;
        padding: 0;
    }

    .modern-card:hover {
        border: solid $accent;
        background: $surface-lighten-1;
    }

    .card-title {
        background: $primary;
        color: white;
        text-style: bold;
        padding: 1;
        text-align: center;
        border-bottom: solid $primary;
    }

    .card-content {
        padding: 1;
        background: $surface;
    }

    .section-label {
        text-style: bold;
        color: $accent;
        background: $surface-lighten-2;
        padding: 0 1;
        margin: 0 0 1 0;
        border: round $primary;
        text-align: center;
    }

    /* ========== CONFIGURATION PANEL ========== */
    .config-row {
        height: 3;
        margin: 0 0 1 0;
        align: left middle;
        padding: 0 1;
    }

    .config-label {
        width: 13;
        color: $accent;
        text-style: bold;
        text-align: right;
        margin-right: 1;
    }

    .config-input {
        width: 1fr;
        margin-right: 1;
        background: $surface;
        border: solid $primary;
        color: $text;
    }

    .config-input:focus {
        border: thick $accent;
    }

    .config-select {
        width: 1fr;
        margin-right: 1;
        background: $surface;
        border: solid $primary;
        color: $text;
    }

    .config-btn {
        min-width: 10;
        height: 3;
        margin: 0 1;
        text-style: bold;
        background: $primary;
        border: round $primary;
    }

    .config-btn:hover {
        background: $primary-lighten-1;
        text-style: bold italic;
    }

    .scan-btn {
        width: 1fr;
        height: 3;
        margin: 1 0 0 0;
        text-style: bold;
        background: $success;
        border: round $success;
        color: white;
    }

    .scan-btn:hover {
        background: $success-lighten-1;
        text-style: bold italic;
    }

    /* ========== METRICS GRID ========== */
    .metrics-grid {
        grid-size: 3 2;
        grid-gutter: 1;
        margin: 1;
        min-height: 12;
    }

    .metric-card {
        background: $surface-lighten-1;
        border: solid $primary;
        padding: 1;
        text-align: center;
        text-style: bold;
        height: 5;
    }

    .metric-card:hover {
        background: $surface-lighten-2;
    }

    .metric-total {
        border: solid $primary;
        color: $primary;
        background: $surface-lighten-2;
    }

    .metric-critical {
        border: solid $error;
        color: white;
        background: $error;
    }

    .metric-critical:hover {
        background: $error-lighten-1;
    }

    .metric-high {
        border: solid $warning;
        color: white;
        background: $warning;
    }

    .metric-high:hover {
        background: $warning-lighten-1;
    }

    .metric-medium {
        border: solid yellow;
        color: black;
        background: yellow;
    }

    .metric-medium:hover {
        background: $warning-lighten-2;
    }

    .metric-low {
        border: solid $primary;
        color: white;
        background: $primary;
    }

    .metric-low:hover {
        background: $primary-lighten-1;
    }

    .metric-score {
        border: solid $success;
        color: white;
        background: $success;
    }

    .metric-score:hover {
        background: $success-lighten-1;
    }

    /* ========== PROGRESS & STATUS ========== */
    .modern-progress {
        background: $surface;
        border: round $primary;
        margin: 1 0;
        height: 3;
    }

    .status-row {
        height: 3;
        align: center middle;
        background: $surface-lighten-1;
        border: round $accent;
        margin: 1 0;
        padding: 1;
    }

    .status-text {
        width: 1fr;
        text-align: center;
        color: $accent;
        text-style: bold;
    }

    .modern-spinner {
        width: 3;
        margin-left: 1;
    }

    /* ========== LOG DISPLAY ========== */
    .modern-log {
        background: $surface;
        border: solid $primary;
        height: 1fr;
        min-height: 15;
        padding: 1;
        margin: 1 0;
    }

    /* ========== FINDINGS TABLE ========== */
    .findings-table {
        background: $surface;
        border: solid $primary;
        margin: 1 0;
        min-height: 20;
    }

    /* ========== EXPORT BAR ========== */
    .export-bar {
        background: $surface-lighten-1;
        border: round $primary;
        height: 4;
        align: center middle;
        padding: 1;
        margin: 1 0 0 0;
    }

    .export-label {
        color: $accent;
        text-style: bold;
        margin-right: 1;
    }

    .export-btn {
        margin: 0 1;
        min-width: 10;
        text-style: bold;
    }

    .export-btn:hover {
        text-style: bold italic;
    }
    """

    TITLE = "🚀 Impact Scan - Modern Security Intelligence Platform"
    SUB_TITLE = "🔮 AI-Powered Security Analysis (OpenAI • Claude • Gemini)"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("s", "start_scan", "Start Scan"),
        Binding("b", "browse_path", "Browse"),
        Binding("k", "manage_keys", "API Keys"),
        Binding("h", "help", "Help"),
        Binding("c", "clear_log", "Clear Log"),
        Binding("ctrl+p", "command_palette", "Commands", show=False),
    ]

    COMMANDS = {ModernCommandProvider}

    scan_running = reactive(False)
    current_config: Optional[schema.ScanConfig] = None
    current_results: Optional[schema.ScanResult] = None

    def compose(self) -> ComposeResult:
        """Create the ultra-modern UI layout."""
        yield Header()

        with Horizontal():
            # Left column: Configuration + Progress
            with Vertical(classes="left-column"):
                # Configuration Card
                with Container(classes="modern-card"):
                    yield Label("⚙️ Advanced Scan Configuration", classes="card-title")
                    with Vertical(classes="card-content"):
                        with Container():
                            yield Label("🎯 Target Configuration", classes="section-label")
                            with Horizontal(classes="config-row"):
                                yield Label("📁 Scan Path:", classes="config-label")
                                yield Input(placeholder="Enter directory path...",
                                          classes="config-input", id="scan-path")
                                yield Button("📂", variant="primary", classes="config-btn", id="browse-btn")

                        with Container():
                            yield Label("🤖 AI & Profile Settings", classes="section-label")
                            with Horizontal(classes="config-row"):
                                yield Label("⚡ Profile:", classes="config-label")
                                yield Select(
                                    options=[
                                        ("🧠 Comprehensive", "comprehensive"),
                                        ("⚡ Quick Scan", "quick"),
                                        ("🔍 Standard", "standard"),
                                        ("🤖 CI/CD", "ci"),
                                    ],
                                    value="comprehensive",
                                    classes="config-select",
                                    id="profile-select"
                                )

                            with Horizontal(classes="config-row"):
                                yield Label("🤖 AI Provider:", classes="config-label")
                                yield Select(
                                    options=[
                                        ("✨ Auto-Detect", "auto"),
                                        ("🧠 OpenAI GPT-4", "openai"),
                                        ("🔮 Anthropic Claude", "anthropic"),
                                        ("💎 Google Gemini", "gemini"),
                                        ("❌ Disabled", "none"),
                                    ],
                                    value="auto",
                                    classes="config-select",
                                    id="ai-select"
                                )
                                yield Button("🔑", variant="default", classes="config-btn", id="keys-btn")

                        yield Button("🚀 Start Comprehensive Scan", variant="success",
                                   classes="scan-btn", id="start-scan-btn")

                # Progress Card
                with Container(classes="modern-card"):
                    yield Label("📈 Scan Progress & Activity Log", classes="card-title")
                    with Vertical(classes="card-content"):
                        yield ProgressBar(total=100, show_eta=True,
                                        classes="modern-progress", id="scan-progress")

                        with Horizontal(classes="status-row"):
                            yield Static("Ready to scan - Press 's' or click the button above",
                                       classes="status-text", id="status-text")
                            yield LoadingIndicator(classes="modern-spinner", id="loading-spinner")

                        yield Log(highlight=True, classes="modern-log",
                                id="scan-log", auto_scroll=True)

            # Right column: Metrics + Findings
            with Vertical(classes="right-column"):
                # Metrics Card
                with Container(classes="modern-card"):
                    yield Label("📊 Security Metrics", classes="card-title")
                    with Grid(classes="metrics-grid"):
                        yield Static("📊 Total\n0", id="total-metric", classes="metric-card metric-total")
                        yield Static("🔴 Critical\n0", id="critical-metric", classes="metric-card metric-critical")
                        yield Static("🟠 High\n0", id="high-metric", classes="metric-card metric-high")
                        yield Static("🟡 Medium\n0", id="medium-metric", classes="metric-card metric-medium")
                        yield Static("🔵 Low\n0", id="low-metric", classes="metric-card metric-low")
                        yield Static("🟢 Score\n100%", id="score-metric", classes="metric-card metric-score")

                # Findings Card
                with Container(classes="modern-card"):
                    yield Label("🔍 Security Findings", classes="card-title")
                    with Vertical(classes="card-content"):
                        table = DataTable(classes="findings-table", id="findings-table", zebra_stripes=True)
                        table.add_columns("🚨 Severity", "🔍 Type", "📁 File", "📍 Line", "📝 Description")
                        yield table

                        with Horizontal(classes="export-bar"):
                            yield Label("📤 Export:", classes="export-label")
                            yield Button("📄 HTML", variant="success", classes="export-btn", id="export-html")
                            yield Button("📊 SARIF", variant="primary", classes="export-btn", id="export-sarif")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize the application."""
        self.log_message("🚀 [STARTUP] Impact Scan initialized")
        self.log_message("🧠 [AI] Multi-agent security platform ready")
        self.log_message("💎 [INFO] Gemini, OpenAI, and Claude fully supported!")
        self.log_message("🎯 [READY] Configure scan and press 's' to start")

        # Set default path
        self.query_one("#scan-path", Input).value = str(Path.cwd())

        # Check API keys
        self.check_api_keys()

        # Hide loading spinner initially
        self.query_one("#loading-spinner", LoadingIndicator).display = False

    def check_api_keys(self) -> None:
        """Check and log API key status with prominent Gemini display."""
        api_keys = schema.APIKeys()
        providers = []

        if api_keys.openai:
            providers.append("🧠 OpenAI")
        if api_keys.anthropic:
            providers.append("🔮 Anthropic")
        if api_keys.gemini:
            providers.append("💎 Gemini")

        if providers:
            self.log_message(f"✅ [AI] Detected providers: {', '.join(providers)}")
            if api_keys.gemini:
                self.log_message("💎 [GEMINI] Google Gemini is active and ready!")
        else:
            self.log_message("⚠️ [AI] No API keys found - Press 'k' to configure")
            self.log_message("💡 [TIP] Gemini offers excellent free tier!")

    def log_message(self, message: str) -> None:
        """Add timestamped message to scan log."""
        log_widget = self.query_one("#scan-log", Log)
        timestamp = time.strftime("%H:%M:%S")
        log_widget.write(f"[{timestamp}] {message}")

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle all button presses with immediate feedback."""
        button_id = event.button.id

        # IMMEDIATE visual feedback - button was clicked!
        if button_id == "start-scan-btn":
            self.log_message("⏳ [CLICK] Scan button pressed - initializing...")

        handlers = {
            "start-scan-btn": self.action_start_scan,
            "browse-btn": self.action_browse_path,
            "keys-btn": self.action_manage_keys,
            "export-html": self.action_export_html,
            "export-sarif": self.action_export_sarif,
        }

        handler = handlers.get(button_id)
        if handler:
            handler()

    def action_start_scan(self) -> None:
        """Start scan with IMMEDIATE visual feedback."""
        if self.scan_running:
            self.log_message("⚠️ [SCAN] Already running!")
            return

        # IMMEDIATE feedback #1: Show loading spinner
        loading_spinner = self.query_one("#loading-spinner", LoadingIndicator)
        loading_spinner.display = True

        # IMMEDIATE feedback #2: Update status
        status_text = self.query_one("#status-text", Static)
        status_text.update("⏳ Initializing scan...")

        # IMMEDIATE feedback #3: Log message
        self.log_message("🚀 [SCAN] Starting scan initialization...")

        # Get configuration
        path_input = self.query_one("#scan-path", Input)
        if not path_input.value.strip():
            self.log_message("❌ [ERROR] Please specify a target path")
            loading_spinner.display = False
            status_text.update("❌ Error: No path specified")
            return

        target_path = Path(path_input.value.strip())
        if not target_path.exists():
            self.log_message(f"❌ [ERROR] Path does not exist: {target_path}")
            loading_spinner.display = False
            status_text.update("❌ Error: Invalid path")
            return

        # Get profile and AI settings
        profile_select = self.query_one("#profile-select", Select)
        ai_select = self.query_one("#ai-select", Select)

        # Load profile configuration
        try:
            profile = profiles.get_profile(profile_select.value)

            # Override AI provider if specified
            ai_provider = ai_select.value
            if ai_provider == "none":
                profile.enable_ai_fixes = False
                profile.ai_provider = None
            elif ai_provider != "auto":
                profile.ai_provider = ai_provider

            # Create configuration
            config = profiles.create_config_from_profile(
                root_path=target_path,
                profile=profile,
                api_keys=schema.APIKeys()
            )

            self.current_config = config
            self.log_message(f"✅ [CONFIG] Configuration loaded successfully")

            # Launch worker
            self.run_scan_worker(config)

        except Exception as e:
            self.log_message(f"❌ [ERROR] Configuration failed: {e}")
            logging.error(f"Scan configuration failed: {e}", exc_info=True)
            loading_spinner.display = False
            status_text.update("❌ Configuration error")

    def action_browse_path(self) -> None:
        """Browse for target directory."""
        current_path = Path(self.query_one("#scan-path", Input).value or Path.cwd())

        def on_path_selected(path: Optional[str]) -> None:
            if path:
                self.query_one("#scan-path", Input).value = path
                self.log_message(f"📁 [PATH] Selected: {path}")

        self.push_screen(PathBrowserModal(current_path), on_path_selected)

    def action_manage_keys(self) -> None:
        """Manage API keys."""
        def on_keys_updated(result: Optional[dict]) -> None:
            if result and result.get("action") == "saved":
                count = result.get("count", 0)
                self.log_message(f"✅ [AI] Saved {count} API key(s)")
                self.check_api_keys()
            elif result and result.get("action") == "cleared":
                self.log_message("🧽 [AI] API keys cleared")
            else:
                self.log_message("❌ [AI] Key update cancelled")

        self.push_screen(APIKeysModal(), on_keys_updated)

    def action_export_html(self) -> None:
        """Export HTML report."""
        if not self.current_results:
            self.log_message("⚠️ [EXPORT] No scan results available")
            return

        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_report_{timestamp}.html"

            self.log_message(f"📄 [EXPORT] Generating HTML report...")
            save_report(self.current_results, str(output_file))
            self.log_message(f"✅ [SUCCESS] Report saved: {output_file.name}")

            # Open in browser
            webbrowser.open(f"file://{output_file.absolute()}")
            self.log_message("🌐 [BROWSER] Opening report...")

        except Exception as e:
            self.log_message(f"❌ [ERROR] Export failed: {e}")
            logging.exception("HTML export failed")

    def action_export_sarif(self) -> None:
        """Export SARIF report."""
        if not self.current_results:
            self.log_message("⚠️ [EXPORT] No scan results available")
            return

        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_sarif_{timestamp}.json"

            self.log_message(f"📊 [EXPORT] Generating SARIF report...")

            # Save directly using aggregator
            aggregator.save_to_sarif(self.current_results, output_file)

            self.log_message(f"✅ [SUCCESS] SARIF saved: {output_file.name}")

        except Exception as e:
            self.log_message(f"❌ [ERROR] SARIF export failed: {e}")
            logging.exception("SARIF export failed")

    def action_clear_log(self) -> None:
        """Clear the log display."""
        log_widget = self.query_one("#scan-log", Log)
        log_widget.clear()
        self.log_message("🧽 [CLEAR] Log cleared")

    def action_help(self) -> None:
        """Show help information."""
        help_text = """
[bold cyan]🚀 Impact Scan - AI Security Platform[/bold cyan]

[bold]Keyboard Shortcuts:[/bold]
• [yellow]s[/yellow] - Start comprehensive scan
• [yellow]b[/yellow] - Browse for directory
• [yellow]k[/yellow] - Configure API keys (OpenAI, Claude, [bold]Gemini[/bold])
• [yellow]c[/yellow] - Clear log
• [yellow]h[/yellow] - Show this help
• [yellow]q[/yellow] - Quit

[bold]AI Providers:[/bold]
• 💎 [bold green]Google Gemini[/bold green] - Recommended, excellent free tier
• 🧠 OpenAI GPT-4 - Advanced analysis
• 🔮 Anthropic Claude - Context-aware scanning

[bold]Features:[/bold]
• Real-time vulnerability detection
• AI-powered fix suggestions
• Professional HTML/SARIF reports
• Multiple scan profiles
        """
        self.log_message(help_text.strip())

    @work(exclusive=True, thread=True)
    def run_scan_worker(self, config: schema.ScanConfig) -> None:
        """Run security scan in background with real-time updates."""
        try:
            self.scan_running = True
            progress_bar = self.query_one("#scan-progress", ProgressBar)
            status_text = self.query_one("#status-text", Static)
            loading_spinner = self.query_one("#loading-spinner", LoadingIndicator)

            loading_spinner.display = True
            progress_bar.update(total=100, progress=0)

            self.log_message(f"🎯 [TARGET] {config.target_path}")
            self.log_message(f"⚡ [PROFILE] {config.profile}")
            self.log_message(f"🤖 [AI] Provider: {config.ai_provider or 'disabled'}")

            # Phase 1: Entry point detection
            status_text.update("🔍 Analyzing codebase...")
            progress_bar.update(progress=10)
            self.log_message("   🔍 [cyan]Scanning for entry points...[/cyan]")

            # Run main scan
            scan_result = entrypoint.run_scan(config)

            progress_bar.update(progress=40)
            status_text.update("✅ Static analysis complete")

            if scan_result.entry_points:
                self.log_message(f"✅ [ENTRY] Found {len(scan_result.entry_points)} entry points")

            progress_bar.update(progress=60)

            # Web search (if enabled)
            if config.enable_web_search and scan_result.findings:
                status_text.update("🌐 Web intelligence...")
                progress_bar.update(progress=70)
                self.log_message("   🌐 [cyan]Gathering web intelligence...[/cyan]")

                try:
                    from impact_scan.core import web_search
                    web_search.process_findings_for_web_fixes(scan_result.findings, config)
                    self.log_message("✅ [WEB] Intelligence gathered")
                except Exception as e:
                    self.log_message(f"⚠️ [WEB] Enhancement failed: {e}")

                progress_bar.update(progress=80)

            # AI fixes (if enabled)
            if config.enable_ai_fixes and config.ai_provider and scan_result.findings:
                status_text.update("🧠 Generating AI fixes...")
                progress_bar.update(progress=85)
                self.log_message(f"   🧠 [cyan]Generating fixes with {config.ai_provider}...[/cyan]")

                try:
                    fix_ai.generate_fixes(scan_result.findings, config)
                    self.log_message("✅ [AI] Fix generation complete")
                except Exception as e:
                    self.log_message(f"⚠️ [AI] Fix generation failed: {e}")

                progress_bar.update(progress=95)

            # Complete
            progress_bar.update(progress=100)
            status_text.update("🎉 Scan completed!")
            loading_spinner.display = False

            # Store and display results
            self.current_results = scan_result
            self.update_results_display(scan_result)

            # Summary
            total = len(scan_result.findings)
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in scan_result.findings:
                severity_counts[finding.severity.value.lower()] += 1

            self.log_message(f"\n🎯 [SUMMARY] Scan completed!")
            self.log_message(f"📊 [RESULTS] {total} findings:")
            self.log_message(f"   🔴 Critical: {severity_counts['critical']}")
            self.log_message(f"   🟠 High: {severity_counts['high']}")
            self.log_message(f"   🟡 Medium: {severity_counts['medium']}")
            self.log_message(f"   🔵 Low: {severity_counts['low']}")
            self.log_message(f"\n💡 [TIP] Use export buttons to save results!")

        except Exception as e:
            self.log_message(f"❌ [ERROR] Scan failed: {e}")
            logging.exception("Scan execution failed")
            status_text.update("❌ Scan failed")
            loading_spinner.display = False
        finally:
            self.scan_running = False

    def update_results_display(self, scan_result: schema.ScanResult) -> None:
        """Update UI with scan results."""
        # Calculate metrics
        total = len(scan_result.findings)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in scan_result.findings:
            severity_counts[finding.severity.value.lower()] += 1

        # Update metric cards
        self.query_one("#total-metric", Static).update(f"📊 Total\n{total}")
        self.query_one("#critical-metric", Static).update(f"🔴 Critical\n{severity_counts['critical']}")
        self.query_one("#high-metric", Static).update(f"🟠 High\n{severity_counts['high']}")
        self.query_one("#medium-metric", Static).update(f"🟡 Medium\n{severity_counts['medium']}")
        self.query_one("#low-metric", Static).update(f"🔵 Low\n{severity_counts['low']}")

        # Calculate security score
        if total > 0:
            score = max(0, 100 - (
                severity_counts['critical'] * 25 +
                severity_counts['high'] * 10 +
                severity_counts['medium'] * 5 +
                severity_counts['low'] * 1
            ))
            score_icon = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
            self.query_one("#score-metric", Static).update(f"{score_icon} Score\n{score}%")
        else:
            self.query_one("#score-metric", Static).update("🟢 Score\n100%")

        # Update findings table
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        # Add findings (limit to 100 for performance)
        for finding in scan_result.findings[:100]:
            severity_map = {
                "critical": "🔴 CRIT",
                "high": "🟠 HIGH",
                "medium": "🟡 MED",
                "low": "🔵 LOW"
            }
            severity_display = severity_map.get(finding.severity.value.lower(), "⚪ UNK")

            file_path_str = str(finding.file_path)
            short_path = f"...{file_path_str[-25:]}" if len(file_path_str) > 28 else file_path_str

            description = finding.description or finding.title or "No description"
            short_desc = description[:50] + "..." if len(description) > 50 else description

            table.add_row(
                severity_display,
                finding.vuln_id or finding.rule_id or "N/A",
                short_path,
                str(finding.line_number) if finding.line_number else "N/A",
                short_desc
            )

        if len(scan_result.findings) > 100:
            table.add_row("...", "...", "...", "...",
                         f"+ {len(scan_result.findings) - 100} more findings")

        # Force refresh
        table.refresh()
        self.refresh()


def run_modern_hybrid_tui() -> None:
    """Launch the modern hybrid TUI."""
    logging.basicConfig(
        level="INFO",
        handlers=[logging.FileHandler("tui_debug.log", mode="w")],
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    app = ModernHybridTUI()
    app.run()


if __name__ == "__main__":
    run_modern_hybrid_tui()
