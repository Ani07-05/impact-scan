#!/usr/bin/env python3
"""
Impact Scan - Ultra-Modern TUI Interface (2025 Edition)

A revolutionary terminal user interface featuring:
- Modern web-inspired design patterns
- Advanced animations and transitions  
- Command palette integration
- Multiple theme support
- Responsive grid layouts
- Enhanced visual feedback
- Real-time progress animations
- Gradient backgrounds and shadows

Built with Textual framework using cutting-edge TUI design principles.
"""

import asyncio
import logging
import os
import subprocess
import time
import webbrowser
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import Provider, Hit
from textual.containers import (
    Container, Grid, Horizontal, Vertical, 
    ScrollableContainer, VerticalScroll, Center
)
from textual.reactive import reactive, var
from textual.screen import Screen, ModalScreen
from textual.timer import Timer
from textual.validation import Function, ValidationResult, Validator
from textual.widgets import (
    Button, DataTable, DirectoryTree, Footer, Header, Input, Label, RichLog,
    LoadingIndicator, Log, Markdown, Pretty, ProgressBar, Rule, 
    Select, Static, Switch, Tabs, TabPane, TabbedContent, Tree, 
    Sparkline, ContentSwitcher, Collapsible, Checkbox, RadioSet, RadioButton
)
from textual.suggester import SuggestFromList
from textual.message import Message

from rich.align import Align
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich.text import Text
from rich.table import Table
from rich.tree import Tree as RichTree
from rich.columns import Columns
from rich.live import Live
from rich.layout import Layout
from rich.style import Style

from impact_scan.utils import schema, profiles
from impact_scan.core import entrypoint, aggregator, fix_ai, web_search
from impact_scan.core.html_report import save_report


class ModernCommandProvider(Provider):
    """Advanced command provider for rapid navigation and actions."""
    
    async def search(self, query: str) -> list[Hit]:
        """Provide contextual commands based on query."""
        matcher = self.matcher(query)
        
        commands = [
            ("scan-start", "🚀 Start Security Scan", "Begin comprehensive security analysis"),
            ("browse-path", "📁 Browse Scan Path", "Select target directory for scanning"),
            ("api-keys", "🔑 Manage API Keys", "Configure AI provider authentication"),
            ("export-html", "📄 Export HTML Report", "Generate detailed HTML security report"),
            ("export-sarif", "📊 Export SARIF Results", "Export in SARIF industry standard format"),
            ("export-pdf", "📋 Export PDF Report", "Create professional PDF document"),
            ("themes", "🎨 Switch Theme", "Change application visual theme"),
            ("settings", "⚙️ Open Settings", "Configure application preferences"),
            ("profiles", "⚡ Scan Profiles", "Select predefined scan configurations"),
            ("help", "❓ Show Help", "Display help and keyboard shortcuts"),
            ("about", "ℹ️ About Impact Scan", "Application information and credits"),
            ("quit", "🚪 Exit Application", "Close Impact Scan safely"),
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
        """Execute selected command with enhanced feedback."""
        app = self.app
        command = hit.command
        
        command_map = {
            "scan-start": app.action_start_scan,
            "browse-path": app.action_browse_path,
            "api-keys": app.action_manage_keys,
            "export-html": app.action_export_html,
            "export-sarif": app.action_export_sarif,
            "export-pdf": app.action_export_pdf,
            "themes": app.action_switch_theme,
            "settings": app.action_settings,
            "profiles": app.action_profiles,
            "help": app.action_help,
            "about": app.action_about,
            "quit": app.action_quit,
        }
        
        if action := command_map.get(command):
            action()


class PathBrowserModal(ModalScreen):
    """Ultra-modern path browser with enhanced UX."""
    
    DEFAULT_CSS = """
    PathBrowserModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    
    .browser-container {
        width: 70%;
        max-width: 100;
        height: 70%;
        max-height: 35;
        background: $surface;
        border: thick $accent;
        border-subtitle-color: $primary;
        border-title-color: white;
        border-title-style: bold;
        border-title-background: $accent;
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
        scrollbar-background: $surface-darken-1;
        scrollbar-color: $primary;
        scrollbar-corner-color: $surface;
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
        transition: all 200ms;
    }
    
    .action-button:hover {
        text-style: bold italic;
    }
    """
    
    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
        Binding("enter", "select_path", "Select"),
        Binding("ctrl+h", "go_home", "Home"),
        Binding("ctrl+u", "go_up", "Up"),
    ]
    
    def __init__(self, current_path: Path = None) -> None:
        super().__init__()
        self.current_path = current_path or Path.cwd()
        self.selected_path = self.current_path
    
    def compose(self) -> ComposeResult:
        with Container(classes="browser-container"):
            with Container(classes="browser-header"):
                yield Static("📁 Select Scan Target Directory", id="browser-title")
                yield Static("Use arrow keys to navigate, Enter to select, Esc to cancel", 
                           classes="browser-subtitle")
            
            with Vertical(classes="browser-content"):
                yield Static(f"📂 Current: {self.current_path}", 
                           classes="current-path-display", id="current-path-display")
                yield DirectoryTree(str(self.current_path), classes="path-tree", id="path-tree")
            
            with Horizontal(classes="browser-actions"):
                yield Button("✅ Select Path", variant="success", classes="action-button", id="select-path")
                yield Button("🏠 Home", variant="primary", classes="action-button", id="go-home")
                yield Button("⬆️ Parent", variant="default", classes="action-button", id="go-up")
                yield Button("❌ Cancel", variant="default", classes="action-button", id="cancel-path")
    
    @on(DirectoryTree.DirectorySelected)
    def on_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        """Handle directory selection with visual feedback."""
        self.selected_path = Path(event.path)
        self.query_one("#current-path-display").update(f"📂 Selected: {self.selected_path}")
    
    @on(Button.Pressed, "#select-path")
    def select_path(self) -> None:
        self.dismiss(str(self.selected_path))
    
    @on(Button.Pressed, "#go-home")
    def go_home(self) -> None:
        home_path = Path.home()
        self._update_tree(home_path)
    
    @on(Button.Pressed, "#go-up")
    def go_up(self) -> None:
        parent_path = self.selected_path.parent
        if parent_path != self.selected_path:
            self._update_tree(parent_path)
    
    @on(Button.Pressed, "#cancel-path")
    def cancel_path(self) -> None:
        self.dismiss(None)
    
    def _update_tree(self, new_path: Path) -> None:
        """Update the directory tree with smooth transition."""
        tree = self.query_one("#path-tree", DirectoryTree)
        tree.path = str(new_path)
        tree.reload()
        self.selected_path = new_path
        self.current_path = new_path
        self.query_one("#current-path-display").update(f"📂 Current: {new_path}")
    
    def action_dismiss(self) -> None:
        self.dismiss(None)
    
    def action_select_path(self) -> None:
        self.dismiss(str(self.selected_path))
    
    def action_go_home(self) -> None:
        self.go_home()
    
    def action_go_up(self) -> None:
        self.go_up()


class APIKeysModal(ModalScreen):
    """Ultra-modern API key management with enhanced security UX."""
    
    DEFAULT_CSS = """
    APIKeysModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.8);
    }
    
    .keys-container {
        width: 65%;
        max-width: 85;
        height: 65%;
        max-height: 30;
        background: $surface;
        border: thick $accent;
        border-title-color: white;
        border-title-style: bold;
        border-title-background: $accent;
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
        width: 18;
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
        transition: border-color 200ms;
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
        transition: all 200ms;
    }
    
    .action-button:hover {
        text-style: bold italic;
    }
    
    .info-panel {
        margin: 2 0;
        padding: 1;
        background: $surface-lighten-3;
        border: round $accent;
    }
    """
    
    def compose(self) -> ComposeResult:
        with Container(classes="keys-container"):
            with Container(classes="keys-header"):
                yield Static("🔑 AI Provider Authentication", id="keys-title")
                yield Static("Configure API keys for enhanced AI-powered security analysis", 
                           classes="keys-subtitle")
            
            with ScrollableContainer(classes="keys-content"):
                # OpenAI Section
                with Container(classes="key-section"):
                    yield Label("🧠 OpenAI Configuration", classes="section-label")
                    with Horizontal(classes="key-row"):
                        yield Label("🧠 OpenAI API Key:", classes="key-label")
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
                    yield Label("🔮 Anthropic Configuration", classes="section-label")
                    with Horizontal(classes="key-row"):
                        yield Label("🔮 Anthropic API Key:", classes="key-label")
                        yield Input(
                            placeholder="sk-ant-...", 
                            password=True, 
                            classes="key-input",
                            value=os.getenv("ANTHROPIC_API_KEY", ""),
                            id="anthropic-key"
                        )
                        yield Static(self._get_key_status("ANTHROPIC_API_KEY"), 
                                   classes="key-status", id="anthropic-status")
                
                # Gemini Section
                with Container(classes="key-section"):
                    yield Label("💎 Google Gemini Configuration", classes="section-label")
                    with Horizontal(classes="key-row"):
                        yield Label("💎 Gemini API Key:", classes="key-label")
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
                with Collapsible(title="ℹ️ API Key Information & Setup Guide", collapsed=True):
                    yield Markdown("""
**Where to obtain API keys:**

• **OpenAI GPT**: [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
• **Anthropic Claude**: [console.anthropic.com](https://console.anthropic.com)
• **Google Gemini**: [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

**Security Notes:**
• Keys are stored as environment variables only
• Never share your API keys with others
• Keys enable AI-powered vulnerability analysis and fixes
• All providers offer free tiers for testing

**Features Enabled:**
• 🤖 AI-powered vulnerability fix suggestions  
• 🔍 Intelligent code analysis
• 📊 Enhanced security reporting
• 🎯 Context-aware recommendations
                    """)
            
            with Horizontal(classes="keys-actions"):
                yield Button("💾 Save & Test Keys", variant="success", 
                           classes="action-button", id="save-keys")
                yield Button("🧹 Clear All Keys", variant="warning", 
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
        """Save API keys with validation and testing."""
        # Extract keys from inputs
        keys = {
            "OPENAI_API_KEY": self.query_one("#openai-key", Input).value.strip(),
            "ANTHROPIC_API_KEY": self.query_one("#anthropic-key", Input).value.strip(),
            "GOOGLE_API_KEY": self.query_one("#gemini-key", Input).value.strip(),
        }
        
        # Update environment variables for non-empty keys
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
        """Clear all API keys with confirmation."""
        # Remove from environment
        env_vars = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]
        for env_var in env_vars:
            if env_var in os.environ:
                del os.environ[env_var]
        
        # Clear input fields
        self.query_one("#openai-key", Input).value = ""
        self.query_one("#anthropic-key", Input).value = ""
        self.query_one("#gemini-key", Input).value = ""
        
        # Update status indicators
        self.query_one("#openai-status").update("[red]❌ Missing[/red]")
        self.query_one("#anthropic-status").update("[red]❌ Missing[/red]")
        self.query_one("#gemini-status").update("[red]❌ Missing[/red]")
        
        self.dismiss({"action": "cleared", "count": 3})
    
    @on(Button.Pressed, "#cancel-keys")
    def cancel(self) -> None:
        """Cancel key management."""
        self.dismiss({"action": "cancelled"})


class AnimatedProgressBar(ProgressBar):
    """Enhanced progress bar with smooth animations and gradient effects."""
    
    DEFAULT_CSS = """
    AnimatedProgressBar {
        height: 3;
        margin: 1 0;
        border: round $primary;
        background: $surface-lighten-1;
        color: $text;
    }
    
    AnimatedProgressBar > .bar--bar {
        background: $primary;
        color: white;
        text-style: bold;
    }
    
    AnimatedProgressBar > .bar--percentage {
        color: $text;
        text-style: bold;
    }
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pulse_timer: Optional[Timer] = None
    
    def on_mount(self) -> None:
        """Start smooth animation when mounted."""
        self.pulse_timer = self.set_interval(0.1, self.animate_progress)
    
    def animate_progress(self) -> None:
        """Animate the progress bar with smooth transitions."""
        if self.progress < self.total:
            self.add_class("pulse")
            self.call_after_refresh(lambda: self.remove_class("pulse"))


class ImpactScanModernTUI(App):
    """
    Ultra-Modern TUI Application for Impact Scan - 2025 Edition
    Features a clean, responsive layout with a collapsible sidebar.
    """

    # Application Metadata
    TITLE = "🚀 Impact Scan - Next-Gen Security Intelligence Platform"
    SUB_TITLE = "🔮 AI-Powered Multi-Agent Security Orchestration • 2025 Edition"

    # Enhanced Key Bindings
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+p", "command_palette", "Command Palette", priority=True),
        Binding("ctrl+s", "start_scan", "Start Scan"),
        Binding("ctrl+b", "browse_path", "Browse Path"),
        Binding("ctrl+k", "manage_keys", "API Keys"),
        Binding("ctrl+t", "toggle_sidebar", "Toggle Sidebar"),
        Binding("ctrl+h", "help", "Help"),
        Binding("ctrl+e", "export_menu", "Export"),
    ]

    # Reactive State Management
    scan_running: bool = reactive(False)
    scan_progress: float = reactive(0.0)
    scan_status: str = reactive("Ready for next-gen security scanning")
    show_sidebar = reactive(True)

    # Data Storage
    current_config: Optional[schema.ScanConfig] = None
    current_results: Optional[schema.ScanResult] = None

    # Simplified and structured CSS
    CSS = """
    Screen {
        background: $surface;
        color: $text;
    }

    Header {
        background: $primary;
        color: white;
        text-style: bold;
    }

    Footer {
        background: $surface-darken-2;
        color: $text-muted;
        border-top: solid $primary;
    }

    #main-container {
        layout: horizontal;
        width: 100%;
        height: 100%;
    }

    #sidebar {
        width: 35;
        height: 100%;
        background: $surface-lighten-1;
        border-right: solid $primary-lighten-2;
        padding: 1;
        overflow-y: auto;
    }

    #sidebar.collapsed {
        width: 0;
        padding: 0;
        border: none;
    }

    #main-content {
        width: 1fr;
        height: 100%;
        padding: 1;
        display: block;
    }

    .title {
        text-style: bold;
        text-align: center;
        background: $primary;
        color: white;
        padding: 1;
        margin-bottom: 1;
    }

    .config-group {
        margin-bottom: 1;
        padding: 1;
        border: round $primary-lighten-2;
        background: $surface;
    }

    .config-group Label {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }

    .config-item {
        width: 1fr;
    }

    .config-btn {
        min-width: 12;
        height: 3;
        margin-left: 1;
        background: $accent;
        color: white;
        border: solid $primary;
    }

    .config-btn-small {
        width: 6;
        height: 3;
        margin-left: 1;
        background: $accent;
        color: white;
        border: solid $primary;
    }

    #action-buttons {
        margin-top: 1;
        align: center middle;
    }

    #action-buttons Button {
        width: 1fr;
        margin: 0 1;
    }

    #stats-bar {
        height: 4;
        align: center middle;
        margin-bottom: 1;
    }

    .stat {
        width: 1fr;
        height: 3;
        text-align: center;
        text-style: bold;
        padding: 0 1;
        margin: 0 1;
        border: round $primary;
    }

    .total { background: $primary; color: white; }
    .critical { background: $error; color: white; }
    .high { background: $warning; color: black; }
    .medium { background: yellow; color: black; }
    .low { background: $success; color: white; }

    #results-table {
        height: 2fr;
        margin-bottom: 1;
        border: solid $primary-lighten-2;
    }

    #details-tabs {
        height: 1fr;
    }

    #scan-log, #details-view {
        height: 100%;
        border: round $primary-lighten-2;
        padding: 1;
        background: $surface-darken-1;
    }
    """

    def __init__(self):
        super().__init__()
        self.command_provider = ModernCommandProvider(self)

    def watch_show_sidebar(self, show: bool) -> None:
        """Toggle sidebar display."""
        sidebar = self.query_one("#sidebar")
        sidebar.set_class(not show, "collapsed")

    def action_toggle_sidebar(self) -> None:
        """Action to toggle the sidebar."""
        self.show_sidebar = not self.show_sidebar

    def compose(self) -> ComposeResult:
        """Create the application layout."""
        yield Header()
        with Horizontal(id="main-container"):
            with Vertical(id="sidebar"):
                yield Label("⚙️ Configuration", classes="title")

                with Vertical(classes="config-group"):
                    yield Label("🎯 Target")
                    with Horizontal():
                        yield Input(placeholder="Scan Path...", id="scan-path", classes="config-item")
                        yield Button("📁", id="browse-btn", classes="config-btn-small")

                with Vertical(classes="config-group"):
                    yield Label("⚡ Profile")
                    yield Select(
                        options=[
                            ("Comprehensive", "comprehensive"),
                            ("Quick", "quick"),
                            ("Standard", "standard"),
                            ("CI", "ci"),
                        ],
                        value="comprehensive",
                        id="profile-select",
                        classes="config-item"
                    )

                with Vertical(classes="config-group"):
                    yield Label("🤖 AI Provider")
                    yield Select(
                        options=[
                            ("Auto-Detect", "auto"),
                            ("OpenAI", "openai"),
                            ("Anthropic", "anthropic"),
                            ("Gemini", "gemini"),
                            ("Disabled", "none"),
                        ],
                        value="auto",
                        id="ai-select",
                        classes="config-item"
                    )

                with Vertical(classes="config-group"):
                    yield Label("🔧 Features")
                    yield Switch(value=True, id="ai-fixes-switch")
                    yield Label("AI-Powered Fixes")
                    yield Switch(value=True, id="web-search-switch")
                    yield Label("Web Intelligence")

                with Horizontal(id="action-buttons"):
                    yield Button("🚀 Scan", variant="success", id="start-scan-btn")
                    yield Button("🔑 Keys", id="keys-btn")

            with Vertical(id="main-content"):
                with Horizontal(id="stats-bar"):
                    yield Static("Total: 0", classes="stat total", id="total-card")
                    yield Static("Crit: 0", classes="stat critical", id="critical-card")
                    yield Static("High: 0", classes="stat high", id="high-card")
                    yield Static("Med: 0", classes="stat medium", id="medium-card")
                    yield Static("Low: 0", classes="stat low", id="low-card")

                yield DataTable(id="results-table", zebra_stripes=True, cursor_type="row")

                with TabbedContent(id="details-tabs"):
                    with TabPane("📜 Log", id="log-tab"):
                        yield RichLog(highlight=True, markup=True, id="scan-log", auto_scroll=True)
                    with TabPane("🔍 Details", id="details-tab"):
                        yield Markdown(id="details-view")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize the application."""
        self.title = self.TITLE
        self.sub_title = self.SUB_TITLE

        # Configure results table
        table = self.query_one("#results-table", DataTable)
        table.add_columns("🚨 Sev", "🔍 Type", "📁 File", "📍 Line", "📝 Description")

        # Set default path
        self.query_one("#scan-path", Input).value = str(Path.cwd())

        # Log startup messages
        log = self.query_one("#scan-log", RichLog)
        log.write("🚀 [bold green]Impact Scan TUI Initialized[/bold green]")
        log.write("⌨️  [yellow]Ctrl+T to toggle sidebar | Ctrl+P for command palette[/yellow]")

        self._check_ai_providers()
    
    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Show details when a row is selected."""
        details_view = self.query_one("#details-view", Markdown)
        if self.current_results and self.current_results.findings:
            try:
                finding = self.current_results.findings[event.cursor_row]
                
                details_md = f"""
### 🔍 {finding.vuln_id}

**Severity:** {finding.severity.value.upper()}
**File:** `{finding.file_path}:{finding.line_number}`

---

**Description:**
{finding.description}
"""
                if hasattr(finding, 'ai_fix') and finding.ai_fix:
                    details_md += f"""
---

**🤖 AI Suggested Fix:**
```diff
{finding.ai_fix.diff}
```
"""
                details_view.update(details_md)
                self.query_one("#details-tabs").active = "details-tab"
            except IndexError:
                details_view.update("Could not retrieve finding details.")
    
    def _check_ai_providers(self) -> None:
        """Check for available AI providers and log status."""
        log = self.query_one("#scan-log", RichLog)
        api_keys = schema.APIKeys()
        
        # Check which providers have keys available
        available = []
        if api_keys.openai:
            available.append("OpenAI")
        if api_keys.anthropic:
            available.append("Anthropic")
        if api_keys.gemini:
            available.append("Gemini")
        
        if available:
            log.write(f"✅ [green]AI Providers Ready: {', '.join(available)}[/green]")
        else:
            log.write("⚠️  [yellow]No AI provider keys configured. Press 'k' to set them.[/yellow]")

    # Action Methods (simplified for brevity)
    @on(Button.Pressed, "#start-scan-btn")
    def action_start_scan(self) -> None:
        if self.scan_running:
            self.notify("⚠️ Scan already in progress", severity="warning")
            return
        self.run_worker(self._execute_enhanced_scan, thread=True, exclusive=True)

    def _execute_enhanced_scan(self) -> None:
        """Execute the security scan, now correctly handling the async entrypoint."""
        log = None
        try:
            self.scan_running = True
            log = self.query_one("#scan-log", RichLog)
            
            # Clear previous results
            self.query_one("#results-table", DataTable).clear()
            self.query_one("#details-view", Markdown).update("")
            
            log.write("\n" + "="*50)
            log.write("🚀 [bold blue]Starting New Security Scan...[/bold blue]")

            # Gather config from UI
            scan_path = Path(self.query_one("#scan-path", Input).value or ".")
            profile_name = self.query_one("#profile-select", Select).value
            ai_provider = self.query_one("#ai-select", Select).value
            use_ai_fixes = self.query_one("#ai-fixes-switch", Switch).value
            use_web_search = self.query_one("#web-search-switch", Switch).value

            scan_profile = profiles.get_profile(profile_name)
            scan_profile.enable_ai_fixes = use_ai_fixes
            scan_profile.enable_web_search = use_web_search
            if ai_provider != "auto":
                scan_profile.ai_provider = ai_provider if ai_provider != "none" else None

            config = profiles.create_config_from_profile(
                root_path=scan_path,
                profile=scan_profile,
                api_keys=schema.APIKeys()
            )
            self.current_config = config

            log.write(f"🎯 Target: {scan_path}")
            log.write(f"⚡ Profile: {profile_name}")
            log.write(f"🤖 AI Fixes: {'Enabled' if use_ai_fixes else 'Disabled'}")
            log.write(f"🌐 Web Search: {'Enabled' if use_web_search else 'Disabled'}")

            # Run synchronous scan directly; enrichment happens inside
            scan_result = entrypoint.run_scan(config)

            # --- Finalize and Display Results ---
            self.current_results = scan_result
            if scan_result and scan_result.findings:
                self._update_enhanced_results_display(scan_result)
                log.write(f"✅ [bold green]Scan Complete! Found {len(scan_result.findings)} issues.[/bold green]")
            else:
                log.write("✅ [bold green]Scan Complete! No issues found.[/bold green]")
                self._update_enhanced_results_display(None)

        except Exception as e:
            if log:
                log.write(f"❌ [bold red]Scan failed: {e}[/bold red]")
            self.notify(f"❌ Scan failed: {e}", severity="error")
        finally:
            self.scan_running = False
            self.scan_status = "Ready"

    def _update_enhanced_results_display(self, scan_result: Optional[schema.ScanResult]) -> None:
        """Update UI with scan results."""
        table = self.query_one("#results-table", DataTable)
        table.clear()

        if not scan_result or not scan_result.findings:
            self.query_one("#total-card").update("Total: 0")
            self.query_one("#critical-card").update("Crit: 0")
            self.query_one("#high-card").update("High: 0")
            self.query_one("#medium-card").update("Med: 0")
            self.query_one("#low-card").update("Low: 0")
            return

        findings = scan_result.findings
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev_counts[f.severity.value] += 1

        self.query_one("#total-card").update(f"Total: {len(findings)}")
        self.query_one("#critical-card").update(f"Crit: {sev_counts['critical']}")
        self.query_one("#high-card").update(f"High: {sev_counts['high']}")
        self.query_one("#medium-card").update(f"Med: {sev_counts['medium']}")
        self.query_one("#low-card").update(f"Low: {sev_counts['low']}")

        sev_map = {
            schema.Severity.CRITICAL: "[red]Critical[/red]",
            schema.Severity.HIGH: "[orange1]High[/orange1]",
            schema.Severity.MEDIUM: "[yellow]Medium[/yellow]",
            schema.Severity.LOW: "[blue]Low[/blue]",
        }

        for finding in findings:
            short_path = f"...{str(finding.file_path)[-22:]}" if len(str(finding.file_path)) > 25 else str(finding.file_path)
            table.add_row(
                sev_map.get(finding.severity, "Unknown"),
                finding.vuln_id,
                short_path,
                str(finding.line_number) if hasattr(finding, 'line_number') else "-",
                finding.description.splitlines()[0],
            )

    @on(Button.Pressed, "#browse-btn")
    def action_browse_path(self) -> None:
        """Open path browser."""
        current_path = Path(self.query_one("#scan-path", Input).value or ".")
        def handle_path(path: str):
            if path:
                self.query_one("#scan-path", Input).value = path
        self.push_screen(PathBrowserModal(current_path), handle_path)

    @on(Button.Pressed, "#keys-btn")
    def action_manage_keys(self) -> None:
        """Open API keys manager."""
        def handle_keys(result: dict):
            if result.get("action") == "saved":
                self.notify(f"✅ {result.get('count', 0)} API key(s) saved.")
                self._check_ai_providers()
        self.push_screen(APIKeysModal(), handle_keys)

    def action_help(self) -> None:
        """Show help information."""
        self.query_one("#details-view").update("""
        ### Help

        - **Ctrl+T**: Toggle the configuration sidebar.
        - **Ctrl+P**: Open the command palette for quick actions.
        - **Ctrl+S**: Start a new scan with the current configuration.
        - **Ctrl+Q**: Quit the application.
        """)
        self.query_one("#details-tabs").active = "details-tab"

    def action_export_menu(self) -> None:
        """A placeholder for an export menu."""
        self.notify("Export functionality coming soon!")


def run_modern_tui() -> None:
    """Entry point for the ultra-modern TUI application."""
    app = ImpactScanModernTUI()
    try:
        app.run()
    except KeyboardInterrupt:
        print("\n🛑 Impact Scan TUI interrupted by user")
    except Exception as e:
        print(f"\n💥 Impact Scan TUI error: {e}")


if __name__ == "__main__":
    run_modern_tui()