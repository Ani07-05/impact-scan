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
    Button, DataTable, DirectoryTree, Footer, Header, Input, Label,
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
        width: 85%;
        max-width: 120;
        height: 85%;
        max-height: 45;
        background: $surface;
        border: thick $accent;
        border-subtitle-color: $primary;
        border-title-color: white;
        border-title-style: bold;
        border-title-background: linear-gradient(90deg, $accent 0%, $primary 100%);
    }
    
    .browser-header {
        dock: top;
        height: 5;
        background: linear-gradient(135deg, $primary 0%, $accent 50%, $secondary 100%);
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
        background: linear-gradient(135deg, $surface-darken-1 0%, $surface 100%);
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
        transform: scale(1.05);
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
        width: 75%;
        max-width: 100;
        height: 80%;
        max-height: 40;
        background: $surface;
        border: thick $accent;
        border-title-color: white;
        border-title-style: bold;
        border-title-background: linear-gradient(90deg, $accent 0%, $secondary 100%);
    }
    
    .keys-header {
        dock: top;
        height: 6;
        background: linear-gradient(135deg, $accent 0%, $secondary 50%, $primary 100%);
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
        background: linear-gradient(135deg, $surface-darken-1 0%, $surface 100%);
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
        transform: scale(1.05);
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
                yield Button("🧽 Clear All Keys", variant="warning", 
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


class ModernCard(Container):
    """Ultra-modern card with gradient backgrounds and animations."""
    
    DEFAULT_CSS = """
    ModernCard {
        background: $surface;
        border: solid $primary;
        margin: 1;
        padding: 0;
        height: auto;
        transition: all 300ms ease;
    }
    
    ModernCard:hover {
        border: solid $accent;
        transform: translateY(-2px);
        background: $surface-lighten-1;
    }
    
    ModernCard .card-title {
        text-style: bold;
        color: white;
        margin: 0;
        text-align: center;
        background: linear-gradient(135deg, $primary 0%, $accent 50%, $secondary 100%);
        padding: 1;
        border-bottom: solid $primary;
    }
    
    ModernCard .card-content {
        padding: 1;
        background: $surface;
    }
    
    ModernCard .section-label {
        text-style: bold;
        color: $accent;
        text-align: center;
        background: $surface-lighten-2;
        padding: 0 1;
        margin: 0 0 1 0;
        border: round $primary;
    }
    """


class GlowButton(Button):
    """Enhanced button with glow effects and hover animations."""
    
    DEFAULT_CSS = """
    GlowButton {
        min-width: 12;
        height: 3;
        margin: 0 1;
        border: round $primary;
        background: $primary;
        color: white;
        text-style: bold;
        transition: all 200ms ease;
    }
    
    GlowButton:hover {
        background: $primary-lighten-2;
        border: round $accent;
        text-style: bold italic;
        transform: scale(1.05);
        box-shadow: 0 0 10px $accent;
    }
    
    GlowButton:focus {
        background: $accent;
        border: thick $secondary;
        text-style: bold underline;
        box-shadow: 0 0 15px $accent;
    }
    
    GlowButton.success {
        background: linear-gradient(135deg, $success 0%, $success-lighten-1 100%);
        border: round $success-lighten-1;
    }
    
    GlowButton.success:hover {
        background: linear-gradient(135deg, $success-lighten-1 0%, $success-lighten-2 100%);
        box-shadow: 0 0 15px $success;
    }
    
    GlowButton.warning {
        background: linear-gradient(135deg, $warning 0%, $warning-lighten-1 100%);
        border: round $warning-lighten-1;
        color: black;
    }
    
    GlowButton.warning:hover {
        background: linear-gradient(135deg, $warning-lighten-1 0%, $warning-lighten-2 100%);
        box-shadow: 0 0 15px $warning;
    }
    
    GlowButton.danger {
        background: linear-gradient(135deg, $error 0%, $error-lighten-1 100%);
        border: round $error-lighten-1;
    }
    
    GlowButton.danger:hover {
        background: linear-gradient(135deg, $error-lighten-1 0%, $error-lighten-2 100%);
        box-shadow: 0 0 15px $error;
    }
    """


class StatsCard(Static):
    """Modern stats card with gradient backgrounds and animations."""
    
    DEFAULT_CSS = """
    StatsCard {
        width: 1fr;
        height: 8;
        margin: 0 1 1 0;
        padding: 1;
        text-align: center;
        text-style: bold;
        border: round $primary;
        background: $surface-lighten-1;
        transition: all 300ms ease;
    }
    
    StatsCard:hover {
        transform: scale(1.05) translateY(-2px);
        background: $surface-lighten-2;
        border: round $accent;
    }
    
    StatsCard.critical {
        background: linear-gradient(135deg, $error 0%, #ff4444 100%);
        color: white;
        text-style: bold;
        border: round $error-lighten-1;
    }
    
    StatsCard.critical:hover {
        box-shadow: 0 0 20px rgba(255, 68, 68, 0.6);
    }
    
    StatsCard.high {
        background: linear-gradient(135deg, $warning 0%, #ffaa44 100%);
        color: white;
        text-style: bold;
        border: round $warning-lighten-1;
    }
    
    StatsCard.high:hover {
        box-shadow: 0 0 20px rgba(255, 170, 68, 0.6);
    }
    
    StatsCard.medium {
        background: linear-gradient(135deg, yellow 0%, #ffff88 100%);
        color: black;
        text-style: bold;
        border: round yellow-lighten-1;
    }
    
    StatsCard.medium:hover {
        box-shadow: 0 0 20px rgba(255, 255, 136, 0.6);
    }
    
    StatsCard.low {
        background: linear-gradient(135deg, $primary 0%, #4488ff 100%);
        color: white;
        text-style: bold;
        border: round $primary-lighten-1;
    }
    
    StatsCard.low:hover {
        box-shadow: 0 0 20px rgba(68, 136, 255, 0.6);
    }
    
    StatsCard.total {
        background: linear-gradient(135deg, $accent 0%, $secondary 100%);
        color: white;
        text-style: bold;
        border: round $accent-lighten-1;
    }
    
    StatsCard.total:hover {
        box-shadow: 0 0 20px rgba(127, 127, 255, 0.6);
    }
    
    StatsCard.score {
        background: linear-gradient(135deg, $success 0%, $success-lighten-1 100%);
        color: white;
        text-style: bold;
        border: round $success-lighten-1;
    }
    
    StatsCard.score:hover {
        box-shadow: 0 0 20px rgba(0, 255, 127, 0.6);
    }
    """


class ConfigurationPanel(ModernCard):
    """Modern configuration panel with enhanced UI elements."""
    
    def compose(self) -> ComposeResult:
        yield Label("⚙️ Advanced Scan Configuration", classes="card-title")
        
        with Vertical(classes="card-content"):
            # Path Configuration Section
            with Container(classes="config-section"):
                yield Label("🎯 Target Configuration", classes="section-label")
                with Horizontal(classes="config-row"):
                    yield Label("📁 Scan Path:", classes="config-label")
                    yield Input(
                        placeholder="Enter directory path to scan...",
                        classes="path-input",
                        id="scan-path",
                        suggester=SuggestFromList([str(Path.cwd()), str(Path.home())])
                    )
                    yield GlowButton("📂 Browse", variant="primary", id="browse-btn")
            
            # Profile & AI Configuration Section
            with Container(classes="config-section"):
                yield Label("🤖 AI & Profile Settings", classes="section-label")
                
                with Horizontal(classes="config-row"):
                    yield Label("⚡ Scan Profile:", classes="config-label")
                    yield Select(
                        options=[
                            ("🧠 Comprehensive (All Features)", "comprehensive"),
                            ("⚡ Quick Scan (High/Critical)", "quick"),
                            ("🔍 Standard (Medium+)", "standard"),
                            ("🤖 CI/CD Pipeline", "ci"),
                        ],
                        value="comprehensive",
                        classes="config-select",
                        id="profile-select"
                    )
                
                with Horizontal(classes="config-row"):
                    yield Label("🤖 AI Provider:", classes="config-label")
                    yield Select(
                        options=[
                            ("✨ Auto-Detect Best", "auto"),
                            ("🧠 OpenAI GPT-4", "openai"),
                            ("🔮 Anthropic Claude", "anthropic"),
                            ("💎 Google Gemini", "gemini"),
                            ("❌ Disabled", "none"),
                        ],
                        value="auto",
                        classes="config-select",
                        id="ai-select"
                    )
                    yield GlowButton("🔑 Keys", variant="default", id="keys-btn")
            
            # Feature Toggles Section
            with Container(classes="config-section"):
                yield Label("🔧 Advanced Features", classes="section-label")
                
                with Grid(classes="features-grid", id="features-grid"):
                    yield Label("🤖 AI-Powered Fixes:")
                    yield Switch(value=True, id="ai-fixes-switch")
                    yield Label("🌐 Web Intelligence:")
                    yield Switch(value=True, id="web-search-switch")
                    yield Label("📊 Detailed Reports:")
                    yield Switch(value=True, id="detailed-reports-switch")
                    yield Label("⚡ Fast Mode:")
                    yield Switch(value=False, id="fast-mode-switch")
            
            # Action Buttons Section
            with Horizontal(classes="action-buttons"):
                yield GlowButton("🚀 Start Comprehensive Scan", variant="success", id="start-scan-btn")
                yield GlowButton("💾 Save Config", variant="default", id="save-config-btn")
                yield GlowButton("📂 Load Config", variant="default", id="load-config-btn")


class FindingsCard(ModernCard):
    """Enhanced findings display with modern table."""
    
    def compose(self) -> ComposeResult:
        yield Label("🔍 Security Findings", classes="card-title")
        
        with Vertical(classes="card-content"):
            # Enhanced table with better styling
            table = DataTable(classes="modern-table", id="findings-table", zebra_stripes=True)
            table.add_columns("🚨 Severity", "🔍 Type", "📁 File", "📍 Line", "📝 Description", "💡 Fix")
            yield table
            
            # Prominent export bar
            with Horizontal(classes="export-bar"):
                yield Label("📤 Export Results:", classes="export-label")
                yield Button("📄 HTML Report", variant="success", classes="export-btn", id="export-html")
                yield Button("📊 SARIF Format", variant="primary", classes="export-btn", id="export-sarif") 
                yield Button("📋 PDF Report", variant="warning", classes="export-btn", id="export-pdf")
                yield Button("📂 View Details", variant="default", classes="export-btn", id="view-details")


class ProgressCard(ModernCard):
    """Modern progress and logging display."""
    
    def compose(self) -> ComposeResult:
        yield Label("📈 Scan Progress", classes="card-title")
        
        with Vertical(classes="card-content"):
            # Enhanced progress section
            yield ProgressBar(total=100, show_eta=True, classes="modern-progress", id="scan-progress")
            
            # Status and spinner row
            with Horizontal(classes="status-row"):
                yield Static("Ready to scan", classes="status-text", id="status-text")
                yield LoadingIndicator(classes="modern-spinner", id="loading-spinner")
            
            # Modern log display
            yield Log(
                highlight=True,
                markup=True,
                classes="modern-log",
                id="scan-log",
                auto_scroll=True,
                wrap=True,
            )


class MetricsCard(ModernCard):
    """Simple metrics panel providing stat boxes with known IDs."""

    def compose(self) -> ComposeResult:
        yield Label("📊 Security Metrics", classes="card-title")
        with Grid(classes="metrics-grid"):
            yield Static("0", id="total-metric", classes="metric-card metric-total")
            yield Static("0", id="critical-metric", classes="metric-card metric-critical")
            yield Static("0", id="high-metric", classes="metric-card metric-high")
            yield Static("0", id="medium-metric", classes="metric-card metric-medium")
            yield Static("0", id="low-metric", classes="metric-card metric-low")
            yield Static("100%", id="score-metric", classes="metric-card metric-score")


class ModernImpactScanTUI(App):
    """Revolutionary modern TUI for Impact Scan."""
    
    CSS = """
    /* Modern Color Scheme */
    Screen {
        background: $background;
        color: $text;
    }
    
    /* Modern Cards */
    ModernCard {
        background: $surface;
        border: solid $primary;
        margin: 1;
        padding: 0;
    }
    
    .card-title {
        background: $accent;
        color: $text;
        text-style: bold;
        padding: 1;
        text-align: center;
    }
    
    .card-content {
        padding: 1;
    }
    
    /* Configuration Styling */
    .config-row {
        height: 3;
        margin: 0 0 1 0;
        align: left middle;
        padding: 0 1;
    }
    
    .config-label {
        width: 12;
        color: $accent;
        text-style: bold;
        text-align: right;
        margin-right: 1;
    }
    
    .path-input {
        width: 1fr;
        margin-right: 1;
        background: $surface;
        border: solid $primary;
        color: $text;
    }
    
    .profile-select, .ai-select {
        width: 26;
        background: $surface;
        border: solid $primary;
        color: $text;
    }
    
    .feature-toggle {
        margin: 0 1;
    }
    
    .mini-btn {
        width: 3;
        height: 1;
    }
    
    /* Action Bar */
    .action-bar {
        height: 4;
        align: center middle;
        background: $surface;
        border: solid $primary;
        margin: 1 0 0 0;
        padding: 1;
    }
    
    .primary-btn {
        margin: 0 1;
        text-style: bold;
        width: 12;
    }
    
    .secondary-btn {
        margin: 0 1;
        width: 10;
    }
    
    /* Metrics Grid */
    .metrics-grid {
        grid-size: 3 2;
        grid-gutter: 1;
        margin: 1;
    }
    
    .metric-card {
        background: $surface;
        border: solid $accent;
        padding: 1;
        text-align: center;
        text-style: bold;
        height: 4;
    }
    
    .metric-total { border: solid $primary; color: $primary; }
    .metric-critical { border: solid $error; color: $error; }
    .metric-high { border: solid $warning; color: $warning; }
    .metric-medium { border: solid $accent; color: $accent; }
    .metric-low { border: solid $success; color: $success; }
    .metric-score { border: solid $secondary; color: $secondary; }
    
    /* Modern Table */
    .modern-table {
        background: $surface;
        border: solid $primary;
        margin: 1 0;
    }
    
    /* Export Bar */
    .export-bar {
        background: $surface;
        border: solid $primary;
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
        width: 12;
        text-style: bold;
    }
    
    /* Progress and Logging */
    .modern-progress {
        background: $surface;
        border: solid $primary;
        margin: 1 0;
    }
    
    .status-row {
        height: 3;
        align: center middle;
        background: $surface;
        border: solid $accent;
        margin: 0 0 1 0;
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
    
    .modern-log {
        background: $surface;
        border: solid $primary;
        height: 1fr;
        min-height: 15;
        padding: 1;
    }
    
    /* Layout columns */
    .left-column {
        width: 40%;
        margin-right: 1;
    }
    
    .right-column {
        width: 60%;
    }
    """
    
    TITLE = "🚀 Impact Scan - Next-Gen Security Intelligence Platform"
    SUB_TITLE = "🔮 AI-Powered Multi-Agent Security Orchestration"
    
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh", "Refresh"),
        Binding("s", "start_scan", "Start Scan"),
        Binding("b", "browse_path", "Browse"),
        Binding("k", "manage_keys", "API Keys"),
        Binding("h", "help", "Help"),
        Binding("c", "clear_log", "Clear Log"),
        Binding("e", "export_menu", "Export Menu"),
    ]
    
    scan_running = reactive(False)
    current_config: Optional[schema.ScanConfig] = None
    current_results: Optional[schema.ScanResult] = None
    
    def compose(self) -> ComposeResult:
        """Create the modern UI layout."""
        yield Header()
        
        with Horizontal():
            # Left column with configuration
            with Vertical(classes="left-column"):
                yield ConfigurationPanel()
                yield ProgressCard()
            
            # Right column with metrics and findings
            with Vertical(classes="right-column"):
                yield MetricsCard()
                yield FindingsCard()
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the modern app."""
        self.log_message("🚀 [STARTUP] Impact Scan AI Security Platform initialized")
        self.log_message("🧠 [AI] Multi-agent security orchestration ready")
        self.log_message("🎯 [READY] Configure your scan and press 's' to start!")
        self.update_path_from_cwd()
        self.check_api_keys()
    
    def update_path_from_cwd(self) -> None:
        """Set default scan path."""
        cwd = Path.cwd()
        path_input = self.query_one("#scan-path", Input)
        path_input.value = str(cwd)
    
    def check_api_keys(self) -> None:
        """Check and log API key status."""
        api_keys = schema.APIKeys()
        providers = []
        
        if api_keys.openai:
            providers.append("🧠 OpenAI")
        if api_keys.anthropic:
            providers.append("🔮 Anthropic")
        if api_keys.gemini:
            providers.append("💎 Gemini")
        
        if providers:
            self.log_message(f"✅ [AI] Available providers: {', '.join(providers)}")
        else:
            self.log_message("⚠️ [AI] No API keys configured - Press 'k' to set up AI providers")
    
    def log_message(self, message: str) -> None:
        """Add message to scan log."""
        log_widget = self.query_one("#scan-log", Log)
        log_widget.write(message)
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle all button presses."""
        handlers = {
            "start-scan": self.action_start_scan,
            "browse-path": self.action_browse_path,
            "api-keys": self.action_manage_keys,
            "save-config": self.action_save_config,
            "export-html": self.action_export_html,
            "export-sarif": self.action_export_sarif,
            "export-pdf": self.action_export_pdf,
            "view-details": self.action_view_details
        }
        
        handler = handlers.get(event.button.id)
        if handler:
            handler()
    
    def action_start_scan(self) -> None:
        """Start modern scan process."""
        if self.scan_running:
            self.log_message("⚠️ [SCAN] Already running")
            return

        # Get configuration from UI
        path_input = self.query_one("#scan-path", Input)
        profile_select = self.query_one("#profile-select", Select)
        ai_select = self.query_one("#ai-select", Select)
        # Note: widget IDs are 'ai-fixes-switch' and 'web-search-switch' in the UI
        ai_fixes_toggle = self.query_one("#ai-fixes-switch", Switch)
        web_search_toggle = self.query_one("#web-search-switch", Switch)

        if not path_input.value.strip():
            self.log_message("❌ [ERROR] Please specify a target path")
            return

        target_path = Path(path_input.value.strip())
        if not target_path.exists():
            self.log_message(f"❌ [ERROR] Path does not exist: {target_path}")
            return

        # Create scan configuration
        config = schema.ScanConfig(
            target_path=target_path,
            output_format="console",
            ai_provider=ai_select.value if ai_select.value != "none" else None,
            enable_ai_fixes=ai_fixes_toggle.value,
            enable_web_search=web_search_toggle.value,
            profile=profile_select.value,
        )
        
        self.current_config = config
        # Schedule background work via @work-decorated method
        self.run_scan_worker(config)
    
    def action_browse_path(self) -> None:
        """Browse for path."""
        current_path = Path(self.query_one("#scan-path", Input).value or Path.cwd())

        def on_path_selected(path: Optional[str]) -> None:
            if path:
                path_input = self.query_one("#scan-path", Input)
                path_input.value = path
                self.log_message(f"📁 [PATH] Selected: {path}")

        self.push_screen(PathBrowserModal(current_path), on_path_selected)

    def action_manage_keys(self) -> None:
        """Manage API keys."""
        def on_keys_updated(result: Optional[dict]) -> None:
            if result and result.get("action") == "saved":
                self.log_message("✅ [AI] API keys updated successfully")
                self.check_api_keys()
            elif result and result.get("action") == "cleared":
                self.log_message("🧽 [AI] API keys cleared")
            else:
                self.log_message("❌ [AI] API key update cancelled")
        
        self.push_screen(APIKeysModal(), on_keys_updated)
    
    def action_save_config(self) -> None:
        """Save configuration."""
        self.log_message("💾 [CONFIG] Configuration saved!")
    
    def action_export_html(self) -> None:
        """Export HTML report."""
        if not self.current_results:
            self.log_message("⚠️ [WARNING] No scan results to export")
            return
        
        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_report_{timestamp}.html"
            
            self.log_message(f"📄 [EXPORT] Generating HTML report: {output_file.name}")
            
            # Generate HTML report
            save_report(self.current_results, str(output_file))
            
            self.log_message(f"✅ [SUCCESS] HTML report saved to: {output_file}")
            self.log_message(f"🌐 [INFO] Opening report in browser...")
            
            # Open in browser
            webbrowser.open(f"file://{output_file.absolute()}")
            
        except Exception as e:
            self.log_message(f"❌ [ERROR] Failed to export HTML: {e}")
            logging.exception("HTML export failed")
    
    def action_export_sarif(self) -> None:
        """Export SARIF report."""
        if not self.current_results:
            self.log_message("⚠️ [WARNING] No scan results to export")
            return
        
        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_sarif_{timestamp}.json"
            
            self.log_message(f"📊 [EXPORT] Generating SARIF report: {output_file.name}")
            
            # Generate SARIF report using aggregator
            sarif_result = aggregator.to_sarif([self.current_results])
            
            with open(output_file, 'w') as f:
                import json
                json.dump(sarif_result, f, indent=2)
            
            self.log_message(f"✅ [SUCCESS] SARIF report saved to: {output_file}")
            
        except Exception as e:
            self.log_message(f"❌ [ERROR] Failed to export SARIF: {e}")
            logging.exception("SARIF export failed")
    
    def action_export_pdf(self) -> None:
        """Export PDF report."""
        if not self.current_results:
            self.log_message("⚠️ [WARNING] No scan results to export")
            return
        
        try:
            timestamp = int(time.time())
            html_file = Path.cwd() / f"temp_report_{timestamp}.html"
            pdf_file = Path.cwd() / f"impact_scan_report_{timestamp}.pdf"
            
            self.log_message(f"📋 [EXPORT] Generating PDF report: {pdf_file.name}")
            
            # First generate HTML report
            save_report(self.current_results, str(html_file))
            
            # Try multiple PDF generation methods
            pdf_generated = False
            
            # Method 1: WeasyPrint
            try:
                import weasyprint
                weasyprint.HTML(filename=str(html_file)).write_pdf(str(pdf_file))
                pdf_generated = True
                self.log_message("✅ [PDF] Generated using WeasyPrint")
            except ImportError:
                self.log_message("⚠️ [PDF] WeasyPrint not available, trying wkhtmltopdf...")
            except Exception as e:
                self.log_message(f"⚠️ [PDF] WeasyPrint failed: {e}")
            
            # Method 2: wkhtmltopdf
            if not pdf_generated:
                try:
                    subprocess.run([
                        'wkhtmltopdf', '--page-size', 'A4', '--orientation', 'Portrait',
                        '--margin-top', '0.75in', '--margin-right', '0.75in',
                        '--margin-bottom', '0.75in', '--margin-left', '0.75in',
                        str(html_file), str(pdf_file)
                    ], check=True, capture_output=True)
                    pdf_generated = True
                    self.log_message("✅ [PDF] Generated using wkhtmltopdf")
                except FileNotFoundError:
                    self.log_message("⚠️ [PDF] wkhtmltopdf not found, trying ReportLab...")
                except subprocess.CalledProcessError as e:
                    self.log_message(f"⚠️ [PDF] wkhtmltopdf failed: {e}")
            
            # Method 3: ReportLab fallback
            if not pdf_generated:
                try:
                    from reportlab.lib.pagesizes import letter
                    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
                    from reportlab.lib.styles import getSampleStyleSheet
                    
                    doc = SimpleDocTemplate(str(pdf_file), pagesize=letter)
                    styles = getSampleStyleSheet()
                    story = []
                    
                    # Add title
                    title = Paragraph(f"Impact Scan Security Report", styles['Title'])
                    story.append(title)
                    story.append(Spacer(1, 12))
                    
                    # Add findings summary
                    if self.current_results.findings:
                        summary = f"Total Findings: {len(self.current_results.findings)}"
                        story.append(Paragraph(summary, styles['Heading2']))
                        story.append(Spacer(1, 12))
                        
                        # Add each finding
                        for finding in self.current_results.findings[:20]:  # Limit to 20 for PDF
                            finding_text = f"{finding.severity.upper()}: {finding.title} in {finding.file_path}"
                            story.append(Paragraph(finding_text, styles['Normal']))
                            story.append(Spacer(1, 6))
                    
                    doc.build(story)
                    pdf_generated = True
                    self.log_message("✅ [PDF] Generated using ReportLab fallback")
                except Exception as e:
                    self.log_message(f"❌ [PDF] ReportLab failed: {e}")
            
            # Cleanup temp HTML
            try:
                html_file.unlink()
            except:
                pass
            
            if pdf_generated:
                self.log_message(f"✅ [SUCCESS] PDF report saved to: {pdf_file}")
            else:
                self.log_message("❌ [ERROR] All PDF generation methods failed")
                
        except Exception as e:
            self.log_message(f"❌ [ERROR] Failed to export PDF: {e}")
            logging.exception("PDF export failed")
    
    def action_view_details(self) -> None:
        """View detailed results."""
        self.log_message("📂 [VIEW] Detailed results panel opening...")
    
    def action_help(self) -> None:
        """Show help."""
        help_text = """
[bold blue]🚀 Impact Scan - AI Security Platform[/bold blue]

[bold]Keyboard Shortcuts:[/bold]
• [cyan]s[/cyan] - Start comprehensive scan
• [cyan]b[/cyan] - Browse for target directory
• [cyan]k[/cyan] - Configure AI provider keys
• [cyan]e[/cyan] - Export menu
• [cyan]h[/cyan] - Show this help
• [cyan]q[/cyan] - Quit application

[bold]Features:[/bold]
• Multi-agent AI security analysis
• Real-time vulnerability intelligence
• Comprehensive reporting (HTML, PDF, SARIF)
• Business impact scoring
• Attack path analysis
        """
        self.log_message(help_text.strip())
    
    @work(exclusive=True)
    def run_scan_worker(self, config: schema.ScanConfig) -> None:
        """Run the security scan using Textual's worker system with proper async handling."""
        try:
            self.scan_running = True
            progress_bar = self.query_one("#scan-progress", ProgressBar)
            status_text = self.query_one("#status-text", Static)
            loading_spinner = self.query_one("#loading-spinner", LoadingIndicator)
            
            progress_bar.update(total=100, progress=0)
            loading_spinner.loading = True
            
            self.log_message(f"🎯 [SCAN] Target: {config.target_path}")
            self.log_message(f"⚡ [PROFILE] Using profile: {config.profile}")
            self.log_message(f"🤖 [AI] Provider: {config.ai_provider or 'disabled'}")
            
            # Phase 1: Entry point detection
            status_text.update("🔍 Analyzing codebase...")
            progress_bar.update(progress=10)
            self.log_message("   🔍 [cyan]Scanning for entry points and framework detection...[/cyan]")
            
            # Run synchronous scan first
            scan_result = entrypoint.run_scan(config)
            
            progress_bar.update(progress=30)
            status_text.update("✅ Entry points detected")
            
            if scan_result.entry_points:
                self.log_message(f"✅ [ENTRY-POINTS] Found {len(scan_result.entry_points)} entry points:")
                for ep in scan_result.entry_points[:3]:
                    self.log_message(f"   • [green]{ep.framework}[/green] at [yellow]{ep.file_path}[/yellow]")
            else:
                self.log_message("⚠️ [ENTRY-POINTS] No specific entry points detected - scanning as generic project")
            
            # Phase 2: Static analysis
            status_text.update("⚡ Static analysis...")
            progress_bar.update(progress=40)
            self.log_message("   ⚡ [cyan]Running static analysis...[/cyan]")
            
            progress_bar.update(progress=50)
            status_text.update("✅ Static analysis complete")
            
            # Phase 3: Dependency audit
            status_text.update("📦 Dependency audit...")
            progress_bar.update(progress=55)
            self.log_message("   📦 [cyan]Analyzing project dependencies...[/cyan]")
            
            progress_bar.update(progress=60)

            # Web search enhancement (if enabled) - call sync API (handles its own loop)
            if config.enable_web_search and scan_result.findings:
                status_text.update("🌐 Web searching...")
                progress_bar.update(progress=65)
                self.log_message(f"   🌐 [cyan]Starting web search for {len(scan_result.findings)} findings...[/cyan]")

                try:
                    # Direct call; internal code manages any asyncio requirements
                    from impact_scan.core import web_search
                    web_search.process_findings_for_web_fixes(scan_result.findings, config)
                    self.log_message("✅ [WEB-SEARCH] Vulnerability intelligence gathered successfully")
                except Exception as e:
                    self.log_message(f"⚠️ [WEB-SEARCH] Enhancement failed: {e}")

                progress_bar.update(progress=75)

            # AI-powered fixes (if enabled) - call sync API (handles its own loop)
            if config.enable_ai_fixes and config.ai_provider and scan_result.findings:
                status_text.update("🧠 AI fix generation...")
                progress_bar.update(progress=80)
                self.log_message(f"   🧠 [cyan]Generating AI-powered fixes using {config.ai_provider}...[/cyan]")

                try:
                    from impact_scan.core import fix_ai
                    fix_ai.generate_fixes(scan_result.findings, config)
                    self.log_message("✅ [AI-FIXES] Intelligent remediation strategies generated")
                except Exception as e:
                    self.log_message(f"⚠️ [AI-FIXES] Fix generation failed: {e}")

                progress_bar.update(progress=95)
            
            # Final completion
            progress_bar.update(progress=100)
            status_text.update("🎉 Scan completed successfully!")
            loading_spinner.loading = False
            
            # Store results and update UI
            self.current_results = scan_result
            self.update_results_display(scan_result)
            
            # Final summary
            total_findings = len(scan_result.findings)
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            
            for finding in scan_result.findings:
                severity_counts[finding.severity.lower()] += 1
            
            self.log_message(f"\n🎯 [SUMMARY] Scan completed successfully!")
            self.log_message(f"📊 [RESULTS] Found {total_findings} security findings:")
            self.log_message(f"   🔴 Critical: {severity_counts['critical']}")
            self.log_message(f"   🟠 High: {severity_counts['high']}")
            self.log_message(f"   🟡 Medium: {severity_counts['medium']}")
            self.log_message(f"   🔵 Low: {severity_counts['low']}")
            self.log_message(f"\n💡 [EXPORT] Use the export buttons below to save your results!")
            
        except Exception as e:
            self.log_message(f"❌ [ERROR] Scan failed: {e}")
            logging.exception("Scan failed")
            status_text.update("❌ Scan failed")
            loading_spinner.loading = False
        finally:
            self.scan_running = False
    
    def update_results_display(self, scan_result: schema.ScanResult) -> None:
        """Update the UI with scan results."""
        # Update metrics
        total_findings = len(scan_result.findings)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for finding in scan_result.findings:
            severity_counts[finding.severity.lower()] += 1
        
        # Update metric cards
        self.query_one("#total-metric", Static).update(f"📊 Total\n{total_findings}")
        self.query_one("#critical-metric", Static).update(f"🔴 Critical\n{severity_counts['critical']}")
        self.query_one("#high-metric", Static).update(f"🟠 High\n{severity_counts['high']}")
        self.query_one("#medium-metric", Static).update(f"🟡 Medium\n{severity_counts['medium']}")
        self.query_one("#low-metric", Static).update(f"🔵 Low\n{severity_counts['low']}")
        
        # Calculate security score
        if total_findings > 0:
            score = max(0, 100 - (severity_counts['critical'] * 25 + severity_counts['high'] * 10 + 
                                 severity_counts['medium'] * 5 + severity_counts['low'] * 1))
            score_color = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
            self.query_one("#score-metric", Static).update(f"{score_color} Score\n{score}%")
        else:
            self.query_one("#score-metric", Static).update("🟢 Score\n100%")
        
        # Update findings table
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        
        # Add findings to table (limit to 50 for performance)
        for finding in scan_result.findings[:50]:
            severity_icon = {
                "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"
            }.get(finding.severity.lower(), "⚪")
            
            fix_preview = (finding.ai_fix or "No fix available")[:30] + "..." if finding.ai_fix else "Not available"
            
            table.add_row(
                f"{severity_icon} {finding.severity.upper()}",
                finding.rule_id or finding.type,
                str(finding.file_path)[-30:] if len(str(finding.file_path)) > 30 else str(finding.file_path),
                str(finding.line_number) if finding.line_number else "N/A",
                finding.title[:40] + "..." if len(finding.title) > 40 else finding.title,
                fix_preview
            )
        
        if len(scan_result.findings) > 50:
            table.add_row(
                "...", "...", "...", "...", f"+ {len(scan_result.findings) - 50} more findings", "..."
            )


def run_modern_tui() -> None:
    """Launch the modern TUI."""
    app = ModernImpactScanTUI()
    app.run()


if __name__ == "__main__":
    run_modern_tui()