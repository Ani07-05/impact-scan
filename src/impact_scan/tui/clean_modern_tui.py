#!/usr/bin/env python3
"""
Impact Scan - Clean Modern TUI
Inspired by k9s, lazygit, btop

Clean, functional, professional design.
"""

import logging
import os
import time
import webbrowser
from pathlib import Path
from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Grid, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button, DataTable, DirectoryTree, Footer, Header, Input, Label,
    LoadingIndicator, Log, ProgressBar, Select, Static
)

from impact_scan.utils import schema, profiles
from impact_scan.core import entrypoint, aggregator, fix_ai
from impact_scan.core.html_report import save_report


# ============================================================================
# MODALS
# ============================================================================

class PathBrowserModal(ModalScreen):
    """Simple path browser."""

    DEFAULT_CSS = """
    PathBrowserModal {
        align: center middle;
    }

    .path-dialog {
        width: 80;
        height: 35;
        background: $panel;
        border: thick $primary;
    }

    .path-header {
        dock: top;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
    }

    .path-info {
        dock: top;
        height: 1;
        padding: 0 1;
        background: $surface;
        color: $text-muted;
    }

    .path-tree {
        height: 1fr;
        margin: 1;
    }

    .path-actions {
        dock: bottom;
        height: 4;
        padding: 1;
        align: center middle;
        background: $surface;
    }

    .path-btn {
        margin: 0 1;
        min-width: 12;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
        Binding("enter", "select", "Select"),
    ]

    def __init__(self, current_path: Path = None) -> None:
        super().__init__()
        self.current_path = current_path or Path.cwd()
        self.selected_path = self.current_path

    def compose(self) -> ComposeResult:
        with Container(classes="path-dialog"):
            yield Static("Select Directory", classes="path-header")
            yield Static(f"Current: {self.selected_path}", classes="path-info", id="path-info")
            yield DirectoryTree(str(self.current_path), classes="path-tree", id="path-tree")
            with Horizontal(classes="path-actions"):
                yield Button("Back", variant="default", classes="path-btn", id="back-btn")
                yield Button("Select", variant="success", classes="path-btn", id="select-btn")
                yield Button("Cancel", variant="default", classes="path-btn", id="cancel-btn")

    @on(DirectoryTree.DirectorySelected)
    def on_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        self.selected_path = Path(event.path)
        self.query_one("#path-info").update(f"Current: {self.selected_path}")

    @on(Button.Pressed, "#select-btn")
    def select_path(self) -> None:
        self.dismiss(str(self.selected_path))

    @on(Button.Pressed, "#back-btn")
    def go_back(self) -> None:
        """Go to parent directory."""
        if self.selected_path.parent != self.selected_path:
            self.selected_path = self.selected_path.parent
            tree = self.query_one("#path-tree", DirectoryTree)
            tree.path = str(self.selected_path)
            tree.reload()
            self.query_one("#path-info").update(f"Current: {self.selected_path}")

    @on(Button.Pressed, "#cancel-btn")
    def cancel_path(self) -> None:
        self.dismiss(None)

    def action_dismiss(self) -> None:
        self.dismiss(None)

    def action_select(self) -> None:
        self.dismiss(str(self.selected_path))


class APIKeysModal(ModalScreen):
    """API key configuration modal."""

    DEFAULT_CSS = """
    APIKeysModal {
        align: center middle;
    }

    .keys-dialog {
        width: 70;
        height: 25;
        background: $panel;
        border: thick $primary;
    }

    .keys-header {
        dock: top;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
    }

    .keys-content {
        height: 1fr;
        padding: 2;
    }

    .key-row {
        height: 3;
        margin: 0 0 1 0;
    }

    .key-label {
        width: 12;
        text-align: right;
        margin-right: 1;
    }

    .key-input {
        width: 1fr;
        margin-right: 1;
    }

    .key-status {
        width: 10;
        text-align: center;
    }

    .keys-actions {
        dock: bottom;
        height: 4;
        padding: 1;
        align: center middle;
        background: $surface;
    }

    .keys-btn {
        margin: 0 1;
        min-width: 12;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(classes="keys-dialog"):
            yield Static("API Keys", classes="keys-header")

            with Vertical(classes="keys-content"):
                with Horizontal(classes="key-row"):
                    yield Label("OpenAI", classes="key-label")
                    yield Input(
                        placeholder="sk-proj-...",
                        password=True,
                        value=os.getenv("OPENAI_API_KEY", ""),
                        id="openai-key",
                        classes="key-input"
                    )
                    yield Static(self._status("OPENAI_API_KEY"),
                               classes="key-status", id="openai-status")

                with Horizontal(classes="key-row"):
                    yield Label("Anthropic", classes="key-label")
                    yield Input(
                        placeholder="sk-ant-...",
                        password=True,
                        value=os.getenv("ANTHROPIC_API_KEY", ""),
                        id="anthropic-key",
                        classes="key-input"
                    )
                    yield Static(self._status("ANTHROPIC_API_KEY"),
                               classes="key-status", id="anthropic-status")

                with Horizontal(classes="key-row"):
                    yield Label("Gemini", classes="key-label")
                    yield Input(
                        placeholder="AIza...",
                        password=True,
                        value=os.getenv("GOOGLE_API_KEY", ""),
                        id="gemini-key",
                        classes="key-input"
                    )
                    yield Static(self._status("GOOGLE_API_KEY"),
                               classes="key-status", id="gemini-status")

            with Horizontal(classes="keys-actions"):
                yield Button("Save", variant="success", classes="keys-btn", id="save-btn")
                yield Button("Clear", variant="warning", classes="keys-btn", id="clear-btn")
                yield Button("Cancel", variant="default", classes="keys-btn", id="cancel-btn")

    def _status(self, env_var: str) -> str:
        key = os.getenv(env_var)
        return "[green]Active[/green]" if key and len(key) > 10 else "[dim]Missing[/dim]"

    @on(Button.Pressed, "#save-btn")
    def save_keys(self) -> None:
        keys = {
            "OPENAI_API_KEY": self.query_one("#openai-key", Input).value.strip(),
            "ANTHROPIC_API_KEY": self.query_one("#anthropic-key", Input).value.strip(),
            "GOOGLE_API_KEY": self.query_one("#gemini-key", Input).value.strip(),
        }

        saved = 0
        for var, val in keys.items():
            if val:
                os.environ[var] = val
                saved += 1

        for var, sid in [
            ("OPENAI_API_KEY", "#openai-status"),
            ("ANTHROPIC_API_KEY", "#anthropic-status"),
            ("GOOGLE_API_KEY", "#gemini-status")
        ]:
            self.query_one(sid).update(self._status(var))

        self.dismiss({"saved": saved})

    @on(Button.Pressed, "#clear-btn")
    def clear_keys(self) -> None:
        for var in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]:
            if var in os.environ:
                del os.environ[var]

        self.query_one("#openai-key", Input).value = ""
        self.query_one("#anthropic-key", Input).value = ""
        self.query_one("#gemini-key", Input).value = ""

        self.query_one("#openai-status").update("[dim]Missing[/dim]")
        self.query_one("#anthropic-status").update("[dim]Missing[/dim]")
        self.query_one("#gemini-status").update("[dim]Missing[/dim]")

        self.dismiss({"cleared": True})

    @on(Button.Pressed, "#cancel-btn")
    def cancel(self) -> None:
        self.dismiss(None)


# ============================================================================
# MAIN APP
# ============================================================================

class CleanModernTUI(App):
    """Clean, modern TUI inspired by k9s/lazygit/btop."""

    CSS = """
    /* Base theme */
    Screen {
        background: $background;
        color: $text;
    }

    /* Main layout */
    #main-container {
        height: 1fr;
        layout: grid;
        grid-size: 2;
        grid-columns: 1fr 2fr;
        grid-gutter: 0;
    }

    /* Left panel */
    #left-panel {
        height: 1fr;
        width: 1fr;
        border-right: solid $primary;
        background: $surface;
    }

    /* Config section */
    #config-section {
        height: auto;
        padding: 1;
        border-bottom: solid $primary-darken-2;
    }

    .section-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    .input-row {
        height: 3;
        margin-bottom: 1;
    }

    .input-label {
        width: 10;
        text-align: right;
        margin-right: 1;
    }

    #scan-path-input {
        width: 1fr;
        margin-right: 1;
    }

    #browse-btn {
        width: 8;
    }

    #profile-select {
        width: 1fr;
        margin-right: 1;
    }

    #ai-select {
        width: 1fr;
        margin-right: 1;
    }

    #keys-btn {
        width: 8;
    }

    #start-scan-btn {
        width: 1fr;
        height: 3;
        margin-top: 1;
    }

    /* Progress section */
    #progress-section {
        height: 1fr;
        padding: 1;
    }

    #scan-progress {
        height: 1;
        margin-bottom: 1;
    }

    #status-text {
        height: 1;
        content-align: center middle;
        margin-bottom: 1;
        text-style: italic;
    }

    #scan-log {
        height: 1fr;
        border: solid $primary-darken-2;
    }

    /* Right panel */
    #right-panel {
        height: 1fr;
        width: 1fr;
        background: $background;
    }

    /* Metrics section */
    #metrics-section {
        height: 10;
        padding: 1;
        border-bottom: solid $primary-darken-2;
    }

    #metrics-grid {
        grid-size: 6;
        grid-gutter: 1;
        height: 1fr;
    }

    .metric-box {
        height: 1fr;
        border: solid $primary;
        content-align: center middle;
        text-align: center;
    }

    .metric-value {
        text-style: bold;
    }

    .metric-label {
        color: $text-muted;
    }

    .metric-critical {
        border: solid $error;
    }

    .metric-critical .metric-value {
        color: $error;
    }

    .metric-high {
        border: solid $warning;
    }

    .metric-high .metric-value {
        color: $warning;
    }

    .metric-medium {
        border: solid yellow;
    }

    .metric-medium .metric-value {
        color: yellow;
    }

    .metric-low {
        border: solid $accent;
    }

    .metric-low .metric-value {
        color: $accent;
    }

    /* Findings section */
    #findings-section {
        height: 1fr;
        padding: 1;
    }

    #findings-table {
        height: 1fr;
        margin-bottom: 1;
    }

    .export-bar {
        height: 3;
    }

    .export-btn {
        margin-right: 1;
    }
    """

    TITLE = "Impact Scan"
    SUB_TITLE = "Security Analysis Platform"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "scan", "Scan"),
        Binding("b", "browse", "Browse"),
        Binding("k", "keys", "Keys"),
        Binding("c", "clear", "Clear"),
    ]

    scan_running = reactive(False)
    current_config: Optional[schema.ScanConfig] = None
    current_results: Optional[schema.ScanResult] = None

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="main-container"):
            # Left panel
            with Vertical(id="left-panel"):
                # Config section
                with Container(id="config-section"):
                    yield Static("Configuration", classes="section-title")

                    with Horizontal(classes="input-row"):
                        yield Label("Path", classes="input-label")
                        yield Input(placeholder="/path/to/scan", id="scan-path-input")
                        yield Button("Browse", variant="primary", id="browse-btn")

                    with Horizontal(classes="input-row"):
                        yield Label("Profile", classes="input-label")
                        yield Select(
                            options=[
                                ("Comprehensive", "comprehensive"),
                                ("Quick", "quick"),
                                ("Standard", "standard"),
                                ("CI/CD", "ci"),
                            ],
                            value="comprehensive",
                            id="profile-select"
                        )

                    with Horizontal(classes="input-row"):
                        yield Label("AI", classes="input-label")
                        yield Select(
                            options=[
                                ("Auto", "auto"),
                                ("OpenAI", "openai"),
                                ("Anthropic", "anthropic"),
                                ("Gemini", "gemini"),
                                ("None", "none"),
                            ],
                            value="auto",
                            id="ai-select"
                        )
                        yield Button("Keys", variant="default", id="keys-btn")

                    yield Button("Start Scan", variant="success", id="start-scan-btn")

                # Progress section
                with Container(id="progress-section"):
                    yield Static("Activity", classes="section-title")
                    yield ProgressBar(total=100, show_eta=False, id="scan-progress")
                    yield Static("Ready", id="status-text")
                    yield Log(highlight=True, id="scan-log", auto_scroll=True)

            # Right panel
            with Vertical(id="right-panel"):
                # Metrics section
                with Container(id="metrics-section"):
                    yield Static("Security Metrics", classes="section-title")

                    with Grid(id="metrics-grid"):
                        with Vertical(classes="metric-box"):
                            yield Static("0", classes="metric-value", id="total-val")
                            yield Static("Total", classes="metric-label")

                        with Vertical(classes="metric-box metric-critical"):
                            yield Static("0", classes="metric-value", id="critical-val")
                            yield Static("Critical", classes="metric-label")

                        with Vertical(classes="metric-box metric-high"):
                            yield Static("0", classes="metric-value", id="high-val")
                            yield Static("High", classes="metric-label")

                        with Vertical(classes="metric-box metric-medium"):
                            yield Static("0", classes="metric-value", id="medium-val")
                            yield Static("Medium", classes="metric-label")

                        with Vertical(classes="metric-box metric-low"):
                            yield Static("0", classes="metric-value", id="low-val")
                            yield Static("Low", classes="metric-label")

                        with Vertical(classes="metric-box"):
                            yield Static("100", classes="metric-value", id="score-val")
                            yield Static("Score", classes="metric-label")

                # Findings section
                with Container(id="findings-section"):
                    yield Static("Findings", classes="section-title")

                    table = DataTable(id="findings-table", zebra_stripes=True)
                    table.add_columns("Severity", "Type", "File", "Line", "Description")
                    yield table

                    with Horizontal(classes="export-bar"):
                        yield Button("Export HTML", variant="success", classes="export-btn", id="export-html-btn")
                        yield Button("Export SARIF", variant="primary", classes="export-btn", id="export-sarif-btn")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize app."""
        self.query_one("#scan-path-input", Input).value = str(Path.cwd())
        self.log_msg("System ready")
        self.check_keys()

    def check_keys(self) -> None:
        """Check API keys."""
        keys = schema.APIKeys()
        providers = []
        if keys.openai:
            providers.append("OpenAI")
        if keys.anthropic:
            providers.append("Anthropic")
        if keys.gemini:
            providers.append("Gemini")

        if providers:
            self.log_msg(f"AI providers: {', '.join(providers)}")
        else:
            self.log_msg("No API keys (press K)")

    def log_msg(self, msg: str) -> None:
        """Log message."""
        log_widget = self.query_one("#scan-log", Log)
        ts = time.strftime("%H:%M:%S")
        log_widget.write(f"[{ts}] {msg}")

    @on(Button.Pressed, "#start-scan-btn")
    def on_scan_pressed(self) -> None:
        self.action_scan()

    @on(Button.Pressed, "#browse-btn")
    def on_browse_pressed(self) -> None:
        self.action_browse()

    @on(Button.Pressed, "#keys-btn")
    def on_keys_pressed(self) -> None:
        self.action_keys()

    @on(Button.Pressed, "#export-html-btn")
    def on_export_html_pressed(self) -> None:
        self.export_html()

    @on(Button.Pressed, "#export-sarif-btn")
    def on_export_sarif_pressed(self) -> None:
        self.export_sarif()

    def action_scan(self) -> None:
        """Start scan."""
        if self.scan_running:
            self.log_msg("Scan in progress")
            return

        path_input = self.query_one("#scan-path-input", Input)
        if not path_input.value.strip():
            self.log_msg("Error: No path")
            return

        target = Path(path_input.value.strip())
        if not target.exists():
            self.log_msg(f"Error: Path not found")
            return

        self.query_one("#status-text", Static).update("Starting...")
        self.log_msg("Starting scan")

        profile_sel = self.query_one("#profile-select", Select)
        ai_sel = self.query_one("#ai-select", Select)

        try:
            profile = profiles.get_profile(profile_sel.value)

            ai_prov = ai_sel.value
            if ai_prov == "none":
                profile.enable_ai_fixes = False
                profile.ai_provider = None
            elif ai_prov != "auto":
                profile.ai_provider = ai_prov

            config = profiles.create_config_from_profile(
                root_path=target,
                profile=profile,
                api_keys=schema.APIKeys()
            )

            self.current_config = config
            self.log_msg("Config loaded")
            self.scan_worker(config)

        except Exception as e:
            self.log_msg(f"Error: {e}")
            logging.exception("Config error")

    def action_browse(self) -> None:
        """Browse path."""
        current = Path(self.query_one("#scan-path-input", Input).value or Path.cwd())

        def on_selected(path: Optional[str]) -> None:
            if path:
                self.query_one("#scan-path-input", Input).value = path
                self.log_msg(f"Selected: {path}")

        self.push_screen(PathBrowserModal(current), on_selected)

    def action_keys(self) -> None:
        """Manage keys."""
        def on_done(result: Optional[dict]) -> None:
            if result and "saved" in result:
                self.log_msg(f"Saved {result['saved']} key(s)")
                self.check_keys()
            elif result and "cleared" in result:
                self.log_msg("Keys cleared")

        self.push_screen(APIKeysModal(), on_done)

    def action_clear(self) -> None:
        """Clear log."""
        self.query_one("#scan-log", Log).clear()
        self.log_msg("Cleared")

    def export_html(self) -> None:
        """Export HTML."""
        if not self.current_results:
            self.log_msg("No results")
            return

        try:
            ts = int(time.time())
            out = Path.cwd() / f"impact_report_{ts}.html"
            save_report(self.current_results, str(out))
            self.log_msg(f"Saved: {out.name}")
            webbrowser.open(f"file://{out.absolute()}")
        except Exception as e:
            self.log_msg(f"Export failed: {e}")

    def export_sarif(self) -> None:
        """Export SARIF."""
        if not self.current_results:
            self.log_msg("No results")
            return

        try:
            ts = int(time.time())
            out = Path.cwd() / f"impact_sarif_{ts}.json"
            aggregator.save_to_sarif(self.current_results, out)
            self.log_msg(f"Saved: {out.name}")
        except Exception as e:
            self.log_msg(f"SARIF failed: {e}")

    @work(exclusive=True, thread=True)
    def scan_worker(self, config: schema.ScanConfig) -> None:
        """Run scan."""
        try:
            self.scan_running = True
            progress = self.query_one("#scan-progress", ProgressBar)
            status = self.query_one("#status-text", Static)

            progress.update(total=100, progress=0)

            self.log_msg(f"Target: {config.root_path}")
            self.log_msg(f"Profile: {config.min_severity.value}")

            status.update("Analyzing...")
            progress.update(progress=10)

            result = entrypoint.run_scan(config)

            progress.update(progress=40)
            status.update("Analysis complete")

            if result.entry_points:
                self.log_msg(f"Found {len(result.entry_points)} entry points")

            progress.update(progress=60)

            if config.enable_web_search and result.findings:
                status.update("Web search...")
                progress.update(progress=70)
                try:
                    from impact_scan.core import web_search
                    web_search.process_findings_for_web_fixes(result.findings, config)
                    self.log_msg("Web search done")
                except Exception as e:
                    self.log_msg(f"Web search failed: {e}")
                progress.update(progress=80)

            if config.enable_ai_fixes and config.ai_provider and result.findings:
                status.update("AI fixes...")
                progress.update(progress=85)
                try:
                    fix_ai.generate_fixes(result.findings, config)
                    self.log_msg("AI fixes done")
                except Exception as e:
                    self.log_msg(f"AI failed: {e}")
                progress.update(progress=95)

            progress.update(progress=100)
            status.update("Complete")

            self.current_results = result
            self.update_display(result)

            total = len(result.findings)
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in result.findings:
                counts[f.severity.value.lower()] += 1

            self.log_msg(f"Done: {total} findings")
            self.log_msg(f"Crit:{counts['critical']} High:{counts['high']} Med:{counts['medium']} Low:{counts['low']}")

        except Exception as e:
            self.log_msg(f"Scan failed: {e}")
            logging.exception("Scan failed")
            status.update("Failed")
        finally:
            self.scan_running = False

    def update_display(self, result: schema.ScanResult) -> None:
        """Update display with results."""
        total = len(result.findings)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for f in result.findings:
            counts[f.severity.value.lower()] += 1

        self.query_one("#total-val", Static).update(str(total))
        self.query_one("#critical-val", Static).update(str(counts['critical']))
        self.query_one("#high-val", Static).update(str(counts['high']))
        self.query_one("#medium-val", Static).update(str(counts['medium']))
        self.query_one("#low-val", Static).update(str(counts['low']))

        if total > 0:
            score = max(0, 100 - (
                counts['critical'] * 25 +
                counts['high'] * 10 +
                counts['medium'] * 5 +
                counts['low'] * 1
            ))
            self.query_one("#score-val", Static).update(str(score))
        else:
            self.query_one("#score-val", Static).update("100")

        table = self.query_one("#findings-table", DataTable)
        table.clear()

        for f in result.findings[:100]:
            sev = f.severity.value.upper()
            file_str = str(f.file_path)
            short_file = f"...{file_str[-22:]}" if len(file_str) > 25 else file_str
            desc = f.description or f.title or "No desc"
            short_desc = desc[:45] + "..." if len(desc) > 45 else desc

            table.add_row(
                sev,
                f.vuln_id or f.rule_id or "N/A",
                short_file,
                str(f.line_number) if f.line_number else "N/A",
                short_desc
            )

        if len(result.findings) > 100:
            table.add_row("...", "...", "...", "...", f"+{len(result.findings)-100} more")

        table.refresh()
        self.refresh()


def run_clean_modern_tui() -> None:
    """Launch clean modern TUI."""
    logging.basicConfig(
        level="INFO",
        handlers=[logging.FileHandler("tui_debug.log", mode="w")],
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    app = CleanModernTUI()
    app.run()


if __name__ == "__main__":
    run_clean_modern_tui()
