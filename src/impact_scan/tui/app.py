"""
Main TUI application for Impact Scan with compact, terminal-friendly layout.
"""
import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional, List

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import (
    Button, DataTable, DirectoryTree, Footer, Header, Input, Label,
    ProgressBar, RichLog, Static, Select, Switch, LoadingIndicator,
    TabbedContent, TabPane
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.screen import ModalScreen

from impact_scan.utils import schema
from impact_scan.core import entrypoint, aggregator, fix_ai
from impact_scan.core.html_report import save_report
from impact_scan.utils import profiles


class PathBrowserScreen(ModalScreen):
    """Compact modal for path selection."""
    
    CSS = """
    PathBrowserScreen {
        align: center middle;
    }

    #path-dialog {
        width: 80;
        height: 30;
        background: $panel;
        border: thick $primary;
        padding: 1;
    }

    #path-tree {
        height: 22;
        border: solid $primary-lighten-2;
    }

    .modal-buttons {
        dock: bottom;
        height: 3;
        align: center middle;
    }

    .modal-buttons Button {
        margin: 0 1;
        width: 12;
    }

    #current-path {
        background: $surface-lighten-1;
        padding: 0 1;
        text-style: bold;
        margin-bottom: 1;
    }
    """
    
    def __init__(self, current_path: Path = None):
        super().__init__()
        self.current_path = current_path or Path.cwd()
        self.selected_path = self.current_path

    def compose(self) -> ComposeResult:
        with Vertical(id="path-dialog"):
            yield Static("🗂️ Full Filesystem Browser - Navigate to any directory", classes="title")
            yield Static(f"📁 {self.selected_path}", id="current-path")
            # Start from root filesystem to allow full navigation
            tree = DirectoryTree("/", id="path-tree")
            # Try to expand to current path initially if possible
            yield tree
            with Horizontal(classes="modal-buttons"):
                yield Button("Home", id="home-btn")
                yield Button("Select", variant="success", id="select-btn")
                yield Button("Cancel", id="cancel-btn")
    
    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        self.selected_path = Path(event.path)
        self.query_one("#current-path").update(f"📁 {self.selected_path}")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "select-btn":
            self.dismiss(self.selected_path or self.current_path)
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
        elif event.button.id == "home-btn":
            # Navigate to home directory
            home_path = Path.home()
            self.selected_path = home_path
            self.query_one("#current-path").update(f"📁 {self.selected_path}")
            # Refresh tree to show home directory
            tree = self.query_one("#path-tree", DirectoryTree)
            try:
                tree.reload_node(tree.root)
            except:
                pass  # If reload fails, that's ok


class APIKeyScreen(ModalScreen):
    """Compact API key configuration modal."""
    
    CSS = """
    APIKeyScreen {
        align: center middle;
    }
    
    #api-dialog {
        width: 50;
        height: 16;
        background: $panel;
        border: thick $primary;
        padding: 1;
    }
    
    .key-grid {
        grid-size: 2;
        grid-gutter: 1;
        height: auto;
        margin: 1 0;
    }
    
    .key-input {
        width: 100%;
    }
    
    .modal-buttons {
        dock: bottom;
        height: 3;
        align: center middle;
    }
    
    .modal-buttons Button {
        margin: 0 1;
        width: 10;
    }
    """
    
    def compose(self) -> ComposeResult:
        with Vertical(id="api-dialog"):
            yield Static("🔑 API Keys")
            with Grid(classes="key-grid"):
                yield Static("OpenAI:")
                yield Input(placeholder="sk-...", password=True, id="openai-key", 
                           value=os.getenv("OPENAI_API_KEY", ""))
                yield Static("Claude:")
                yield Input(placeholder="sk-ant-...", password=True, id="anthropic-key",
                           value=os.getenv("ANTHROPIC_API_KEY", ""))
                yield Static("Gemini:")
                yield Input(placeholder="AIza...", password=True, id="gemini-key",
                           value=os.getenv("GOOGLE_API_KEY", ""))
            
            with Horizontal(classes="modal-buttons"):
                yield Button("Save", variant="success", id="save-keys")
                yield Button("Cancel", id="cancel-keys")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-keys":
            # Save keys to environment
            if self.query_one("#openai-key", Input).value.strip():
                os.environ["OPENAI_API_KEY"] = self.query_one("#openai-key", Input).value.strip()
            if self.query_one("#anthropic-key", Input).value.strip():
                os.environ["ANTHROPIC_API_KEY"] = self.query_one("#anthropic-key", Input).value.strip()
            if self.query_one("#gemini-key", Input).value.strip():
                os.environ["GOOGLE_API_KEY"] = self.query_one("#gemini-key", Input).value.strip()
            self.dismiss(True)
        elif event.button.id == "cancel-keys":
            self.dismiss(False)


class ImpactScanTUI(App):
    """A modern TUI for Impact Scan."""

    CSS_PATH = "app.css"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "scan", "Scan"),
        ("b", "browse", "Browse"),
        ("k", "keys", "Keys"),
        ("c", "clear", "Clear"),
        Binding("t", "toggle_sidebar", "Toggle Sidebar", show=True),
    ]
    
    show_sidebar = reactive(True)
    scan_running = reactive(False)

    def watch_show_sidebar(self, show_sidebar: bool) -> None:
        """Called when show_sidebar is modified."""
        self.query_one("#sidebar").display = show_sidebar

    def action_toggle_sidebar(self) -> None:
        """Toggle the sidebar."""
        self.show_sidebar = not self.show_sidebar

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("Configuration", classes="title")
                with Vertical(classes="config-group"):
                    yield Label("Scan Path")
                    with Horizontal():
                        yield Input(placeholder="Path", id="scan-path", classes="config-item")
                        yield Button("📁", id="browse-btn", classes="config-btn")
                with Vertical(classes="config-group"):
                    yield Label("Profile")
                    yield Select(
                        [(p, p.lower()) for p in ["Comprehensive", "Quick", "Standard", "CI"]],
                        value="comprehensive",
                        id="profile-select",
                        classes="config-item",
                    )
                with Vertical(classes="config-group"):
                    yield Label("AI Provider")
                    yield Select(
                        [("Auto", "auto"), ("OpenAI", "openai"), ("Anthropic", "anthropic"),
                         ("Gemini", "gemini"), ("None", "none")],
                        value="auto",
                        id="ai-select",
                        classes="config-item",
                    )
                with Vertical(classes="config-group"):
                    yield Label("Stack Overflow Citations")
                    with Horizontal(classes="switch-container"):
                        yield Switch(value=True, id="stackoverflow-switch")
                        yield Static("Enable SO fixes", classes="switch-label")
                with Horizontal(id="action-buttons"):
                    yield Button("Scan", variant="success", id="start-scan")
                    yield Button("API Keys", id="api-keys-btn")

            with Vertical(id="main-content"):
                with Horizontal(id="stats-bar"):
                    yield Static("Total: 0", classes="stat total", id="total")
                    yield Static("Crit: 0", classes="stat critical", id="critical")
                    yield Static("High: 0", classes="stat high", id="high")
                    yield Static("Med: 0", classes="stat medium", id="medium")
                    yield Static("Low: 0", classes="stat low", id="low")
                
                table = DataTable(id="results-table", zebra_stripes=True, cursor_type="row")
                table.add_columns("SEV", "Type", "File", "Line", "Description")
                yield table

                with TabbedContent(id="details-tabs"):
                    with TabPane("Logs", id="log-tab"):
                        yield RichLog(highlight=True, markup=True, id="scan-log", auto_scroll=True)
                    with TabPane("Details", id="details-tab"):
                        yield RichLog(id="details-log", highlight=True)
        
        yield Footer()

    def on_mount(self) -> None:
        """Initialize on mount."""
        self.current_results = None
        self.current_config = None
        self.query_one("#scan-path", Input).value = str(Path.cwd())
        
        # Note: Column widths will be set by CSS if needed
        
        self.log_message("Ready. Press 's' to scan or 't' to toggle sidebar.")
        self.check_api_keys()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection to show details."""
        details_log = self.query_one("#details-log", RichLog)
        details_log.clear()
        
        if self.current_results and self.current_results.findings:
            try:
                finding = self.current_results.findings[event.cursor_row]
                details_log.write(f"[bold]Finding Details[/bold]\n")
                details_log.write(f"ID: {finding.vuln_id}")
                details_log.write(f"Severity: {finding.severity.value}")
                details_log.write(f"File: {finding.file_path}:{finding.line_number}")
                details_log.write(f"\n[bold]Description[/bold]\n{finding.description}\n")
                
                # Display available fixes
                if finding.ai_fix:
                    details_log.write(f"[bold green]AI Generated Fix[/bold green]\n")
                    details_log.write(f"```diff\n{finding.ai_fix}\n```\n")
                
                if finding.web_fix:
                    details_log.write(f"[bold blue]Web Research Fix[/bold blue]\n")
                    details_log.write(f"{finding.web_fix}\n")
                
                if finding.fix_suggestion:
                    details_log.write(f"[bold yellow]Fix Suggestion[/bold yellow]\n")
                    details_log.write(f"{finding.fix_suggestion}\n")

                self.query_one("#details-tabs").active = "details-tab"
            except IndexError:
                details_log.write("Could not retrieve finding details.")

    def check_api_keys(self) -> None:
        """Check for available API keys."""
        keys = schema.APIKeys()
        available = []
        if keys.openai: available.append("OpenAI")
        if keys.anthropic: available.append("Anthropic")
        if keys.gemini: available.append("Gemini")
        
        if available:
            self.log_message(f"AI providers available: [bold]{', '.join(available)}[/bold]")
        else:
            self.log_message("[yellow]No API keys found. Press 'k' to configure.[/yellow]")
    
    def log_message(self, message: str) -> None:
        """Log a message to the scan log."""
        self.query_one("#scan-log", RichLog).write(f"[{time.strftime('%H:%M:%S')}] {message}")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id
        if button_id == "start-scan":
            self.action_scan()
        elif button_id == "browse-btn":
            self.action_browse()
        elif button_id == "api-keys-btn":
            self.action_keys()
    
    def action_scan(self) -> None:
        """Start a new scan."""
        if self.scan_running:
            self.log_message("[bold red]A scan is already in progress.[/bold red]")
            return
        
        path_str = self.query_one("#scan-path", Input).value
        scan_path = Path(path_str) if path_str else Path.cwd()
        
        if not scan_path.exists() or not scan_path.is_dir():
            self.log_message(f"[bold red]Error: Invalid path '{scan_path}'.[/bold red]")
            return
        
        try:
            profile_name = self.query_one("#profile-select", Select).value
            profile = profiles.get_profile(profile_name)

            ai_provider = self.query_one("#ai-select", Select).value
            if ai_provider == "none":
                profile.enable_ai_fixes = False
                profile.ai_provider = None
            elif ai_provider != "auto":
                profile.ai_provider = ai_provider

            # Get Stack Overflow setting from switch
            enable_stackoverflow = self.query_one("#stackoverflow-switch", Switch).value
            profile.enable_stackoverflow_scraper = enable_stackoverflow

            config = profiles.create_config_from_profile(
                root_path=scan_path,
                profile=profile,
                api_keys=schema.APIKeys()
            )
            
            self.current_config = config
            self.log_message(f"Starting scan on '{scan_path}' with '{profile_name}' profile...")
            if enable_stackoverflow:
                self.log_message("[cyan]Stack Overflow citations enabled[/cyan]")
            else:
                self.log_message("[dim]Stack Overflow citations disabled[/dim]")

            # Clear previous results
            self.query_one("#results-table", DataTable).clear()
            self.query_one("#details-log", RichLog).clear()
            self.reset_stats()

            # Use run_worker to run scan asynchronously in Textual
            self.run_worker(self.run_scan(config), exclusive=True)
            
        except Exception as e:
            self.log_message(f"[bold red]Failed to start scan: {e}[/bold red]")
            logging.error(f"Scan configuration failed: {e}", exc_info=True)

    def reset_stats(self):
        self.query_one("#total").update("Total: 0")
        self.query_one("#critical").update("Crit: 0")
        self.query_one("#high").update("High: 0")
        self.query_one("#medium").update("Med: 0")
        self.query_one("#low").update("Low: 0")

    async def run_scan(self, config: schema.ScanConfig) -> None:
        """Run scan asynchronously and update UI."""
        self.scan_running = True
        status_bar = self.query_one("#stats-bar")
        loading_indicator = LoadingIndicator()
        await status_bar.mount(loading_indicator)

        try:
            self.log_message("Running dependency and static analysis...")
            result = await asyncio.to_thread(entrypoint.run_scan, config)
            
            if not result or not result.findings:
                self.log_message("Scan complete. No findings.")
                self.update_results(result)
                return

            self.log_message(f"Analysis complete. Found {len(result.findings)} potential issues.")
            self.update_results(result)

            if config.enable_web_search:
                self.log_message("Searching for context online with modern intelligence...")
                await entrypoint.enrich_findings_async(result.findings, config)
                self.log_message("Modern web intelligence complete.")

            if config.enable_ai_fixes and config.ai_provider:
                self.log_message("Generating AI-powered fixes...")
                await asyncio.to_thread(
                    fix_ai.generate_fixes,
                    result.findings, config
                )
                self.log_message("AI fix generation complete.")
            
            self.current_results = result
            self.update_results(result) # Refresh with fixes
            self.log_message("[bold green]Scan finished successfully.[/bold green]")

        except Exception as e:
            self.log_message(f"[bold red]Scan failed: {e}[/bold red]")
            logging.error(f"Scan execution failed: {e}", exc_info=True)
        finally:
            self.scan_running = False
            await loading_indicator.remove()
    
    def update_results(self, result: Optional[schema.ScanResult]) -> None:
        """Update results display."""
        table = self.query_one("#results-table", DataTable)
        table.clear()

        if not result or not result.findings:
            self.reset_stats()
            return
        
        findings = result.findings
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            by_sev[f.severity.value] += 1
        
        self.query_one("#total").update(f"Total: {len(findings)}")
        self.query_one("#critical").update(f"Crit: {by_sev['critical']}")
        self.query_one("#high").update(f"High: {by_sev['high']}")
        self.query_one("#medium").update(f"Med: {by_sev['medium']}")
        self.query_one("#low").update(f"Low: {by_sev['low']}")
        
        sev_map = {
            schema.Severity.CRITICAL: "[red]CRIT[/red]",
            schema.Severity.HIGH: "[orange]HIGH[/orange]",
            schema.Severity.MEDIUM: "[yellow]MED[/yellow]",
            schema.Severity.LOW: "[blue]LOW[/blue]",
        }
        
        for f in findings:
            file_path_str = str(f.file_path)
            short_path = f"...{file_path_str[-22:]}" if len(file_path_str) > 25 else file_path_str
            
            table.add_row(
                sev_map.get(f.severity, "UNKN"),
                f.vuln_id,
                short_path,
                str(f.line_number) if hasattr(f, 'line_number') else "-",
                f.description.splitlines()[0],
            )
    
    def action_browse(self) -> None:
        """Browse for a directory."""
        def on_select(path: Optional[Path]):
            if path:
                self.query_one("#scan-path", Input).value = str(path)
                self.log_message(f"Selected path: '{path}'")
        
        current_path = Path(self.query_one("#scan-path", Input).value)
        self.push_screen(PathBrowserScreen(current_path=current_path), on_select)
    
    def action_keys(self) -> None:
        """Open API key configuration screen."""
        def on_save(saved: bool):
            if saved:
                self.log_message("API keys updated.")
                self.check_api_keys()
        
        self.push_screen(APIKeyScreen(), on_save)
    
    def export(self, format_type: str) -> None:
        """Export scan results."""
        if not self.current_results:
            self.log_message("[yellow]No results to export.[/yellow]")
            return
        
        try:
            timestamp = int(time.time())
            filename = f"impact-scan-report-{timestamp}"
            
            if format_type == "html":
                path = Path(f"{filename}.html")
                save_report(self.current_results, path)
            elif format_type == "sarif":
                path = Path(f"{filename}.sarif")
                aggregator.save_to_sarif(self.current_results, path)
            else:
                self.log_message(f"[red]Unknown export format: {format_type}[/red]")
                return
            
            self.log_message(f"Successfully exported results to [bold]'{path}'[/bold]")
        except Exception as e:
            self.log_message(f"[bold red]Export failed: {e}[/bold red]")
            logging.error(f"Export failed: {e}", exc_info=True)
    
    def action_clear(self) -> None:
        """Clear logs and results."""
        self.query_one("#scan-log", RichLog).clear()
        self.query_one("#details-log", RichLog).clear()
        self.query_one("#results-table", DataTable).clear()
        self.reset_stats()
        self.log_message("Cleared logs and results.")

def run_tui() -> None:
    """Run the TUI application."""
    logging.basicConfig(
        level="INFO",
        handlers=[
            logging.FileHandler("tui_debug.log", mode="w"),
        ],
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    app = ImpactScanTUI()
    app.run()

if __name__ == "__main__":
    run_tui()