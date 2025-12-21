#!/usr/bin/env python3
"""
Impact Scan - Ultra-Modern TUI (OpenTUI-inspired)

Clean, professional, minimal design.
No emojis. Pure functionality.
"""

import logging
import time
import webbrowser
from pathlib import Path
from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import (
    Container,
    Horizontal,
    Vertical,
    VerticalScroll,
)
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Footer,
    Header,
    Static,
    TabbedContent,
    TabPane,
)

from impact_scan.core import aggregator, entrypoint, fix_ai
from impact_scan.core.html_report import save_report
from impact_scan.utils import profiles, schema

# Import modular TUI components
from .screens import APIKeysModal, PathBrowserModal
from .theme import MAIN_CSS
from .widgets import (
    OverviewPanel,
    CodebaseTree,
    ScanInfo,
    ProgressLog,
    ConfigPanel,
    RichFindingsTable,
    RichMetricsPanel,
    ReportsPanel,
)

# ============================================================================
# MAIN APPLICATION
# ============================================================================


class UltraModernTUI(App):
    """Ultra-modern, minimal TUI inspired by OpenTUI."""

    # Combine MAIN_CSS with custom overrides for better layout
    CSS = MAIN_CSS + """
    /* Tab styling */
    #main-tabs {
        height: 1fr;
        background: $background;
    }

    TabbedContent {
        border: none;
    }

    Tabs {
        background: $surface;
        color: $text;
    }

    Tab {
        background: $surface;
        color: $text-muted;
        text-style: none;
        padding: 0 2;
    }

    Tab.-active {
        background: $primary;
        color: white;
        text-style: bold;
    }

    Tab:hover {
        background: $primary-darken-1;
        color: white;
    }

    TabPane {
        padding: 0;
        background: $background;
    }

    /* Overview container - wide enough for ASCII art */
    #overview-container {
        width: 100%;
        min-width: 85;
        background: $surface;
        padding: 0;
        height: 1fr;
    }

    /* Findings scroll container */
    #findings-scroll {
        height: 1fr;
        background: $background;
        padding: 1;
    }

    .metrics-container {
        height: auto;
        margin: 0 0 1 0;
    }

    .findings-container {
        height: 1fr;
        padding: 2;
        border: round $primary;
        background: $surface-lighten-1;
    }
    """

    # Define color scheme from theme
    COLORS = {
        "primary": "#00A8E8",
        "secondary": "#6C757D",
        "accent": "#00D9FF",
        "error": "#FF4757",
        "warning": "#FFA502",
        "success": "#2ED573",
        "background": "#1E1E2E",
        "surface": "#2A2A3E",
    }

    TITLE = "Impact Scan | Security Analysis Platform"
    SUB_TITLE = "AI-Powered Vulnerability Detection"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "start_scan", "Scan"),
        Binding("b", "browse_path", "Browse"),
        Binding("k", "manage_keys", "Keys"),
        Binding("c", "clear_log", "Clear"),
        Binding("tab", "switch_tab", "Switch Tab", show=False),
        Binding("f", "show_findings", "Findings"),
        Binding("r", "show_reports", "Reports"),
    ]

    scan_running = reactive(False)
    current_config: Optional[schema.ScanConfig] = None
    current_results: Optional[schema.ScanResult] = None

    def compose(self) -> ComposeResult:
        yield Header()

        # Browser-style tabs for different views
        with TabbedContent(initial="overview-tab", id="main-tabs"):
            # Tab 1: Overview (config, tree, activity)
            with TabPane("Overview", id="overview-tab"):
                with Container(id="overview-container"):
                    yield OverviewPanel()

            # Tab 2: Findings (metrics and findings table)
            with TabPane("Findings", id="findings-tab"):
                with VerticalScroll(id="findings-scroll"):
                    # Metrics
                    with Container(classes="metrics-container"):
                        yield RichMetricsPanel()

                    # Findings
                    with Container(classes="findings-container"):
                        yield Static("Security Findings", classes="panel-header")
                        yield RichFindingsTable()

            # Tab 3: Reports (export and download)
            with TabPane("Reports", id="reports-tab"):
                with Container(id="reports-container"):
                    yield ReportsPanel()

        yield Footer()

    def on_mount(self) -> None:
        """Initialize application."""
        # Set initial scan path in ConfigPanel (but don't load into tree yet)
        config_panel = self.query_one(ConfigPanel)
        config_panel.set_scan_path(str(Path.cwd()))

        self.log_message("System initialized", "green")
        self.check_api_keys()

        # Don't load the path into tree yet - let the AnimatedBanner show
        # The tree will be loaded when user browses or starts a scan

    def check_api_keys(self) -> None:
        """Check available API keys."""
        api_keys = schema.APIKeys()
        providers = []

        if api_keys.openai:
            providers.append("OpenAI")
        if api_keys.anthropic:
            providers.append("Anthropic")
        if api_keys.gemini:
            providers.append("Gemini")

        if providers:
            self.log_message(f"AI: {', '.join(providers)}")
        else:
            self.log_message("No API keys configured (press 'k')")

    def log_message(self, message: str, style: str = "cyan") -> None:
        """Add timestamped message to log."""
        try:
            log_widget = self.query_one(ProgressLog)
            log_widget.log(message, style)
        except Exception as e:
            # Fallback if log widget not available
            logging.info(f"Log message: {message}")

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        handlers = {
            "start-scan-btn": self.action_start_scan,
            "browse-btn": self.action_browse_path,
            "keys-btn": self.action_manage_keys,
            "export-html": self.action_export_html,
            "export-sarif": self.action_export_sarif,
            "export-html-btn": self.action_reports_html,
            "export-sarif-btn": self.action_reports_sarif,
            "export-md-btn": self.action_reports_markdown,
        }

        handler = handlers.get(event.button.id)
        if handler:
            handler()

    def action_start_scan(self) -> None:
        """Start security scan."""
        if self.scan_running:
            self.log_message("Scan already in progress")
            return

        # Get configuration from ConfigPanel
        config_panel = self.query_one(ConfigPanel)
        scan_path = config_panel.get_scan_path()

        if not scan_path.strip():
            self.log_message("Error: No path specified", "red")
            return

        target_path = Path(scan_path.strip())
        if not target_path.exists():
            self.log_message(f"Error: Path not found: {target_path}", "red")
            return

        self.log_message("Starting scan...", "green")

        # Load path into tree if not already loaded
        codebase_tree = self.query_one(CodebaseTree)
        if codebase_tree.current_path != target_path:
            try:
                stats = codebase_tree.load_path(target_path)
                scan_info = self.query_one(ScanInfo)
                scan_info.update_stats(stats)
                self.log_message(f"Loaded {stats.get('total_files', 0)} files", "cyan")
            except Exception as e:
                self.log_message(f"Error loading path: {e}", "red")

        # Get configuration
        profile_name = config_panel.get_profile()
        ai_provider_name = config_panel.get_ai_provider()
        ai_validation = config_panel.get_ai_validation()

        try:
            profile = profiles.get_profile(profile_name)

            # Override AI provider if specified
            if ai_provider_name == "none":
                profile.enable_ai_fixes = False
                profile.ai_provider = None
            elif ai_provider_name != "auto":
                profile.ai_provider = ai_provider_name

            # Create configuration
            config = profiles.create_config_from_profile(
                root_path=target_path,
                profile=profile,
                api_keys=schema.APIKeys(),
            )

            # Override AI validation if checkbox is set
            config.enable_ai_validation = ai_validation

            self.current_config = config
            self.log_message("Configuration loaded", "cyan")

            # Update AI status in ScanInfo
            scan_info = self.query_one(ScanInfo)
            scan_info.update_ai_status(ai_provider_name, config.enable_ai_fixes)

            # Launch scan worker
            self.run_scan_worker(config)

        except Exception as e:
            self.log_message(f"Configuration error: {e}", "red")
            logging.error(f"Scan config failed: {e}", exc_info=True)

    def action_browse_path(self) -> None:
        """Browse for target directory."""
        config_panel = self.query_one(ConfigPanel)
        current_path = Path(config_panel.get_scan_path() or Path.cwd())

        def on_path_selected(path: Optional[str]) -> None:
            if path:
                config_panel.set_scan_path(path)
                self.log_message(f"Selected: {path}", "green")

                # Load the new path into codebase tree
                codebase_tree = self.query_one(CodebaseTree)
                try:
                    stats = codebase_tree.load_path(Path(path))
                    scan_info = self.query_one(ScanInfo)
                    scan_info.update_stats(stats)
                    self.log_message(f"Loaded {stats.get('total_files', 0)} files", "cyan")
                except Exception as e:
                    self.log_message(f"Error loading path: {e}", "red")

        self.push_screen(PathBrowserModal(current_path), on_path_selected)

    def action_manage_keys(self) -> None:
        """Manage API keys."""

        def on_keys_updated(result: Optional[dict]) -> None:
            if result and result.get("action") == "saved":
                count = result.get("count", 0)
                self.log_message(f"Saved {count} API key(s)")
                self.check_api_keys()
            elif result and result.get("action") == "cleared":
                self.log_message("API keys cleared")

        self.push_screen(APIKeysModal(), on_keys_updated)

    def action_export_html(self) -> None:
        """Export HTML report."""
        if not self.current_results:
            self.log_message("No results to export")
            return

        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_report_{timestamp}.html"

            self.log_message("Generating HTML report...")
            save_report(self.current_results, str(output_file))
            self.log_message(f"Saved: {output_file.name}")

            webbrowser.open(f"file://{output_file.absolute()}")

        except Exception as e:
            self.log_message(f"Export failed: {e}")
            logging.exception("HTML export failed")

    def action_export_sarif(self) -> None:
        """Export SARIF report."""
        if not self.current_results:
            self.log_message("No results to export")
            return

        try:
            timestamp = int(time.time())
            output_file = Path.cwd() / f"impact_scan_sarif_{timestamp}.json"

            self.log_message("Generating SARIF report...")
            aggregator.save_to_sarif(self.current_results, output_file)
            self.log_message(f"Saved: {output_file.name}")

        except Exception as e:
            self.log_message(f"SARIF export failed: {e}")
            logging.exception("SARIF export failed")

    def action_clear_log(self) -> None:
        """Clear activity log."""
        try:
            log_widget = self.query_one(ProgressLog)
            log_widget.clear()
            self.log_message("Log cleared", "cyan")
        except Exception as e:
            logging.error(f"Failed to clear log: {e}")

    def action_switch_tab(self) -> None:
        """Switch between Overview and Findings tabs."""
        tabs = self.query_one(TabbedContent)
        if tabs.active == "overview-tab":
            tabs.active = "findings-tab"
        else:
            tabs.active = "overview-tab"

    def action_show_findings(self) -> None:
        """Switch to Findings tab."""
        tabs = self.query_one(TabbedContent)
        tabs.active = "findings-tab"

    def action_show_reports(self) -> None:
        """Switch to Reports tab."""
        tabs = self.query_one(TabbedContent)
        tabs.active = "reports-tab"

    def action_reports_html(self) -> None:
        """Export HTML from Reports tab."""
        try:
            reports_panel = self.query_one(ReportsPanel)
            reports_panel.export_html()
        except Exception as e:
            logging.error(f"HTML export from Reports tab failed: {e}")

    def action_reports_sarif(self) -> None:
        """Export SARIF from Reports tab."""
        try:
            reports_panel = self.query_one(ReportsPanel)
            reports_panel.export_sarif()
        except Exception as e:
            logging.error(f"SARIF export from Reports tab failed: {e}")

    def action_reports_markdown(self) -> None:
        """Export Markdown from Reports tab."""
        try:
            reports_panel = self.query_one(ReportsPanel)
            reports_panel.export_markdown()
        except Exception as e:
            logging.error(f"Markdown export from Reports tab failed: {e}")

    def _show_findings_and_update(self, scan_result: schema.ScanResult) -> None:
        """Switch to findings tab and update results (called from worker thread)."""
        # First switch to the tab so widgets are mounted
        tabs = self.query_one(TabbedContent)
        tabs.active = "findings-tab"

        # Give the tab a moment to mount widgets, then update
        # Use set_timer to delay the update slightly
        self.set_timer(0.1, lambda: self.update_results_display(scan_result))

    @work(exclusive=True, thread=True)
    def run_scan_worker(self, config: schema.ScanConfig) -> None:
        """Run security scan in background."""
        try:
            self.scan_running = True

            self.log_message(f"Target: {config.root_path}", "cyan")
            self.log_message(f"Profile: {config.min_severity.value}", "cyan")
            self.log_message(f"AI: {config.ai_provider or 'disabled'}", "cyan")

            # Phase 1: Entry point detection
            self.log_message("Analyzing codebase...", "yellow")

            scan_result = entrypoint.run_scan(config)

            self.log_message("Static analysis complete", "green")

            if scan_result.entry_points:
                self.log_message(f"Found {len(scan_result.entry_points)} entry points", "cyan")

            # Web search (if enabled)
            if config.enable_web_search and scan_result.findings:
                self.log_message("Running web intelligence...", "yellow")

                try:
                    from impact_scan.core import web_search

                    web_search.process_findings_for_web_fixes(
                        scan_result.findings, config
                    )
                    self.log_message("Web intelligence complete", "green")
                except Exception as e:
                    self.log_message(f"Web search failed: {e}", "red")

            # AI fixes (if enabled)
            if config.enable_ai_fixes and config.ai_provider and scan_result.findings:
                self.log_message("Generating AI fixes...", "yellow")

                try:
                    fix_ai.generate_fixes(scan_result.findings, config)
                    self.log_message("AI fixes generated", "green")
                except Exception as e:
                    self.log_message(f"AI fix generation failed: {e}", "red")

            # Complete
            self.log_message("Scan complete!", "green")

            # Store results
            self.current_results = scan_result

            # Summary
            total = len(scan_result.findings)
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in scan_result.findings:
                severity_counts[finding.severity.value.lower()] += 1

            self.log_message(f"Total findings: {total}", "purple")
            if severity_counts['critical'] > 0:
                self.log_message(f"Critical: {severity_counts['critical']}", "red")
            if severity_counts['high'] > 0:
                self.log_message(f"High: {severity_counts['high']}", "orange")
            if severity_counts['medium'] > 0:
                self.log_message(f"Medium: {severity_counts['medium']}", "yellow")
            if severity_counts['low'] > 0:
                self.log_message(f"Low: {severity_counts['low']}", "cyan")

            # Auto-switch to findings tab and update display
            if total > 0:
                self.log_message("Switching to Findings tab...", "cyan")
                # Use call_from_thread to safely update UI from worker thread
                self.call_from_thread(self._show_findings_and_update, scan_result)
            else:
                self.log_message("No findings detected", "green")

        except Exception as e:
            self.log_message(f"Scan failed: {e}", "red")
            logging.exception("Scan execution failed")
        finally:
            self.scan_running = False

    def update_results_display(self, scan_result: schema.ScanResult) -> None:
        """Update UI with scan results."""
        try:
            # Update metrics panel
            try:
                metrics_panel = self.query_one(RichMetricsPanel)
                metrics_panel.update_metrics(scan_result)
                logging.info("Metrics panel updated successfully")
            except Exception as e:
                logging.warning(f"Could not update metrics panel: {e}")

            # Update findings table
            try:
                findings_table = self.query_one(RichFindingsTable)
                findings_table.update_findings(scan_result)
                logging.info("Findings table updated successfully")
            except Exception as e:
                logging.warning(f"Could not update findings table: {e}")

            # Update reports panel
            try:
                reports_panel = self.query_one(ReportsPanel)
                reports_panel.update_statistics(scan_result)
                logging.info("Reports panel updated successfully")
            except Exception as e:
                logging.warning(f"Could not update reports panel: {e}")

            # Force refresh
            self.refresh()

        except Exception as e:
            self.log_message(f"Error updating results: {e}", "red")
            logging.exception("Failed to update results display")


def run_ultra_modern_tui() -> None:
    """Launch the ultra-modern TUI."""
    logging.basicConfig(
        level="INFO",
        handlers=[logging.FileHandler("tui_debug.log", mode="w")],
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    app = UltraModernTUI()
    app.run()


if __name__ == "__main__":
    run_ultra_modern_tui()
