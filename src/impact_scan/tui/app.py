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
    Grid,
    Horizontal,
    Vertical,
)
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    ProgressBar,
    Select,
    Static,
)

from impact_scan.core import aggregator, entrypoint, fix_ai
from impact_scan.core.html_report import save_report
from impact_scan.utils import profiles, schema

# Import modular TUI components
from .screens import APIKeysModal, PathBrowserModal
from .theme import MAIN_CSS

# ============================================================================
# MAIN APPLICATION
# ============================================================================


class UltraModernTUI(App):
    """Ultra-modern, minimal TUI inspired by OpenTUI."""

    CSS = MAIN_CSS  # Import from theme.py

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
    ]

    scan_running = reactive(False)
    current_config: Optional[schema.ScanConfig] = None
    current_results: Optional[schema.ScanResult] = None

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal(classes="layout"):
            # Left panel: Configuration & Progress
            with Vertical(classes="left-panel"):
                # Configuration
                with Container(classes="config-panel"):
                    yield Static("Configuration", classes="panel-header")

                    with Container(classes="config-section"):
                        with Horizontal(classes="config-row"):
                            yield Label("Path:", classes="config-label")
                            yield Input(
                                placeholder="/path/to/scan",
                                id="scan-path",
                                classes="config-input",
                            )
                            yield Button(
                                "...",
                                variant="primary",
                                id="browse-btn",
                                classes="mini-btn",
                            )

                    with Container(classes="config-section"):
                        with Horizontal(classes="config-row"):
                            yield Label("Profile:", classes="config-label")
                            yield Select(
                                options=[
                                    ("Comprehensive", "comprehensive"),
                                    ("Quick", "quick"),
                                    ("Standard", "standard"),
                                    ("CI/CD", "ci"),
                                ],
                                value="comprehensive",
                                id="profile-select",
                                classes="config-select",
                            )

                        with Horizontal(classes="config-row"):
                            yield Label("AI Provider:", classes="config-label")
                            yield Select(
                                options=[
                                    ("Auto-Detect", "auto"),
                                    ("OpenAI", "openai"),
                                    ("Anthropic", "anthropic"),
                                    ("Gemini", "gemini"),
                                    ("None", "none"),
                                ],
                                value="auto",
                                id="ai-select",
                                classes="config-select",
                            )
                            yield Button(
                                "K",
                                variant="default",
                                id="keys-btn",
                                classes="mini-btn",
                            )

                    yield Button(
                        "Start Scan",
                        variant="success",
                        id="start-scan-btn",
                        classes="scan-button",
                    )

                # Progress
                with Container(classes="progress-panel"):
                    yield Static("Activity", classes="panel-header")

                    with Container(classes="progress-bar-container"):
                        yield ProgressBar(total=100, show_eta=False, id="scan-progress")

                    yield Static("Ready", classes="status-line", id="status-text")

                    yield Log(
                        highlight=True,
                        classes="activity-log",
                        id="scan-log",
                        auto_scroll=True,
                    )

            # Right panel: Metrics & Findings
            with Vertical(classes="right-panel"):
                # Metrics
                with Container(classes="metrics-panel"):
                    yield Static("Security Metrics", classes="panel-header")

                    with Grid(classes="metrics-grid"):
                        with Container(classes="metric"):
                            yield Static("0", classes="metric-value", id="total-value")
                            yield Static("Total", classes="metric-label")

                        with Container(classes="metric metric-critical"):
                            yield Static(
                                "0", classes="metric-value", id="critical-value"
                            )
                            yield Static("Critical", classes="metric-label")

                        with Container(classes="metric metric-high"):
                            yield Static("0", classes="metric-value", id="high-value")
                            yield Static("High", classes="metric-label")

                        with Container(classes="metric metric-medium"):
                            yield Static("0", classes="metric-value", id="medium-value")
                            yield Static("Medium", classes="metric-label")

                        with Container(classes="metric metric-low"):
                            yield Static("0", classes="metric-value", id="low-value")
                            yield Static("Low", classes="metric-label")

                        with Container(classes="metric"):
                            yield Static(
                                "100", classes="metric-value", id="score-value"
                            )
                            yield Static("Score", classes="metric-label")

                # Findings
                with Container(classes="findings-panel"):
                    yield Static("Findings", classes="panel-header")

                    table = DataTable(
                        classes="findings-table",
                        id="findings-table",
                        zebra_stripes=True,
                    )
                    table.add_columns("Severity", "Type", "File", "Line", "Description")
                    yield table

                    with Horizontal(classes="export-bar"):
                        yield Button(
                            "Export HTML",
                            variant="success",
                            classes="export-btn",
                            id="export-html",
                        )
                        yield Button(
                            "Export SARIF",
                            variant="primary",
                            classes="export-btn",
                            id="export-sarif",
                        )

        yield Footer()

    def on_mount(self) -> None:
        """Initialize application."""
        self.query_one("#scan-path", Input).value = str(Path.cwd())
        self.log_message("System initialized")
        self.check_api_keys()

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

    def log_message(self, message: str) -> None:
        """Add timestamped message to log."""
        log_widget = self.query_one("#scan-log", Log)
        timestamp = time.strftime("%H:%M:%S")
        log_widget.write(f"[{timestamp}] {message}")

    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        handlers = {
            "start-scan-btn": self.action_start_scan,
            "browse-btn": self.action_browse_path,
            "keys-btn": self.action_manage_keys,
            "export-html": self.action_export_html,
            "export-sarif": self.action_export_sarif,
        }

        handler = handlers.get(event.button.id)
        if handler:
            handler()

    def action_start_scan(self) -> None:
        """Start security scan."""
        if self.scan_running:
            self.log_message("Scan already in progress")
            return

        path_input = self.query_one("#scan-path", Input)
        if not path_input.value.strip():
            self.log_message("Error: No path specified")
            return

        target_path = Path(path_input.value.strip())
        if not target_path.exists():
            self.log_message(f"Error: Path not found: {target_path}")
            return

        # Update status immediately
        status_text = self.query_one("#status-text", Static)
        status_text.update("Initializing...")
        self.log_message("Starting scan...")

        # Get configuration
        profile_select = self.query_one("#profile-select", Select)
        ai_select = self.query_one("#ai-select", Select)

        try:
            profile = profiles.get_profile(profile_select.value)

            # Override AI provider if specified
            ai_provider = ai_select.value
            if ai_provider == "none":
                profile.enable_ai_fixes = False
                profile.ai_provider = None
            elif ai_provider != "auto":
                profile.ai_provider = ai_provider

            # Create configuration - USE root_path NOT target_path
            config = profiles.create_config_from_profile(
                root_path=target_path,  # FIX: Use root_path
                profile=profile,
                api_keys=schema.APIKeys(),
            )

            self.current_config = config
            self.log_message("Configuration loaded")

            # Launch scan worker
            self.run_scan_worker(config)

        except Exception as e:
            self.log_message(f"Configuration error: {e}")
            logging.error(f"Scan config failed: {e}", exc_info=True)
            status_text.update("Error")

    def action_browse_path(self) -> None:
        """Browse for target directory."""
        current_path = Path(self.query_one("#scan-path", Input).value or Path.cwd())

        def on_path_selected(path: Optional[str]) -> None:
            if path:
                self.query_one("#scan-path", Input).value = path
                self.log_message(f"Selected: {path}")

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
        log_widget = self.query_one("#scan-log", Log)
        log_widget.clear()
        self.log_message("Log cleared")

    @work(exclusive=True, thread=True)
    def run_scan_worker(self, config: schema.ScanConfig) -> None:
        """Run security scan in background."""
        try:
            self.scan_running = True
            progress_bar = self.query_one("#scan-progress", ProgressBar)
            status_text = self.query_one("#status-text", Static)

            progress_bar.update(total=100, progress=0)

            self.log_message(f"Target: {config.root_path}")
            self.log_message(f"Profile: {config.min_severity.value}")
            self.log_message(f"AI: {config.ai_provider or 'disabled'}")

            # Phase 1: Entry point detection
            status_text.update("Analyzing codebase...")
            progress_bar.update(progress=10)

            scan_result = entrypoint.run_scan(config)

            progress_bar.update(progress=40)
            status_text.update("Static analysis complete")

            if scan_result.entry_points:
                self.log_message(f"Found {len(scan_result.entry_points)} entry points")

            progress_bar.update(progress=60)

            # Web search (if enabled)
            if config.enable_web_search and scan_result.findings:
                status_text.update("Web intelligence...")
                progress_bar.update(progress=70)

                try:
                    from impact_scan.core import web_search

                    web_search.process_findings_for_web_fixes(
                        scan_result.findings, config
                    )
                    self.log_message("Web intelligence complete")
                except Exception as e:
                    self.log_message(f"Web search failed: {e}")

                progress_bar.update(progress=80)

            # AI fixes (if enabled)
            if config.enable_ai_fixes and config.ai_provider and scan_result.findings:
                status_text.update("Generating AI fixes...")
                progress_bar.update(progress=85)

                try:
                    fix_ai.generate_fixes(scan_result.findings, config)
                    self.log_message("AI fixes generated")
                except Exception as e:
                    self.log_message(f"AI fix generation failed: {e}")

                progress_bar.update(progress=95)

            # Complete
            progress_bar.update(progress=100)
            status_text.update("Scan complete")

            # Store and display results
            self.current_results = scan_result
            self.update_results_display(scan_result)

            # Summary
            total = len(scan_result.findings)
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in scan_result.findings:
                severity_counts[finding.severity.value.lower()] += 1

            self.log_message(f"Scan complete: {total} findings")
            self.log_message(
                f"Critical: {severity_counts['critical']}, High: {severity_counts['high']}, Medium: {severity_counts['medium']}, Low: {severity_counts['low']}"
            )

        except Exception as e:
            self.log_message(f"Scan failed: {e}")
            logging.exception("Scan execution failed")
            status_text.update("Scan failed")
        finally:
            self.scan_running = False

    def update_results_display(self, scan_result: schema.ScanResult) -> None:
        """Update UI with scan results."""
        # Calculate metrics
        total = len(scan_result.findings)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in scan_result.findings:
            severity_counts[finding.severity.value.lower()] += 1

        # Update metric values
        self.query_one("#total-value", Static).update(str(total))
        self.query_one("#critical-value", Static).update(
            str(severity_counts["critical"])
        )
        self.query_one("#high-value", Static).update(str(severity_counts["high"]))
        self.query_one("#medium-value", Static).update(str(severity_counts["medium"]))
        self.query_one("#low-value", Static).update(str(severity_counts["low"]))

        # Calculate security score
        if total > 0:
            score = max(
                0,
                100
                - (
                    severity_counts["critical"] * 25
                    + severity_counts["high"] * 10
                    + severity_counts["medium"] * 5
                    + severity_counts["low"] * 1
                ),
            )
            self.query_one("#score-value", Static).update(str(score))
        else:
            self.query_one("#score-value", Static).update("100")

        # Update findings table
        table = self.query_one("#findings-table", DataTable)
        table.clear()

        # Add findings (limit to 100)
        for finding in scan_result.findings[:100]:
            severity_display = finding.severity.value.upper()

            file_path_str = str(finding.file_path)
            short_path = (
                f"...{file_path_str[-25:]}"
                if len(file_path_str) > 28
                else file_path_str
            )

            description = finding.description or finding.title or "No description"
            short_desc = (
                description[:50] + "..." if len(description) > 50 else description
            )

            table.add_row(
                severity_display,
                finding.vuln_id or finding.rule_id or "N/A",
                short_path,
                str(finding.line_number) if finding.line_number else "N/A",
                short_desc,
            )

        if len(scan_result.findings) > 100:
            table.add_row(
                "...", "...", "...", "...", f"+ {len(scan_result.findings) - 100} more"
            )

        # Force refresh
        table.refresh()
        self.refresh()


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
