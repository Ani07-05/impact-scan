#!/usr/bin/env python3
"""
Impact Scan - Modern TUI with Animated ASCII Art
Beautiful, professional interface with the animated IMPACT SCAN banner.
"""

import logging
from pathlib import Path
from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import Footer, TabbedContent, TabPane, Static, Button

from impact_scan.core import entrypoint
from impact_scan.utils import profiles, schema

# Import the beautiful widgets with ASCII art
from .widgets.overview_panel import OverviewPanel, CodebaseTree, ScanInfo, ProgressLog, ConfigPanel
from .widgets.rich_findings_table import RichFindingsTable
from .widgets.reports_panel import ReportsPanel
from .screens import APIKeysModal, PathBrowserModal


class ModernImpactScanTUI(App):
    """Modern TUI with animated ASCII art branding."""

    CSS = """
    Screen {
        background: #0D1117;
    }

    Header {
        display: none;
    }

    Footer {
        background: #161B22;
        color: #7D8590;
        border-top: solid #30363D;
    }

    TabbedContent {
        height: 100%;
        background: #0D1117;
    }

    TabbedContent ContentSwitcher {
        background: #0D1117;
        height: 100%;
    }

    Tabs {
        background: #161B22;
        border-bottom: solid #30363D;
    }

    Tab {
        background: #161B22;
        color: #7D8590;
        border-right: solid #30363D;
        padding: 0 2;
    }

    Tab:hover {
        background: #1C2128;
        color: #00D4FF;
    }

    Tab.-active {
        background: #0D1117;
        color: #00D4FF;
        text-style: bold;
    }

    TabPane {
        background: #0D1117;
        padding: 0;
        height: 100%;
    }
    """

    TITLE = "Impact Scan | AI Security Analysis Platform"
    SUB_TITLE = "Modern Security Scanner with Animated ASCII Art"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("s", "start_scan", "Scan", show=True),
        Binding("b", "browse_path", "Browse", show=False),
        Binding("1", "switch_tab('overview')", "Overview", show=False),
        Binding("2", "switch_tab('findings')", "Findings", show=False),
        Binding("3", "switch_tab('reports')", "Reports", show=False),
    ]

    scan_running: bool = False
    current_config: Optional[schema.ScanConfig] = None
    current_results: Optional[schema.ScanResult] = None

    def compose(self) -> ComposeResult:
        """Create the beautiful modern UI."""
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                yield OverviewPanel()

            with TabPane("Findings", id="findings"):
                yield RichFindingsTable()

            with TabPane("Reports", id="reports"):
                yield ReportsPanel()

        yield Footer()

    def on_mount(self) -> None:
        """Initialize the app when mounted."""
        from .config import get_config_manager
        config_mgr = get_config_manager()

        if config_mgr.state.first_run:
            # Show onboarding flow
            self._show_onboarding_flow()
        else:
            # Normal startup
            self.log_message("Impact Scan v0.3.0 initialized", "green")
            self.log_message("Ready to scan codebases for security vulnerabilities", "cyan")

    def _show_onboarding_flow(self) -> None:
        """Display onboarding screens as modals."""
        from .onboarding import WelcomeScreen
        from .config import get_config_manager

        def on_onboarding_complete(result) -> None:
            config_mgr = get_config_manager()
            config_mgr.mark_tutorial_complete()
            self.log_message("Impact Scan v0.3.0 initialized", "green")
            self.log_message("Setup complete! Ready to scan", "cyan")

        self.push_screen(WelcomeScreen(), on_onboarding_complete)

    def log_message(self, message: str, style: str = "cyan") -> None:
        """Log a message to the activity log."""
        try:
            overview = self.query_one(OverviewPanel)
            log_widget = overview.query_one(ProgressLog)
            log_widget.log(message, style)
        except Exception as e:
            logging.error(f"Failed to log message: {e}")

    @on(TabbedContent.TabActivated)
    def tab_changed(self, event: TabbedContent.TabActivated) -> None:
        """Handle tab changes."""
        tab_id = event.tab.id
        if tab_id:
            self.log_message(f"Switched to {event.tab.label} view", "cyan")

    def action_switch_tab(self, tab_id: str) -> None:
        """Switch to a specific tab."""
        try:
            tabs = self.query_one(TabbedContent)
            tabs.active = tab_id
        except Exception as e:
            logging.error(f"Failed to switch tab to '{tab_id}': {e}")

    @on(Button.Pressed, "#browse-btn")
    def on_browse_button(self, event: Button.Pressed) -> None:
        """Handle browse button press."""
        self.action_browse_path()

    @on(Button.Pressed, "#keys-btn")
    def on_keys_button(self, event: Button.Pressed) -> None:
        """Handle keys button press."""
        self.push_screen(APIKeysModal())

    @on(Button.Pressed, "#start-scan-btn")
    def on_start_scan_button(self, event: Button.Pressed) -> None:
        """Handle start scan button press."""
        self.action_start_scan()

    @on(Button.Pressed, "#export-html-btn")
    def on_export_html_button(self, event: Button.Pressed) -> None:
        """Handle HTML export button press."""
        self.action_export_html()

    @on(Button.Pressed, "#export-sarif-btn")
    def on_export_sarif_button(self, event: Button.Pressed) -> None:
        """Handle SARIF export button press."""
        self.action_export_sarif()

    @on(Button.Pressed, "#export-md-btn")
    def on_export_md_button(self, event: Button.Pressed) -> None:
        """Handle Markdown export button press."""
        self.action_export_markdown()

    def action_browse_path(self) -> None:
        """Browse for a codebase path."""
        def on_path_selected(path: str) -> None:
            """Handle path selection from modal."""
            try:
                overview = self.query_one(OverviewPanel)
                config_panel = overview.query_one(ConfigPanel)
                config_panel.set_scan_path(path)
                self.log_message(f"Selected: {Path(path).name}", "green")
            except Exception as e:
                logging.error(f"Failed to set scan path to '{path}': {e}")
                self.log_message(f"Error: Failed to set path", "red")

        self.push_screen(PathBrowserModal(), on_path_selected)

    @work(exclusive=True)
    async def action_start_scan(self) -> None:
        """Start a security scan."""
        if self.scan_running:
            self.log_message("Scan already in progress", "yellow")
            return

        try:
            self.scan_running = True
            self.log_message("Starting security scan...", "green")

            # Get config from ConfigPanel
            overview = self.query_one(OverviewPanel)
            config_panel = overview.query_one(ConfigPanel)

            # Get scan path
            scan_path = Path(config_panel.get_path())
            if not scan_path.exists():
                self.log_message(f"Path not found: {scan_path}", "red")
                self.scan_running = False
                return

            self.log_message(f"Scanning: {scan_path}", "cyan")

            # Load codebase into tree
            tree = overview.query_one(CodebaseTree)
            stats = tree.load_path(scan_path)
            self.log_message(f"Found {stats.get('code_files', 0)} code files", "green")

            # Update scan info
            scan_info = overview.query_one(ScanInfo)
            scan_info.update_stats(stats)

            # Get profile and AI provider
            profile_name = config_panel.get_profile()
            ai_provider = config_panel.get_ai_provider()
            ai_validation = config_panel.get_ai_validation()

            self.log_message(f"Profile: {profile_name}", "cyan")
            self.log_message(f"AI Provider: {ai_provider}", "cyan")

            # Update AI status
            scan_info.update_ai_status(ai_provider, ai_provider != "none")

            # Create scan config using the profile
            profile = profiles.get_profile(profile_name)
            
            # Override AI provider if specified
            if ai_provider == "none":
                profile.enable_ai_fixes = False
                profile.ai_provider = None
            elif ai_provider != "auto":
                profile.ai_provider = ai_provider
            
            # Create configuration using the same method as CLI
            config = profiles.create_config_from_profile(
                root_path=scan_path,
                profile=profile,
                api_keys=schema.APIKeys(),
            )

            self.current_config = config

            # Run scan (this is synchronous but @work makes it non-blocking)
            self.log_message("Running static analysis...", "cyan")

            # Log enabled features
            if config.enable_stackoverflow_scraper:
                self.log_message("Stack Overflow scraping: Enabled", "cyan")
            if config.enable_ai_fixes:
                self.log_message("AI fixes: Enabled", "cyan")

            results = entrypoint.run_scan(config)

            # Enrich findings with AI fixes and additional intelligence
            if results.findings:
                self.log_message(f"Found {len(results.findings)} issues", "green")

                # Stack Overflow solutions (already done in run_scan if enabled)
                if config.enable_stackoverflow_scraper:
                    so_count = sum(1 for f in results.findings if f.stackoverflow_fixes)
                    if so_count > 0:
                        self.log_message(f"✓ Found {so_count} Stack Overflow solutions", "green")
                    else:
                        self.log_message("⚠ No Stack Overflow solutions (likely rate limited)", "yellow")
                        self.log_message("Try: Use AI provider for automated fixes instead", "cyan")

                # AI fix generation (async enrichment)
                if config.enable_ai_fixes and config.ai_provider:
                    # Count SO-guided vs pure AI fixes
                    so_guided_count = sum(1 for f in results.findings if f.stackoverflow_fixes)

                    if so_guided_count > 0:
                        self.log_message(f"Generating AI fixes ({so_guided_count} guided by Stack Overflow)...", "yellow")
                    else:
                        self.log_message("Generating AI fixes...", "yellow")

                    try:
                        await entrypoint.enrich_findings_async(results.findings, config)
                        ai_fix_count = sum(1 for f in results.findings if f.ai_fix)
                        if ai_fix_count > 0:
                            if so_guided_count > 0:
                                self.log_message(f"✓ Generated {ai_fix_count} AI fixes ({so_guided_count} based on Stack Overflow)", "green")
                            else:
                                self.log_message(f"✓ Generated {ai_fix_count} AI fixes", "green")
                    except Exception as e:
                        self.log_message(f"AI fix generation failed: {str(e)[:80]}", "red")
                        logging.exception("AI fix generation error")

                self.log_message(f"Scan complete! Total findings: {len(results.findings)}", "green")
            else:
                self.log_message("Scan complete but no findings detected", "yellow")
                self.log_message(f"Scanned files: {results.scanned_files}", "yellow")
                self.log_message(f"Scan duration: {results.scan_duration:.2f}s", "yellow")

            self.current_results = results

            # Update findings table
            findings_table = self.query_one(RichFindingsTable)
            findings_table.update_findings(results)

            # Update reports panel with results
            reports_panel = self.query_one(ReportsPanel)
            reports_panel.set_scan_result(results)

            # Switch to findings tab
            self.action_switch_tab("findings")

        except Exception as e:
            self.log_message(f"Scan failed: {str(e)}", "red")
            logging.exception("Scan error")
            import traceback
            tb = traceback.format_exc()
            # Log first 500 chars of traceback
            for line in tb.split('\n')[:10]:
                if line.strip():
                    self.log_message(line[:100], "red")

        finally:
            self.scan_running = False

    def action_export_html(self) -> None:
        """Export HTML report."""
        try:
            reports_panel = self.query_one(ReportsPanel)
            output_file = reports_panel.export_html()

            if output_file:
                self.log_message(f"HTML report saved: {output_file.name}", "green")
        except Exception as e:
            self.log_message(f"HTML export failed: {e}", "red")
            logging.exception("HTML export error")

    def action_export_sarif(self) -> None:
        """Export SARIF report."""
        try:
            reports_panel = self.query_one(ReportsPanel)
            output_file = reports_panel.export_sarif()

            if output_file:
                self.log_message(f"SARIF report saved: {output_file.name}", "green")
        except Exception as e:
            self.log_message(f"SARIF export failed: {e}", "red")
            logging.exception("SARIF export error")

    def action_export_markdown(self) -> None:
        """Export Markdown report."""
        try:
            reports_panel = self.query_one(ReportsPanel)
            output_file = reports_panel.export_markdown()

            if output_file:
                self.log_message(f"Markdown report saved: {output_file.name}", "green")
        except Exception as e:
            self.log_message(f"Markdown export failed: {e}", "red")
            logging.exception("Markdown export error")


def run_modern_tui():
    """Run the modern TUI with animated ASCII art."""
    app = ModernImpactScanTUI()
    app.run()


if __name__ == "__main__":
    run_modern_tui()
