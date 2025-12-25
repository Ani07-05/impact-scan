"""
Beautiful TUI Onboarding Experience for Impact-Scan

First-run setup wizard with API key configuration.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Header, Footer, Static, Input, Button, Label
from textual.binding import Binding
from textual.screen import Screen
from pathlib import Path
import os
import keyring


class WelcomeScreen(Screen):
    """Welcome screen with ASCII art."""

    BINDINGS = [
        Binding("enter", "continue", "Continue"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static("""
[bold cyan]
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗            ║
║    ██║████╗ ████║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝            ║
║    ██║██╔████╔██║██████╔╝███████║██║        ██║               ║
║    ██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║        ██║               ║
║    ██║██║ ╚═╝ ██║██║     ██║  ██║╚██████╗   ██║               ║
║    ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝               ║
║                                                               ║
║              ███████╗ ██████╗ █████╗ ███╗   ██╗               ║
║              ██╔════╝██╔════╝██╔══██╗████╗  ██║               ║
║              ███████╗██║     ███████║██╔██╗ ██║               ║
║              ╚════██║██║     ██╔══██║██║╚██╗██║               ║
║              ███████║╚██████╗██║  ██║██║ ╚████║               ║
║              ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
[/bold cyan]

[bold white]Welcome to Impact-Scan v0.3.0[/bold white]

[dim]AI-Powered Security Scanner for Code[/dim]

[bold green]What Impact-Scan does:[/bold green]
  • Finds security vulnerabilities in your code
  • Uses AI to understand logic bugs & auth issues
  • Provides fixes with Stack Overflow citations
  • Generates beautiful security reports

[bold yellow]Let's get you set up![/bold yellow]

[dim]Press [bold]Enter[/bold] to continue or [bold]Q[/bold] to quit[/dim]
            """, id="welcome-text"),
            id="welcome-container"
        )
        yield Footer()

    def action_continue(self) -> None:
        """Switch to API key setup."""
        self.app.push_screen(APIKeyScreen())

    def action_quit(self) -> None:
        """Quit the app."""
        self.app.exit()


class APIKeyScreen(Screen):
    """API key configuration screen."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save & Continue"),
        Binding("escape", "back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Static("\n[bold white]API Key Setup[/bold white]\n", classes="section-title"),
                Static(
                    "Impact-Scan uses AI to find vulnerabilities that static tools miss.\n"
                    "Configure your API keys below (optional but recommended).\n",
                    classes="section-desc"
                ),
                Label(""),
                Static("[bold green]Groq (Recommended - Fast & Free)[/bold green]", classes="provider-header"),
                Static(
                    "  • Get your free API key: [cyan]https://console.groq.com[/cyan]\n"
                    "  • Best for: Lightning-fast AI analysis\n"
                    "  • Model: Llama 3.3 70B\n",
                    classes="provider-info"
                ),
                Label("[bold cyan]Groq API Key:[/bold cyan]", classes="input-label"),
                Input(
                    placeholder="Enter your Groq API key (gsk_...)",
                    password=True,
                    id="groq-key"
                ),
                Label(""),
                Label(""),
                Static("[bold yellow]Optional: Other AI Providers[/bold yellow]", classes="provider-header"),
                Label(""),
                Label("[bold cyan]OpenAI API Key (optional):[/bold cyan]", classes="input-label"),
                Input(
                    placeholder="sk-...",
                    password=True,
                    id="openai-key"
                ),
                Label(""),
                Label("[bold cyan]Anthropic API Key (optional):[/bold cyan]", classes="input-label"),
                Input(
                    placeholder="sk-ant-...",
                    password=True,
                    id="anthropic-key"
                ),
                Label(""),
                Label(""),
                Horizontal(
                    Button("Skip for Now", variant="default", id="skip-btn"),
                    Button("Save & Continue", variant="success", id="save-btn"),
                    id="button-row"
                ),
                Label(""),
                Static("[dim]🔒 Keys are stored securely in your system keychain[/dim]", classes="security-note"),
                id="api-form"
            ),
            id="api-container"
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "save-btn":
            self.action_save()
        elif event.button.id == "skip-btn":
            self.app.push_screen(RepoAnalysisScreen(api_keys_configured=False))

    def action_save(self) -> None:
        """Save API keys and continue."""
        groq_input = self.query_one("#groq-key", Input)
        openai_input = self.query_one("#openai-key", Input)
        anthropic_input = self.query_one("#anthropic-key", Input)

        saved_any = False

        # Save Groq key
        if groq_input.value.strip():
            try:
                keyring.set_password("impact-scan", "groq_api_key", groq_input.value.strip())
                os.environ["GROQ_API_KEY"] = groq_input.value.strip()
                saved_any = True
            except Exception:
                # Fallback to .env file
                self._save_to_env("GROQ_API_KEY", groq_input.value.strip())
                saved_any = True

        # Save OpenAI key
        if openai_input.value.strip():
            try:
                keyring.set_password("impact-scan", "openai_api_key", openai_input.value.strip())
                os.environ["OPENAI_API_KEY"] = openai_input.value.strip()
                saved_any = True
            except Exception:
                self._save_to_env("OPENAI_API_KEY", openai_input.value.strip())
                saved_any = True

        # Save Anthropic key
        if anthropic_input.value.strip():
            try:
                keyring.set_password("impact-scan", "anthropic_api_key", anthropic_input.value.strip())
                os.environ["ANTHROPIC_API_KEY"] = anthropic_input.value.strip()
                saved_any = True
            except Exception:
                self._save_to_env("ANTHROPIC_API_KEY", anthropic_input.value.strip())
                saved_any = True

        self.app.push_screen(RepoAnalysisScreen(api_keys_configured=saved_any))

    def _save_to_env(self, key: str, value: str) -> None:
        """Fallback: Save to .env file in user's home directory."""
        env_file = Path.home() / ".impact-scan.env"
        try:
            # Read existing
            existing = {}
            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        existing[k.strip()] = v.strip()

            # Update
            existing[key] = value

            # Write
            with open(env_file, "w") as f:
                for k, v in existing.items():
                    f.write(f"{k}={v}\n")

        except Exception as e:
            pass  # Silently fail

    def action_back(self) -> None:
        """Go back to welcome screen."""
        self.app.pop_screen()


class RepoAnalysisScreen(Screen):
    """Repository analysis screen - optional step for generating custom security rules."""

    BINDINGS = [
        Binding("enter", "analyze", "Analyze"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, api_keys_configured: bool = False):
        super().__init__()
        self.api_keys_configured = api_keys_configured
        self.selected_path = None
        self.analysis_status = "idle"  # idle, browsing, analyzing, completed, error
        self.analysis_result = None

    def compose(self) -> ComposeResult:
        yield Header()

        message = """
[bold cyan]Repository Analysis - Optional Step[/bold cyan]

Generate custom security rules tailored to your codebase using Groq AI.

[bold white]What this does:[/bold white]
  • Analyzes your repository's architecture and tech stack
  • Identifies common vulnerability patterns
  • Generates custom Semgrep rules specific to your code
  • Saves rules to [bold].impact-scan/custom-rules.yml[/bold]

[dim]Note: Requires Groq API key (free at console.groq.com)[/dim]
        """

        yield Container(
            Static(message, id="repo-intro-text"),
            Static("", id="repo-status", classes="analysis-status"),
            Label(""),
            Static("No repository selected", id="path-display", classes="path-display"),
            Label(""),
            Horizontal(
                Button("Skip for Now", variant="default", id="skip-btn"),
                Button("Browse Repository", variant="primary", id="browse-btn"),
                Button("Back", variant="default", id="back-btn"),
                id="repo-buttons",
            ),
            id="repo-form"
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "skip-btn":
            self.action_skip()
        elif event.button.id == "browse-btn":
            self.action_browse()
        elif event.button.id == "analyze-btn":
            self.action_analyze()
        elif event.button.id == "back-btn":
            self.action_back()

    def action_browse(self) -> None:
        """Open path browser modal."""
        try:
            from .screens import PathBrowserModal

            def on_path_selected(path: str) -> None:
                if path:
                    self.selected_path = Path(path)
                    self.update_path_display(str(path))
                    # Enable analyze button by changing browse button to analyze
                    try:
                        btn = self.query_one("#browse-btn", Button)
                        btn.label = "Analyze Repository"
                        btn.variant = "success"
                        # Update binding
                        btn.id = "analyze-btn"
                    except Exception:
                        pass

            # Start from home directory instead of cwd (which might be impact-scan repo)
            from pathlib import Path as PathLib
            start_path = PathLib.home()
            self.app.push_screen(PathBrowserModal(current_path=start_path), on_path_selected)
        except ImportError:
            self.update_status("Error: PathBrowserModal not available", "error")

    def update_path_display(self, path: str) -> None:
        """Update the path display."""
        try:
            path_display = self.query_one("#path-display", Static)
            # Truncate if too long
            if len(path) > 60:
                display_path = f"...{path[-57:]}"
            else:
                display_path = path
            path_display.update(f"[bold cyan]Selected:[/bold cyan] {display_path}")
        except Exception:
            pass

    def update_status(self, message: str, status_type: str = "info") -> None:
        """Update the status message."""
        try:
            status_widget = self.query_one("#repo-status", Static)
            if status_type == "analyzing":
                status_widget.update(f"[bold yellow]{message}[/bold yellow]")
            elif status_type == "success":
                status_widget.update(f"[bold green]{message}[/bold green]")
            elif status_type == "error":
                status_widget.update(f"[bold red]{message}[/bold red]")
            else:
                status_widget.update(f"[dim]{message}[/dim]")
        except Exception:
            pass

    def action_analyze(self) -> None:
        """Run repository analysis."""
        if not self.selected_path:
            self.update_status("Please select a repository first", "error")
            return

        self.analysis_status = "analyzing"
        self.update_status("Analyzing repository... This may take a minute.", "analyzing")

        try:
            from impact_scan.core.groq_repo_analyzer import GroqRepoAnalyzer
            from impact_scan.utils.api_key_manager import get_api_key_manager
        except Exception as import_exc:
            self.update_status(f"Import error: {import_exc}", "error")
            self.analysis_status = "error"
            return

        try:
            # Get Groq API key
            api_mgr = get_api_key_manager()
            groq_key = api_mgr.get_api_key("groq")

            if not groq_key:
                self.update_status(
                    "Error: Groq API key not found. Please configure it in API Keys screen.",
                    "error"
                )
                self.analysis_status = "error"
                return

            # Run analysis (synchronous for now - could be made async)
            try:
                analyzer = GroqRepoAnalyzer(
                    repo_path=self.selected_path,
                    api_key=groq_key
                )
            except Exception as analyzer_exc:
                self.update_status(f"Analyzer init error: {analyzer_exc}", "error")
                self.analysis_status = "error"
                return

            try:
                # This will analyze and generate custom rules
                analysis_md, rules_yml = analyzer.run_full_analysis()
            except Exception as run_exc:
                self.update_status(f"Analysis failed: {run_exc}", "error")
                self.analysis_status = "error"
                import traceback
                traceback.print_exc()
                return

            if rules_yml:
                self.analysis_status = "completed"
                self.analysis_result = {"md": analysis_md, "rules": rules_yml}
                self.update_status(
                    f"✓ Analysis complete! Generated custom rules in .impact-scan/",
                    "success"
                )

                # Save state
                try:
                    from .config import get_config_manager
                    config_mgr = get_config_manager()
                    config_mgr.mark_repo_analysis_complete(str(self.selected_path))
                except Exception as state_exc:
                    self.update_status(f"State save error: {state_exc}", "error")

                # Auto-proceed to completion after 2 seconds
                self.set_timer(2.0, self.action_complete)
            else:
                self.update_status("Analysis completed but no rules generated", "error")
                self.analysis_status = "error"

        except Exception as e:
            self.update_status(f"Error: {str(e)}", "error")
            self.analysis_status = "error"
            import traceback
            traceback.print_exc()

    def action_skip(self) -> None:
        """Skip repository analysis and go to completion."""
        self.app.push_screen(CompletionScreen(skipped=not self.api_keys_configured, repo_analyzed=False))

    def action_complete(self) -> None:
        """Proceed to completion screen after successful analysis."""
        self.app.push_screen(CompletionScreen(skipped=False, repo_analyzed=True))

    def action_back(self) -> None:
        """Go back to API key screen."""
        self.app.pop_screen()


class CompletionScreen(Screen):
    """Setup completion screen."""

    BINDINGS = [
        Binding("enter", "finish", "Get Started"),
    ]

    def __init__(self, skipped: bool = False, repo_analyzed: bool = False):
        super().__init__()
        self.skipped = skipped
        self.repo_analyzed = repo_analyzed

    def compose(self) -> ComposeResult:
        yield Header()

        if self.skipped:
            message = """
[bold yellow]Setup Skipped[/bold yellow]

No problem! You can still use Impact-Scan with:
  • AST-based Python scanning (no API key needed)
  • Semgrep static analysis
  • Dependency scanning

[dim]To enable AI features later, run:[/dim]
  [bold cyan]impact-scan setup[/bold cyan]

Or set environment variables:
  [bold]export GROQ_API_KEY=your_key_here[/bold]
            """
        else:
            message = """
[bold green]✓ Setup Complete![/bold green]

Your API keys have been saved securely.
"""

            if self.repo_analyzed:
                message += """
[bold cyan]✓ Custom security rules generated![/bold cyan]
Rules saved to [bold].impact-scan/custom-rules.yml[/bold]
Analysis report: [bold]impact-scan.md[/bold]

"""

            message += """
[bold white]Ready to scan![/bold white]

[bold cyan]Quick Start:[/bold cyan]
  1. Navigate to your project directory
  2. Run: [bold]impact-scan scan --ai-flow[/bold]

[bold green]Special Features:[/bold green]
  • [bold]--ai-flow[/bold]    - AI-powered logic bug detection
  • [bold]--no-semgrep[/bold]  - Fast AST-only scanning
  • [bold]--ai-deep-scan[/bold] - Deep security audit

[dim]Tip: Run [bold]impact-scan --help[/bold] to see all options[/dim]
            """

        yield Container(
            Static(message, id="completion-text"),
            Label(""),
            Button("Get Started!", variant="success", id="finish-btn"),
            id="completion-container"
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Finish onboarding."""
        self.action_finish()

    def action_finish(self) -> None:
        """Exit the onboarding."""
        from .config import get_config_manager
        config_mgr = get_config_manager()
        config_mgr.mark_tutorial_complete()

        try:
            # Try to dismiss if modal (embedded in main TUI)
            self.dismiss({"completed": True})
        except Exception:
            # Fallback to exit if standalone
            self.app.exit()


class OnboardingApp(App):
    """Impact-Scan Onboarding TUI Application."""

    CSS = """
    Screen {
        background: #0f1729;
    }

    #welcome-container {
        align: center middle;
        width: 100%;
        height: 100%;
        background: #0f1729;
    }

    #welcome-text {
        width: 90;
        padding: 4;
        text-align: center;
        background: $surface;
        border: heavy cyan;
    }

    #api-container {
        align: center middle;
        width: 100%;
        height: 100%;
        background: #0f1729;
        overflow-y: auto;
    }

    #api-form {
        width: 90;
        max-width: 120;
        padding: 4;
        border: heavy cyan;
        background: $surface;
    }

    .section-title {
        text-align: center;
        color: $accent;
        text-style: bold;
        padding: 1 0;
    }

    .section-desc {
        color: $text-muted;
        padding: 0 2 2 2;
        text-align: center;
    }

    .provider-header {
        padding: 1 0;
        text-style: bold;
    }

    .provider-info {
        color: $text-muted;
        padding: 0 2 1 2;
    }

    .input-label {
        padding: 1 0 0 0;
        color: $accent;
        text-style: bold;
    }

    .security-note {
        text-align: center;
        padding: 1 0;
    }

    Input {
        margin: 1 0 2 0;
        width: 100%;
        border: tall $primary;
        background: $surface-darken-1;
        padding: 1 2;
        height: 3;
    }

    Input:focus {
        border: heavy cyan;
        background: $surface;
    }

    #button-row {
        align: center middle;
        width: 100%;
        height: auto;
        margin-top: 1;
    }

    Button {
        margin: 0 2;
        min-width: 24;
        height: 3;
        border: tall $primary;
        text-style: bold;
    }

    Button:hover {
        background: $primary;
        border: heavy cyan;
    }

    #completion-container {
        align: center middle;
        width: 100%;
        height: 100%;
        background: #0f1729;
    }

    #completion-text {
        width: 90;
        padding: 4;
        text-align: center;
        background: $surface;
        border: heavy green;
    }

    Label {
        padding: 0;
        color: $text;
    }

    Static {
        color: $text;
    }

    Header {
        background: $primary;
        text-style: bold;
    }

    Footer {
        background: $surface-darken-2;
    }

    #repo-container {
        align: center middle;
        width: 100%;
        height: 100%;
        background: #0f1729;
    }

    #repo-form {
        width: 90;
        max-width: 120;
        padding: 4;
        border: heavy cyan;
        background: $surface;
    }

    .analysis-status {
        text-align: center;
        padding: 2;
        color: $accent;
    }

    .path-display {
        padding: 1;
        background: $surface-darken-1;
        border: tall $primary;
        margin: 1 0;
        text-align: center;
        color: cyan;
    }

    #repo-buttons {
        align: center middle;
        width: 100%;
        height: auto;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
    ]

    def on_mount(self) -> None:
        """Start with welcome screen."""
        self.push_screen(WelcomeScreen())


def run_onboarding():
    """Run the onboarding TUI."""
    app = OnboardingApp()
    app.run()


if __name__ == "__main__":
    run_onboarding()
