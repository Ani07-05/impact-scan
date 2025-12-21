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
║    ██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗          ║
║    ██║████╗ ████║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝          ║
║    ██║██╔████╔██║██████╔╝███████║██║        ██║             ║
║    ██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║        ██║             ║
║    ██║██║ ╚═╝ ██║██║     ██║  ██║╚██████╗   ██║             ║
║    ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝             ║
║                                                               ║
║              ███████╗ ██████╗ █████╗ ███╗   ██╗              ║
║              ██╔════╝██╔════╝██╔══██╗████╗  ██║              ║
║              ███████╗██║     ███████║██╔██╗ ██║              ║
║              ╚════██║██║     ██╔══██║██║╚██╗██║              ║
║              ███████║╚██████╗██║  ██║██║ ╚████║              ║
║              ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝              ║
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
            self.app.push_screen(CompletionScreen(skipped=True))

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

        self.app.push_screen(CompletionScreen(skipped=not saved_any))

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


class CompletionScreen(Screen):
    """Setup completion screen."""

    BINDINGS = [
        Binding("enter", "finish", "Get Started"),
    ]

    def __init__(self, skipped: bool = False):
        super().__init__()
        self.skipped = skipped

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

[bold white]Ready to scan![/bold white]

[bold cyan]Quick Start:[/bold cyan]
  1. Navigate to your project directory
  2. Run: [bold]impact-scan init[/bold]
  3. Then: [bold]impact-scan scan --ai-flow[/bold]

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
