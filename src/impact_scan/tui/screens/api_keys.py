"""API Keys Management Modal Screen"""

import os
from typing import Dict

from textual import on
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from ..config import get_config_manager
from ..theme import MODAL_CSS


class APIKeysModal(ModalScreen[Dict[str, any]]):
    """Clean API key management interface with keyring support."""

    DEFAULT_CSS = MODAL_CSS

    def compose(self) -> ComposeResult:
        """Compose API keys UI."""
        config_mgr = get_config_manager()

        with Container(classes="keys-container"):
            yield Static("API Key Configuration", classes="keys-header")

            with ScrollableContainer(classes="keys-content"):
                # OpenAI
                with Horizontal(classes="key-row"):
                    yield Label("OpenAI:", classes="key-label")
                    yield Input(
                        placeholder="sk-proj-...",
                        password=True,
                        value=config_mgr.get_api_key("openai")
                        or os.getenv("OPENAI_API_KEY", ""),
                        id="openai-key",
                        classes="key-input",
                    )
                    yield Static(
                        self._get_status("openai"),
                        classes="key-status",
                        id="openai-status",
                    )

                # Anthropic
                with Horizontal(classes="key-row"):
                    yield Label("Anthropic:", classes="key-label")
                    yield Input(
                        placeholder="sk-ant-...",
                        password=True,
                        value=config_mgr.get_api_key("anthropic")
                        or os.getenv("ANTHROPIC_API_KEY", ""),
                        id="anthropic-key",
                        classes="key-input",
                    )
                    yield Static(
                        self._get_status("anthropic"),
                        classes="key-status",
                        id="anthropic-status",
                    )

                # Gemini
                with Horizontal(classes="key-row"):
                    yield Label("Gemini:", classes="key-label")
                    yield Input(
                        placeholder="AIza...",
                        password=True,
                        value=config_mgr.get_api_key("gemini")
                        or os.getenv("GOOGLE_API_KEY", ""),
                        id="gemini-key",
                        classes="key-input",
                    )
                    yield Static(
                        self._get_status("gemini"),
                        classes="key-status",
                        id="gemini-status",
                    )

                # Groq
                with Horizontal(classes="key-row"):
                    yield Label("Groq:", classes="key-label")
                    yield Input(
                        placeholder="gsk_...",
                        password=True,
                        value=config_mgr.get_api_key("groq")
                        or os.getenv("GROQ_API_KEY", ""),
                        id="groq-key",
                        classes="key-input",
                    )
                    yield Static(
                        self._get_status("groq"),
                        classes="key-status",
                        id="groq-status",
                    )

            with Horizontal(classes="keys-actions"):
                yield Button(
                    "Save", variant="success", classes="action-btn", id="save-keys"
                )
                yield Button(
                    "Clear All", variant="warning", classes="action-btn", id="clear-keys"
                )
                yield Button(
                    "Cancel", variant="default", classes="action-btn", id="cancel-keys"
                )

    def _get_status(self, provider: str) -> str:
        """
        Get status for API key.

        Args:
            provider: Provider name

        Returns:
            Formatted status string
        """
        config_mgr = get_config_manager()
        key = config_mgr.get_api_key(provider) or os.getenv(
            {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "gemini": "GOOGLE_API_KEY",
                "groq": "GROQ_API_KEY",
            }.get(provider, ""),
            "",
        )

        if key and len(key) > 10:
            return "[green]Active[/green]"
        return "[red]Missing[/red]"

    @on(Button.Pressed, "#save-keys")
    def save_keys(self) -> None:
        """Save API keys to keyring."""
        config_mgr = get_config_manager()

        keys = {
            "openai": self.query_one("#openai-key", Input).value.strip(),
            "anthropic": self.query_one("#anthropic-key", Input).value.strip(),
            "gemini": self.query_one("#gemini-key", Input).value.strip(),
            "groq": self.query_one("#groq-key", Input).value.strip(),
        }

        saved_count = 0
        for provider, key_value in keys.items():
            if key_value:
                if config_mgr.save_api_key(provider, key_value):
                    saved_count += 1
                # Also set env var for current session
                env_var_map = {
                    "openai": "OPENAI_API_KEY",
                    "anthropic": "ANTHROPIC_API_KEY",
                    "gemini": "GOOGLE_API_KEY",
                    "groq": "GROQ_API_KEY",
                }
                if provider in env_var_map:
                    os.environ[env_var_map[provider]] = key_value

        # Update status
        for provider, status_id in [
            ("openai", "#openai-status"),
            ("anthropic", "#anthropic-status"),
            ("gemini", "#gemini-status"),
            ("groq", "#groq-status"),
        ]:
            self.query_one(status_id).update(self._get_status(provider))

        self.dismiss({"action": "saved", "count": saved_count})

    @on(Button.Pressed, "#clear-keys")
    def clear_keys(self) -> None:
        """Clear all API keys from keyring and env."""
        config_mgr = get_config_manager()
        count = config_mgr.clear_all_api_keys()

        # Clear env vars
        for env_var in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GOOGLE_API_KEY",
            "GROQ_API_KEY",
        ]:
            if env_var in os.environ:
                del os.environ[env_var]

        # Clear inputs
        self.query_one("#openai-key", Input).value = ""
        self.query_one("#anthropic-key", Input).value = ""
        self.query_one("#gemini-key", Input).value = ""
        self.query_one("#groq-key", Input).value = ""

        # Update status
        self.query_one("#openai-status").update("[red]Missing[/red]")
        self.query_one("#anthropic-status").update("[red]Missing[/red]")
        self.query_one("#gemini-status").update("[red]Missing[/red]")
        self.query_one("#groq-status").update("[red]Missing[/red]")

        self.dismiss({"action": "cleared", "count": count})

    @on(Button.Pressed, "#cancel-keys")
    def cancel(self) -> None:
        """Cancel without saving."""
        self.dismiss({"action": "cancelled"})
