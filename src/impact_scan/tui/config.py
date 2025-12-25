"""
TUI Configuration Management
Handles persistent state and secure credential storage via keyring.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional

import keyring
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Service name for keyring
SERVICE_NAME = "impact-scan"

# Config file location
CONFIG_DIR = Path.home() / ".config" / "impact-scan"
TUI_STATE_FILE = CONFIG_DIR / "tui_state.json"


class TUIState(BaseModel):
    """Persistent TUI state."""

    first_run: bool = True
    tutorial_completed: bool = False
    repo_analysis_completed: bool = False
    last_analyzed_repo: Optional[str] = None
    last_scan_path: Optional[str] = None
    preferred_profile: str = "standard"
    preferred_ai_provider: str = "auto"
    recent_paths: list[str] = []
    bookmarks: list[str] = []

    class Config:
        """Pydantic config."""

        extra = "allow"  # Allow additional fields


class TUIConfigManager:
    """Manages TUI configuration and credentials."""

    def __init__(self):
        """Initialize config manager."""
        self.state: TUIState = self._load_state()

    def _ensure_config_dir(self) -> None:
        """Ensure config directory exists."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    def _load_state(self) -> TUIState:
        """Load TUI state from disk."""
        try:
            if TUI_STATE_FILE.exists():
                with open(TUI_STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return TUIState(**data)
        except Exception as e:
            logger.warning(f"Failed to load TUI state: {e}")

        return TUIState()

    def save_state(self) -> None:
        """Save TUI state to disk."""
        try:
            self._ensure_config_dir()
            with open(TUI_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.state.dict(), f, indent=2)
            logger.debug("TUI state saved")
        except Exception as e:
            logger.error(f"Failed to save TUI state: {e}")

    def mark_tutorial_complete(self) -> None:
        """Mark first-run tutorial as completed."""
        self.state.first_run = False
        self.state.tutorial_completed = True
        self.save_state()

    def mark_repo_analysis_complete(self, repo_path: str) -> None:
        """Mark repository analysis as completed."""
        self.state.repo_analysis_completed = True
        self.state.last_analyzed_repo = str(repo_path)
        self.save_state()

    def has_completed_repo_analysis(self) -> bool:
        """Check if user has ever completed repo analysis."""
        return self.state.repo_analysis_completed

    def update_last_scan_path(self, path: str) -> None:
        """Update last scanned path."""
        self.state.last_scan_path = path
        self._add_to_recent(path)
        self.save_state()

    def _add_to_recent(self, path: str) -> None:
        """Add path to recent list (max 10)."""
        if path in self.state.recent_paths:
            self.state.recent_paths.remove(path)
        self.state.recent_paths.insert(0, path)
        self.state.recent_paths = self.state.recent_paths[:10]

    def add_bookmark(self, path: str) -> None:
        """Add path to bookmarks."""
        if path not in self.state.bookmarks:
            self.state.bookmarks.append(path)
            self.save_state()

    def remove_bookmark(self, path: str) -> None:
        """Remove path from bookmarks."""
        if path in self.state.bookmarks:
            self.state.bookmarks.remove(path)
            self.save_state()

    # Keyring-based API key management

    def save_api_key(self, provider: str, api_key: str) -> bool:
        """
        Save API key securely using OS keyring.

        Args:
            provider: Provider name (openai, anthropic, gemini, groq)
            api_key: API key to store

        Returns:
            True if saved successfully
        """
        try:
            keyring.set_password(SERVICE_NAME, provider, api_key)
            logger.info(f"Saved {provider} API key to keyring")
            return True
        except Exception as e:
            logger.error(f"Failed to save {provider} API key: {e}")
            return False

    def get_api_key(self, provider: str) -> Optional[str]:
        """
        Retrieve API key from keyring.

        Args:
            provider: Provider name

        Returns:
            API key or None if not found
        """
        try:
            key = keyring.get_password(SERVICE_NAME, provider)
            return key
        except Exception as e:
            logger.debug(f"Failed to retrieve {provider} API key: {e}")
            return None

    def delete_api_key(self, provider: str) -> bool:
        """
        Delete API key from keyring.

        Args:
            provider: Provider name

        Returns:
            True if deleted successfully
        """
        try:
            keyring.delete_password(SERVICE_NAME, provider)
            logger.info(f"Deleted {provider} API key from keyring")
            return True
        except Exception as e:
            logger.debug(f"Failed to delete {provider} API key: {e}")
            return False

    def get_all_api_keys(self) -> Dict[str, Optional[str]]:
        """
        Get all configured API keys.

        Returns:
            Dict mapping provider to API key (or None)
        """
        providers = ["openai", "anthropic", "gemini", "groq"]
        return {provider: self.get_api_key(provider) for provider in providers}

    def clear_all_api_keys(self) -> int:
        """
        Clear all API keys from keyring.

        Returns:
            Number of keys deleted
        """
        count = 0
        for provider in ["openai", "anthropic", "gemini", "groq"]:
            if self.delete_api_key(provider):
                count += 1
        return count


# Global instance
_config_manager: Optional[TUIConfigManager] = None


def get_config_manager() -> TUIConfigManager:
    """Get global TUI config manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = TUIConfigManager()
    return _config_manager
