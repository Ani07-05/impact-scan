"""Tests for TUI configuration management"""

import tempfile
from pathlib import Path

import pytest

from impact_scan.tui.config import TUIConfigManager, TUIState


def test_tui_state_defaults():
    """Test TUIState default values."""
    state = TUIState()

    assert state.first_run is True
    assert state.tutorial_completed is False
    assert state.last_scan_path is None
    assert state.preferred_profile == "standard"
    assert state.preferred_ai_provider == "auto"
    assert state.recent_paths == []
    assert state.bookmarks == []


def test_tui_state_validation():
    """Test TUIState Pydantic validation."""
    # Valid state
    state = TUIState(
        first_run=False,
        tutorial_completed=True,
        last_scan_path="/test/path",
        preferred_profile="quick",
        preferred_ai_provider="gemini",
        recent_paths=["/path1", "/path2"],
        bookmarks=["/bookmark1"],
    )

    assert state.first_run is False
    assert state.tutorial_completed is True
    assert state.last_scan_path == "/test/path"
    assert state.preferred_profile == "quick"
    assert state.preferred_ai_provider == "gemini"
    assert len(state.recent_paths) == 2
    assert len(state.bookmarks) == 1


def test_config_manager_initialization():
    """Test TUIConfigManager initializes correctly."""
    config_mgr = TUIConfigManager()

    assert config_mgr.state is not None
    assert isinstance(config_mgr.state, TUIState)


def test_config_manager_mark_tutorial_complete():
    """Test marking tutorial as complete."""
    config_mgr = TUIConfigManager()

    config_mgr.mark_tutorial_complete()

    assert config_mgr.state.first_run is False
    assert config_mgr.state.tutorial_completed is True


def test_config_manager_update_last_scan_path():
    """Test updating last scan path."""
    config_mgr = TUIConfigManager()

    test_path = "/test/scan/path"
    config_mgr.update_last_scan_path(test_path)

    assert config_mgr.state.last_scan_path == test_path
    assert test_path in config_mgr.state.recent_paths


def test_config_manager_recent_paths_limit():
    """Test recent paths limited to 10."""
    config_mgr = TUIConfigManager()

    # Add 15 paths
    for i in range(15):
        config_mgr.update_last_scan_path(f"/path{i}")

    # Should only keep 10 most recent
    assert len(config_mgr.state.recent_paths) == 10
    assert config_mgr.state.recent_paths[0] == "/path14"  # Most recent first


def test_config_manager_add_bookmark():
    """Test adding bookmarks."""
    config_mgr = TUIConfigManager()

    test_path = "/test/bookmark"
    config_mgr.add_bookmark(test_path)

    assert test_path in config_mgr.state.bookmarks


def test_config_manager_remove_bookmark():
    """Test removing bookmarks."""
    config_mgr = TUIConfigManager()

    test_path = "/test/bookmark"
    config_mgr.add_bookmark(test_path)
    assert test_path in config_mgr.state.bookmarks

    config_mgr.remove_bookmark(test_path)
    assert test_path not in config_mgr.state.bookmarks


def test_config_manager_duplicate_bookmark():
    """Test adding duplicate bookmark has no effect."""
    config_mgr = TUIConfigManager()

    test_path = "/test/bookmark"
    config_mgr.add_bookmark(test_path)
    config_mgr.add_bookmark(test_path)  # Add again

    # Should only appear once
    assert config_mgr.state.bookmarks.count(test_path) == 1


@pytest.mark.skipif(
    not hasattr(pytest, "requires_keyring"),
    reason="Keyring may not be available in CI",
)
def test_config_manager_api_key_operations():
    """Test API key save/get/delete operations."""
    config_mgr = TUIConfigManager()

    # Test save
    result = config_mgr.save_api_key("test-provider", "test-key-123")
    # Result may be True or False depending on keyring availability

    # Test get (may return None if keyring not available)
    key = config_mgr.get_api_key("test-provider")

    # Test delete
    config_mgr.delete_api_key("test-provider")

    # Verify deleted
    key_after_delete = config_mgr.get_api_key("test-provider")
    assert key_after_delete is None


def test_config_manager_get_all_api_keys():
    """Test getting all API keys."""
    config_mgr = TUIConfigManager()

    all_keys = config_mgr.get_all_api_keys()

    # Should return dict with all providers
    assert "openai" in all_keys
    assert "anthropic" in all_keys
    assert "gemini" in all_keys
    assert "groq" in all_keys
