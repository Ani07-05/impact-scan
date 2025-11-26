"""Tests for TUI modal screens"""

from pathlib import Path

import pytest

from impact_scan.tui import ImpactScanTUI
from impact_scan.tui.screens import APIKeysModal, PathBrowserModal


@pytest.mark.asyncio
async def test_path_browser_modal_composition():
    """Test PathBrowserModal composes correctly."""
    # Test modal can be instantiated and composed
    app = ImpactScanTUI()
    modal = PathBrowserModal(current_path=Path.cwd())

    async with app.run_test() as pilot:
        app.push_screen(modal)
        await pilot.pause()

        # Verify modal is on screen
        assert app.screen is modal

        # Verify key widgets exist
        assert modal.query_one("#path-tree") is not None
        assert modal.query_one("#select-path") is not None
        assert modal.query_one("#go-home") is not None
        assert modal.query_one("#cancel-path") is not None


@pytest.mark.asyncio
async def test_path_browser_modal_initial_state():
    """Test PathBrowserModal initial state."""
    modal = PathBrowserModal(current_path=Path.home())
    assert modal.selected_path == Path.home()

    modal_cwd = PathBrowserModal()  # Defaults to cwd
    assert modal_cwd.selected_path is not None


@pytest.mark.asyncio
async def test_api_keys_modal_composition():
    """Test APIKeysModal composes correctly."""
    app = ImpactScanTUI()
    modal = APIKeysModal()

    async with app.run_test() as pilot:
        app.push_screen(modal)
        await pilot.pause()

        # Verify modal is on screen
        assert app.screen is modal

        # Verify key widgets exist
        assert modal.query_one("#openai-key") is not None
        assert modal.query_one("#anthropic-key") is not None
        assert modal.query_one("#gemini-key") is not None
        assert modal.query_one("#groq-key") is not None

        # Verify status indicators exist
        assert modal.query_one("#openai-status") is not None
        assert modal.query_one("#anthropic-status") is not None
        assert modal.query_one("#gemini-status") is not None
        assert modal.query_one("#groq-status") is not None

        # Verify buttons exist
        assert modal.query_one("#save-keys") is not None
        assert modal.query_one("#clear-keys") is not None
        assert modal.query_one("#cancel-keys") is not None
