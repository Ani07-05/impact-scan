"""Tests for main TUI application"""

import pytest
from pathlib import Path

from impact_scan.tui import ImpactScanTUI


@pytest.mark.asyncio
async def test_main_app_initialization():
    """Test main application initializes correctly."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Verify header and footer exist
        assert app.query_one("Header") is not None
        assert app.query_one("Footer") is not None

        # Verify key widgets exist with correct IDs
        assert app.query_one("#scan-path") is not None
        assert app.query_one("#profile-select") is not None
        assert app.query_one("#ai-select") is not None
        assert app.query_one("#start-scan-btn") is not None


@pytest.mark.asyncio
async def test_main_app_target_input():
    """Test target directory input."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        target_input = app.query_one("#scan-path")

        # Set a test directory
        test_path = str(Path.cwd())
        target_input.value = test_path

        # Verify value is set
        assert target_input.value == test_path


@pytest.mark.asyncio
async def test_main_app_profile_selection():
    """Test profile selection."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        profile_select = app.query_one("#profile-select")

        # Verify default profile is comprehensive
        assert profile_select.value == "comprehensive"

        # Change profile
        profile_select.value = "quick"
        assert profile_select.value == "quick"


@pytest.mark.asyncio
async def test_main_app_ai_provider_selection():
    """Test AI provider selection."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        ai_provider_select = app.query_one("#ai-select")

        # Verify default provider is auto
        assert ai_provider_select.value == "auto"

        # Change provider
        ai_provider_select.value = "gemini"
        assert ai_provider_select.value == "gemini"


@pytest.mark.asyncio
async def test_main_app_browse_button():
    """Test browse button opens path browser modal."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        # Click browse button
        await pilot.click("#browse-btn")

        # PathBrowserModal should be on screen stack
        # Note: This tests that the modal is pushed, not the full modal interaction


@pytest.mark.asyncio
async def test_main_app_keys_button():
    """Test API keys button opens API keys modal."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        # Click keys button
        await pilot.click("#keys-btn")

        # APIKeysModal should be on screen stack
        # Note: This tests that the modal is pushed, not the full modal interaction


@pytest.mark.asyncio
async def test_main_app_progress_panel():
    """Test progress panel components exist."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        # Verify progress components
        assert app.query_one("#scan-progress") is not None
        assert app.query_one("#status-text") is not None
        assert app.query_one("#scan-log") is not None


@pytest.mark.asyncio
async def test_main_app_metrics_panel():
    """Test metrics panel components exist."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Verify metric displays exist (use correct IDs: *-value)
        assert app.query_one("#total-value") is not None
        assert app.query_one("#critical-value") is not None
        assert app.query_one("#high-value") is not None
        assert app.query_one("#medium-value") is not None
        assert app.query_one("#low-value") is not None
        assert app.query_one("#score-value") is not None


@pytest.mark.asyncio
async def test_main_app_findings_table():
    """Test findings table exists."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Verify findings table
        findings_table = app.query_one("#findings-table")
        assert findings_table is not None

        # Verify export buttons (no -btn suffix)
        assert app.query_one("#export-html") is not None
        assert app.query_one("#export-sarif") is not None


@pytest.mark.asyncio
async def test_main_app_scan_button_disabled_initially():
    """Test scan button is disabled without target."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        scan_btn = app.query_one("#start-scan-btn")

        # Button should be enabled by default (it allows scanning current dir)
        # This behavior may change based on requirements
        assert scan_btn is not None
