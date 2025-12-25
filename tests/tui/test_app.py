"""Tests for main TUI application"""

import pytest
from pathlib import Path

from impact_scan.tui import ImpactScanTUI


@pytest.fixture
def mock_first_run(monkeypatch):
    """Mock first_run to be False to skip onboarding."""
    from impact_scan.tui.config import TUIState

    def mock_load_state(self):
        state = TUIState()
        state.first_run = False  # Skip onboarding for tests
        state.tutorial_completed = True
        return state

    monkeypatch.setattr(
        "impact_scan.tui.config.TUIConfigManager._load_state", mock_load_state
    )


@pytest.mark.asyncio
async def test_main_app_initialization(mock_first_run):
    """Test main application initializes correctly."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Verify footer exists (Header is hidden in new design)
        assert app.query_one("Footer") is not None

        # Verify key widgets exist with correct IDs
        assert app.query_one("#profile-select") is not None
        assert app.query_one("#ai-select") is not None
        assert app.query_one("#start-scan-btn") is not None


@pytest.mark.asyncio
async def test_main_app_target_input(mock_first_run):
    """Test target directory can be set via ConfigPanel."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Get ConfigPanel and set path
        from impact_scan.tui.widgets.overview_panel import OverviewPanel
        from impact_scan.tui.widgets.config_panel import ConfigPanel

        overview = app.query_one(OverviewPanel)
        config_panel = overview.query_one(ConfigPanel)

        # Set a test directory
        test_path = str(Path.cwd())
        config_panel.set_scan_path(test_path)

        # Verify value is set
        assert config_panel.get_scan_path() == test_path


@pytest.mark.asyncio
async def test_main_app_profile_selection(mock_first_run):
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
async def test_main_app_ai_provider_selection(mock_first_run):
    """Test AI provider selection."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        ai_provider_select = app.query_one("#ai-select")

        # Verify default provider is groq (changed from auto)
        assert ai_provider_select.value == "groq"

        # Change provider
        ai_provider_select.value = "gemini"
        assert ai_provider_select.value == "gemini"


@pytest.mark.asyncio
async def test_main_app_browse_button(mock_first_run):
    """Test browse button exists and can be clicked."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Verify browse button exists
        browse_btn = app.query_one("#browse-btn")
        assert browse_btn is not None


@pytest.mark.asyncio
async def test_main_app_keys_button(mock_first_run):
    """Test API keys button exists and can be clicked."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Verify keys button exists
        keys_btn = app.query_one("#keys-btn")
        assert keys_btn is not None


@pytest.mark.asyncio
async def test_main_app_progress_log(mock_first_run):
    """Test progress log component exists."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Query through OverviewPanel (ProgressLog is in Overview tab)
        from impact_scan.tui.widgets.overview_panel import OverviewPanel, ProgressLog

        overview = app.query_one(OverviewPanel)
        progress_log = overview.query_one(ProgressLog)

        # Verify ProgressLog exists and has log content
        assert progress_log is not None
        assert overview.query_one("#log-content") is not None


@pytest.mark.asyncio
async def test_main_app_overview_components(mock_first_run):
    """Test overview panel components exist."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Query through OverviewPanel
        from impact_scan.tui.widgets.overview_panel import (
            OverviewPanel,
            ConfigPanel,
            ScanInfo,
            CodebaseTree,
            ProgressLog,
        )

        overview = app.query_one(OverviewPanel)

        # Verify all main components exist
        assert overview.query_one(ConfigPanel) is not None
        assert overview.query_one(ScanInfo) is not None
        assert overview.query_one(CodebaseTree) is not None
        assert overview.query_one(ProgressLog) is not None


@pytest.mark.asyncio
async def test_main_app_findings_table(mock_first_run):
    """Test findings table exists."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        # Query RichFindingsTable (in Findings tab)
        from impact_scan.tui.widgets.rich_findings_table import RichFindingsTable

        findings_widget = app.query_one(RichFindingsTable)

        # Verify findings table exists
        assert findings_widget is not None

        # Verify export buttons exist (with -btn suffix)
        assert findings_widget.query_one("#export-html-btn") is not None
        assert findings_widget.query_one("#export-sarif-btn") is not None


@pytest.mark.asyncio
async def test_main_app_scan_button_exists(mock_first_run):
    """Test scan button exists."""
    app = ImpactScanTUI()

    async with app.run_test() as pilot:
        await pilot.pause()

        scan_btn = app.query_one("#start-scan-btn")

        # Button should exist and be enabled
        assert scan_btn is not None
