"""Tests for TUI theme module"""

import pytest

from impact_scan.tui.theme import (
    IMPACT_DARK_THEME,
    MAIN_CSS,
    MODAL_CSS,
    SEVERITY_COLORS,
    format_severity,
    get_severity_color,
)


def test_impact_dark_theme_colors():
    """Test Impact dark theme color definitions."""
    assert "primary" in IMPACT_DARK_THEME
    assert "secondary" in IMPACT_DARK_THEME
    assert "accent" in IMPACT_DARK_THEME
    assert "error" in IMPACT_DARK_THEME
    assert "warning" in IMPACT_DARK_THEME
    assert "success" in IMPACT_DARK_THEME
    assert "background" in IMPACT_DARK_THEME
    assert "surface" in IMPACT_DARK_THEME
    assert "foreground" in IMPACT_DARK_THEME

    # Verify colors are hex strings
    assert IMPACT_DARK_THEME["primary"].startswith("#")
    assert IMPACT_DARK_THEME["error"].startswith("#")
    assert IMPACT_DARK_THEME["success"].startswith("#")


def test_severity_colors():
    """Test severity color mapping."""
    assert "critical" in SEVERITY_COLORS
    assert "high" in SEVERITY_COLORS
    assert "medium" in SEVERITY_COLORS
    assert "low" in SEVERITY_COLORS

    assert SEVERITY_COLORS["critical"] == "red"
    assert SEVERITY_COLORS["high"] == "yellow"
    assert SEVERITY_COLORS["medium"] == "blue"
    assert SEVERITY_COLORS["low"] == "cyan"


def test_get_severity_color():
    """Test get_severity_color function."""
    assert get_severity_color("critical") == "red"
    assert get_severity_color("high") == "yellow"
    assert get_severity_color("medium") == "blue"
    assert get_severity_color("low") == "cyan"

    # Test case insensitivity
    assert get_severity_color("CRITICAL") == "red"
    assert get_severity_color("High") == "yellow"

    # Test unknown severity returns white
    assert get_severity_color("unknown") == "white"


def test_format_severity():
    """Test format_severity function."""
    # Test critical severity
    result = format_severity("critical")
    assert "[red]CRITICAL[/red]" == result

    # Test high severity
    result = format_severity("high")
    assert "[yellow]HIGH[/yellow]" == result

    # Test medium severity
    result = format_severity("medium")
    assert "[blue]MEDIUM[/blue]" == result

    # Test low severity
    result = format_severity("low")
    assert "[cyan]LOW[/cyan]" == result

    # Test case insensitivity
    result = format_severity("CrItIcAl")
    assert "[red]CRITICAL[/red]" == result


def test_main_css_defined():
    """Test MAIN_CSS is defined and not empty."""
    assert MAIN_CSS is not None
    assert len(MAIN_CSS) > 0
    assert isinstance(MAIN_CSS, str)


def test_main_css_contains_key_styles():
    """Test MAIN_CSS contains key style definitions."""
    # Check for important class names
    assert ".config-panel" in MAIN_CSS
    assert ".progress-panel" in MAIN_CSS
    assert ".metrics-panel" in MAIN_CSS
    assert ".findings-panel" in MAIN_CSS

    # Check for severity styles
    assert ".metric-critical" in MAIN_CSS
    assert ".metric-high" in MAIN_CSS
    assert ".metric-medium" in MAIN_CSS
    assert ".metric-low" in MAIN_CSS


def test_modal_css_defined():
    """Test MODAL_CSS is defined and not empty."""
    assert MODAL_CSS is not None
    assert len(MODAL_CSS) > 0
    assert isinstance(MODAL_CSS, str)


def test_modal_css_contains_key_styles():
    """Test MODAL_CSS contains modal style definitions."""
    # Check for PathBrowserModal styles
    assert "PathBrowserModal" in MODAL_CSS
    assert ".browser-container" in MODAL_CSS
    assert ".browser-header" in MODAL_CSS

    # Check for APIKeysModal styles
    assert "APIKeysModal" in MODAL_CSS
    assert ".keys-container" in MODAL_CSS
    assert ".keys-header" in MODAL_CSS
    assert ".key-row" in MODAL_CSS


def test_css_no_emojis():
    """Test CSS does not contain emoji characters."""
    # Check MAIN_CSS
    for char in MAIN_CSS:
        # Emoji range: U+1F300 to U+1F9FF
        assert ord(char) < 0x1F300 or ord(char) > 0x1F9FF

    # Check MODAL_CSS
    for char in MODAL_CSS:
        assert ord(char) < 0x1F300 or ord(char) > 0x1F9FF


def test_format_severity_no_emojis():
    """Test format_severity does not add emojis."""
    for severity in ["critical", "high", "medium", "low"]:
        result = format_severity(severity)

        # Check no emoji characters
        for char in result:
            assert ord(char) < 0x1F300 or ord(char) > 0x1F9FF

        # Should only contain severity text and Rich markup
        assert severity.upper() in result
        assert "[" in result
        assert "]" in result
