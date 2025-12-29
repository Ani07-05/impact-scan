"""
Automatic dependency installer for Impact-Scan.
Ensures seamless out-of-box experience.

Handles:
- Ripgrep availability check
- Playwright browser setup
"""

import logging
import shutil
import subprocess
import sys
from typing import Optional, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

logger = logging.getLogger(__name__)
console = Console()


class DependencyInstaller:
    """Manages automatic installation of security scanning tools."""

    def __init__(self, silent: bool = False):
        """
        Initialize dependency installer.

        Args:
            silent: If True, suppress console output (for CI/CD)
        """
        self.silent = silent
        self.console = Console() if not silent else None

    def _print(self, message: str, style: str = "") -> None:
        """Print message to console if not silent."""
        if not self.silent and self.console:
            if style:
                self.console.print(f"[{style}]{message}[/{style}]")
            else:
                self.console.print(message)

    def check_tool(self, tool_name: str) -> bool:
        """
        Check if a tool is installed and accessible.

        Args:
            tool_name: Name of the tool (e.g., 'rg', 'ripgrep')

        Returns:
            True if tool is available, False otherwise
        """
        return shutil.which(tool_name) is not None

    def ensure_ripgrep(self) -> Tuple[bool, str]:
        """
        Ensure ripgrep is installed.

        Returns:
            Tuple of (available: bool, message: str)
        """
        # First check for bundled ripgrep (for executable distributions)
        import sys
        from pathlib import Path

        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # Running as PyInstaller bundle - check for bundled ripgrep
            bundle_dir = Path(sys._MEIPASS)
            rg_name = 'rg.exe' if sys.platform == 'win32' else 'rg'
            bundled_rg = bundle_dir / 'impact_scan_tools' / rg_name

            if bundled_rg.exists():
                logger.info(f"Found bundled ripgrep at: {bundled_rg}")
                return True, f"ripgrep (bundled) is available"

        # Check system ripgrep
        if self.check_tool("rg"):
            try:
                result = subprocess.run(
                    ["rg", "--version"], capture_output=True, text=True, timeout=5
                )
                version = (
                    result.stdout.strip().split("\n")[0]
                    if result.returncode == 0
                    else "unknown"
                )
                logger.info(f"ripgrep {version} found")
                return True, f"ripgrep {version} is available"
            except Exception as e:
                logger.warning(f"ripgrep found but version check failed: {e}")
                return True, "ripgrep is available (version unknown)"

        # Not installed - provide installation instructions
        self._print("\n[yellow][WARNING] ripgrep (rg) not found[/yellow]")
        self._print("ripgrep is required for static code analysis")
        self._print("\nInstallation instructions:")
        self._print("  Windows:  choco install ripgrep  or  winget install BurntSushi.ripgrep.MSVC")
        self._print("  macOS:    brew install ripgrep")
        self._print("  Linux:    sudo apt install ripgrep  (Ubuntu/Debian)")
        self._print("            sudo dnf install ripgrep  (Fedora/RHEL)")
        self._print("\nOr download from: https://github.com/BurntSushi/ripgrep/releases")

        return False, "ripgrep not installed"

    def ensure_all_tools(self) -> dict:
        """
        Ensure all security scanning tools are available.

        Returns:
            Dict with tool availability status
        """
        results = {}

        # Critical: ripgrep (required)
        ripgrep_ok, ripgrep_msg = self.ensure_ripgrep()
        results["ripgrep"] = {
            "available": ripgrep_ok,
            "message": ripgrep_msg,
            "required": True,
        }

        return results

    def setup_playwright(self) -> Tuple[bool, str]:
        """
        Set up Playwright browsers for web intelligence.

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            __import__("playwright")
        except ImportError:
            return False, "Playwright not installed (pip install playwright)"

        # Check if browsers are installed
        try:
            result = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return False, "Playwright CLI not available"

            # Install Chromium only (smallest footprint)
            self._print("\n🌐 Setting up Playwright browser...", "cyan")

            result = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                self._print("✓ Playwright browser ready", "green")
                return True, "Playwright browser installed"
            else:
                return False, f"Browser installation failed: {result.stderr[:200]}"

        except Exception as e:
            logger.exception("Playwright setup failed")
            return False, f"Setup error: {str(e)}"


# Global instance for easy access
_installer = None


def get_installer(silent: bool = False) -> DependencyInstaller:
    """Get global dependency installer instance."""
    global _installer
    if _installer is None:
        _installer = DependencyInstaller(silent=silent)
    return _installer


def ensure_scanning_tools(silent: bool = False) -> bool:
    """
    Convenience function to ensure all scanning tools are available.

    Args:
        silent: If True, suppress console output

    Returns:
        True if all required tools are available, False otherwise
    """
    installer = get_installer(silent=silent)
    results = installer.ensure_all_tools()

    # Check if required tools are available
    required_ok = all(
        result["available"] for tool, result in results.items() if result["required"]
    )

    return required_ok


if __name__ == "__main__":
    # Test auto-installer
    installer = DependencyInstaller(silent=False)
    results = installer.ensure_all_tools()

    console.print("\n[bold cyan]Installation Results:[/bold cyan]")
    for tool, result in results.items():
        status = "[green]✓[/green]" if result["available"] else "[red]✗[/red]"
        required = (
            "[red](required)[/red]" if result["required"] else "[dim](optional)[/dim]"
        )
        console.print(f"{status} {tool} {required}: {result['message']}")
