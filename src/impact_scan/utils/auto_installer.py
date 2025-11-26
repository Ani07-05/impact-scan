"""
Automatic dependency installer for Impact-Scan.
Ensures seamless out-of-box experience like Claude Code.

Handles:
- Semgrep auto-installation
- pip-audit auto-installation
- Safety auto-installation
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
            tool_name: Name of the tool (e.g., 'semgrep', 'pip-audit')

        Returns:
            True if tool is available, False otherwise
        """
        return shutil.which(tool_name) is not None

    def install_package(
        self, package_name: str, display_name: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Install a Python package using pip.

        Args:
            package_name: PyPI package name
            display_name: Human-readable name for display

        Returns:
            Tuple of (success: bool, message: str)
        """
        display = display_name or package_name

        try:
            self._print(f"\n📦 Installing {display}...", "yellow")

            # Use --user flag for non-virtual environments
            in_venv = hasattr(sys, "real_prefix") or (
                hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
            )

            cmd = [sys.executable, "-m", "pip", "install", package_name]
            if not in_venv:
                cmd.append("--user")

            # Show progress with spinner
            if not self.silent:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    transient=True,
                ) as progress:
                    task = progress.add_task(f"Installing {display}...", total=None)
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300,  # 5 minutes timeout
                    )
                    progress.update(task, completed=True)
            else:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )

            if result.returncode == 0:
                self._print(f"✓ {display} installed successfully!", "green")
                logger.info(f"{package_name} installed successfully")
                return True, f"{display} installed successfully"
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                self._print(f"✗ Failed to install {display}", "red")
                logger.error(f"Failed to install {package_name}: {error_msg}")
                return False, f"Installation failed: {error_msg[:200]}"

        except subprocess.TimeoutExpired:
            self._print("✗ Installation timed out after 5 minutes", "red")
            return False, "Installation timed out"
        except Exception as e:
            self._print(f"✗ Installation error: {e}", "red")
            logger.exception(f"Error installing {package_name}")
            return False, f"Installation error: {str(e)}"

    def ensure_semgrep(self, auto_install: bool = True) -> Tuple[bool, str]:
        """
        Ensure Semgrep is installed.

        Args:
            auto_install: If True, automatically install if missing

        Returns:
            Tuple of (available: bool, message: str)
        """
        if self.check_tool("semgrep"):
            try:
                result = subprocess.run(
                    ["semgrep", "--version"], capture_output=True, text=True, timeout=5
                )
                version = (
                    result.stdout.strip().split("\n")[0]
                    if result.returncode == 0
                    else "unknown"
                )
                logger.info(f"Semgrep {version} found")
                return True, f"Semgrep {version} is available"
            except Exception as e:
                logger.warning(f"Semgrep found but version check failed: {e}")
                return True, "Semgrep is available (version unknown)"

        # Not installed
        if not auto_install:
            return False, "Semgrep not installed"

        # Auto-install
        self._print("\n[yellow]⚠ Semgrep not found[/yellow]")
        self._print("Semgrep is required for static code analysis")

        if not self.silent:
            try:
                from rich.prompt import Confirm

                if not Confirm.ask("Install Semgrep now?", default=True):
                    return False, "User declined Semgrep installation"
            except Exception:
                # If prompting fails, proceed with installation
                pass

        success, message = self.install_package("semgrep", "Semgrep")

        if success:
            # Verify installation
            if self.check_tool("semgrep"):
                return True, "Semgrep installed and ready"
            else:
                return False, "Semgrep installed but not in PATH (restart terminal)"

        return False, message

    def ensure_pip_audit(self, auto_install: bool = True) -> Tuple[bool, str]:
        """
        Ensure pip-audit is installed (optional but recommended).

        Args:
            auto_install: If True, automatically install if missing

        Returns:
            Tuple of (available: bool, message: str)
        """
        if self.check_tool("pip-audit"):
            logger.info("pip-audit found")
            return True, "pip-audit is available"

        if not auto_install:
            return False, "pip-audit not installed (optional)"

        # Auto-install (silent for optional dependency)
        logger.info("Installing pip-audit (optional dependency)")
        success, message = self.install_package("pip-audit", "pip-audit")

        return success, message if success else "pip-audit not installed (optional)"

    def ensure_safety(self, auto_install: bool = True) -> Tuple[bool, str]:
        """
        Ensure Safety is installed (optional fallback).

        Args:
            auto_install: If True, automatically install if missing

        Returns:
            Tuple of (available: bool, message: str)
        """
        try:
            __import__("safety")
            logger.info("Safety found")
            return True, "Safety is available"
        except ImportError:
            pass

        if not auto_install:
            return False, "Safety not installed (optional)"

        # Auto-install (silent for optional dependency)
        logger.info("Installing Safety (optional dependency)")
        success, message = self.install_package("safety", "Safety")

        return success, message if success else "Safety not installed (optional)"

    def ensure_all_tools(self, auto_install: bool = True) -> dict:
        """
        Ensure all security scanning tools are available.

        Args:
            auto_install: If True, automatically install missing tools

        Returns:
            Dict with tool availability status
        """
        results = {}

        # Critical: Semgrep (required)
        semgrep_ok, semgrep_msg = self.ensure_semgrep(auto_install)
        results["semgrep"] = {
            "available": semgrep_ok,
            "message": semgrep_msg,
            "required": True,
        }

        # Optional: pip-audit (recommended)
        pip_audit_ok, pip_audit_msg = self.ensure_pip_audit(auto_install)
        results["pip-audit"] = {
            "available": pip_audit_ok,
            "message": pip_audit_msg,
            "required": False,
        }

        # Optional: Safety (fallback)
        safety_ok, safety_msg = self.ensure_safety(auto_install)
        results["safety"] = {
            "available": safety_ok,
            "message": safety_msg,
            "required": False,
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


def ensure_scanning_tools(auto_install: bool = True, silent: bool = False) -> bool:
    """
    Convenience function to ensure all scanning tools are available.

    Args:
        auto_install: If True, automatically install missing tools
        silent: If True, suppress console output

    Returns:
        True if all required tools are available, False otherwise
    """
    installer = get_installer(silent=silent)
    results = installer.ensure_all_tools(auto_install)

    # Check if required tools are available
    required_ok = all(
        result["available"] for tool, result in results.items() if result["required"]
    )

    return required_ok


if __name__ == "__main__":
    # Test auto-installer
    installer = DependencyInstaller(silent=False)
    results = installer.ensure_all_tools(auto_install=True)

    console.print("\n[bold cyan]Installation Results:[/bold cyan]")
    for tool, result in results.items():
        status = "[green]✓[/green]" if result["available"] else "[red]✗[/red]"
        required = (
            "[red](required)[/red]" if result["required"] else "[dim](optional)[/dim]"
        )
        console.print(f"{status} {tool} {required}: {result['message']}")
