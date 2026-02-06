"""
Automatic dependency installer for Impact-Scan.
Ensures seamless out-of-box experience.

Handles:
- Ripgrep availability check
- Playwright browser setup
"""

import logging
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Optional, Tuple
from urllib.request import urlopen

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

    def _get_ripgrep_install_dir(self) -> Path:
        """Get the directory where ripgrep should be installed."""
        if sys.platform == 'win32':
            # Use user's local bin directory on Windows
            base = Path.home() / '.impact-scan' / 'tools' / 'ripgrep'
        else:
            # Use ~/.local/bin on Unix-like systems
            base = Path.home() / '.local' / 'share' / 'impact-scan' / 'ripgrep'
        
        base.mkdir(parents=True, exist_ok=True)
        return base

    def _download_ripgrep(self) -> Optional[str]:
        """
        Auto-download and install ripgrep.
        
        Returns:
            Path to rg executable if successful, None otherwise
        """
        import platform
        
        # Determine download URL based on platform and architecture
        machine = platform.machine().lower()
        system = sys.platform
        
        if system == 'win32':
            if machine in ('amd64', 'x86_64'):
                url = 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-x86_64-pc-windows-msvc.zip'
                rg_name = 'rg.exe'
            else:
                return None
        elif system == 'darwin':  # macOS
            if machine == 'arm64':
                url = 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-aarch64-apple-darwin.tar.gz'
            else:
                url = 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-x86_64-apple-darwin.tar.gz'
            rg_name = 'rg'
        elif system.startswith('linux'):
            if machine in ('amd64', 'x86_64'):
                url = 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-x86_64-unknown-linux-musl.tar.gz'
            elif machine == 'aarch64':
                url = 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-aarch64-unknown-linux-musl.tar.gz'
            else:
                return None
            rg_name = 'rg'
        else:
            return None
        
        try:
            install_dir = self._get_ripgrep_install_dir()
            self._print(f"\n[cyan]Downloading ripgrep...[/cyan]")
            
            # Download the file
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir_path = Path(tmpdir)
                download_path = tmpdir_path / 'ripgrep-archive'
                
                # Download with progress
                with urlopen(url) as response:
                    total_size = int(response.headers.get('content-length', 0))
                    downloaded = 0
                    chunk_size = 8192
                    
                    with open(download_path, 'wb') as f:
                        while True:
                            chunk = response.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0 and not self.silent:
                                percent = (downloaded / total_size) * 100
                                logger.debug(f"Downloaded {percent:.1f}%")
                
                # Extract the archive
                if url.endswith('.zip'):
                    with zipfile.ZipFile(download_path, 'r') as zip_ref:
                        zip_ref.extractall(tmpdir_path)
                else:  # tar.gz
                    import tarfile
                    with tarfile.open(download_path, 'r:gz') as tar_ref:
                        tar_ref.extractall(tmpdir_path)
                
                # Find the rg executable in the extracted files
                rg_path = None
                for root, dirs, files in os.walk(tmpdir_path):
                    if rg_name in files:
                        rg_path = Path(root) / rg_name
                        break
                
                if not rg_path or not rg_path.exists():
                    logger.error("Could not find rg executable in downloaded archive")
                    return None
                
                # Copy to install directory
                final_path = install_dir / rg_name
                shutil.copy2(rg_path, final_path)
                
                # Make executable on Unix
                if sys.platform != 'win32':
                    os.chmod(final_path, 0o755)
                
                logger.info(f"Ripgrep installed to: {final_path}")
                self._print(f"[green]✓ Ripgrep installed successfully[/green]")
                return str(final_path)
                
        except Exception as e:
            logger.error(f"Failed to auto-download ripgrep: {e}")
            self._print(f"[red]Failed to download ripgrep: {e}[/red]")
            return None

    def ensure_ripgrep(self) -> Tuple[bool, str]:
        """
        Ensure ripgrep is installed.
        
        Will attempt to auto-download ripgrep if not found in system PATH.

        Returns:
            Tuple of (available: bool, message: str)
        """
        # First check for bundled ripgrep (for executable distributions)
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

        # Check if we previously downloaded ripgrep to ~/.impact-scan/tools
        install_dir = self._get_ripgrep_install_dir()
        rg_name = 'rg.exe' if sys.platform == 'win32' else 'rg'
        local_rg = install_dir / rg_name
        
        if local_rg.exists():
            try:
                result = subprocess.run(
                    [str(local_rg), "--version"], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    # Add to PATH for this process
                    if str(install_dir) not in os.environ.get('PATH', ''):
                        os.environ['PATH'] = str(install_dir) + os.pathsep + os.environ.get('PATH', '')
                    logger.info(f"Found locally installed ripgrep at: {local_rg}")
                    return True, f"ripgrep is available (local install)"
            except Exception as e:
                logger.warning(f"Local ripgrep exists but failed to verify: {e}")

        # Not found - attempt auto-download
        self._print("\n[yellow]ripgrep not found in system PATH[/yellow]")
        self._print("[cyan]Attempting to auto-download ripgrep...[/cyan]")
        
        rg_path = self._download_ripgrep()
        if rg_path:
            # Add to PATH for this process
            install_dir = Path(rg_path).parent
            if str(install_dir) not in os.environ.get('PATH', ''):
                os.environ['PATH'] = str(install_dir) + os.pathsep + os.environ.get('PATH', '')
            return True, "ripgrep auto-installed successfully"
        
        # Failed to auto-install - provide manual instructions
        self._print("\n[red]Failed to auto-download ripgrep[/red]")
        self._print("[yellow]Please install ripgrep manually:[/yellow]")
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
