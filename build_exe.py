#!/usr/bin/env python3
"""
Build standalone executables for Windows, macOS, and Linux
using PyInstaller.

Usage:
    python build_exe.py        # Build for current platform
    python build_exe.py --all  # Build for all platforms (requires cross-compilation)
"""

import sys
import subprocess
import shutil
from pathlib import Path
import os

# Fix encoding for Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def ensure_package_structure():
    """Ensure the package has proper __init__.py files"""
    src_path = Path("src/impact_scan")
    init_file = src_path / "__init__.py"

    if not init_file.exists():
        print("Creating missing __init__.py...")
        init_file.write_text('''"""
Impact Scan - AI-powered security vulnerability scanner
"""

__version__ = "0.3.0"
__author__ = "Anirudh"

from pathlib import Path

# Package metadata
PACKAGE_ROOT = Path(__file__).parent

__all__ = ["__version__", "__author__", "PACKAGE_ROOT"]
''')
        print("Created __init__.py")

def build_executable(platform="current"):
    """Build Impact-Scan standalone executable"""

    print(f"Building Impact-Scan executable for {platform}...")

    # Ensure package structure is correct
    ensure_package_structure()

    # Use the simplified spec file to avoid dependency conflicts
    spec_file = Path("impact-scan-simple.spec")

    if not spec_file.exists():
        print("Error: impact-scan-simple.spec file not found!")
        print("Please ensure impact-scan-simple.spec exists in the project root.")
        return False

    try:
        # Install PyInstaller and required packages
        print("Installing build dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)

        # Build executable using spec file
        print("Building executable with PyInstaller...")
        cmd = [
            "pyinstaller",
            "--clean",
            "--noconfirm",
            str(spec_file)
        ]

        subprocess.run(cmd, check=True)

        print("Build successful!")
        exe_name = "impact-scan.exe" if sys.platform == "win32" else "impact-scan"
        print(f"Executable location: dist/{exe_name}")

        # Create a README for the distribution
        create_dist_readme()

        return True

    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        return False

def create_dist_readme():
    """Create a README for the distribution package"""
    readme_content = """# Impact-Scan Portable Executable

This is a standalone executable of Impact-Scan that doesn't require Python to be installed.

## ✨ What's Included

This executable bundles all required dependencies including:
- ✓ All Python libraries
- ✓ Ripgrep binary (bundled for code scanning)
- ✓ AI validation tools
- ✓ Report generation tools

**No additional installation required!** Just download and run.

## Important Notes

### Bundled Ripgrep
Impact-Scan includes a bundled ripgrep binary that works out of the box.
The tool automatically detects and uses the bundled version when running as an executable.

If you want to use a system-installed ripgrep instead, you can install it:

**Windows:**
```bash
choco install ripgrep
# Or
winget install BurntSushi.ripgrep.MSVC
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install ripgrep

# Fedora/RHEL
sudo dnf install ripgrep
```

**macOS:**
```bash
brew install ripgrep
```

### Usage

```bash
# Show help
impact-scan --help

# Run TUI mode
impact-scan tui

# Scan a project
impact-scan scan /path/to/project

# Check version
impact-scan --version
```

### First Run
On first run, the tool may need to download additional dependencies. This is normal.

### Troubleshooting

If you encounter "No module named 'impact_scan.cli'" error:
- Make sure you're running the executable from the correct location
- Try running from the directory where the executable is located

If ripgrep is not found:
- Install ripgrep using instructions above
- Make sure ripgrep (rg) is in your PATH

### Groq API Key (Optional)
For AI-powered validation and fix suggestions, set the GROQ_API_KEY environment variable:
```bash
export GROQ_API_KEY="your-api-key"
```
Get a free API key from: https://console.groq.com/

For more information, visit: https://github.com/Ani07-05/impact-scan
"""

    dist_path = Path("dist")
    if dist_path.exists():
        (dist_path / "README.txt").write_text(readme_content, encoding='utf-8')
        print("Created distribution README")

def create_installer_script():
    """Create Windows installer script using Inno Setup"""

    inno_script = """
; Impact-Scan Windows Installer
; Generated with Inno Setup

#define MyAppName "Impact-Scan"
#define MyAppVersion "0.3.0"
#define MyAppPublisher "Anirudh"
#define MyAppURL "https://github.com/Ani07-05/impact-scan"
#define MyAppExeName "impact-scan.exe"

[Setup]
AppId={{YOUR-GUID-HERE}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=installers
OutputBaseFilename=impact-scan-setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"
Name: "addtopath"; Description: "Add to PATH environment variable"; GroupDescription: "System:"

[Files]
Source: "dist\\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"
Name: "{autodesktop}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\\{#MyAppExeName}"; Description: "Launch Impact-Scan"; Flags: nowait postinstall skipifsilent
"""

    Path("impact-scan.iss").write_text(inno_script)
    print("✅ Created Inno Setup script: impact-scan.iss")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build Impact-Scan executables")
    parser.add_argument("--platform", choices=["windows", "linux", "macos", "current"],
                       default="current", help="Target platform")
    parser.add_argument("--installer", action="store_true",
                       help="Create Windows installer script")

    args = parser.parse_args()

    if args.installer:
        create_installer_script()
    else:
        build_executable(args.platform)
