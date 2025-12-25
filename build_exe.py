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

def build_executable(platform="current"):
    """Build Impact-Scan standalone executable"""

    print(f"🔨 Building Impact-Scan executable for {platform}...")

    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--name=impact-scan",
        "--onefile",  # Single executable
        "--console",  # CLI tool
        "--noconfirm",
        "--clean",
        # Include all necessary packages
        "--hidden-import=impact_scan",
        "--hidden-import=semgrep",
        "--hidden-import=bandit",
        "--hidden-import=textual",
        "--hidden-import=typer",
        "--hidden-import=openai",
        "--hidden-import=anthropic",
        "--hidden-import=google.generativeai",
        "--hidden-import=groq",
        # Entry point
        "src/impact_scan/cli.py",
    ]

    # Platform-specific options
    if platform == "windows":
        cmd.extend([
            "--icon=NONE",  # Add icon later
        ])

    try:
        # Install PyInstaller if not present
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)

        # Build executable
        subprocess.run(cmd, check=True)

        print("✅ Build successful!")
        print(f"📦 Executable location: dist/impact-scan{'.exe' if platform == 'windows' else ''}")

        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        return False

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
