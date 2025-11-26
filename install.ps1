# Impact-Scan Installation Script for Windows (PowerShell)
# Automatically installs Impact-Scan with all dependencies

$ErrorActionPreference = "Stop"

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Impact-Scan Installation Script" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
Write-Host "Checking Python installation..." -ForegroundColor Yellow

try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green

    # Check if Python version is 3.9+
    $version = python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
    $majorMinor = [decimal]$version

    if ($majorMinor -lt 3.9) {
        Write-Host "Error: Python 3.9 or higher is required" -ForegroundColor Red
        Write-Host "Current version: $pythonVersion" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error: Python 3 is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.9+ from https://www.python.org/" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Choose installation method:" -ForegroundColor Cyan
Write-Host "1) Poetry (recommended for development)" -ForegroundColor White
Write-Host "2) pip (simple installation)" -ForegroundColor White
Write-Host "3) Docker (containerized)" -ForegroundColor White
$choice = Read-Host "Enter choice [1-3]"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "Installing with Poetry..." -ForegroundColor Yellow

        # Check if Poetry is installed
        try {
            $poetryVersion = poetry --version 2>&1
            Write-Host "Poetry is already installed: $poetryVersion" -ForegroundColor Green
        } catch {
            Write-Host "Poetry not found. Installing Poetry..." -ForegroundColor Yellow

            # Install Poetry using the official installer
            (Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -

            # Add Poetry to PATH for current session
            $env:Path += ";$env:APPDATA\Python\Scripts"

            Write-Host "Poetry installed successfully" -ForegroundColor Green
        }

        # Install dependencies
        Write-Host "Installing Impact-Scan dependencies..." -ForegroundColor Yellow
        poetry install --all-extras

        Write-Host ""
        Write-Host "Installation complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "To use Impact-Scan:" -ForegroundColor Cyan
        Write-Host "  poetry run impact-scan --help" -ForegroundColor White
        Write-Host "  poetry run impact-scan scan <path>" -ForegroundColor White
        Write-Host "  poetry run impact-scan web" -ForegroundColor White
        Write-Host ""
        Write-Host "Or activate the virtual environment:" -ForegroundColor Cyan
        Write-Host "  poetry shell" -ForegroundColor White
        Write-Host "  impact-scan --help" -ForegroundColor White
    }

    "2" {
        Write-Host ""
        Write-Host "Installing with pip..." -ForegroundColor Yellow

        # Create virtual environment
        Write-Host "Creating virtual environment..." -ForegroundColor Yellow
        python -m venv venv

        # Activate virtual environment
        .\venv\Scripts\Activate.ps1

        # Upgrade pip
        Write-Host "Upgrading pip..." -ForegroundColor Yellow
        python -m pip install --upgrade pip

        # Install Impact-Scan
        Write-Host "Installing Impact-Scan..." -ForegroundColor Yellow
        pip install -e .[all]

        # Install external tools
        Write-Host "Installing external security tools..." -ForegroundColor Yellow
        pip install semgrep pip-audit safety

        Write-Host ""
        Write-Host "Installation complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "To use Impact-Scan:" -ForegroundColor Cyan
        Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor White
        Write-Host "  impact-scan --help" -ForegroundColor White
        Write-Host "  impact-scan scan <path>" -ForegroundColor White
        Write-Host "  impact-scan web" -ForegroundColor White
        Write-Host ""
        Write-Host "Virtual environment created in: .\venv" -ForegroundColor Yellow
    }

    "3" {
        Write-Host ""
        Write-Host "Installing with Docker..." -ForegroundColor Yellow

        # Check if Docker is installed
        try {
            $dockerVersion = docker --version 2>&1
            Write-Host "Found: $dockerVersion" -ForegroundColor Green
        } catch {
            Write-Host "Error: Docker is not installed" -ForegroundColor Red
            Write-Host "Please install Docker Desktop from https://www.docker.com/" -ForegroundColor Red
            exit 1
        }

        Write-Host "Building Docker image..." -ForegroundColor Yellow
        docker build -t impact-scan:latest .

        Write-Host ""
        Write-Host "Docker installation complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "To use Impact-Scan with Docker:" -ForegroundColor Cyan
        Write-Host "  docker run -v ${PWD}:/workspace impact-scan scan /workspace" -ForegroundColor White
        Write-Host "  docker run -p 5000:5000 -v ${PWD}:/workspace impact-scan web" -ForegroundColor White
        Write-Host ""
        Write-Host "Or use docker-compose:" -ForegroundColor Cyan
        Write-Host "  docker-compose run scan" -ForegroundColor White
        Write-Host "  docker-compose up web" -ForegroundColor White
    }

    default {
        Write-Host "Invalid choice" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Optional: Configure API keys for AI-powered features" -ForegroundColor Cyan
Write-Host "Set environment variables:" -ForegroundColor Yellow
Write-Host '  $env:GROQ_API_KEY = "your-key-here"        # Recommended (fastest + free tier)' -ForegroundColor White
Write-Host '  $env:GOOGLE_API_KEY = "your-key-here"      # Gemini (cheapest)' -ForegroundColor White
Write-Host '  $env:OPENAI_API_KEY = "your-key-here"      # GPT models' -ForegroundColor White
Write-Host '  $env:ANTHROPIC_API_KEY = "your-key-here"   # Claude models' -ForegroundColor White
Write-Host ""
Write-Host "Verify installation:" -ForegroundColor Cyan
Write-Host "  impact-scan --version" -ForegroundColor White
Write-Host "  impact-scan doctor  # Health check" -ForegroundColor White
Write-Host ""
Write-Host "Installation script completed successfully!" -ForegroundColor Green
