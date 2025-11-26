# Installation Guide

Impact-Scan can be installed using Poetry, pip, or Docker. Choose the method that best fits your workflow.

## Quick Start

### Linux/macOS
```bash
# Run the automated installation script
chmod +x install.sh
./install.sh
```

### Windows (PowerShell)
```powershell
# Run the automated installation script
.\install.ps1
```

## Manual Installation

### Method 1: Poetry (Recommended for Development)

Poetry automatically manages dependencies and virtual environments.

```bash
# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Install Impact-Scan with all dependencies
poetry install --all-extras

# Run Impact-Scan
poetry run impact-scan --help
poetry run impact-scan scan <path>
```

**Note**: Always use `poetry run` prefix when running commands with Poetry.

### Method 2: pip (Simple Installation)

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

# Install Impact-Scan
pip install -e .[all]

# Install external security tools
pip install semgrep pip-audit safety

# Run Impact-Scan
impact-scan --help
impact-scan scan <path>
```

### Method 3: Docker (Containerized)

Docker provides a fully self-contained environment with all dependencies.

```bash
# Build the Docker image
docker build -t impact-scan:latest .

# Run a scan
docker run -v $(pwd):/workspace impact-scan scan /workspace

# Use docker-compose for easier management
docker-compose run scan
docker-compose up web  # Launch web UI
```

**Windows PowerShell**:
```powershell
docker run -v ${PWD}:/workspace impact-scan scan /workspace
```

## Installation Options

### Basic Installation
```bash
pip install -e .
```

### With Development Tools
```bash
pip install -e .[dev]
```

### With Local LLM Support
```bash
pip install -e .[local-llm]
```

### Full Installation (All Features)
```bash
pip install -e .[all]
```

## External Dependencies

Impact-Scan requires these external tools for full functionality:

### Required Tools
- **Semgrep**: Static code analysis
  ```bash
  pip install semgrep
  ```

- **pip-audit**: Python dependency vulnerability scanning
  ```bash
  pip install pip-audit
  ```

- **Safety**: Alternative dependency scanner
  ```bash
  pip install safety
  ```

### Optional Tools
- **Playwright**: Web intelligence features
  ```bash
  pip install playwright
  playwright install chromium
  ```

- **Local LLM**: Air-gapped AI features
  ```bash
  pip install llama-cpp-python
  ```

## API Key Configuration

For AI-powered features, configure at least one API key:

### Option 1: Environment Variables (Recommended)
```bash
# Groq (recommended: fastest + free tier)
export GROQ_API_KEY='your-key-here'

# Google Gemini (cheapest: $0.15/1M tokens)
export GOOGLE_API_KEY='your-key-here'

# OpenAI GPT models
export OPENAI_API_KEY='your-key-here'

# Anthropic Claude models
export ANTHROPIC_API_KEY='your-key-here'
```

**Windows PowerShell**:
```powershell
$env:GROQ_API_KEY = "your-key-here"
$env:GOOGLE_API_KEY = "your-key-here"
```

### Option 2: Configuration File
Create `.impact-scan.yml` in your project root:
```yaml
ai:
  provider: groq  # or: gemini, openai, anthropic
  api_key: your-key-here
```

### Option 3: Interactive Setup
```bash
impact-scan init  # Generates config file
impact-scan config  # Check configuration
```

## Verify Installation

```bash
# Check version
impact-scan --version

# Health check (verifies all dependencies)
impact-scan doctor

# List available commands
impact-scan --help

# List scan profiles
impact-scan profiles
```

## Troubleshooting

### "No module named 'impact_scan'"
**Problem**: Multiple installations exist (system vs virtual environment).

**Solution**: Use the correct command prefix:
- **Poetry**: Always use `poetry run impact-scan`
- **pip (venv)**: Activate virtual environment first with `source venv/bin/activate`

Check which version you're using:
```bash
which impact-scan  # Shows system version
poetry run which impact-scan  # Shows Poetry version
```

### "semgrep: command not found"
**Solution**: Install Semgrep separately:
```bash
pip install semgrep
```

### Docker Build Fails
**Solution**: Ensure you have the required files:
- `pyproject.toml`
- `README.md`
- `LICENSE`
- `src/` directory

### Permission Denied (Linux/macOS)
**Solution**: Make installation script executable:
```bash
chmod +x install.sh
./install.sh
```

## System Requirements

- **Python**: 3.9 or higher
- **OS**: Linux, macOS, or Windows
- **Disk Space**: ~500MB for full installation with dependencies
- **Memory**: 2GB minimum, 4GB recommended
- **Network**: Internet connection required for initial setup and AI features

## Docker System Requirements

- **Docker**: 20.10 or higher
- **Docker Compose**: 1.29 or higher (optional, for docker-compose)
- **Disk Space**: ~1.5GB for Docker image
- **Memory**: 2GB minimum

## Next Steps

After installation:

1. **Verify Setup**
   ```bash
   impact-scan doctor
   ```

2. **Run Your First Scan**
   ```bash
   impact-scan scan /path/to/project
   ```

3. **Try Different Interfaces**
   ```bash
   impact-scan tui      # Interactive terminal UI
   impact-scan web      # Web browser UI
   ```

4. **Explore Scan Profiles**
   ```bash
   impact-scan profiles           # List available profiles
   impact-scan scan . --profile quick
   impact-scan scan . --profile comprehensive
   ```

5. **Enable AI Features**
   ```bash
   # With AI-powered fix generation
   impact-scan scan . --ai groq

   # With AI-powered false positive reduction
   impact-scan scan . --ai-validation
   ```

## Uninstallation

### Poetry
```bash
poetry env remove python
```

### pip
```bash
pip uninstall impact-scan
rm -rf venv
```

### Docker
```bash
docker rmi impact-scan:latest
```

## Getting Help

- Documentation: See [README.md](README.md) and [CLAUDE.md](CLAUDE.md)
- Issues: https://github.com/your-repo/impact-scan/issues
- Version Info: `impact-scan --version`
- Health Check: `impact-scan doctor`
