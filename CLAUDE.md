# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Impact Scan is a comprehensive security vulnerability scanner for codebases that combines static code analysis, dependency vulnerability scanning, and AI-powered fix generation. It's built in Python using Poetry for dependency management and provides multiple interfaces: CLI, TUI (Textual), and Web UI (Flask), along with professional HTML and SARIF report outputs.

## Development Commands

### Available Commands
The tool provides several commands:
- `impact-scan scan` - Main security scanning command with profiles
- `impact-scan tui` - Launch interactive terminal UI
- `impact-scan web` - Launch web-based UI in browser
- `impact-scan agent-scan` - Multi-agent security platform (advanced)
- `impact-scan profiles` - List available scan profiles
- `impact-scan config` - Check API key configuration
- `impact-scan init` - Generate configuration file

### Installation & Setup
```bash
# Poetry (recommended for development - handles virtual environment automatically)
poetry install                  # Install all dependencies

# Alternative: pip with virtual environment
python -m venv venv             # Create virtual environment
source venv/bin/activate        # Activate (Linux/Mac)
pip install -e .                # Basic installation
pip install -e .[dev]           # With development tools
pip install -e .[local-llm]     # With local LLM support
pip install -e .[all]           # Everything
```

**Important**: After installing with Poetry, always use `poetry run` prefix:
```bash
poetry run impact-scan web      # ✓ Correct
impact-scan web                 # ✗ Won't work (uses system installation)
```

**Note**: Poetry 2.0+ removed the `shell` command. Use `poetry run` for all commands.

If you get "module not found" errors, see the Troubleshooting section below.

### Running the Application
```bash
# Basic scanning (use 'poetry run' prefix if using Poetry, omit if in activated venv)
poetry run impact-scan scan <path>                     # Basic scan
poetry run impact-scan scan <path> --ai gemini         # With AI fixes using Gemini
poetry run impact-scan scan <path> --output report.html # Generate HTML report

# Using profiles (simplifies configuration)
poetry run impact-scan scan --profile quick            # High/critical only
poetry run impact-scan scan --profile standard         # Medium+ with AI fixes
poetry run impact-scan scan --profile comprehensive    # Full scan with web search
poetry run impact-scan scan --profile ci               # CI/CD optimized

# User interfaces
poetry run impact-scan tui                             # Interactive TUI mode
poetry run impact-scan web                             # Web-based UI (Flask)
poetry run impact-scan web --port 8080                 # Custom port
poetry run impact-scan web --no-browser                # Don't auto-open browser

# Configuration management
poetry run impact-scan init                            # Generate config file
poetry run impact-scan profiles                        # List available profiles
poetry run impact-scan config                          # Check API key configuration

# Without Poetry (if installed via pip in activated venv):
# impact-scan scan <path>
# impact-scan tui
# impact-scan web
```

### Testing & Code Quality
```bash
# Testing (use 'poetry run' or activate venv with 'poetry shell' first)
poetry run pytest                               # Run all tests
poetry run pytest tests/test_*.py               # Run specific test file
poetry run pytest --cov                         # Run tests with coverage
poetry run pytest -v tests/test_entrypoint.py   # Run single test file with verbose output

# Code quality (if dev dependencies installed)
poetry run black src/ tests/                    # Format code
poetry run isort src/ tests/                    # Sort imports
poetry run mypy src/                            # Type checking
```

## Architecture Overview

### Core Modules Structure
- `src/impact_scan/core/` - Main scanning logic
  - `entrypoint.py` - Entry point detection (Flask, Next.js) and scan orchestration
  - `static_scan.py` - Static code analysis using Bandit and Semgrep
  - `dep_audit.py` - Dependency vulnerability scanning via OSV database and Safety
  - `aggregator.py` - Result aggregation, deduplication, and SARIF export
  - `fix_ai.py` - AI-powered fix generation (OpenAI, Anthropic, Gemini)
  - `web_search.py` - Web-based security research and context gathering
  - `renderer.py` - Terminal output formatting with Rich
  - `html_report.py` - Professional HTML report generation with dark theme
  - `modern_web_intelligence.py` - Advanced web intelligence gathering
  - `stealth_crawler.py` - Stealthy web crawling capabilities
- `src/impact_scan/utils/` - Shared utilities
  - `schema.py` - Pydantic data models with validation and type safety
  - `paths.py` - File system discovery and content reading
  - `profiles.py` - Predefined scan profiles (quick, standard, comprehensive, ci)
  - `config_file.py` - Configuration file discovery and YAML/TOML parsing
  - `api_key_manager.py` - API key management and validation
  - `logging_config.py` - Centralized logging configuration
- `src/impact_scan/cli.py` - Main CLI interface using Typer framework
- `src/impact_scan/web_ui.py` - Flask-based web interface for browser-based scanning
- `src/impact_scan/tui/` - Terminal User Interface
  - `app.py` - Main TUI application using Textual framework
  - `modern_app.py` - Enhanced TUI with additional features
- `src/impact_scan/agents/` - Multi-agent security platform (advanced feature)
  - `orchestrator.py` - Coordinates multiple specialized agents with different strategies
  - `base.py` - Base agent classes and interfaces
  - `recon.py`, `vuln.py`, `exploit.py`, `fix.py`, `compliance.py` - Specialized agents
  - `static_analysis_agent.py`, `dependency_agent.py` - Agent implementations
  - `factory.py` - Agent factory for dynamic agent creation

### Data Flow
1. CLI parses arguments and loads configuration from profiles or config files
2. `entrypoint.run_scan()` orchestrates the scanning process
3. Entry point detectors identify application frameworks (Flask, Django, etc.)
4. Static and dependency scanners run in parallel
5. `aggregator.py` merges and deduplicates findings
6. Findings are filtered by minimum severity level
7. Optional AI fix generation via `fix_ai.py` (supports multiple providers)
8. Optional web search enhancement via `web_search.py`
9. Results rendered to terminal (`renderer.py`), HTML (`html_report.py`), or SARIF formats

### Interface Options
- **CLI**: Command-line interface with profiles and extensive options (primary interface)
- **TUI**: Interactive terminal interface using Textual framework for real-time scanning
- **Web UI**: Flask-based browser interface accessible via `poetry run impact-scan web`
  - Automatically opens in browser at http://127.0.0.1:5000 (customizable with `--port`)
  - Provides real-time scan progress and interactive reports
  - Use `--no-browser` flag to prevent auto-opening browser
- **Agent System**: Advanced multi-agent orchestration for complex security assessments

### Key Data Models
- `ScanConfig` - Configuration parameters including paths, API keys, severity thresholds
- `Finding` - Individual security findings with metadata, severity, and fix suggestions
- `ScanResult` - Complete scan results with findings, entry points, and metadata
- `EntryPoint` - Detected application entry points with framework identification

### AI Integration
The tool supports multiple AI providers for fix generation:
- OpenAI GPT models via `openai` library
- Anthropic Claude via `anthropic` library  
- Google Gemini via `google-generativeai` library
- Local LLM support via `llama-cpp-python`

API keys are configured via environment variables or CLI parameters and stored in the `APIKeys` model.

## Configuration Management

### Scan Profiles
The tool includes predefined profiles in `utils/profiles.py`:
- `quick`: Fast scan, HIGH+ severity only, no AI features
- `standard`: Balanced scan, MEDIUM+ severity, AI fixes enabled
- `comprehensive`: Full scan, LOW+ severity, AI fixes + web search
- `ci`: CI/CD optimized, configurable severity, minimal output

### Configuration Files
Configuration discovery follows this order (see `config_file.py`):
- `.impact-scan.yml` / `.impact-scan.yaml`
- `impact-scan.yml` / `impact-scan.yaml`
- `pyproject.toml` (under `[tool.impact-scan]` section)

### Environment Variables
```bash
OPENAI_API_KEY        # OpenAI GPT models
ANTHROPIC_API_KEY     # Anthropic Claude models
GOOGLE_API_KEY        # Google Gemini models
STACKOVERFLOW_API_KEY # Web search enhancement
```

## Testing Notes

- Test files are in `tests/` directory
- Uses pytest with configuration in `pyproject.toml`
- Mock objects available via `pytest-mock` for testing AI integrations
- Test data includes vulnerable Flask application in `examples/vuln_flask_app/`
- Tests cover core modules: schema, entrypoint, dep_audit, aggregator

## Dependencies

Key dependencies include:
- **Static Analysis**: `bandit`, `semgrep` for code vulnerability detection
- **Dependency Scanning**: `safety` for dependency vulnerability checking, OSV database integration
- **CLI/UI Frameworks**: `typer` (CLI), `textual` (TUI), `flask` (web UI)
- **Output Formatting**: `rich` (terminal), `sarif-om` (SARIF format), `reportlab` (PDF)
- **Data Validation**: `pydantic` for type-safe data models and validation
- **AI Providers**: `openai`, `anthropic`, `google-generativeai` for fix generation
- **Web Tools**: `requests`, `beautifulsoup4`, `httpx`, `playwright`, `crawlee` for web intelligence
- **Optional**: `llama-cpp-python` for local LLM support (air-gapped environments)

## Important Implementation Notes

### Package Structure
- Uses `src/` layout with `impact_scan` as the main package
- Entry point defined in `pyproject.toml` as `impact-scan = "impact_scan.cli:app"`
- Build system uses `hatchling` backend (PEP 517 compliant)
- Dual packaging: `pyproject.toml` (primary) and `setup.py` (backwards compatibility)
- Dependencies managed via `pyproject.toml` [project.dependencies] section
- **Important**: Use Poetry for development (`poetry install`, `poetry run`) as it handles virtual environments and dependencies automatically

### CLI Interface
- `cli.py`: Full-featured CLI with extensive options, profiles, and TUI integration
- Uses Typer framework for robust command-line interaction

### Multi-Agent Architecture (Advanced)
The `agents/` directory contains an experimental multi-agent security platform:
- `orchestrator.py`: Coordinates agent execution with different strategies (sequential, parallel, pipeline, adaptive)
- Specialized agents for reconnaissance, vulnerability detection, exploitation, fixes, and compliance
- Supports complex dependency management and result sharing between agents
- Agent orchestration strategies allow for flexible execution plans and priority-based scheduling

### Entry Point Detection
The scanner automatically detects application frameworks and entry points:
- **Flask**: Detects `app = Flask(__name__)` patterns and `if __name__ == '__main__'` blocks
- **Next.js**: Identifies canonical Next.js files (App Router, Pages Router, config files)
- Framework detection uses pattern matching and file structure analysis
- Entry points are reported with confidence scores (0.0-1.0)

### Profile System
Profiles in `utils/profiles.py` provide pre-configured scan settings:
- Auto-detection of AI providers based on available API keys (priority: Gemini > OpenAI > Anthropic)
- Profile selection affects severity thresholds, AI features, and web search behavior
- CLI arguments override profile defaults for fine-grained control
- Custom profiles can be defined in configuration files

## Troubleshooting

### "No module named 'flask'" or Missing Dependencies
If you get errors about missing modules when running `impact-scan` commands:

**Problem**: You have multiple installations of impact-scan (system vs Poetry environment).
- System installation: `/home/user/.local/bin/impact-scan` (no dependencies)
- Poetry installation: `~/.cache/pypoetry/virtualenvs/.../bin/impact-scan` (all dependencies)

**Solution**: Always use `poetry run` prefix with Poetry installations:
```bash
poetry run impact-scan web      # ✓ Correct
poetry run impact-scan scan     # ✓ Correct
impact-scan web                 # ✗ Wrong (uses system version)
```

**Check which version you're using**:
```bash
which impact-scan                # Shows system version
poetry run which impact-scan     # Shows Poetry version
```

**Alternative for Poetry 2.0+**: Use `poetry env activate` to get the activation command:
```bash
# Get activation command (one-time)
poetry env activate

# Then source the activation script manually:
source /path/to/venv/bin/activate  # Path shown by above command

# Now you can use impact-scan directly
impact-scan web
```

### Verifying Your Setup
```bash
poetry env info              # Shows Poetry environment details
poetry run pip list | grep flask  # Check if Flask is installed
poetry install               # Reinstall all dependencies if needed
```
