# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Impact Scan is a comprehensive security vulnerability scanner for codebases that combines static code analysis, dependency vulnerability scanning, and AI-powered fix generation. It's built in Python using Poetry for dependency management and provides multiple interfaces: CLI, TUI, and Web UI (Flask), along with professional HTML, Markdown, and SARIF report outputs.

**Current version:** 0.2.0 (as of pyproject.toml)

**Recent changes:**
- Added JWT/OAuth security scanning (25+ Semgrep rules + 16 custom rules)
- Implemented AI-powered false positive reduction (optional, ~91% FP reduction)
- Enhanced Hexa OAuth vulnerability detection (missing state, ID token, CORS)
- Major cleanup and restructuring (removed legacy TUI modules)
- Added unified dependency scanner for Python and JavaScript
- Enhanced ParseBot and Stack Overflow scraper integration
- Added quality and review agents to multi-agent platform
- Improved SARIF 2.1.0 and Markdown report generation

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

# Multiple output formats
poetry run impact-scan scan . --output-format all      # Generate all formats
poetry run impact-scan scan . --output-format html,sarif  # Specific formats
poetry run impact-scan scan . -o report.md             # Markdown report
poetry run impact-scan scan . -o report.sarif          # SARIF for GitHub Security

# JWT/OAuth security scanning (NEW)
poetry run impact-scan scan . --profile comprehensive  # Includes JWT/OAuth rules
poetry run impact-scan scan hexa/backend               # Scan for OAuth vulnerabilities
# Detects: Missing state parameter, ID token issues, CORS misconfig, weak secrets

# AI-powered false positive reduction (NEW - optional, ~$0.01/scan)
poetry run impact-scan scan . --ai-validation          # Reduce false positives by ~91%
poetry run impact-scan scan . --ai-validation --ai-validation-provider gemini  # Use Gemini
poetry run impact-scan scan . --ai-validation --save-false-positives  # Save FP to JSON

# Web intelligence features
poetry run impact-scan scan . --no-stackoverflow       # Disable Stack Overflow only
poetry run impact-scan scan . --no-web-search          # Disable all web features

# User interfaces
poetry run impact-scan tui                             # Interactive TUI mode
poetry run impact-scan web                             # Web-based UI (Flask)
poetry run impact-scan web --port 8080                 # Custom port
poetry run impact-scan web --no-browser                # Don't auto-open browser
poetry run impact-scan agent-scan                      # Multi-agent platform

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
  - `unified_dependency_scanner.py` - Unified scanner for Python and JavaScript dependencies
  - `aggregator.py` - Result aggregation, deduplication, and filtering
  - `fix_ai.py` - AI-powered fix generation (OpenAI, Anthropic, Gemini, Groq)
  - `ai_validator.py` - AI-powered false positive reduction (NEW - optional, ~91% FP reduction)
  - `renderer.py` - Terminal output formatting with Rich
  - `html_report.py` - Professional HTML report generation with dark theme
  - `markdown_report.py` - Markdown report generation for GitHub integration
  - `sarif_report.py` - SARIF 2.1.0 format export for CI/CD tools
  - `parsebot_client.py` - ParseBot integration for web intelligence
  - `stackoverflow_scraper.py` - Stack Overflow scraping for vulnerability fixes
  - `vulnerability_knowledge_base.py` - Centralized vulnerability information database
  - `scanners/` - Language-specific scanners
    - `python_scanner.py` - Python-specific vulnerability detection
    - `javascript_scanner.py` - JavaScript/Node.js vulnerability detection
- `src/impact_scan/rules/` - Custom Semgrep security rules (NEW)
  - `jwt.yml` - JWT security rules (8 rules: decode without verify, hardcoded secrets, weak secrets, none algorithm, etc.)
  - `oauth-security.yml` - OAuth/authentication rules (8 rules: missing state parameter, ID token verification, CORS misconfiguration, cookie security)
  - `python-security.yml` - Python-specific SQL injection and hardcoded secret detection
  - `nextjs.yml` - Next.js/React XSS and SSRF detection
  - **Total**: 40+ custom rules + 25+ Semgrep p/jwt registry rules
  - **Legacy/Experimental** (see `_LEGACY_MODULES.md`):
    - `comprehensive_security_crawler.py` - Not used in v1.0
    - `modern_web_intelligence.py` - Not used in v1.0
- `src/impact_scan/utils/` - Shared utilities
  - `schema.py` - Pydantic data models with validation and type safety
  - `paths.py` - File system discovery and content reading
  - `profiles.py` - Predefined scan profiles (quick, standard, comprehensive, ci)
  - `config_file.py` - Configuration file discovery and YAML/TOML parsing
  - `api_key_manager.py` - API key management and validation
  - `logging_config.py` - Centralized logging configuration
- `src/impact_scan/cli.py` - Main CLI interface using Typer framework
- `src/impact_scan/web_ui.py` - Flask-based web interface for browser-based scanning
- `src/impact_scan/tui/` - Terminal User Interface (removed in recent cleanup)
  - TUI functionality has been consolidated into the web UI and CLI
- `src/impact_scan/agents/` - Multi-agent security platform (advanced feature)
  - `orchestrator.py` - Coordinates multiple specialized agents with different strategies
  - `base.py` - Base agent classes and interfaces
  - `recon.py`, `vuln.py`, `exploit.py`, `fix.py`, `compliance.py` - Specialized security agents
  - `quality.py`, `review.py` - Code quality and review agents
  - `static_analysis_agent.py`, `dependency_agent.py` - Agent implementations
  - `factory.py` - Agent factory for dynamic agent creation

### Data Flow
1. CLI parses arguments and loads configuration from profiles or config files
2. `entrypoint.run_scan()` orchestrates the scanning process
3. Entry point detectors identify application frameworks (Flask, Django, Next.js, etc.)
4. Language-specific scanners (in `scanners/`) detect Python and JavaScript vulnerabilities
5. Static analysis (Bandit, Semgrep) and dependency scanners run in parallel
6. `aggregator.py` merges, deduplicates, and filters findings by severity
7. Optional AI fix generation via `fix_ai.py` (supports OpenAI, Anthropic, Gemini, Groq)
8. Optional web intelligence via `stackoverflow_scraper.py` and `parsebot_client.py`
9. Results rendered to:
   - Terminal: `renderer.py` with Rich formatting
   - HTML: `html_report.py` with dark theme and interactive features
   - Markdown: `markdown_report.py` for GitHub integration
   - SARIF: `sarif_report.py` for CI/CD tools (GitHub Security, GitLab, etc.)

### Interface Options
- **CLI**: Command-line interface with profiles and extensive options (primary interface)
  - Supports multiple output formats: JSON, HTML, Markdown, SARIF
  - Use `--output-format all` to generate all formats simultaneously
- **TUI**: Interactive terminal interface using pytermgui framework
  - Launched via `impact-scan tui` for file browsing and real-time scanning
- **Web UI**: Flask-based browser interface accessible via `poetry run impact-scan web`
  - Automatically opens in browser at http://127.0.0.1:5000 (customizable with `--port`)
  - Provides real-time scan progress and interactive reports
  - Use `--no-browser` flag to prevent auto-opening browser
- **Agent System**: Advanced multi-agent orchestration for complex security assessments
  - Accessed via `impact-scan agent-scan` command

### Key Data Models
- `ScanConfig` - Configuration parameters including paths, API keys, severity thresholds
- `Finding` - Individual security findings with metadata, severity, and fix suggestions
- `ScanResult` - Complete scan results with findings, entry points, and metadata
- `EntryPoint` - Detected application entry points with framework identification

### AI Integration
The tool supports multiple AI providers for **fix generation** and **false positive reduction**:
- **OpenAI**: GPT-4 and other models via `openai` library
- **Anthropic**: Claude models via `anthropic` library
- **Google Gemini**: Latest Gemini models via `google-generativeai` library
- **Groq**: Fast inference via `groq` library
- **Local LLM**: Air-gapped environments via `llama-cpp-python` (optional)

Provider auto-detection priority: Groq > Gemini > OpenAI > Anthropic

API keys are configured via environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `GROQ_API_KEY`) or CLI parameters.

#### AI-Powered False Positive Reduction
**NEW**: Optional AI validation feature to reduce false positives by ~91% (based on SAST-Genius research).

**How it works:**
1. Semgrep/Bandit find potential vulnerabilities (rule-based, fast, free)
2. AI validates each finding with contextual code analysis (optional, requires API key)
3. False positives are filtered out, dramatically improving signal-to-noise ratio

**Usage:**
```bash
# Enable AI validation (opt-in)
poetry run impact-scan scan . --ai-validation

# Specify provider and cost limit
poetry run impact-scan scan . --ai-validation --ai-validation-provider groq --ai-validation-limit 20

# Save false positives for review
poetry run impact-scan scan . --ai-validation --save-false-positives
```

**Cost:** ~$0.01/scan with Gemini Flash, ~$0.00/scan with Groq free tier

**Architecture:**
- `src/impact_scan/core/ai_validator.py` - AI validation logic
- Integrates into `entrypoint.py` pipeline after severity filtering
- Fail-open design: keeps findings if AI validation fails (prevents false negatives)

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
GROQ_API_KEY          # Groq fast inference models
STACKOVERFLOW_API_KEY # Stack Overflow API access (optional)
```

## GitHub Actions Integration

The repository includes a production-ready GitHub Actions workflow (`.github/workflows/impact-scan.yml`) that:
- Runs security scans on push, PR, and weekly schedule
- Uploads SARIF results to GitHub Security tab
- Generates HTML and Markdown reports as artifacts
- Posts scan results as PR comments
- Fails the build if critical vulnerabilities are found

**Key features:**
- Configurable scan profiles via workflow dispatch
- Support for multiple AI providers via secrets
- Automatic SARIF upload to GitHub Advanced Security
- 90-day artifact retention for reports
- jq-based parsing for vulnerability thresholds

**Required secrets** (optional, for AI-powered fixes):
- `GROQ_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, or `OPENAI_API_KEY`

**Required permissions:**
- `contents: read` - Checkout code
- `security-events: write` - Upload SARIF to Security tab
- `pull-requests: write` - Comment on PRs

## Testing Notes

- Test files are in `tests/` directory
- Uses pytest with configuration in `pyproject.toml`
- Mock objects available via `pytest-mock` for testing AI integrations
- Test data available in `tests/data/` directory
- Integration tests for:
  - Dependency scanning (`test_dependency_integration.py`)
  - Static analysis on vulnerable code (`test_static_scan_vulnerable.py`)
  - Real CVE detection (`test_real_cve.py`)
  - Web intelligence features (`test_modern_web_intelligence.py`)
- Many test JSON outputs are committed for reference (e.g., `gemini_scan.json`, `vulnerable_flask_scan_results.json`)

## Dependencies

Key dependencies include:
- **Static Analysis**: `bandit`, `semgrep` for code vulnerability detection
- **Dependency Scanning**: `safety` for dependency vulnerability checking, OSV database integration
- **CLI/UI Frameworks**: `typer` (CLI), `flask` (web UI), `pytermgui` (TUI)
- **Output Formatting**: `rich` (terminal), `sarif-om` (SARIF format), `reportlab` (PDF), `markdown` (Markdown)
- **Data Validation**: `pydantic` for type-safe data models and validation
- **AI Providers**: `openai`, `anthropic`, `google-generativeai`, `google-genai`, `groq` for fix generation
- **Web Tools**: `requests`, `beautifulsoup4`, `httpx`, `playwright`, `crawlee`, `aiofiles` for web intelligence
- **Code Analysis**: `radon` for complexity metrics, `pygments` for syntax highlighting
- **Configuration**: `pyyaml` (YAML), `tomli` (TOML for Python <3.11)
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

## JWT/OAuth Security Detection

Impact-Scan now includes comprehensive JWT and OAuth vulnerability detection with 40+ security rules.

**Detection Coverage:**
- **Semgrep p/jwt ruleset**: 25+ official JWT security rules from Semgrep registry
- **Custom OAuth rules** (`rules/oauth-security.yml`): 8 rules for OAuth/OIDC vulnerabilities
  - Missing OAuth state parameter (CSRF protection) - CWE-352
  - ID token not verified (uses access_token without signature validation) - CWE-345
  - Wildcard CORS with credentials - CWE-942
  - Session cookie security issues (secure, samesite, httponly flags)
- **Custom JWT rules** (`rules/jwt.yml`): 8 rules for JWT vulnerabilities
  - JWT decode without signature verification - CWE-347
  - Missing algorithm specification (algorithm confusion attacks) - CWE-327
  - Hardcoded JWT secrets - CWE-798
  - "none" algorithm usage
  - Weak secrets - CWE-521
  - Missing token expiration - CWE-613

**Supported Languages:** Python, JavaScript, TypeScript, Node.js, Ruby, Java, Go

**Real-World Validation:** Successfully detects vulnerabilities from Hexa OAuth implementation (commit b611ecf):
- Missing state parameter in Google OAuth flow
- Access token used without ID token verification
- Wildcard CORS configuration with credentials enabled

**Example Usage:**
```bash
# Scan for JWT/OAuth vulnerabilities
poetry run impact-scan scan backend/auth --profile comprehensive

# Scan Hexa repository for OAuth issues
poetry run impact-scan scan d:\oss\impact-scan\hexa\hexa\backend --output hexa_scan.html

# Results: Detects ID token verification issues and CORS misconfigurations
```

## AI-Powered False Positive Reduction

Optionally reduce false positives by ~91% using AI validation.

**How It Works:**
1. Static analysis (Semgrep, Bandit) detects potential vulnerabilities
2. Optional AI validation (`--ai-validation` flag) analyzes each finding in full code context
3. LLM determines TRUE_POSITIVE or FALSE_POSITIVE with detailed reasoning
4. Only true positives are included in final report
5. False positives can be saved for review (`--save-false-positives`)

**Benefits:**
- **91% false positive reduction** (based on SAST-Genius research: arxiv.org/abs/2509.15433)
- **Contextual analysis** catches business logic flaws that rule-based tools miss
- **Time savings**: ~350+ hours/year in manual false positive review
- **Cost-effective**: ~$0.01/scan with Gemini 2.5 Flash (~$1/month for 100 scans)

**Configuration:**
```bash
# Enable AI validation (opt-in, disabled by default)
poetry run impact-scan scan . --ai-validation

# Specify AI provider (auto-detects by default: Groq > Gemini > OpenAI > Anthropic)
poetry run impact-scan scan . --ai-validation --ai-validation-provider gemini

# Limit findings for cost control (validate only first N findings)
poetry run impact-scan scan . --ai-validation --ai-validation-limit 20

# Save false positives to ai_false_positives.json for analysis
poetry run impact-scan scan . --ai-validation --save-false-positives
```

**Supported Providers:**
- **Groq**: Fastest, free tier available, good quality
- **Gemini 2.5 Flash**: Cheapest ($0.15/1M input tokens), excellent quality
- **OpenAI GPT-4o-mini**: Good balance ($0.15/1M input)
- **Anthropic Claude 3.7 Sonnet**: Highest quality but most expensive ($3/1M input)

**Cost Estimates** (per scan with 50 findings):
- Gemini 2.5 Flash: ~$0.01
- Groq: Free tier or ~$0.02
- GPT-4o-mini: ~$0.08
- Claude 3.7 Sonnet: ~$0.23

**Fail-Open Design:** If AI validation fails (network issues, API errors), all findings are kept to avoid false negatives.

**Implementation Details:**
- Module: `src/impact_scan/core/ai_validator.py`
- Reuses existing `AIFixProvider` infrastructure for consistency
- Runs after severity filtering, before reporting
- Adds `ai_validated` metadata to each finding with validation reason
