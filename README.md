# Impact-Scan

A comprehensive security vulnerability scanner for codebases that combines static analysis, dependency vulnerability scanning, and AI-powered fix generation.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

## Features

### Security Scanning
- **Static Code Analysis**: Powered by Semgrep and Bandit with 40+ custom security rules
- **Dependency Vulnerability Scanning**: Detect vulnerable packages using OSV database, pip-audit, and Safety
- **JWT/OAuth Security**: Specialized detection for authentication vulnerabilities (25+ rules)
- **Multi-Language Support**: Python, JavaScript, TypeScript, Node.js, and more
- **AI-Powered False Positive Reduction**: Optional AI validation to reduce false positives by up to 91%

### AI-Powered Fix Generation
- **Multiple AI Providers**: Support for Groq, Gemini, OpenAI, and Anthropic
- **Intelligent Fix Suggestions**: Context-aware security fixes with code examples
- **Local LLM Support**: Air-gapped environments supported via llama-cpp-python

### Professional Reporting
- **HTML Reports**: Interactive reports with dark theme and code highlighting
- **SARIF 2.1.0 Format**: GitHub Security tab integration
- **Markdown Reports**: GitHub-friendly documentation
- **JSON Export**: Machine-readable output for automation

### Multiple Interfaces
- **CLI**: Command-line interface with scan profiles
- **TUI**: Interactive terminal user interface
- **Web UI**: Flask-based browser interface

## Installation

### Quick Start

**Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows (PowerShell):**
```powershell
.\install.ps1
```

### Manual Installation

**With Poetry (Recommended):**
```bash
poetry install --all-extras
poetry run impact-scan --help
```

**With pip:**
```bash
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\Activate.ps1
pip install -e .[all]
pip install semgrep pip-audit safety
```

**With Docker:**
```bash
docker build -t impact-scan:latest .
docker run -v $(pwd):/workspace impact-scan scan /workspace
```

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

## Quick Start

### Basic Scan
```bash
impact-scan scan /path/to/project
```

### Using Scan Profiles
```bash
# Quick scan (HIGH+ severity only)
impact-scan scan . --profile quick

# Standard scan (MEDIUM+ severity, AI fixes)
impact-scan scan . --profile standard

# Comprehensive scan (LOW+ severity, AI fixes, web intelligence)
impact-scan scan . --profile comprehensive

# CI/CD optimized
impact-scan scan . --profile ci
```

### AI-Powered Features
```bash
# Generate AI fixes
impact-scan scan . --ai groq

# AI-powered false positive reduction (optional, ~$0.01/scan)
impact-scan scan . --ai-validation

# Specify AI provider
impact-scan scan . --ai gemini --ai-validation --ai-validation-provider groq
```

### Output Formats
```bash
# HTML report
impact-scan scan . --output report.html

# SARIF for GitHub Security
impact-scan scan . --output-format sarif --output results.sarif

# Multiple formats
impact-scan scan . --output-format html,sarif,markdown
```

## Configuration

### API Keys (Optional)

For AI-powered features, configure at least one provider:

```bash
# Groq (recommended: fastest + free tier)
export GROQ_API_KEY='your-key-here'

# Google Gemini (cheapest: $0.15/1M tokens)
export GOOGLE_API_KEY='your-key-here'

# OpenAI
export OPENAI_API_KEY='your-key-here'

# Anthropic Claude
export ANTHROPIC_API_KEY='your-key-here'
```

### Configuration File

Create `.impact-scan.yml` in your project root:

```yaml
# Scan settings
min_severity: medium
max_findings: 100

# AI provider
ai:
  provider: groq
  enable_fixes: true
  enable_validation: false

# Web intelligence
web_search:
  enabled: true
  max_results: 200

stackoverflow:
  enabled: true
  max_answers: 5
```

## Scan Profiles

| Profile | Min Severity | AI Fixes | Web Search | Dependency Scan | Use Case |
|---------|-------------|----------|------------|-----------------|----------|
| `quick` | HIGH | No | No | No | Fast CI checks |
| `standard` | MEDIUM | Yes | No | Yes | Regular development scans |
| `comprehensive` | LOW | Yes | Yes | Yes | Complete security audit |
| `ci` | Configurable | Optional | No | Yes | CI/CD pipelines |

## Command Reference

```bash
# Scanning
impact-scan scan <path>                    # Basic scan
impact-scan scan . --profile comprehensive # Use profile
impact-scan scan . --min-severity high     # Filter by severity

# AI Features
impact-scan scan . --ai groq              # Generate fixes
impact-scan scan . --ai-validation        # Reduce false positives

# Output
impact-scan scan . -o report.html         # HTML report
impact-scan scan . --output-format sarif  # SARIF format
impact-scan scan . --output-format all    # All formats

# Interfaces
impact-scan tui                           # Interactive TUI
impact-scan web                           # Web UI (http://127.0.0.1:5000)
impact-scan web --port 8080               # Custom port

# Configuration
impact-scan init                          # Generate config file
impact-scan profiles                      # List available profiles
impact-scan config                        # Check API key configuration
impact-scan --version                     # Show version
```

## JWT/OAuth Security Detection

Impact-Scan includes comprehensive JWT and OAuth vulnerability detection:

**Custom Rules (16 rules):**
- JWT decode without signature verification (CWE-347)
- Missing algorithm specification (CWE-327)
- Hardcoded JWT secrets (CWE-798)
- "none" algorithm usage
- Weak secrets (CWE-521)
- Missing OAuth state parameter (CWE-352)
- ID token not verified (CWE-345)
- Wildcard CORS with credentials (CWE-942)

**Semgrep Registry (25+ rules):**
- Official JWT security rules from Semgrep p/jwt ruleset

**Supported Languages:** Python, JavaScript, TypeScript, Node.js, Ruby, Java, Go

## AI-Powered False Positive Reduction

Optionally reduce false positives by up to 91% using AI validation:

```bash
# Enable AI validation (opt-in)
impact-scan scan . --ai-validation

# Specify provider and cost limit
impact-scan scan . --ai-validation --ai-validation-provider groq --ai-validation-limit 20

# Save false positives for review
impact-scan scan . --ai-validation --save-false-positives
```

**Benefits:**
- 91% false positive reduction (based on SAST-Genius research)
- Contextual analysis catches business logic flaws
- Cost-effective: ~$0.01/scan with Gemini 2.5 Flash
- Fail-open design: keeps findings if validation fails

**Supported Providers:**
- Groq: Fastest, free tier available
- Gemini 2.5 Flash: Cheapest ($0.15/1M input tokens)
- GPT-4o-mini: Good balance ($0.15/1M input)
- Claude 3.7 Sonnet: Highest quality ($3/1M input)

## GitHub Actions Integration

The repository includes a production-ready GitHub Actions workflow:

```bash
# Use the included workflow
cp .github/workflows/impact-scan.yml.example .github/workflows/impact-scan.yml
```

**Features:**
- Runs on push, PR, and weekly schedule
- Uploads SARIF to GitHub Security tab
- Generates HTML and Markdown reports as artifacts
- Posts scan results as PR comments
- Configurable scan profiles via workflow dispatch
- Fails build on critical vulnerabilities

**Required Secrets (optional, for AI features):**
- `GROQ_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, or `OPENAI_API_KEY`

**Required Permissions:**
- `contents: read` - Checkout code
- `security-events: write` - Upload SARIF
- `pull-requests: write` - Comment on PRs

## Docker Usage

```bash
# Build image
docker build -t impact-scan:latest .

# Run scan
docker run -v $(pwd):/workspace impact-scan scan /workspace

# Use profiles
docker run -v $(pwd):/workspace impact-scan scan /workspace --profile comprehensive

# Web UI
docker run -p 5000:5000 -v $(pwd):/workspace impact-scan web --no-browser

# Docker Compose
docker-compose run scan
docker-compose up web
```

## Architecture

### Core Modules
- **entrypoint.py**: Scan orchestration and entry point detection
- **static_scan.py**: Static analysis (Bandit, Semgrep)
- **dep_audit.py**: Dependency vulnerability scanning
- **unified_dependency_scanner.py**: Python and JavaScript package scanning
- **aggregator.py**: Result deduplication and filtering
- **fix_ai.py**: AI-powered fix generation
- **ai_validator.py**: AI-powered false positive reduction
- **renderer.py**: Terminal output with Rich formatting
- **html_report.py**: HTML report generation
- **parsebot_client.py**: Web intelligence integration
- **stackoverflow_scraper.py**: Stack Overflow integration

### Data Flow
1. CLI parses arguments and loads configuration
2. Entry point detection identifies application frameworks
3. Static analysis and dependency scanners run in parallel
4. Results aggregated, deduplicated, and filtered
5. Optional AI fix generation via supported providers
6. Optional AI validation for false positive reduction
7. Output rendered to terminal, HTML, SARIF, or Markdown

## System Requirements

- **Python**: 3.9 or higher
- **OS**: Linux, macOS, or Windows
- **Disk Space**: ~500MB for full installation
- **Memory**: 2GB minimum, 4GB recommended
- **External Tools**: Semgrep, pip-audit, Safety (auto-installed)

## Troubleshooting

### "No module named 'impact_scan'"

**Solution**: Use `poetry run` prefix with Poetry installations:
```bash
poetry run impact-scan scan .
```

Or activate the virtual environment first:
```bash
source venv/bin/activate  # Then use: impact-scan scan .
```

### "semgrep: command not found"

**Solution**: Install Semgrep:
```bash
pip install semgrep
```

See [INSTALL.md](INSTALL.md) for more troubleshooting.

## Contributing

Contributions are welcome! Areas for contribution:
- Additional Semgrep security rules
- New AI provider integrations
- Improved fix generation logic
- Documentation improvements
- Bug reports and feature requests

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Semgrep for static analysis engine
- OSV database for vulnerability information
- AI providers: Groq, Google, OpenAI, Anthropic
- OWASP for security best practices

## Support

- GitHub Issues: https://github.com/Ani07-05/impact-scan/issues
- Documentation: See [INSTALL.md](INSTALL.md) and [CLAUDE.md](CLAUDE.md)

---

**Version:** 0.2.0 | **Last Updated:** January 2025
