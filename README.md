

# Impact Scan

**A comprehensive, AI-powered security vulnerability scanner for codebases with intelligent fix suggestions and professional reporting.**

> **Note:** For the best results, use the following command:
> ```bash
> poetry run impact-scan scan /path/to/your/app --min-severity MEDIUM --ai-fixes --web-search --ai-provider gemini --gemini-key <your-api-key> --html report.html
> ```

https://github.com/user-attachments/assets/15121d99-8eeb-47fd-b96e-6f4779328adc

## Overview

Impact Scan is a unified security analysis tool that combines static code analysis, dependency vulnerability scanning, and AI-powered fix generation to provide comprehensive security assessments for software projects. The tool generates professional HTML reports with dark-themed interfaces and highlighted security recommendations.

## Features

### Core Security Scanning
- **Static Code Analysis**: Detects security vulnerabilities in Python codebases.
- **Dependency Vulnerability Scanning**: Identifies known vulnerabilities in project dependencies using the OSV database.
- **Entry Point Detection**: Automatically identifies application entry points and potential attack surfaces.
- **Severity-based Filtering**: Configurable minimum severity thresholds (LOW, MEDIUM, HIGH, CRITICAL).

### AI-Powered Enhancements
- **Intelligent Fix Suggestions**: Generates context-aware security fix recommendations using multiple AI providers.
- **Web Search Integration**: Automatically searches for security best practices and remediation guidance.
- **Multiple AI Provider Support**: Compatible with OpenAI, Anthropic Claude, and Google Gemini models.
- **Local LLM Support**: Option to use local language models for offline analysis.

### Professional Reporting
- **HTML Reports**: Modern, dark-themed professional security reports with syntax highlighting.
- **SARIF Export**: Industry-standard SARIF format for integration with security tools.
- **Rich Terminal Output**: Color-coded, formatted console output with progress indicators.
- **Visual Severity Indicators**: Color-coded severity levels and visual highlighting for critical issues.

## Installation

### Prerequisites
- Python 3.13 or higher
- Poetry (recommended) or pip for dependency management

### Using Poetry (Recommended)
```bash
git clone https://github.com/Ani07-05/impact-scan.git
cd impact-scan
poetry install
poetry shell
```

### Using pip
```bash
git clone https://github.com/Ani07-05/impact-scan.git
cd impact-scan
pip install -e .
```

## Configuration

### API Keys
The tool supports multiple AI providers. Configure API keys using environment variables:

```bash
# OpenAI GPT models
export OPENAI_API_KEY="your-openai-api-key"

# Anthropic Claude models
export ANTHROPIC_API_KEY="your-anthropic-api-key"

# Google Gemini models
export GOOGLE_API_KEY="your-google-api-key"

# Stack Overflow API Key
export STACKOVERFLOW_API_KEY="your-stackoverflow-api-key"
```

Alternatively, provide keys directly via command-line options.

## Usage

### Basic Security Scan
```bash
impact-scan scan /path/to/your/project
```

### Advanced Scanning with AI Features
```bash
impact-scan scan /path/to/your/project \
  --min-severity HIGH \
  --ai-fixes \
  --ai-provider openai \
  --web-search \
  --html report.html \
  --sarif results.sarif
```

### Command-Line Options

#### Required Arguments
- `root_path`: Path to the codebase directory to scan.

#### Optional Parameters
- `--min-severity, -s`: Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL). Default: `MEDIUM`.
- `--ai-fixes`: Enable AI-powered fix suggestions.
- `--ai-provider`: Choose AI provider (openai, anthropic, gemini).
- `--web-search`: Enable web-based fix recommendations.
- `--web-limit`: Maximum number of web searches to perform. Default: `100`.
- `--web-batch-size`: Batch size for web searches. Default: `10`.
- `--web-delay`: Delay in seconds between web search requests. Default: `2.0`.
- `--prioritize-high`: Prioritize high/critical severity findings for web search. Default: `True`.
- `--html`: Output path for HTML report.
- `--sarif`: Output path for SARIF results.
- `--openai-key`: OpenAI API key (or use `OPENAI_API_KEY` environment variable).
- `--anthropic-key`: Anthropic API key (or use `ANTHROPIC_API_KEY` environment variable).
- `--gemini-key`: Google API key (or use `GOOGLE_API_KEY` environment variable).
- `--stackoverflow-key`: Stack Overflow API key (or use `STACKOVERFLOW_API_KEY` environment variable).

## Examples

### Example 1: Basic Vulnerability Scan
This command scans the specified project directory with default settings.
```bash
impact-scan scan ./my-python-project
```

### Example 2: Comprehensive Security Assessment
This command runs a comprehensive scan with the following features:
- Reports vulnerabilities of `MEDIUM` severity or higher.
- Enables AI-powered fix suggestions using the `openai` provider.
- Performs web searches for additional context.
- Generates an HTML report named `security-report.html`.
```bash
impact-scan scan ./my-python-project \
  --min-severity MEDIUM \
  --ai-fixes \
  --ai-provider openai \
  --web-search \
  --html security-report.html
```

### Example 3: CI/CD Integration
This command is optimized for CI/CD pipelines:
- Scans the current directory.
- Reports only `HIGH` severity vulnerabilities.
- Generates a SARIF report for integration with security dashboards.
```bash
impact-scan scan . \
  --min-severity HIGH \
  --sarif security-results.sarif
```

## Report Features

### HTML Reports
The generated HTML reports include:
- An executive summary with vulnerability metrics.
- Detailed findings with code snippets.
- AI-generated fix suggestions with syntax highlighting.
- Web-researched security recommendations.
- A professional dark theme with a responsive design.
- Severity-based color coding and visual indicators.

### SARIF Output
SARIF (Static Analysis Results Interchange Format) files are compatible with:
- GitHub Security tab
- Azure DevOps security dashboards
- Visual Studio Code SARIF viewer
- Other security tooling ecosystems

## Architecture

### Core Modules
- `entrypoint.py`: Application entry point detection.
- `dep_audit.py`: Dependency vulnerability scanning.
- `static_scan.py`: Static code analysis.
- `aggregator.py`: Result merging and deduplication.
- `fix_ai.py`: AI-powered fix generation.
- `web_search.py`: Web-based security research.
- `renderer.py`: Output formatting and display.
- `html_report.py`: Professional HTML report generation.

### Data Models
The tool uses Pydantic models for type-safe data handling:
- `ScanConfig`: Configuration parameters.
- `Finding`: Individual security findings.
- `ScanResult`: Complete scan results.
- `Severity`: Enumeration for severity levels.
- `VulnSource`: Vulnerability detection sources.

## Security Considerations

### API Key Security
- **Never commit API keys to version control.**
- Use environment variables or secure key management systems.
- Rotate API keys regularly.
- Monitor API usage for unauthorized access.

### Network Requirements
- AI features require internet connectivity.
- Web search functionality needs external web access.
- A local LLM option is available for air-gapped environments.

## Development

### Project Structure
```
impact-scan/
├── src/impact_scan/          # Main package
│   ├── core/                 # Core scanning modules
│   ├── utils/                # Utilities and schemas
│   └── cli.py                # Command-line interface
├── tests/                    # Test suite
├── examples/                 # Example vulnerable applications
└── README.md                 # Project documentation
```

### Running Tests
```bash
poetry run pytest
```

### Contributing
1. Fork the repository.
2. Create a feature branch.
3. Implement changes with tests.
4. Submit a pull request.

## Supported Vulnerability Types

### Static Code Analysis
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Hardcoded secrets and credentials
- Insecure cryptographic practices
- Path traversal vulnerabilities
- Command injection risks
- Insecure deserialization

### Dependency Vulnerabilities
- Known CVEs in direct dependencies
- Transitive dependency vulnerabilities
- Outdated package versions with security issues
- License compliance issues

## Troubleshooting

### Common Issues

**Configuration Error: AI provider not specified**
```
Error: AI provider must be specified for AI fixes.
```
**Solution**: Specify an AI provider when enabling AI fixes:
```bash
impact-scan scan . --ai-fixes --ai-provider openai
```

**Permission Errors**
```
Permission denied: /path/to/target
```
**Solution**: Ensure the target directory is readable:
```bash
chmod -R +r /path/to/target
```

**Network Connectivity**
```
Failed to connect to AI provider
```
**Solution**: Check internet connectivity and API key validity.

### Getting Help
- Check the command-line help: `impact-scan --help`
- Review example vulnerable applications in the `examples/` directory.
- Ensure all dependencies are properly installed.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Support

For issues, feature requests, or contributions, please use the project's issue tracker.

## Acknowledgments

- Built with Python and modern security scanning tools.
- Utilizes Bandit for static analysis.
- Integrates with the OSV database for dependency scanning.
- Powered by leading AI models for intelligent recommendations.
