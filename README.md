# Impact Scan

![Python CI](https://github.com/Ani07-05/impact-scan/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)

**Impact Scan** is an advanced, AI-powered security vulnerability scanner for codebases. It goes beyond traditional static analysis by leveraging Large Language Models (LLMs) to understand context, reduce false positives, and suggest intelligent fixes.

## Features

- **AI-Powered Analysis**: Uses models like GPT-4, Claude, or Gemini to validate findings and explain vulnerabilities.
- **Agentic Architecture**:
    - **StaticAnalysisAgent**: Deep code scanning using Semgrep and Bandit.
    - **ComprehensiveSecurityCrawler**: Web-enriched thread intelligence and exploit verification.
    - **ModernWebIntelligenceAgent**: Real-time vulnerability research.
- **Intelligent Fixes**: Auto-generates code patches for discovered issues.
- **Knowledge Graph**: visualizations of your project's security posture.
- **CI/CD Ready**: Easy integration with GitHub Actions and other pipelines.

## Installation

```bash
pip install impact-scan
# OR using poetry
poetry add impact-scan
```

## Usage

### Basic Scan
Scan the current directory:
```bash
impact-scan scan .
```

### Scan with AI Enrichment
Enable AI features for better accuracy:
```bash
impact-scan scan . --ai openai
```

### Fix Vulnerabilities
Interactively apply fixes:
```bash
impact-scan scan . --fix
```

### CI/CD Mode
Run in automated environments:
```bash
impact-scan scan . --fix-auto --yes --min-severity high
```

## Configuration

Create a `.impact-scan.yml` file in your root directory:

```yaml
profile: balanced
min_severity: medium
enable_web_search: true
ai_provider: openai
ignore_paths:
  - tests/
  - node_modules/
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

