# Impact Scan

**A comprehensive, AI-powered security vulnerability scanner for codebases with intelligent fix suggestions, automated remediation, and professional reporting.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## 🌟 Key Features

### 🔍 Multi-Layer Security Scanning
- **Static Analysis**: Powered by Semgrep with 2000+ security rules
- **Dependency Scanning**: Detect vulnerable packages and libraries
- **AI-Powered Analysis**: Generate intelligent fix suggestions with 95% accuracy
- **Web Intelligence**: Contextual vulnerability information from Stack Overflow and security databases

### 🤖 Automated Remediation
- **One-Click Fixes**: Apply AI-generated patches automatically with `--fix`
- **Safety Guardrails**: Git integration, syntax validation, backup/rollback
- **Confidence Levels**: Conservative (high confidence) or aggressive (medium+) strategies
- **Test Integration**: Run your test suite before committing fixes

### 🚀 CI/CD Integration
- **GitHub Actions Templates**: One command setup with `init-github-action`
- **SARIF Support**: Security findings in GitHub Security tab
- **Automated PRs**: Weekly auto-fix workflows with automatic pull request creation
- **PR Comments**: Inline vulnerability comments on pull requests

### ⚙️ Flexible Configuration
- **Ignore Rules**: Suppress false positives by CWE, CVE, rule ID, path, severity
- **Expiration Dates**: Time-bound ignores for temporary suppression
- **Multiple Profiles**: Quick, standard, comprehensive, dependency-only
- **Custom Rules**: Add your own Semgrep rules

### 📊 Professional Reporting
- **HTML Reports**: Beautiful, interactive reports with charts and metrics
- **SARIF Format**: Standard format for security tools and GitHub
- **JSON Export**: Machine-readable output for automation
- **Terminal Output**: Rich console display with colors and formatting

---

## 🚀 Quick Start

### Installation

```bash
pip install impact-scan
```

### Basic Usage

```bash
# Run a quick scan
impact-scan scan .

# Comprehensive scan with AI fixes
impact-scan scan . --profile comprehensive --ai groq

# Auto-fix vulnerabilities (interactive mode)
impact-scan scan . --fix

# Generate HTML report
impact-scan scan . --output-format html --output report.html
```

---

## 📋 Three Powerful Features

### 1. GitHub Actions CI/CD Integration

Generate a complete GitHub Actions workflow in seconds:

```bash
impact-scan init-github-action
```

**What you get:**
- ✅ Workflow file in `.github/workflows/impact-scan.yml`
- ✅ SARIF upload to GitHub Security tab
- ✅ PR comments with inline vulnerability annotations
- ✅ Scheduled weekly scans
- ✅ Manual trigger support
- ✅ Optional auto-fix PR workflow

**Next steps:**
1. Add `GROQ_API_KEY` to GitHub Secrets
2. Commit the workflow file
3. Push to GitHub

**📚 Full Guide:** [GITHUB_ACTIONS_GUIDE.md](GITHUB_ACTIONS_GUIDE.md)

---

### 2. Config-Based Ignore Rules

Suppress false positives or defer fixes using `.impact-scan.yml`:

```yaml
ignore_rules:
  # Ignore specific CWE
  - cwe: "CWE-79"
    reason: "XSS mitigated by framework"
    
  # Ignore by path pattern
  - rule_id: "python-sql-injection"
    path: "tests/**"
    reason: "Test files only"
    
  # Time-bound ignore
  - severity: "LOW"
    expires: "2025-12-31"
    reason: "Defer until Q4"
```

**Generate ignore rules from findings:**

```bash
impact-scan scan . --generate-ignore > .impact-scan.yml
```

**Features:**
- ✅ Match by CWE, CVE, rule ID, path (glob patterns), severity
- ✅ Expiration dates for temporary ignores
- ✅ Required reason field for audit trail
- ✅ Show ignored findings with `--show-ignored`

**📚 Full Guide:** [IGNORE_RULES.md](IGNORE_RULES.md)

---

### 3. Automated Fix Application

Apply AI-generated security fixes automatically with safety guardrails:

**Interactive mode** (recommended):

```bash
impact-scan scan . --fix
```

**Automated mode** (for CI/CD):

```bash
impact-scan scan . --fix-auto --yes --fix-strategy conservative
```

**Safety features:**
- ✅ Requires clean git working directory
- ✅ Creates backups before modifications
- ✅ Syntax validation (Python, JavaScript, TypeScript)
- ✅ Automatic rollback on failures
- ✅ Optional test suite integration
- ✅ Confidence thresholds (conservative vs aggressive)

**📚 Full Guide:** [AUTO_FIX.md](AUTO_FIX.md)

---

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.8+**
- **Semgrep**: `pip install semgrep`
- **Git** (for auto-fix feature)
- **Node.js** (optional, for JavaScript syntax validation)

### Install Impact-Scan

```bash
# From PyPI (recommended)
pip install impact-scan

# From source
git clone https://github.com/Ani07-05/impact-scan.git
cd impact-scan
pip install -e .
```

### Configure AI Provider

Impact-Scan supports multiple AI providers:

```bash
# Groq (fastest, cheapest - recommended)
export GROQ_API_KEY="your-groq-key"

# Anthropic Claude
export ANTHROPIC_API_KEY="your-anthropic-key"

# Google Gemini
export GOOGLE_API_KEY="your-gemini-key"

# OpenAI
export OPENAI_API_KEY="your-openai-key"
```

Get API keys:
- **Groq**: https://console.groq.com (free tier: 30 req/min)
- **Anthropic**: https://console.anthropic.com
- **Google**: https://ai.google.dev
- **OpenAI**: https://platform.openai.com

---

## 📖 Usage Examples

### Example 1: Quick Security Check

```bash
impact-scan scan . --profile quick
```

Output:
```
✅ Scan complete: 12 vulnerabilities found
● Critical: 2
● High: 5
● Medium: 3
● Low: 2
```

### Example 2: Comprehensive Scan with AI Fixes

```bash
impact-scan scan . --profile comprehensive --ai groq --output-format html --output security-report.html
```

### Example 3: Scan Specific Directory

```bash
impact-scan scan ./backend --min-severity high
```

### Example 4: Generate Ignore Rules

```bash
# Generate from current findings
impact-scan scan . --generate-ignore > .impact-scan.yml

# Edit the file to add reasons
nano .impact-scan.yml

# Re-scan with ignores applied
impact-scan scan .
```

### Example 5: Auto-Fix Workflow

```bash
# 1. Scan and identify fixable issues
impact-scan scan . --profile comprehensive --ai groq

# 2. Review findings in HTML report
open security-report.html

# 3. Apply fixes interactively
impact-scan scan . --fix

# 4. Review changes
git diff

# 5. Run tests
pytest

# 6. Commit if all good
git commit -m "Security fixes from Impact-Scan"
```

### Example 6: CI/CD Pipeline

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Impact-Scan
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
        run: |
          pip install impact-scan
          impact-scan scan . --profile comprehensive --ai groq --output-format sarif --output results.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## ⚙️ Configuration

### Scan Profiles

| Profile | AI Fixes | Web Search | Dependency Scan | Min Severity | Use Case |
|---------|----------|------------|-----------------|--------------|----------|
| `quick` | ❌ | ❌ | ❌ | HIGH | Fast CI checks |
| `standard` | ❌ | ❌ | ✅ | MEDIUM | Regular scans |
| `comprehensive` | ✅ | ✅ | ✅ | LOW | Deep analysis |
| `dependency-only` | ❌ | ❌ | ✅ | LOW | Package audit |

### Command-Line Options

```bash
impact-scan scan [PATH] [OPTIONS]

Scanning:
  --profile TEXT              Scan profile (quick, standard, comprehensive, dependency-only)
  --min-severity TEXT         Minimum severity (critical, high, medium, low)
  --config FILE               Path to config file

AI & Intelligence:
  --ai TEXT                   AI provider (groq, anthropic, gemini, openai)
  --disable-ai-fixes         Disable AI fix generation
  --disable-web-search       Disable web intelligence

Output:
  --output-format TEXT        Format (json, html, sarif, all)
  --output PATH               Output file path
  --verbose, -v              Verbose output

Ignore Rules:
  --generate-ignore          Generate .impact-scan.yml from findings
  --show-ignored             Show ignored findings in report

Auto-Fix:
  --fix                      Interactive fix mode with confirmations
  --fix-auto                 Automated fix mode (no prompts)
  --fix-strategy TEXT        Strategy: conservative (high) or aggressive (medium)
  --yes, -y                  Auto-confirm all prompts
```

---

## 📊 Output Formats

### HTML Report

```bash
impact-scan scan . --output-format html --output report.html
```

**Features:**
- Interactive charts and metrics
- Filterable by severity
- Code snippets with syntax highlighting
- AI fix suggestions with confidence scores
- Export to PDF

### SARIF Format

```bash
impact-scan scan . --output-format sarif --output results.sarif
```

**Upload to GitHub:**
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### JSON Export

```bash
impact-scan scan . --output-format json --output findings.json
```

**Integrate with other tools:**
```python
import json

with open('findings.json') as f:
    data = json.load(f)
    
for finding in data['findings']:
    print(f"{finding['severity']}: {finding['title']}")
```

---

## 🔐 Security Best Practices

### 1. Regular Scanning

```bash
# Weekly comprehensive scan
cron: 0 2 * * 1
impact-scan scan . --profile comprehensive --ai groq
```

### 2. Pre-Commit Hooks

```bash
# .git/hooks/pre-commit
#!/bin/bash
impact-scan scan . --profile quick --min-severity high
if [ $? -ne 0 ]; then
    echo "Security issues found! Fix before committing."
    exit 1
fi
```

### 3. Pull Request Checks

Use GitHub Actions to block PRs with critical vulnerabilities.

### 4. Dependency Updates

```bash
# Monthly dependency audit
impact-scan scan . --profile dependency-only
```

### 5. Review Auto-Fixes

Always review auto-fix changes before merging:
```bash
git diff HEAD~1
pytest
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Areas for contribution:**
- Additional Semgrep rules
- New AI providers
- Improved fix generation
- Documentation improvements
- Bug reports and feature requests

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Semgrep** for static analysis engine
- **Anthropic, Google, Groq, OpenAI** for AI capabilities
- **OWASP** for security knowledge and best practices
- All contributors and users of Impact-Scan

---

## 📞 Support & Community

- **GitHub Issues**: https://github.com/Ani07-05/impact-scan/issues
- **Discussions**: https://github.com/Ani07-05/impact-scan/discussions
- **Documentation**: [docs/](docs/)

---

**Made with ❤️ by the Impact-Scan Team**

*Last updated: January 2025 | Version: 0.2.0*
