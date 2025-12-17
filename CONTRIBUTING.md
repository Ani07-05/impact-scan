# Contributing to Impact-Scan

Thank you for your interest in contributing to Impact-Scan! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and collaborative environment.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment details** (OS, Python version, impact-scan version)
- **Sample code** or repository that demonstrates the issue

### Suggesting Features

Feature requests are welcome! Please provide:

- **Clear use case** explaining why this feature would be useful
- **Proposed solution** or implementation approach
- **Alternatives considered**

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

3. **Make your changes**:
   - Add tests for new features
   - Update documentation as needed
   - Follow existing code style (use `ruff` for linting)
   - Run tests: `pytest tests/`

4. **Write clear commit messages**:
   ```
   Add pre-commit hook for automated security scanning

   - Implement install-hooks command
   - Add scan-staged for git integration
   - Include tests for hook installation
   ```

5. **Submit pull request** with:
   - Description of changes
   - Related issue number (if applicable)
   - Screenshots/examples (if relevant)

## Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/impact-scan.git
cd impact-scan

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run linter
ruff check src/

# Run type checker
mypy src/
```

## Adding New Security Rules

Security rules are defined in YAML files under `src/impact_scan/rules/`.

Example rule structure:
```yaml
rules:
  - id: your-rule-id
    pattern-regex: 'vulnerable-pattern'
    message: |
      Description of the vulnerability.

      Risk: What could go wrong
      Fix: How to fix it
    severity: ERROR  # or WARNING, INFO
    languages: [python, javascript, typescript]
    metadata:
      category: security
      cwe: "CWE-XXX: Vulnerability Type"
      confidence: HIGH  # or MEDIUM, LOW
```

## Testing

- **Unit tests**: Test individual components
- **Integration tests**: Test scanner against vulnerable code samples
- **Add test cases** in `tests/data/vulnerable_*/` for new rules

## Code Style

- Use **Black** for code formatting (line length: 100)
- Use **Ruff** for linting
- Use **type hints** for function signatures
- Write **docstrings** for public APIs

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (Apache 2.0).

## Questions?

Feel free to open an issue or reach out to the maintainers.

Thank you for contributing to make Impact-Scan better!
