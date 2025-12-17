# Changelog

All notable changes to Impact-Scan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Pre-commit hook integration with `install-hooks`, `scan-staged`, and `uninstall-hooks` commands
- Comprehensive secrets detection rules (Supabase, OpenAI, AWS, GitHub, Stripe, etc.)
- Support for TypeScript/JavaScript secrets detection
- Environment variable template (`.env.example`)

### Fixed
- Dependency version syntax in `pyproject.toml` for proper pip compatibility
- Removed deprecated widget files to reduce codebase bloat

### Changed
- Improved scan performance for staged files only
- Enhanced documentation with CONTRIBUTING.md and SECURITY.md

## [0.3.0] - 2024-12-03

### Added
- AI-powered security scanning with Groq/OpenAI integration
- Terminal User Interface (TUI) for interactive scanning
- Multiple scan profiles (quick, balanced, thorough, comprehensive)
- SARIF export for GitHub Security tab integration
- Custom rule support via YAML
- Semgrep integration for pattern-based detection
- Python security rules (SQL injection, hardcoded secrets, etc.)

### Security
- Local-first scanning (no data sent to cloud by default)
- Environment variable support for API keys
- Secure credential handling

## [0.2.0] - 2024-11-15

### Added
- Initial CLI implementation
- Basic security rule scanning
- HTML report generation

## [0.1.0] - 2024-10-01

### Added
- Project initialization
- Core scanning engine
- Basic rule definitions

---

## Release Types

- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security vulnerability fixes

[Unreleased]: https://github.com/yourusername/impact-scan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/yourusername/impact-scan/releases/tag/v0.3.0
[0.2.0]: https://github.com/yourusername/impact-scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/yourusername/impact-scan/releases/tag/v0.1.0
