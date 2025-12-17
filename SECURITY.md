# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Impact-Scan, please report it responsibly:

### Please DO:

1. **Email security issues** to: [your-email@example.com] *(Update with actual contact)*
2. **Include detailed information**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)
3. **Allow time for a fix** before public disclosure (typically 90 days)

### Please DON'T:

- Open public GitHub issues for security vulnerabilities
- Exploit the vulnerability beyond proof-of-concept
- Share the vulnerability publicly before it's fixed

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Security Features in Impact-Scan

Impact-Scan is designed to help YOU find security issues in your code. We take security of the tool itself seriously:

### What We Do:

- **No data collection**: All scanning happens locally by default
- **No telemetry**: We don't send your code anywhere
- **Open source**: Full code transparency for audit
- **Minimal dependencies**: Reduced attack surface
- **API keys in environment**: Never hardcode credentials

### What You Should Do:

1. **Keep Impact-Scan updated**: `pip install --upgrade impact-scan`
2. **Use environment variables**: For API keys (see `.env.example`)
3. **Review scan results**: Before sharing them publicly
4. **Protect your .env**: Never commit API keys to git

## Known Limitations

- Pre-commit hooks run with your git user permissions
- AI-powered features require API keys (store securely)
- Scanner accuracy depends on rule quality (false positives possible)

## Security Best Practices

When using Impact-Scan:

```bash
# Good: Use environment variables
export GROQ_API_KEY="your-key-here"
impact-scan scan

# Bad: Don't hardcode keys
GROQ_API_KEY="sk-abc123" impact-scan scan  # Don't do this!
```

## Acknowledgments

We appreciate responsible disclosure. Security researchers who report valid vulnerabilities will be:

- Credited in release notes (if desired)
- Listed in our Hall of Fame
- Given early access to security releases

Thank you for helping keep Impact-Scan and its users safe!
