# High-Volume Vulnerability Scanning Guide

## Overview

The enhanced Impact Scan tool now supports intelligent batch processing and rate limiting to handle large codebases with 100+ vulnerabilities without hitting API rate limits.

## New Features

### 1. Enhanced Rate Limiting
- **Progressive Backoff**: Automatically increases delays after high request counts
- **Smart Caching**: Prevents duplicate API calls for similar vulnerabilities
- **Request Counting**: Tracks API usage with detailed logging

### 2. Batch Processing
- **Configurable Batch Sizes**: Process findings in manageable chunks
- **Inter-batch Delays**: Prevents API overload with longer delays between batches
- **Progress Tracking**: Real-time progress monitoring with batch statistics

### 3. Priority-Based Processing
- **Severity Prioritization**: Process CRITICAL → HIGH → MEDIUM → LOW findings first
- **Intelligent Limiting**: Stops at configured limits to prevent rate limit hits
- **Deduplication**: Skips duplicate vulnerabilities automatically

## Configuration Options

### CLI Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--web-limit` | 100 | Maximum number of web searches to perform |
| `--web-batch-size` | 10 | Number of findings to process per batch |
| `--web-delay` | 2.0 | Delay in seconds between requests |
| `--prioritize-high` | True | Prioritize high/critical severity findings |

### Rate Limiting Strategy

```
Request Count → Delay
0-50:         → 2.0s (configurable)
51-80:        → 3.0s (automatic)
81+:          → 5.0s (automatic)
```

## Usage Examples

### 1. Basic High-Volume Scan
```bash
impact-scan scan examples/Vulnerable-Flask-App \
  --web-search \
  --web-limit 100 \
  --ai-fixes \
  --ai-provider gemini
```

### 2. Conservative Scan (Slower, More Respectful)
```bash
impact-scan scan examples/Vulnerable-Flask-App \
  --web-search \
  --web-limit 50 \
  --web-batch-size 5 \
  --web-delay 3.0 \
  --ai-fixes \
  --ai-provider gemini
```

### 3. Aggressive Scan (Faster, Risk of Rate Limits)
```bash
impact-scan scan examples/Vulnerable-Flask-App \
  --web-search \
  --web-limit 150 \
  --web-batch-size 15 \
  --web-delay 1.0 \
  --ai-fixes \
  --ai-provider gemini
```

### 4. High-Priority Only Scan
```bash
impact-scan scan examples/Vulnerable-Flask-App \
  --min-severity HIGH \
  --web-search \
  --web-limit 100 \
  --prioritize-high \
  --ai-fixes \
  --ai-provider gemini
```

## For Your 93-Vulnerability Flask App

### Recommended Command
```bash
impact-scan scan examples/Vulnerable-Flask-App \
  --min-severity MEDIUM \
  --ai-fixes \
  --ai-provider gemini \
  --web-search \
  --web-limit 100 \
  --web-batch-size 8 \
  --web-delay 2.5 \
  --prioritize-high \
  --html vulnerable-app-report.html
```

This configuration will:
- ✅ Process up to 100 vulnerabilities (covering your 93)
- ✅ Use 8-finding batches with 2.5s delays
- ✅ Prioritize CRITICAL/HIGH severity issues first
- ✅ Use intelligent caching to reduce API calls
- ✅ Generate a beautiful HTML report
- ✅ Stay within Gemini API rate limits

## Monitoring Output

The enhanced tool provides detailed progress tracking:

```
🚀 Processing 93 findings for web fixes using intelligent batching...
🤖 Gemini AI web search enabled (delay: 2.5s)
🎯 Prioritizing findings by severity (CRITICAL → HIGH → MEDIUM → LOW)
📊 Processing Strategy:
  • Total findings: 93
  • Processing limit: 100
  • Batch size: 8
  • Rate limit delay: 2.5s
  • Prioritize by severity: True

🔄 Batch 1/12 (8 findings)
(1/93) Processing: CVE-2023-1234 [CRITICAL]
✅ Fix found for CVE-2023-1234
...

📈 Final Results:
  • Total processed: 93/93
  • Successful fixes: 67 (72.0%)
  • Cache hits: 12 (12.9%)
  • Actual API calls: 55
```

## Alternative API Providers

If you continue having rate limit issues with Gemini:

### OpenAI (Higher Rate Limits)
```bash
export OPENAI_API_KEY="your-key"
impact-scan scan examples/Vulnerable-Flask-App \
  --ai-provider openai \
  --web-search \
  --web-limit 100
```

### Anthropic (Claude)
```bash
export ANTHROPIC_API_KEY="your-key"
impact-scan scan examples/Vulnerable-Flask-App \
  --ai-provider anthropic \
  --web-search \
  --web-limit 100
```

## Troubleshooting

### Still Hitting Rate Limits?
1. **Reduce batch size**: `--web-batch-size 5`
2. **Increase delay**: `--web-delay 4.0`
3. **Lower limit**: `--web-limit 50`
4. **Use caching**: The system automatically caches results

### Memory Issues?
The caching system is limited to 200 entries and uses LRU eviction.

### Performance Tips
- Use `--min-severity HIGH` to focus on critical issues
- Set `--web-limit` based on your API quota
- Monitor the progress output for optimal batch sizing

## Testing

Run the test script to validate your setup:

```bash
python test_high_volume_scan.py
```

This will test all the new features with a smaller batch size to ensure everything works correctly before running the full scan.
