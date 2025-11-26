# Legacy/Experimental Modules - Not Used in v1.0

## Status: DEPRECATED/EXPERIMENTAL

The following modules in this directory are **not used** in the production v1.0 codebase and are marked as experimental/legacy:

### 1. `comprehensive_security_crawler.py` (643 lines)
- **Status:** Experimental - Not production ready
- **Purpose:** Orchestration layer for multi-crawler security intelligence
- **Issues:** 
  - Complex, fragile web scraping dependencies
  - Not integrated with agent system
  - High maintenance burden
  - Quality concerns
- **Decision:** Disabled for v1.0, may be revisited in v1.2+ if there's demand

### 2. `modern_web_intelligence.py` (file size unknown)
- **Status:** Experimental - Not production ready  
- **Purpose:** AI-powered web search enrichment
- **Issues:**
  - Only used by comprehensive_security_crawler (also disabled)
  - External API dependencies
  - Quality/reliability unclear
- **Decision:** Disabled for v1.0

### 3. `stackoverflow_scraper.py` (558 lines)
- **Status:** Experimental - Not production ready
- **Purpose:** Scrape Stack Overflow for security fixes
- **Issues:**
  - Fragile web scraping with Playwright
  - Rate limiting concerns
  - Not integrated with core scanning
- **Decision:** Disabled for v1.0

## Why Keep These Files?

These modules represent significant development effort and may have value for:
- Future research into web intelligence enrichment
- Community contributions to improve reliability
- Potential v1.2+ features if demand exists

## v1.0 Focus

**Instead of web scraping**, v1.0 focuses on:
- ✅ Local-first scanning (Semgrep, OSV-Scanner, Bandit)
- ✅ AI-powered fix generation (direct API calls to OpenAI/Anthropic/Gemini)
- ✅ Fast, reliable, privacy-respecting architecture
- ✅ No fragile external dependencies

## Future Consideration

If users request "web enrichment" features in v1.1+, we can:
1. Revive and refactor these modules with proper error handling
2. Add caching and rate limiting
3. Make it optional/plugin-based
4. Improve quality through community feedback

---
**Last Updated:** November 20, 2025  
**Review Date:** Post-v1.0 based on user feedback
