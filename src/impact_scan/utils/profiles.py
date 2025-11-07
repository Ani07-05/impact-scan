"""
Scan profiles for different use cases to simplify CLI usage.
"""
from dataclasses import dataclass
from typing import Optional
from impact_scan.utils import schema


@dataclass
class ScanProfile:
    """Defines a scan configuration profile."""
    name: str
    description: str
    min_severity: schema.Severity
    enable_ai_fixes: bool
    enable_web_search: bool
    ai_provider: Optional[schema.AIProvider]
    web_search_limit: int
    web_search_batch_size: int
    web_search_delay: float
    prioritize_high_severity: bool
    enable_stackoverflow_scraper: bool = True
    stackoverflow_max_answers: int = 3
    stackoverflow_scrape_delay: float = 4.0
    stackoverflow_include_comments: bool = True


# Predefined scan profiles
SCAN_PROFILES = {
    "quick": ScanProfile(
        name="quick",
        description="Fast scan with essential security checks only",
        min_severity=schema.Severity.HIGH,
        enable_ai_fixes=False,
        enable_web_search=False,
        ai_provider=None,
        web_search_limit=0,
        web_search_batch_size=5,
        web_search_delay=1.0,
        prioritize_high_severity=True,
        enable_stackoverflow_scraper=False,
        stackoverflow_max_answers=0,
        stackoverflow_scrape_delay=4.0,
        stackoverflow_include_comments=False,
    ),
    
    "standard": ScanProfile(
        name="standard",
        description="Balanced scan with moderate depth and AI assistance",
        min_severity=schema.Severity.MEDIUM,
        enable_ai_fixes=True,
        enable_web_search=False,
        ai_provider=None,  # Will be auto-detected
        web_search_limit=50,
        web_search_batch_size=10,
        web_search_delay=2.0,
        prioritize_high_severity=True,
        enable_stackoverflow_scraper=False,  # API is now primary, scraper only as fallback
        stackoverflow_max_answers=3,
        stackoverflow_scrape_delay=4.0,
        stackoverflow_include_comments=True,
    ),
    
    "comprehensive": ScanProfile(
        name="comprehensive",
        description="Thorough scan with full AI analysis and web research",
        min_severity=schema.Severity.LOW,
        enable_ai_fixes=True,
        enable_web_search=True,
        ai_provider=None,  # Will be auto-detected
        web_search_limit=200,
        web_search_batch_size=20,
        web_search_delay=1.5,
        prioritize_high_severity=True,
        enable_stackoverflow_scraper=False,  # API is now primary, scraper only as fallback
        stackoverflow_max_answers=5,
        stackoverflow_scrape_delay=3.5,
        stackoverflow_include_comments=True,
    ),
    
    "ci": ScanProfile(
        name="ci",
        description="Fast CI/CD pipeline scan focusing on critical issues",
        min_severity=schema.Severity.HIGH,
        enable_ai_fixes=False,
        enable_web_search=False,
        ai_provider=None,
        web_search_limit=0,
        web_search_batch_size=5,
        web_search_delay=1.0,
        prioritize_high_severity=True,
        enable_stackoverflow_scraper=False,
        stackoverflow_max_answers=0,
        stackoverflow_scrape_delay=4.0,
        stackoverflow_include_comments=False,
    ),
}


def get_profile(profile_name: str) -> ScanProfile:
    """Get a scan profile by name."""
    if profile_name not in SCAN_PROFILES:
        available = ", ".join(SCAN_PROFILES.keys())
        raise ValueError(f"Unknown profile '{profile_name}'. Available profiles: {available}")
    return SCAN_PROFILES[profile_name]


def auto_detect_ai_provider(api_keys: schema.APIKeys) -> Optional[schema.AIProvider]:
    """Auto-detect the best available AI provider from API keys."""
    # Priority order: Gemini (fastest/cheapest) -> OpenAI -> Anthropic
    # Check for valid API keys (not test/dummy values)
    if api_keys.gemini and api_keys.gemini not in ('test', 'dummy', 'placeholder'):
        return schema.AIProvider.GEMINI
    elif api_keys.openai and api_keys.openai not in ('test', 'dummy', 'placeholder'):
        return schema.AIProvider.OPENAI
    elif api_keys.anthropic and api_keys.anthropic not in ('test', 'dummy', 'placeholder'):
        return schema.AIProvider.ANTHROPIC
    
    return None


def create_config_from_profile(
    root_path, 
    profile: ScanProfile, 
    api_keys: schema.APIKeys,
    overrides: dict = None
) -> schema.ScanConfig:
    """Create a ScanConfig from a profile with optional overrides."""
    
    # Auto-detect AI provider if not specified
    ai_provider = profile.ai_provider
    enable_ai_fixes = profile.enable_ai_fixes
    
    if profile.enable_ai_fixes and ai_provider is None:
        ai_provider = auto_detect_ai_provider(api_keys)
        # If no valid AI provider detected, disable AI features
        if ai_provider is None:
            enable_ai_fixes = False
    
    config_dict = {
        "root_path": root_path,
        "min_severity": profile.min_severity,
        "enable_ai_fixes": enable_ai_fixes,
        "enable_web_search": profile.enable_web_search,
        "ai_provider": ai_provider,
        "api_keys": api_keys,
        "web_search_limit": profile.web_search_limit,
        "web_search_batch_size": profile.web_search_batch_size,
        "web_search_delay": profile.web_search_delay,
        "prioritize_high_severity": profile.prioritize_high_severity,
        "enable_stackoverflow_scraper": profile.enable_stackoverflow_scraper,
        "stackoverflow_max_answers": profile.stackoverflow_max_answers,
        "stackoverflow_scrape_delay": profile.stackoverflow_scrape_delay,
        "stackoverflow_include_comments": profile.stackoverflow_include_comments,
    }
    
    # Apply any overrides
    if overrides:
        config_dict.update(overrides)
    
    return schema.ScanConfig(**config_dict)