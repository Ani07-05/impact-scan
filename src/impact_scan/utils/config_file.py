"""
Configuration file support for Impact Scan.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from impact_scan.utils import profiles, schema

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILES = [
    ".impact-scan.yml",
    ".impact-scan.yaml",
    "impact-scan.yml",
    "impact-scan.yaml",
    "pyproject.toml",  # For [tool.impact-scan] section
]


def find_config_file(start_path: Path = None) -> Optional[Path]:
    """
    Find configuration file by searching up the directory tree.
    """
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()

    # Search up the directory tree
    while current != current.parent:  # Stop at root
        for config_name in DEFAULT_CONFIG_FILES:
            config_path = current / config_name
            if config_path.exists() and config_path.is_file():
                logger.debug(f"Found config file: {config_path}")
                return config_path
        current = current.parent

    return None


def load_config_file(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from a YAML or TOML file.
    """
    try:
        if config_path.suffix.lower() in [".yml", ".yaml"]:
            return load_yaml_config(config_path)
        elif config_path.suffix.lower() == ".toml":
            return load_toml_config(config_path)
        else:
            logger.warning(f"Unsupported config file format: {config_path}")
            return {}
    except Exception as e:
        logger.error(f"Failed to load config file {config_path}: {e}")
        return {}


def load_yaml_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
            logger.info(f"Loaded config from {config_path}")
            return config
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {config_path}: {e}")


def load_toml_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from TOML file (pyproject.toml)."""
    try:
        import tomli

        with open(config_path, "rb") as f:
            data = tomli.load(f)
            # Extract [tool.impact-scan] section
            config = data.get("tool", {}).get("impact-scan", {})
            if config:
                logger.info(f"Loaded config from {config_path} [tool.impact-scan]")
            return config
    except ImportError:
        logger.warning("tomli package not available, cannot load TOML config")
        return {}
    except Exception as e:
        raise ValueError(f"Invalid TOML in {config_path}: {e}")


def validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalize configuration values.
    """
    validated = {}

    # Profile
    if "profile" in config:
        profile_name = config["profile"]
        if profile_name not in profiles.SCAN_PROFILES:
            available = list(profiles.SCAN_PROFILES.keys())
            raise ValueError(
                f"Invalid profile '{profile_name}'. Available: {available}"
            )
        validated["profile"] = profile_name

    # Severity level
    if "min_severity" in config or "severity" in config:
        severity = config.get("min_severity", config.get("severity"))
        if isinstance(severity, str):
            try:
                validated["min_severity"] = schema.Severity(severity.lower())
            except ValueError:
                available = [s.value for s in schema.Severity]
                raise ValueError(
                    f"Invalid severity '{severity}'. Available: {available}"
                )

    # AI provider
    if "ai_provider" in config or "ai" in config:
        provider = config.get("ai_provider", config.get("ai"))
        if isinstance(provider, str):
            try:
                validated["ai_provider"] = schema.AIProvider(provider.lower())
            except ValueError:
                available = [p.value for p in schema.AIProvider]
                raise ValueError(
                    f"Invalid AI provider '{provider}'. Available: {available}"
                )

    # Boolean flags
    for key in ["enable_ai_fixes", "ai_fixes", "enable_web_search", "web_search"]:
        if key in config:
            validated[
                key.replace("_", "_")
                .replace("ai_fixes", "enable_ai_fixes")
                .replace("web_search", "enable_web_search")
            ] = bool(config[key])

    # Numeric values
    for key in ["web_search_limit", "web_search_batch_size"]:
        if key in config:
            value = config[key]
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"'{key}' must be a non-negative integer")
            validated[key] = value

    if "web_search_delay" in config:
        value = config["web_search_delay"]
        if not isinstance(value, (int, float)) or value < 0:
            raise ValueError("'web_search_delay' must be a non-negative number")
        validated["web_search_delay"] = float(value)

    # Output paths
    for key in ["output", "html_output", "sarif_output"]:
        if key in config:
            validated[key] = Path(config[key])

    # Exclude/include patterns
    for key in ["exclude", "include"]:
        if key in config:
            value = config[key]
            if isinstance(value, str):
                validated[key] = [value]
            elif isinstance(value, list):
                validated[key] = value
            else:
                raise ValueError(f"'{key}' must be a string or list of strings")

    # NEW: Ignore rules
    if "ignore" in config:
        ignore_list = config["ignore"]
        if not isinstance(ignore_list, list):
            raise ValueError("'ignore' must be a list of ignore rules")

        # Parse each ignore rule
        validated_ignores = []
        for rule_dict in ignore_list:
            if not isinstance(rule_dict, dict):
                raise ValueError("Each ignore rule must be a dictionary")
            try:
                ignore_rule = schema.IgnoreRule(**rule_dict)
                validated_ignores.append(ignore_rule)
            except Exception as e:
                logger.warning(f"Skipping invalid ignore rule: {e}")

        validated["ignore_rules"] = validated_ignores

    return validated


def merge_config(
    file_config: Dict[str, Any], cli_overrides: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Merge configuration from file with CLI overrides.
    CLI arguments take precedence over file configuration.
    """
    # Start with file config
    merged = file_config.copy()

    # Override with CLI arguments (only non-None values)
    for key, value in cli_overrides.items():
        if value is not None:
            merged[key] = value

    return merged


def create_sample_config() -> str:
    """Create a sample configuration file content."""
    return """# Impact Scan Configuration File
# Save as .impact-scan.yml in your project root

# Scan profile: quick, standard, comprehensive, ci
profile: standard

# Minimum severity level: low, medium, high, critical
min_severity: medium

# AI provider: openai, anthropic, gemini
ai_provider: gemini

# Enable AI-powered fix suggestions
enable_ai_fixes: true

# Enable web search for additional context
enable_web_search: false

# Web search configuration
web_search_limit: 100
web_search_batch_size: 10
web_search_delay: 2.0

# Output file paths
# output: report.html
# sarif_output: results.sarif

# File patterns to exclude (optional)
# exclude:
#   - "*/node_modules/*"
#   - "*/venv/*"
#   - "*.min.js"

# File patterns to include (optional)
# include:
#   - "*.py"
#   - "*.js"
#   - "*.ts"

# Ignore rules - suppress specific findings (NEW!)
# ignore:
#   # Ignore by CWE ID
#   - cwe: CWE-89
#     reason: "SQL injection in legacy code, using parameterized queries"
#     expires: "2025-12-31"
#   
#   # Ignore by CVE ID (for dependencies)
#   - cve: CVE-2023-12345
#     reason: "False positive, not affected in our usage"
#   
#   # Ignore by file path (glob patterns)
#   - path: "tests/**"
#     reason: "Test files with intentional vulnerabilities"
#   
#   # Ignore by rule ID
#   - rule_id: "python.django.security.injection.sql.sql-injection"
#     path: "legacy/old_queries.py"
#     reason: "Scheduled for refactor in Q2"
#     expires: "2025-06-30"
#   
#   # Ignore by severity
#   - severity: low
#     reason: "Focus on high/critical only"
"""


def save_sample_config(config_path: Path) -> None:
    """Save a sample configuration file."""
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(create_sample_config())
    logger.info(f"Created sample config file: {config_path}")


# For pyproject.toml users
PYPROJECT_TOML_EXAMPLE = """
# Add this section to your pyproject.toml
[tool.impact-scan]
profile = "standard"
min_severity = "medium"
ai_provider = "gemini"
enable_ai_fixes = true
enable_web_search = false
"""
