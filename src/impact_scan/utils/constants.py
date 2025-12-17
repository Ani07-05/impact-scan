"""
Centralized constants for impact-scan to eliminate magic strings and hardcoded values.
"""

from enum import Enum

# AI Models
class AIModel(str, Enum):
    """Supported AI models for fix generation and analysis."""
    
    # OpenAI
    GPT_4O_MINI = "gpt-4o-mini"
    
    # Anthropic
    CLAUDE_3_HAIKU = "claude-3-haiku-20240307"
    
    # Google
    GEMINI_2_5_FLASH = "gemini-2.5-flash"
    
    # Groq
    LLAMA_3_3_70B = "llama-3.3-70b-versatile"


class AIProvider(str, Enum):
    """Supported AI providers."""
    
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    GROQ = "groq"


class SemgrepSeverity(str, Enum):
    """Semgrep severity levels."""
    
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ConfidenceLevel(str, Enum):
    """Confidence levels for findings."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Framework(str, Enum):
    """Common web frameworks."""
    
    # Python
    FLASK = "flask"
    DJANGO = "django"
    FASTAPI = "fastapi"
    
    # JavaScript/Node.js
    EXPRESS = "express"
    NEXT_JS = "next.js"
    REACT = "react"
    
    # Other
    SPRING = "spring"
    RAILS = "rails"


class ScanToolType(str, Enum):
    """Scan tool types."""
    
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY = "dependency"
    SECRETS = "secrets"
    SAST = "sast"
    DAST = "dast"


class ReportFormat(str, Enum):
    """Supported report formats."""
    
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"
    PDF = "pdf"


# Default AI Model Mappings
DEFAULT_AI_MODELS = {
    AIProvider.OPENAI: AIModel.GPT_4O_MINI,
    AIProvider.ANTHROPIC: AIModel.CLAUDE_3_HAIKU,
    AIProvider.GEMINI: AIModel.GEMINI_2_5_FLASH,
    AIProvider.GROQ: AIModel.LLAMA_3_3_70B,
}

# Semgrep to Impact-Scan Severity Mapping
SEMGREP_SEVERITY_MAP = {
    SemgrepSeverity.ERROR: "HIGH",
    SemgrepSeverity.WARNING: "MEDIUM",
    SemgrepSeverity.INFO: "LOW",
}

# Confidence Level Mapping
CONFIDENCE_SCORES = {
    ConfidenceLevel.LOW: 1,
    ConfidenceLevel.MEDIUM: 2,
    ConfidenceLevel.HIGH: 3,
    ConfidenceLevel.CRITICAL: 4,
}

__all__ = [
    "AIModel",
    "AIProvider",
    "SemgrepSeverity",
    "ConfidenceLevel",
    "Framework",
    "ScanToolType",
    "ReportFormat",
    "DEFAULT_AI_MODELS",
    "SEMGREP_SEVERITY_MAP",
    "CONFIDENCE_SCORES",
]
