from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional, Dict, Any
from enum import Enum
from pathlib import Path
import time
import re


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnSource(str, Enum):
    DEPENDENCY = "dependency"
    STATIC_ANALYSIS = "static_analysis"
    AI_DETECTION = "ai_detection"


class Finding(BaseModel):
    file_path: Path
    line_number: int
    vuln_id: str = Field(..., description="CVE ID or rule identifier")
    rule_id: str
    title: str
    severity: Severity
    source: VulnSource
    code_snippet: str
    description: str
    fix_suggestion: Optional[str] = None
    web_fix: Optional[str] = None
    ai_fix: Optional[str] = None
    ai_explanation: Optional[str] = None
    citations: Optional[List[str]] = None
    citation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    stackoverflow_fixes: Optional[List['StackOverflowFix']] = None
    
    @field_validator('file_path')
    @classmethod
    def validate_file_path(cls, v):
        """Validate file path to prevent path traversal attacks."""
        if not isinstance(v, Path):
            v = Path(v)
        
        # Resolve path to detect any traversal attempts
        try:
            resolved_path = v.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid file path: {e}")
        
        # Check for suspicious path components
        path_str = str(resolved_path)
        if '..' in path_str or path_str.startswith('~'):
            raise ValueError("Path traversal attempts are not allowed")
        
        return resolved_path
    
    @field_validator('line_number')
    @classmethod
    def validate_line_number(cls, v):
        if not isinstance(v, int):
            raise ValueError('Line number must be an integer')
        if v < 1:
            raise ValueError('Line number must be positive')
        if v > 1000000:  # Reasonable upper limit
            raise ValueError('Line number is unreasonably large')
        return v
    
    @field_validator('vuln_id')
    @classmethod
    def validate_vuln_id(cls, v):
        if not isinstance(v, str):
            raise ValueError('Vulnerability ID must be a string')
        v = v.strip()
        if not v:
            raise ValueError('Vulnerability ID cannot be empty')
        if len(v) > 200:  # Reasonable limit
            raise ValueError('Vulnerability ID is too long')
        # Allow alphanumeric, hyphens, underscores, dots, commas, and spaces for multi-ID strings
        if not re.match(r'^[a-zA-Z0-9._,\s-]+$', v):
            raise ValueError('Vulnerability ID contains invalid characters')
        return v
    
    @field_validator('rule_id')
    @classmethod
    def validate_rule_id(cls, v):
        if not isinstance(v, str):
            raise ValueError('Rule ID must be a string')
        v = v.strip()
        if not v:
            raise ValueError('Rule ID cannot be empty')
        if len(v) > 200:  # Reasonable limit
            raise ValueError('Rule ID is too long')
        return v
    
    @field_validator('title')
    @classmethod
    def validate_title(cls, v):
        if not isinstance(v, str):
            raise ValueError('Title must be a string')
        v = v.strip()
        if not v:
            raise ValueError('Title cannot be empty')
        if len(v) > 500:  # Reasonable limit
            raise ValueError('Title is too long')
        return v
    
    @field_validator('code_snippet')
    @classmethod
    def validate_code_snippet(cls, v):
        if not isinstance(v, str):
            raise ValueError('Code snippet must be a string')
        if len(v) > 10000:  # Reasonable limit for code snippets
            raise ValueError('Code snippet is too long')
        return v
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        if not isinstance(v, str):
            raise ValueError('Description must be a string')
        v = v.strip()
        if not v:
            raise ValueError('Description cannot be empty')
        if len(v) > 5000:  # Reasonable limit
            raise ValueError('Description is too long')
        return v


class CodeBlock(BaseModel):
    """Represents a code block extracted from Stack Overflow."""
    language: str
    code: str


class StackOverflowFix(BaseModel):
    """Represents a Stack Overflow answer with code fixes and metadata."""
    url: str
    title: str
    question_id: str
    answer_id: str
    votes: int
    accepted: bool
    author: str
    author_reputation: int
    post_date: str
    code_snippets: List[CodeBlock]
    explanation: str
    comments: List[str]
    gemini_analysis: Optional[str] = None  # Gemini's validation/analysis
    score: float


class AIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    LOCAL = "local"


class APIKeys(BaseModel):
    """API keys for AI providers."""
    openai: Optional[str] = None
    anthropic: Optional[str] = None
    gemini: Optional[str] = None
    stackoverflow: Optional[str] = None

    def __init__(self, **data):
        """Initialize with environment variable auto-detection."""
        import os

        # Auto-detect from environment if not explicitly provided
        if 'openai' not in data and not data.get('openai'):
            data['openai'] = os.getenv('OPENAI_API_KEY')
        if 'anthropic' not in data and not data.get('anthropic'):
            data['anthropic'] = os.getenv('ANTHROPIC_API_KEY')
        if 'gemini' not in data and not data.get('gemini'):
            data['gemini'] = os.getenv('GOOGLE_API_KEY')
        if 'stackoverflow' not in data and not data.get('stackoverflow'):
            data['stackoverflow'] = os.getenv('STACKOVERFLOW_API_KEY')

        super().__init__(**data)
    
    @field_validator('openai', 'anthropic', 'gemini', 'stackoverflow')
    @classmethod
    def validate_api_keys(cls, v):
        """Validate API keys format and prevent injection."""
        if v is None:
            return v
        
        if not isinstance(v, str):
            raise ValueError('API key must be a string')
        
        v = v.strip()
        if not v:
            return None  # Empty string becomes None
        
        # Basic format validation
        if len(v) < 10:
            raise ValueError('API key is too short to be valid')
        if len(v) > 500:
            raise ValueError('API key is too long')
        
        # Check for suspicious characters
        if any(char in v for char in ['\n', '\r', '\t', ';', '|', '&']):
            raise ValueError('API key contains invalid characters')
        
        return v


class ScanConfig(BaseModel):
    root_path: Path
    min_severity: Severity = Severity.MEDIUM
    enable_ai_fixes: bool = False
    enable_web_search: bool = False
    ai_provider: Optional[AIProvider] = None
    api_keys: APIKeys = Field(default_factory=APIKeys)
    web_search_limit: int = 100
    web_search_batch_size: int = 10
    web_search_delay: float = 2.0
    prioritize_high_severity: bool = True
    enable_stackoverflow_scraper: bool = True
    stackoverflow_max_answers: int = 3
    stackoverflow_scrape_delay: float = 4.0
    stackoverflow_include_comments: bool = True

    @field_validator('root_path')
    @classmethod
    def validate_root_path(cls, v):
        """Validate root path and prevent directory traversal."""
        if not isinstance(v, Path):
            v = Path(v)
        
        # Resolve to detect traversal attempts
        try:
            v = v.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f'Invalid root path: {e}')
        
        # Check path exists
        if not v.exists():
            raise ValueError(f'Target path does not exist: {v}')
        
        # Must be a directory
        if not v.is_dir():
            raise ValueError(f'Target path must be a directory: {v}')
        
        # Check for reasonable path length
        if len(str(v)) > 1000:
            raise ValueError('Root path is too long')
        
        return v
    
    @field_validator('web_search_limit')
    @classmethod
    def validate_web_search_limit(cls, v):
        if not isinstance(v, int):
            raise ValueError('Web search limit must be an integer')
        if v < 0:
            raise ValueError('Web search limit cannot be negative')
        if v > 10000:
            raise ValueError('Web search limit is too high (max 10000)')
        return v
    
    @field_validator('web_search_batch_size')
    @classmethod
    def validate_web_search_batch_size(cls, v):
        if not isinstance(v, int):
            raise ValueError('Web search batch size must be an integer')
        if v < 1:
            raise ValueError('Web search batch size must be at least 1')
        if v > 1000:
            raise ValueError('Web search batch size is too high (max 1000)')
        return v
    
    @field_validator('web_search_delay')
    @classmethod
    def validate_web_search_delay(cls, v):
        if not isinstance(v, (int, float)):
            raise ValueError('Web search delay must be a number')
        if v < 0:
            raise ValueError('Web search delay cannot be negative')
        if v > 3600:  # 1 hour max
            raise ValueError('Web search delay is too high (max 3600 seconds)')
        return v

    @model_validator(mode='after')
    def check_ai_config(self):
        if self.enable_ai_fixes and not self.ai_provider:
            raise ValueError("AI fixes enabled, but no 'ai_provider' was specified.")
        return self


class ScanResult(BaseModel):
    config: ScanConfig
    findings: List[Finding]
    entry_points: List['EntryPoint']
    scanned_files: int
    scan_duration: float
    timestamp: float = Field(default_factory=time.time)
    
    @property
    def findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        result = {severity: [] for severity in Severity}
        for finding in self.findings:
            result[finding.severity].append(finding)
        return result
    
    @property
    def total_findings(self) -> int:
        return len(self.findings)
    
    @property
    def critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]


class EntryPoint(BaseModel):
    path: Path
    framework: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v

# Update model forward references
Finding.model_rebuild()
ScanResult.model_rebuild()
