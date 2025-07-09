from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from enum import Enum
from pathlib import Path
import time


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
    title: str
    severity: Severity
    source: VulnSource
    code_snippet: str
    description: str
    fix_suggestion: Optional[str] = None
    web_fix: Optional[str] = None
    citation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('line_number')
    def validate_line_number(cls, v):
        if v < 1:
            raise ValueError('Line number must be positive')
        return v
    
    @validator('vuln_id')
    def validate_vuln_id(cls, v):
        if not v.strip():
            raise ValueError('Vulnerability ID cannot be empty')
        return v.strip()


class AIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    LOCAL = "local"


class ScanConfig(BaseModel):
    target_path: Path
    min_severity: Severity = Severity.MEDIUM
    enable_ai_fixes: bool = False
    enable_web_search: bool = False
    ai_provider: Optional[AIProvider] = None
    api_keys: Dict[str, str] = Field(default_factory=dict)

    @validator('target_path')
    def validate_target_path(cls, v):
        if not v.exists():
            raise ValueError(f'Target path does not exist: {v}')
        return v

    @validator('ai_provider', always=True)
    def check_ai_config(cls, v, values):
        enable_ai_fixes = values.get('enable_ai_fixes', False)
        if enable_ai_fixes and not v:
            raise ValueError("AI fixes enabled, but no 'ai_provider' was specified.")
        return v


class ScanResult(BaseModel):
    config: ScanConfig
    findings: List[Finding]
    entry_points: List[Path]
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
    
    @validator('confidence')
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v
