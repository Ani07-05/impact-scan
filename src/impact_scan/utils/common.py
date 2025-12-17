"""
Common utility functions to reduce code duplication across the codebase.
"""

import logging
from pathlib import Path
from typing import Union

from impact_scan.utils.schema import Severity


def to_path(target: Union[str, Path]) -> Path:
    """Convert a string or Path to a Path object.
    
    Args:
        target: A string path or Path object
        
    Returns:
        Path object
        
    Example:
        >>> to_path("/home/user/project")
        PosixPath('/home/user/project')
        >>> to_path(Path("/home/user/project"))
        PosixPath('/home/user/project')
    """
    return Path(target) if isinstance(target, str) else target


def get_logger(name: str) -> logging.Logger:
    """Get or create a logger with the given name.
    
    Provides a centralized way to get loggers across the codebase,
    making it easier to apply consistent logging configuration.
    
    Args:
        name: Logger name, typically __name__
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


def get_severity_order() -> dict[Severity, int]:
    """Get the standard severity ordering for sorting findings.
    
    Returns a mapping from Severity enum values to numeric order,
    where higher numbers indicate more severe vulnerabilities.
    
    Returns:
        Dict mapping Severity to int (higher = more severe)
        
    Example:
        >>> order = get_severity_order()
        >>> order[Severity.CRITICAL]
        4
    """
    return {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
    }


def sort_findings_by_severity(findings: list, reverse: bool = True) -> list:
    """Sort findings by severity level.
    
    Args:
        findings: List of Finding objects with .severity attribute
        reverse: If True (default), sorts CRITICAL first (descending)
        
    Returns:
        Sorted list of findings
    """
    severity_order = get_severity_order()
    return sorted(
        findings,
        key=lambda f: severity_order.get(f.severity, 0),
        reverse=reverse
    )


def count_by_severity(findings: list) -> dict[str, int]:
    """Count findings grouped by severity level.
    
    Args:
        findings: List of Finding objects with .severity attribute
        
    Returns:
        Dict mapping severity name to count
        
    Example:
        >>> counts = count_by_severity(findings)
        >>> counts['CRITICAL']
        3
    """
    counts = {s.name: 0 for s in Severity}
    for finding in findings:
        severity_name = (
            finding.severity.name 
            if hasattr(finding.severity, "name") 
            else str(finding.severity)
        )
        if severity_name in counts:
            counts[severity_name] += 1
    return counts


def filter_by_severity(findings: list, min_severity: Severity) -> list:
    """Filter findings to only those with severity >= min_severity.
    
    Args:
        findings: List of Finding objects
        min_severity: Minimum severity level to include
        
    Returns:
        Filtered list of findings
    """
    severity_order = get_severity_order()
    min_order = severity_order.get(min_severity, 0)
    return [
        f for f in findings
        if severity_order.get(f.severity, 0) >= min_order
    ]


__all__ = [
    "to_path",
    "get_logger",
    "get_severity_order",
    "sort_findings_by_severity",
    "count_by_severity",
    "filter_by_severity",
]
