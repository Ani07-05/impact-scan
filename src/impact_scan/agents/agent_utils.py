"""
Shared utility functions for agents to reduce code duplication.
"""

from typing import Dict, List

from impact_scan.utils.schema import Finding


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    """Count findings grouped by severity level.
    
    Args:
        findings: List of Finding objects
        
    Returns:
        Dict mapping severity name to count
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for finding in findings:
        severity_str = finding.severity.value.upper() if hasattr(finding.severity, 'value') else str(finding.severity).upper()
        if severity_str in counts:
            counts[severity_str] += 1
    
    return counts


def count_by_language(findings: List[Finding]) -> Dict[str, int]:
    """Count findings grouped by programming language.
    
    Args:
        findings: List of Finding objects
        
    Returns:
        Dict mapping language to count
    """
    counts = {}
    
    for finding in findings:
        # Infer language from file extension
        ext = finding.file_path.suffix.lstrip(".").lower() if hasattr(finding.file_path, 'suffix') else ""
        
        # Map extensions to language names
        lang_map = {
            "py": "Python",
            "js": "JavaScript",
            "ts": "TypeScript",
            "jsx": "JavaScript",
            "tsx": "TypeScript",
            "java": "Java",
            "go": "Go",
            "rs": "Rust",
            "rb": "Ruby",
            "php": "PHP",
            "cs": "C#",
            "cpp": "C++",
            "c": "C",
            "swift": "Swift",
            "kt": "Kotlin",
            "scala": "Scala",
        }
        
        language = lang_map.get(ext, "Other")
        counts[language] = counts.get(language, 0) + 1
    
    return counts


def count_by_type(findings: List[Finding]) -> Dict[str, int]:
    """Count findings grouped by vulnerability type/category.
    
    Args:
        findings: List of Finding objects
        
    Returns:
        Dict mapping finding type to count
    """
    counts = {}
    
    for finding in findings:
        # Use the title or rule_id as the vulnerability type
        vuln_type = finding.title or finding.rule_id or "Unknown"
        counts[vuln_type] = counts.get(vuln_type, 0) + 1
    
    return counts


def get_top_findings(findings: List[Finding], limit: int = 5) -> List[Finding]:
    """Get the top N findings by severity.
    
    Args:
        findings: List of Finding objects
        limit: Maximum number of findings to return
        
    Returns:
        Sorted list of top findings (by severity)
    """
    from impact_scan.utils.common import sort_findings_by_severity
    
    return sort_findings_by_severity(findings, reverse=True)[:limit]


def group_findings_by_file(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """Group findings by file path.
    
    Args:
        findings: List of Finding objects
        
    Returns:
        Dict mapping file path to list of findings in that file
    """
    grouped = {}
    
    for finding in findings:
        file_path = str(finding.file_path)
        if file_path not in grouped:
            grouped[file_path] = []
        grouped[file_path].append(finding)
    
    return grouped


def filter_by_rule_id(findings: List[Finding], rule_id: str) -> List[Finding]:
    """Filter findings by rule ID.
    
    Args:
        findings: List of Finding objects
        rule_id: Rule ID to filter by
        
    Returns:
        Filtered list of findings
    """
    return [f for f in findings if f.rule_id == rule_id]


__all__ = [
    "count_by_severity",
    "count_by_language",
    "count_by_type",
    "get_top_findings",
    "group_findings_by_file",
    "filter_by_rule_id",
]
