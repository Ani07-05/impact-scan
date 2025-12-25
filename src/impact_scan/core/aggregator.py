import fnmatch
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple

from sarif_om import (
    ArtifactLocation,
    Location,
    Message,
    MultiformatMessageString,
    PhysicalLocation,
    ReportingDescriptor,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)

from ..utils import schema

logger = logging.getLogger(__name__)


def merge_and_dedupe(*findings_lists: List[schema.Finding]) -> List[schema.Finding]:
    """
    Merges multiple lists of findings and removes duplicates.

    A finding is considered a duplicate if it has the same file path,
    line number, and vulnerability ID as another finding. The first
    occurrence of a finding is kept.

    Args:
        *findings_lists: A variable number of lists of Finding objects.

    Returns:
        A single, deduplicated list of Finding objects.
    """
    unique_findings: List[schema.Finding] = []
    seen: Set[Tuple[str, int, str]] = set()

    for findings_list in findings_lists:
        for finding in findings_list:
            # Create a unique identifier for each finding
            finding_id = (
                str(finding.file_path.resolve()),
                finding.line_number,
                finding.vuln_id,
            )
            if finding_id not in seen:
                seen.add(finding_id)
                unique_findings.append(finding)

    return unique_findings


def should_ignore_finding(
    finding: schema.Finding, ignore_rules: List[schema.IgnoreRule]
) -> Tuple[bool, Optional[str]]:
    """
    Check if a finding should be ignored based on ignore rules.

    Returns:
        (should_ignore: bool, reason: Optional[str])
    """
    for rule in ignore_rules:
        # Check if rule is expired
        if rule.expires:
            try:
                expire_date = datetime.fromisoformat(rule.expires).date()
                if datetime.now().date() > expire_date:
                    logger.warning(
                        f"Ignore rule expired on {rule.expires}: {rule.cwe or rule.cve or rule.rule_id} - {rule.reason}"
                    )
                    continue  # Skip expired rules
            except ValueError:
                pass  # Invalid date, ignore expiration check

        # Check CWE match
        if rule.cwe:
            # Extract CWE from vuln_id or metadata
            if (
                rule.cwe in finding.vuln_id
                or rule.cwe.lower() in finding.vuln_id.lower()
            ):
                return True, rule.reason or f"Ignored by CWE rule: {rule.cwe}"
            # Check in metadata
            if finding.metadata and "cwe" in finding.metadata:
                if rule.cwe in str(finding.metadata["cwe"]):
                    return True, rule.reason or f"Ignored by CWE rule: {rule.cwe}"

        # Check CVE match
        if rule.cve:
            if (
                rule.cve in finding.vuln_id
                or rule.cve.lower() in finding.vuln_id.lower()
            ):
                return True, rule.reason or f"Ignored by CVE rule: {rule.cve}"

        # Check rule_id match
        if rule.rule_id:
            if rule.rule_id == finding.rule_id:
                # If path is also specified, must match both
                if rule.path:
                    file_path_str = str(finding.file_path).replace("\\", "/")
                    pattern_normalized = rule.path.replace("\\", "/")
                    if fnmatch.fnmatch(file_path_str, pattern_normalized):
                        return (
                            True,
                            rule.reason
                            or f"Ignored by rule+path: {rule.rule_id} in {rule.path}",
                        )
                else:
                    return True, rule.reason or f"Ignored by rule: {rule.rule_id}"

        # Check path match (glob pattern)
        if rule.path and not rule.rule_id:  # Path-only rule
            file_path_str = str(finding.file_path).replace("\\", "/")
            pattern_normalized = rule.path.replace("\\", "/")
            if fnmatch.fnmatch(file_path_str, pattern_normalized):
                return True, rule.reason or f"Ignored by path pattern: {rule.path}"

        # Check severity match
        if rule.severity:
            if finding.severity.value.lower() == rule.severity.lower():
                return True, rule.reason or f"Ignored by severity: {rule.severity}"

    return False, None


def apply_ignore_rules(
    findings: List[schema.Finding], ignore_rules: List[schema.IgnoreRule]
) -> Tuple[List[schema.Finding], List[schema.Finding]]:
    """
    Filter findings based on ignore rules.

    Returns:
        (kept_findings, ignored_findings)
    """
    if not ignore_rules:
        return findings, []

    kept = []
    ignored = []

    for finding in findings:
        should_ignore, reason = should_ignore_finding(finding, ignore_rules)
        if should_ignore:
            # Add ignore reason to metadata
            finding.metadata["ignored"] = True
            finding.metadata["ignore_reason"] = reason
            ignored.append(finding)
        else:
            kept.append(finding)

    return kept, ignored


def save_to_json(scan_result: schema.ScanResult, output_path: Path) -> None:
    """
    Saves scan results to JSON format.

    Args:
        scan_result: The scan result to convert to JSON
        output_path: Path where to save the JSON file
    """
    try:
        # Convert to dict for JSON serialization
        result_dict = {
            "scan_summary": {
                "target": str(scan_result.config.root_path),
                "total_findings": len(scan_result.findings),
                "timestamp": scan_result.timestamp,
                "execution_time": getattr(scan_result, "execution_time", 0),
            },
            "findings": [
                {
                    "vuln_id": f.vuln_id,
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "file_path": str(f.file_path),
                    "line_number": f.line_number,
                    "code_snippet": f.code_snippet,
                    "fix_suggestion": f.fix_suggestion,
                    "ai_fix": f.ai_fix,
                    "source": f.source.value,
                    "stackoverflow_fixes": [
                        {
                            "url": fix.url,
                            "title": fix.title,
                            "votes": fix.votes,
                            "accepted": fix.accepted,
                            "author": fix.author,
                            "explanation": fix.explanation,
                            "code_snippets": [
                                {"language": cb.language, "code": cb.code}
                                for cb in fix.code_snippets
                            ],
                        }
                        for fix in (f.stackoverflow_fixes or [])
                    ] if f.stackoverflow_fixes else None,
                }
                for f in scan_result.findings
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False)

    except Exception as e:
        raise RuntimeError(
            f"Failed to save JSON report to {output_path}: {str(e)}"
        ) from e


def save_to_sarif(scan_result: schema.ScanResult, output_path: Path) -> None:
    """
    Saves scan results to SARIF format.

    Args:
        scan_result: The scan result to convert to SARIF
        output_path: Path where to save the SARIF file
    """
    try:
        # Map severity levels to SARIF level strings
        severity_map = {
            schema.Severity.LOW: "note",
            schema.Severity.MEDIUM: "warning",
            schema.Severity.HIGH: "error",
            schema.Severity.CRITICAL: "error",
        }

        # Create tool info
        driver = ToolComponent(
            name="impact-scan",
            version="0.1.0",
            information_uri="https://github.com/Ani07-05/impact-scan",
            rules=[],
        )

        # Collect unique rules from findings
        rule_ids = set()
        for finding in scan_result.findings:
            if finding.rule_id not in rule_ids:
                rule_ids.add(finding.rule_id)
                driver.rules.append(
                    ReportingDescriptor(
                        id=finding.rule_id,
                        name=finding.title,
                        short_description=MultiformatMessageString(
                            text=finding.description
                        ),
                        full_description=MultiformatMessageString(
                            text=finding.description
                        ),
                        help=MultiformatMessageString(
                            text=finding.fix_suggestion or "No fix suggestion available"
                        ),
                    )
                )

        tool = Tool(driver=driver)

        # Convert findings to SARIF results
        results = []
        for finding in scan_result.findings:
            # Create location
            artifact_location = ArtifactLocation(
                uri=str(finding.file_path.relative_to(scan_result.config.root_path))
            )
            physical_location = PhysicalLocation(
                artifact_location=artifact_location,
                region={
                    "startLine": finding.line_number,
                    "snippet": {"text": finding.code_snippet},
                },
            )
            location = Location(physical_location=physical_location)

            # Create result
            result = Result(
                rule_id=finding.rule_id,
                rule_index=list(rule_ids).index(finding.rule_id),
                message=Message(text=finding.description),
                level=severity_map.get(finding.severity, "warning"),
                locations=[location],
            )

            # Add fix suggestions if available
            if finding.fix_suggestion or finding.ai_fix:
                fix_text = finding.ai_fix or finding.fix_suggestion
                result.message.text += f"\n\nSuggested fix: {fix_text}"

            results.append(result)

        # Create run
        run = Run(
            tool=tool,
            results=results,
            invocations=[
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.fromtimestamp(
                        scan_result.timestamp
                    ).isoformat()
                    + "Z",
                }
            ],
        )

        # Create SARIF log
        sarif_log = SarifLog(version="2.1.0", runs=[run])

        # Write to file using attrs serialization
        import attr

        with open(output_path, "w", encoding="utf-8") as f:
            sarif_dict = attr.asdict(sarif_log, recurse=True)
            json.dump(sarif_dict, f, indent=2, ensure_ascii=False)

    except Exception as e:
        # Proper error handling instead of silent failure
        raise RuntimeError(
            f"Failed to save SARIF report to {output_path}: {str(e)}"
        ) from e
