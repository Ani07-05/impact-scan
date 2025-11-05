import json
from pathlib import Path
from typing import List, Set, Tuple
from datetime import datetime

from sarif_om import SarifLog, Run, Tool, ToolComponent, Result, Location, PhysicalLocation, ArtifactLocation, Message, ReportingDescriptor, MultiformatMessageString
from impact_scan.utils import schema


def merge_and_dedupe(
    *findings_lists: List[schema.Finding]
) -> List[schema.Finding]:
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
            schema.Severity.CRITICAL: "error"
        }
        
        # Create tool info
        driver = ToolComponent(
            name="impact-scan",
            version="0.1.0",
            information_uri="https://github.com/Ani07-05/impact-scan",
            rules=[]
        )
        
        # Collect unique rules from findings
        rule_ids = set()
        for finding in scan_result.findings:
            if finding.rule_id not in rule_ids:
                rule_ids.add(finding.rule_id)
                driver.rules.append(ReportingDescriptor(
                    id=finding.rule_id,
                    name=finding.title,
                    short_description=MultiformatMessageString(text=finding.description),
                    full_description=MultiformatMessageString(text=finding.description),
                    help=MultiformatMessageString(text=finding.fix_suggestion or "No fix suggestion available")
                ))
        
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
                region={"startLine": finding.line_number, "snippet": {"text": finding.code_snippet}}
            )
            location = Location(physical_location=physical_location)
            
            # Create result
            result = Result(
                rule_id=finding.rule_id,
                rule_index=list(rule_ids).index(finding.rule_id),
                message=Message(text=finding.description),
                level=severity_map.get(finding.severity, "warning"),
                locations=[location]
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
            invocations=[{
                "executionSuccessful": True,
                "endTimeUtc": datetime.fromtimestamp(scan_result.timestamp).isoformat() + "Z"
            }]
        )
        
        # Create SARIF log
        sarif_log = SarifLog(
            version="2.1.0",
            runs=[run]
        )
        
        # Write to file using attrs serialization
        import attr
        with open(output_path, 'w', encoding='utf-8') as f:
            sarif_dict = attr.asdict(sarif_log, recurse=True)
            json.dump(sarif_dict, f, indent=2, ensure_ascii=False)
            
    except Exception as e:
        # Proper error handling instead of silent failure
        raise RuntimeError(f"Failed to save SARIF report to {output_path}: {str(e)}") from e
