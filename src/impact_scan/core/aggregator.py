from typing import List, Set, Tuple

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
