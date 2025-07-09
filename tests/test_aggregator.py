import pytest
from pathlib import Path

from impact_scan.core import aggregator
from impact_scan.utils import schema


@pytest.fixture
def sample_findings():
    """Provides a set of sample Finding objects for testing."""
    finding1 = schema.Finding(
        file_path=Path("/app/src/main.py"), line_number=10, vuln_id="CVE-2023-0001",
        title="SQL Injection", severity=schema.Severity.HIGH, source=schema.VulnSource.STATIC_ANALYSIS,
        code_snippet="db.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        description="A SQL injection vulnerability."
    )
    finding2 = schema.Finding(
        file_path=Path("/app/package.json"), line_number=1, vuln_id="CVE-2023-0002",
        title="Outdated Dependency", severity=schema.Severity.MEDIUM, source=schema.VulnSource.DEPENDENCY,
        code_snippet="\"library\": \"1.0.0\"", description="An outdated library."
    )
    # This is a duplicate of finding1
    finding3 = schema.Finding(
        file_path=Path("/app/src/main.py"), line_number=10, vuln_id="CVE-2023-0001",
        title="SQLi", severity=schema.Severity.HIGH, source=schema.VulnSource.STATIC_ANALYSIS,
        code_snippet="db.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        description="A duplicate finding."
    )
    # This is different from finding1 only by line number
    finding4 = schema.Finding(
        file_path=Path("/app/src/main.py"), line_number=25, vuln_id="CVE-2023-0001",
        title="Another SQL Injection", severity=schema.Severity.HIGH, source=schema.VulnSource.STATIC_ANALYSIS,
        code_snippet="db.execute(f'SELECT * FROM products WHERE id = {product_id}')",
        description="A different instance of the same CVE."
    )
    return [finding1, finding2, finding3, finding4]


def test_merge_and_dedupe_with_duplicates(sample_findings):
    """
    Tests that findings with the same file, line, and ID are deduplicated.
    """
    list1 = [sample_findings[0]]  # finding1
    list2 = [sample_findings[2]]  # finding3 (duplicate of finding1)

    result = aggregator.merge_and_dedupe(list1, list2)

    assert len(result) == 1
    assert result[0] == sample_findings[0]


def test_merge_and_dedupe_with_no_duplicates(sample_findings):
    """
    Tests that unique findings are all preserved.
    """
    list1 = [sample_findings[0]]  # finding1
    list2 = [sample_findings[1]]  # finding2

    result = aggregator.merge_and_dedupe(list1, list2)

    assert len(result) == 2
    assert sample_findings[0] in result
    assert sample_findings[1] in result


def test_merge_and_dedupe_complex_case(sample_findings):
    """
    Tests a more complex scenario with multiple lists and mixed duplicates.
    """
    list1 = [sample_findings[0], sample_findings[1]]
    list2 = [sample_findings[2], sample_findings[3]]

    result = aggregator.merge_and_dedupe(list1, list2)

    # Expecting finding1, finding2, and finding4. finding3 is a duplicate of finding1.
    assert len(result) == 3
    assert sample_findings[0] in result
    assert sample_findings[1] in result
    assert sample_findings[3] in result


def test_merge_and_dedupe_with_empty_lists():
    """
    Tests that the function handles empty lists correctly.
    """
    assert not aggregator.merge_and_dedupe([], [])
    
    finding = schema.Finding(
        file_path=Path("a.py"), line_number=1, vuln_id="V001", title="T",
        severity=schema.Severity.LOW, source=schema.VulnSource.STATIC_ANALYSIS,
        code_snippet="c", description="d"
    )
    result = aggregator.merge_and_dedupe([finding], [])
    assert len(result) == 1
    assert result[0] == finding
