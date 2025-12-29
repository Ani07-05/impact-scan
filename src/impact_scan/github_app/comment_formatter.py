"""PR comment formatter with Mermaid diagrams and tier messaging."""

from typing import List, Dict, Any, Optional
from ..utils.schema import Finding, ScanResult, Severity


class CommentFormatter:
    """Formats PR comments with progressive disclosure."""

    def __init__(self, tier: str = "free"):
        """Initialize formatter.

        Args:
            tier: Installation tier ("free" or "pro")
        """
        self.tier = tier

    def format_initial_comment(
        self,
        file_count: int,
        scan_duration_ms: int,
        mermaid_diagram: str,
    ) -> str:
        """Format initial comment (Phase 1 - posted immediately).

        Args:
            file_count: Number of files scanned
            scan_duration_ms: Scan duration in milliseconds
            mermaid_diagram: Mermaid diagram code

        Returns:
            Markdown comment body
        """
        scan_duration_s = scan_duration_ms / 1000

        return f"""## Impact Scan

Scanned **{file_count} files** in **{scan_duration_s:.1f}s**. Analyzing findings and generating fixes...

```mermaid
{mermaid_diagram}
```
"""

    def format_final_comment(
        self,
        file_count: int,
        scan_duration_ms: int,
        findings: List[Finding],
        validation_stats: Dict[str, int],
        mermaid_diagram: str,
        truncated: bool = False,
    ) -> str:
        """Format final comment with all results.

        Args:
            file_count: Number of files scanned
            scan_duration_ms: Scan duration in milliseconds
            findings: List of validated findings
            validation_stats: Dict with 'total_found' and 'validated'
            mermaid_diagram: Mermaid diagram with issue badges
            truncated: Whether file list was truncated

        Returns:
            Markdown comment body
        """
        scan_duration_s = scan_duration_ms / 1000

        if not findings:
            return self._format_clean_pr_comment(
                file_count=file_count,
                scan_duration_s=scan_duration_s,
                validation_stats=validation_stats,
                mermaid_diagram=mermaid_diagram,
            )

        return self._format_issues_found_comment(
            file_count=file_count,
            scan_duration_s=scan_duration_s,
            findings=findings,
            validation_stats=validation_stats,
            mermaid_diagram=mermaid_diagram,
            truncated=truncated,
        )

    def _format_clean_pr_comment(
        self,
        file_count: int,
        scan_duration_s: float,
        validation_stats: Dict[str, int],
        mermaid_diagram: str,
    ) -> str:
        """Format comment for PR with no issues."""
        total_found = validation_stats.get("total_found", 0)
        validated = validation_stats.get("validated", 0)
        filtered = total_found - validated

        validation_text = (
            f"Found {total_found} potential issues, validated {validated} as actionable ({filtered} false positives filtered)"
            if total_found > 0
            else "No potential issues found"
        )

        return f"""## Impact Scan - Code Looks Good!

Scanned **{file_count} files** in **{scan_duration_s:.1f}s**

**Validation:** {validation_text}

✓ No bugs or security vulnerabilities detected

```mermaid
{mermaid_diagram}
```

---
*Impact Scan beta - [Give feedback](https://github.com/impact-scan/impact-scan/issues) | [Join Pro waitlist →](https://impact-scan.dev/waitlist)*
"""

    def _format_issues_found_comment(
        self,
        file_count: int,
        scan_duration_s: float,
        findings: List[Finding],
        validation_stats: Dict[str, int],
        mermaid_diagram: str,
        truncated: bool,
    ) -> str:
        """Format comment for PR with issues."""
        total_found = validation_stats.get("total_found", 0)
        validated = validation_stats.get("validated", 0)
        filtered = total_found - validated

        # Separate bugs/security from polish (pro only)
        bugs_security = [
            f
            for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]

        # Count by severity
        critical_count = sum(1 for f in bugs_security if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in bugs_security if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in bugs_security if f.severity == Severity.MEDIUM)

        # Build title
        issue_count = len(bugs_security)
        title_suffix = "" if self.tier == "free" else " + Polish Suggestions (Pro)"

        # Build comment
        comment_parts = []

        # Header
        if self.tier == "pro":
            comment_parts.append(f"## Impact Scan Pro - Found {issue_count} Issues{title_suffix}")
        else:
            comment_parts.append(f"## Impact Scan - Found {issue_count} Issues")

        comment_parts.append(f"\nScanned **{file_count} files** in **{scan_duration_s:.1f}s**")

        if truncated:
            comment_parts.append(f"\n⚠️ Large PR detected - scanned first {file_count} files only")

        comment_parts.append(
            f"\n**Validation:** Found {total_found} potential issues, validated {validated} as actionable ({filtered} false positives filtered)"
        )

        # File impact map
        comment_parts.append("\n### File Impact Map")
        comment_parts.append(f"```mermaid\n{mermaid_diagram}\n```")

        if self.tier == "free":
            comment_parts.append("🔴 Critical/High Issue | 🟠 Medium Issue | Green: Clean")
        else:
            comment_parts.append("🔴 Critical/High | 🟠 Medium | ⚡ Polish suggestions | Green: Clean")

        comment_parts.append("\n---")

        # Bugs & Security section
        comment_parts.append("\n### Bugs & Security")
        comment_parts.append(f"({critical_count} critical, {high_count} high, {medium_count} medium)")
        comment_parts.append("")

        # Show first 10 findings in detail
        for idx, finding in enumerate(bugs_security[:10]):
            comment_parts.append(self._format_finding(finding, idx + 1))

        # Remaining findings
        remaining = len(bugs_security) - 10
        if remaining > 0:
            comment_parts.append(f"\n*{remaining} more issues - see inline comments below*\n")

        # Pro tier upsell for free users
        if self.tier == "free":
            comment_parts.append("\n---\n")
            comment_parts.append("### Want More?\n")
            comment_parts.append("**Pro tier includes:**")
            comment_parts.append("- Polish suggestions (style, performance improvements)")
            comment_parts.append("- Stack Overflow citations for fixes")
            comment_parts.append("- Deeper context analysis")
            comment_parts.append("- Custom rules support")
            comment_parts.append("")
            comment_parts.append("**Early Bird Pricing: $29/month** (Coming Soon)")
            comment_parts.append("")
            comment_parts.append("[Join the waitlist →](https://impact-scan.dev/waitlist)")

        # Footer
        comment_parts.append("\n---")
        comment_parts.append("*Found this helpful? [Give feedback](https://github.com/impact-scan/impact-scan/issues) or ⭐ star the repo*")

        return "\n".join(comment_parts)

    def _format_finding(self, finding: Finding, number: int) -> str:
        """Format a single finding.

        Args:
            finding: Finding object
            number: Finding number

        Returns:
            Markdown formatted finding
        """
        # Severity emoji
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🔴",
            Severity.MEDIUM: "🟠",
            Severity.LOW: "🟡",
        }.get(finding.severity, "⚪")

        parts = []
        parts.append(f"#### {severity_emoji} {finding.severity.value.upper()}: {finding.title}")
        parts.append(f"**File:** [{finding.file_path}:{finding.line_number}]({finding.file_path}#L{finding.line_number})")
        parts.append("")

        # Vulnerable code
        if finding.code_snippet:
            # Detect language from file extension
            lang = self._detect_language(finding.file_path)
            parts.append("**Vulnerable code:**")
            parts.append(f"```{lang}")
            parts.append(finding.code_snippet)
            parts.append("```")
            parts.append("")

        # Fix suggestion
        if finding.fix_suggestion or finding.ai_fix:
            fix_code = finding.ai_fix or finding.fix_suggestion
            lang = self._detect_language(finding.file_path)
            parts.append("**Fix:**")
            parts.append(f"```{lang}")
            parts.append(fix_code)
            parts.append("```")
            parts.append("")

        # Description/explanation
        if finding.description:
            parts.append(f"**Why this matters:** {finding.description}")
            parts.append("")

        # Stack Overflow citations (Pro only - placeholder for now)
        if self.tier == "pro" and finding.stackoverflow_fixes:
            parts.append("**Community Solutions:**")
            for so_fix in finding.stackoverflow_fixes[:2]:  # Show top 2
                parts.append(f"- [{so_fix.title}]({so_fix.url}) - {so_fix.score} upvotes")
            parts.append("")

        parts.append("---")
        parts.append("")

        return "\n".join(parts)

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension.

        Args:
            file_path: File path

        Returns:
            Language name for syntax highlighting
        """
        ext_to_lang = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "jsx",
            ".tsx": "tsx",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
            ".sql": "sql",
            ".sh": "bash",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".html": "html",
            ".css": "css",
        }

        # Convert Path object to string if needed
        file_path_str = str(file_path)
        ext = "." + file_path_str.rsplit(".", 1)[-1] if "." in file_path_str else ""
        return ext_to_lang.get(ext.lower(), "")


def generate_mermaid_diagram(
    changed_files: List[str],
    findings_by_file: Optional[Dict[str, List[Finding]]] = None,
    tier: str = "free",
) -> str:
    """Generate Mermaid diagram showing file relationships.

    Args:
        changed_files: List of changed file paths
        findings_by_file: Optional dict of findings grouped by file
        tier: Installation tier ("free" or "pro")

    Returns:
        Mermaid diagram code
    """
    # For MVP, create a simple graph
    # In full implementation, this would analyze imports/dependencies

    # Simplified version: just list files
    lines = ["graph LR"]

    file_nodes = {}
    for idx, file_path in enumerate(changed_files[:10]):  # Limit to 10 files
        # Simplify file name for display
        file_name = file_path.split("/")[-1]
        node_id = f"F{idx}"
        file_nodes[file_path] = node_id

        # Determine styling based on findings
        style = ""
        if findings_by_file and file_path in findings_by_file:
            findings = findings_by_file[file_path]
            has_critical_high = any(
                f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
            )
            has_medium = any(f.severity == Severity.MEDIUM for f in findings)

            if has_critical_high:
                # Red for critical/high
                style = "fill:#FFB6C6"
                file_name += "🔴"
            elif has_medium:
                # Orange for medium
                style = "fill:#FFE5B4"
                file_name += "🟠"
        else:
            # Green for clean
            style = "fill:#90EE90"

        lines.append(f"    {node_id}[{file_name}]")
        if style:
            lines.append(f"    style {node_id} {style}")

    return "\n".join(lines)
