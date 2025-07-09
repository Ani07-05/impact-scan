import json
from pathlib import Path
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.text import Text
from sarif_om import SarifLog, Tool, ToolComponent, ReportingDescriptor, Run, Result

from impact_scan.utils import schema

# Define colors for different severity levels for terminal
SEVERITY_COLORS = {
    schema.Severity.CRITICAL: "bold red",
    schema.Severity.HIGH: "red",
    schema.Severity.MEDIUM: "yellow",
    schema.Severity.LOW: "cyan",
}


def display_results_in_terminal(result: schema.ScanResult, console: Console) -> None:
    """
    Renders the scan results to the terminal using rich tables and panels.
    """
    console.print("\n" + "="*80)
    console.print(f"[bold green]Scan Summary for {result.config.target_path}[/bold green]")
    console.print("="*80)

    summary_table = Table.grid(expand=True)
    summary_table.add_column(style="cyan")
    summary_table.add_column(justify="right", style="bold magenta")
    summary_table.add_row("Total Findings:", str(result.total_findings))
    summary_table.add_row("Scanned Files:", str(result.scanned_files))
    summary_table.add_row("Scan Duration:", f"{result.scan_duration:.2f} seconds")
    console.print(summary_table)

    if not result.findings:
        console.print("\n[bold green]✔ No vulnerabilities found.[/bold green]")
        return

    severity_order = {s: i for i, s in enumerate(SEVERITY_COLORS.keys())}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order[f.severity])

    for finding in sorted_findings:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        header = f"[{color}]{finding.severity.value.upper()}: {finding.title} ({finding.vuln_id})[/{color}]"
        
        content_table = Table.grid(expand=True)
        content_table.add_column()
        content_table.add_column()
        content_table.add_row("[bold]File[/bold]:", f"[cyan]{finding.file_path}:{finding.line_number}[/cyan]")
        content_table.add_row("[bold]Source[/bold]:", Text(finding.source.value, style="magenta"))
        
        panel = Panel(content_table, title=header, border_style=color, title_align="left")
        console.print(panel)

        console.print("[bold]Code Snippet:[/bold]")
        console.print(Syntax(finding.code_snippet, "python", theme="monokai", line_numbers=True, start_line=finding.line_number))

        if finding.fix_suggestion:
            console.print("[bold]AI Suggested Fix (diff):[/bold]")
            console.print(Syntax(finding.fix_suggestion, "diff", theme="monokai"))

        if finding.web_fix:
            console.print("[bold]Web Fix Suggestion:[/bold]")
            console.print(f"[cyan]{finding.web_fix}[/cyan]")
            if finding.citation:
                console.print(f"[bold]Citation:[/bold] {finding.citation}")
        
        console.print("-" * 80)



def export_to_sarif(result: schema.ScanResult, output_path: Path) -> None:
    """
    Exports the scan results to a SARIF v2.1.0 file.
    """
    tool = Tool(driver=ToolComponent(name="Impact Scan", semantic_version="0.1.0"))
    rules: List[ReportingDescriptor] = []
    results: List[Result] = []
    
    rule_map = {}
    for finding in result.findings:
        if finding.vuln_id not in rule_map:
            rule = ReportingDescriptor(
                id=finding.vuln_id,
                name=finding.title,
                short_description={"text": finding.title},
                full_description={"text": finding.description},
                default_configuration={"level": finding.severity.value} # Map severity
            )
            rules.append(rule)
            rule_map[finding.vuln_id] = rule

    for finding in result.findings:
        sarif_result = Result(
            rule_id=finding.vuln_id,
            message={"text": finding.description},
            locations=[{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path.as_uri()},
                    "region": {"startLine": finding.line_number}
                }
            }]
        )
        # Add proposed fix if available
        if finding.fix_suggestion:
            sarif_result.fixes = [
                {"description": {"text": "AI Suggested Fix"},
                 "artifactChanges": [{
                    "artifactLocation": {"uri": finding.file_path.as_uri()},
                    "replacements": [{"deletedRegions": [{"snippet": {"text": finding.code_snippet}}], "insertedContent": {"text": finding.fix_suggestion}}]
                 }]}
            ]
        results.append(sarif_result)

    tool.driver.rules = rules
    run = Run(tool=tool, results=results)
    sarif_log = SarifLog(version="2.1.0", runs=[run])

    try:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(sarif_log.to_dict(), f, indent=2)
    except IOError as e:
        print(f"Error: Failed to write SARIF file to {output_path}. Reason: {e}")
