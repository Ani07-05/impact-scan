import json
import logging
from pathlib import Path
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from sarif_om import ReportingDescriptor, Result, Run, SarifLog, Tool, ToolComponent

from ..utils import schema

# Set up logging
logger = logging.getLogger(__name__)

# Define colors for different severity levels for terminal
SEVERITY_COLORS = {
    schema.Severity.CRITICAL: "bold red",
    schema.Severity.HIGH: "red",
    schema.Severity.MEDIUM: "yellow",
    schema.Severity.LOW: "cyan",
}

SEVERITY_LEVELS = {
    schema.Severity.LOW: 0,
    schema.Severity.MEDIUM: 1,
    schema.Severity.HIGH: 2,
    schema.Severity.CRITICAL: 3,
}


def print_findings(result: schema.ScanResult, min_severity: schema.Severity) -> None:
    """
    Renders the scan results to the terminal using rich tables and panels with enhanced formatting.
    """
    console = Console()
    console.print("\n" + "=" * 100)
    console.print(
        f"[bold green][SECURITY] Impact Scan Results for {result.config.root_path}[/bold green]"
    )
    console.print("=" * 100)

    summary_table = Table.grid(expand=True)
    summary_table.add_column(style="cyan", min_width=20)
    summary_table.add_column(justify="right", style="bold magenta")
    summary_table.add_row("[STATS] Total Findings:", str(result.total_findings))
    summary_table.add_row("[FILES] Scanned Files:", str(result.scanned_files))
    summary_table.add_row(
        "[TIME] Scan Duration:", f"{result.scan_duration:.2f} seconds"
    )
    if result.config.enable_ai_fixes:
        ai_fixes_count = sum(1 for f in result.findings if f.fix_suggestion)
        summary_table.add_row("[AI] AI Fixes Generated:", str(ai_fixes_count))
    if result.config.enable_web_search:
        web_fixes_count = sum(1 for f in result.findings if f.web_fix)
        summary_table.add_row("[WEB] Web Fixes Found:", str(web_fixes_count))
    console.print(summary_table)

    # Filter findings by min_severity
    min_level = SEVERITY_LEVELS[min_severity]
    filtered_findings = [
        f for f in result.findings if SEVERITY_LEVELS[f.severity] >= min_level
    ]

    if not filtered_findings:
        console.print(
            "\n[bold green][SUCCESS] No vulnerabilities found matching the criteria![/bold green]"
        )
        return

    sorted_findings = sorted(
        filtered_findings, key=lambda f: SEVERITY_LEVELS[f.severity], reverse=True
    )

    console.print(
        f"\n[bold blue][DETAILS] Detailed Findings ([/bold blue][bold red]{len(sorted_findings)}[/bold red][bold blue] vulnerabilities)[/bold blue]\n"
    )

    for i, finding in enumerate(sorted_findings, 1):
        color = SEVERITY_COLORS.get(finding.severity, "white")

        # Enhanced header with better formatting
        severity_icon = (
            "[red]*[/red]"
            if finding.severity.value == "CRITICAL"
            else "[yellow]*[/yellow]"
            if finding.severity.value == "HIGH"
            else "[orange1]*[/orange1]"
            if finding.severity.value == "MEDIUM"
            else "[blue]*[/blue]"
        )
        header = f"{severity_icon} [{color}]{finding.severity.value.upper()}[/{color}] | {finding.title} | [dim]{finding.vuln_id}[/dim]"

        # Create detailed info table
        info_table = Table.grid(expand=True)
        info_table.add_column(style="bold", min_width=12)
        info_table.add_column(style="white")

        # File path with proper highlighting
        file_path_text = (
            f"[cyan]{finding.file_path}[/cyan]:[yellow]{finding.line_number}[/yellow]"
        )
        info_table.add_row("[FILE] File:", file_path_text)
        info_table.add_row(
            "[SOURCE] Source:", f"[magenta]{finding.source.value}[/magenta]"
        )

        # Add web fix metadata if available
        if hasattr(finding, "metadata") and finding.metadata:
            if finding.metadata.get("gemini_powered"):
                info_table.add_row(
                    "[AI] AI Analysis:",
                    "[green][SUCCESS] Enhanced with Gemini AI[/green]",
                )
            if finding.metadata.get("cached_result"):
                info_table.add_row(
                    "[CACHE] Cache:", "[blue][SUCCESS] Cached result[/blue]"
                )

        # Use professional colors for borders (not error-like red)
        border_color = "cyan" if finding.severity in [schema.Severity.CRITICAL, schema.Severity.HIGH] else "blue dim"

        panel = Panel(
            info_table,
            title=f"[bold white]Finding #{i}[/bold white] {header}",
            border_style=border_color,
            title_align="left",
            padding=(0, 1),
        )
        console.print(panel)

        # Enhanced code display with better syntax highlighting
        console.print(
            f"\n[bold white][CODE] Vulnerable Code ([/bold white][cyan]{finding.file_path}[/cyan][bold white]:[/bold white][yellow]{finding.line_number}[/yellow][bold white]):[/bold white]"
        )

        # Determine language for syntax highlighting
        file_ext = (
            str(finding.file_path).split(".")[-1].lower()
            if "." in str(finding.file_path)
            else ""
        )
        language_map = {
            "py": "python",
            "js": "javascript",
            "java": "java",
            "php": "php",
            "cpp": "cpp",
            "c": "c",
            "html": "html",
            "css": "css",
        }
        syntax_lang = language_map.get(file_ext, "python")

        console.print(
            Syntax(
                finding.code_snippet,
                syntax_lang,
                theme="monokai",
                line_numbers=True,
                start_line=max(1, finding.line_number - 2),
                background_color="default",
            )
        )

        # Enhanced AI fix display
        if finding.fix_suggestion:
            console.print("\n[bold green][AI] AI-Powered Security Fix:[/bold green]")
            console.print(Syntax(finding.fix_suggestion, "diff", theme="monokai"))

        # Enhanced web fix display
        if finding.web_fix:
            console.print(
                "\n[bold blue][WEB] Web-Based Fix Recommendation:[/bold blue]"
            )

            # Check if we have structured web fix data
            if (
                hasattr(finding, "metadata")
                and finding.metadata
                and finding.metadata.get("web_fix_explanation")
            ):
                console.print(f"[dim]{finding.metadata['web_fix_explanation']}[/dim]\n")
                console.print("[bold]Secure Code Fix:[/bold]")
                console.print(
                    Syntax(
                        finding.metadata["web_fix_code"], syntax_lang, theme="monokai"
                    )
                )
            else:
                console.print(Syntax(finding.web_fix, syntax_lang, theme="monokai"))

            if finding.citation:
                console.print(
                    f"\n[bold][REFERENCE] Reference:[/bold] [link]{finding.citation}[/link]"
                )

        # Add vulnerability description if available
        if finding.description and len(finding.description) > len(finding.title):
            console.print("\n[bold][DESCRIPTION] Description:[/bold]")
            # Truncate very long descriptions and show first few lines
            desc_lines = finding.description.split("\n")[:3]
            for line in desc_lines:
                if line.strip():
                    console.print(f"[dim]{line.strip()}[/dim]")
            if len(finding.description.split("\n")) > 3:
                console.print("[dim]...[truncated][/dim]")

        console.print("\n" + "-" * 100 + "\n")


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
                default_configuration={"level": finding.severity.value},  # Map severity
            )
            rules.append(rule)
            rule_map[finding.vuln_id] = rule

    for finding in result.findings:
        sarif_result = Result(
            rule_id=finding.vuln_id,
            message={"text": finding.description},
            locations=[
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path.as_uri()},
                        "region": {"startLine": finding.line_number},
                    }
                }
            ],
        )
        # Add proposed fix if available
        if finding.fix_suggestion:
            sarif_result.fixes = [
                {
                    "description": {"text": "AI Suggested Fix"},
                    "artifactChanges": [
                        {
                            "artifactLocation": {"uri": finding.file_path.as_uri()},
                            "replacements": [
                                {
                                    "deletedRegions": [
                                        {"snippet": {"text": finding.code_snippet}}
                                    ],
                                    "insertedContent": {"text": finding.fix_suggestion},
                                }
                            ],
                        }
                    ],
                }
            ]
        results.append(sarif_result)

    tool.driver.rules = rules
    run = Run(tool=tool, results=results)
    sarif_log = SarifLog(version="2.1.0", runs=[run])

    try:
        with output_path.open("w", encoding="utf-8") as f:
            # Convert SarifLog to JSON properly using sarif_om's to_dict method
            if hasattr(sarif_log, "to_dict"):
                sarif_dict = sarif_log.to_dict()
            else:
                # Fallback: manually create dictionary structure
                sarif_dict = {
                    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                    "version": sarif_log.version,
                    "runs": [],
                }
                for run in sarif_log.runs:
                    run_dict = {
                        "tool": {
                            "driver": {
                                "name": run.tool.driver.name,
                                "version": run.tool.driver.semantic_version,
                                "rules": [
                                    {
                                        "id": rule.id,
                                        "name": rule.name,
                                        "shortDescription": rule.short_description,
                                        "fullDescription": rule.full_description,
                                        "defaultConfiguration": rule.default_configuration,
                                    }
                                    for rule in run.tool.driver.rules
                                ]
                                if run.tool.driver.rules
                                else [],
                            }
                        },
                        "results": [],
                    }
                    for result in run.results:
                        result_dict = {
                            "ruleId": result.rule_id,
                            "message": result.message,
                            "locations": result.locations,
                            "level": "warning",
                        }
                        if hasattr(result, "fixes") and result.fixes:
                            result_dict["fixes"] = result.fixes
                        run_dict["results"].append(result_dict)
                    sarif_dict["runs"].append(run_dict)

            json.dump(sarif_dict, f, indent=2)
    except IOError as e:
        logger.error(f"Failed to write SARIF file to {output_path}. Reason: {e}")
