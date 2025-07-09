import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from impact_scan.core import (
    entrypoint, dep_audit, static_scan, aggregator, fix_ai, renderer, web_search
)
from impact_scan.core.html_report import export_to_html
from impact_scan.utils import schema

# Main Typer application instance
app = typer.Typer(
    name="impact-scan",
    help="A unified, AI-powered security scanner for codebases.",
    add_completion=False,
    no_args_is_help=True,
)

# Rich console for consistent output styling
console = Console()


@app.command()
def scan(
    target_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
        help="The path to the codebase directory to scan.",
    ),
    min_severity: schema.Severity = typer.Option(
        schema.Severity.MEDIUM,
        "--min-severity",
        "-s",
        case_sensitive=False,
        help="Minimum severity level to report.",
    ),
    enable_ai_fixes: bool = typer.Option(
        False,
        "--ai-fixes",
        help="Enable generation of fix suggestions using an AI provider.",
    ),
    enable_web_search: bool = typer.Option(
        False,
        "--web-search",
        help="Enable searching for fixes on the web.",
    ),
    ai_provider: Optional[schema.AIProvider] = typer.Option(
        None,
        "--ai-provider",
        case_sensitive=False,
        help="The AI provider to use for generating fixes.",
    ),
    openai_key: Optional[str] = typer.Option(None, envvar="OPENAI_API_KEY"),
    anthropic_key: Optional[str] = typer.Option(None, envvar="ANTHROPIC_API_KEY"),
    gemini_key: Optional[str] = typer.Option(None, envvar="GOOGLE_API_KEY"),
    sarif_output: Optional[Path] = typer.Option(
        None,
        "--sarif",
        help="Path to save the scan results as a SARIF file.",
        dir_okay=False,
        writable=True,
    ),
    html_output: Optional[Path] = typer.Option(
        None,
        "--html",
        help="Path to save the scan results as an HTML file.",
        dir_okay=False,
        writable=True,
    ),
):
    """
    Scans a codebase for vulnerabilities, aggregates results, and suggests fixes.
    """
    start_time = time.time()

    # 1. Build configuration from CLI arguments
    api_keys = {
        "openai": openai_key,
        "anthropic": anthropic_key,
        "google": gemini_key,
    }
    try:
        config = schema.ScanConfig(
            target_path=target_path,
            min_severity=min_severity,
            enable_ai_fixes=enable_ai_fixes,
            enable_web_search=enable_web_search,
            ai_provider=ai_provider,
            api_keys={k: v for k, v in api_keys.items() if v is not None},
        )
    except ValueError as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    console.print(f"🚀 Starting scan on [cyan]{config.target_path}[/cyan]...")

    # 2. Run all scanning stages
    entry_points = entrypoint.find_entry_points(config.target_path)
    dep_findings = dep_audit.audit_dependencies(config.target_path)
    static_findings = static_scan.scan_for_static_issues(config.target_path)

    # 3. Aggregate and filter results
    all_findings = aggregator.merge_and_dedupe(dep_findings, static_findings)
    
    severity_order = {s.value: i for i, s in enumerate(schema.Severity)}
    filtered_findings = [
        f for f in all_findings 
        if severity_order[f.severity.value] >= severity_order[config.min_severity.value]
    ]

    # 4. Generate AI fixes if requested
    if config.enable_ai_fixes:
        console.print("🤖 Generating AI fix suggestions...")
        fix_ai.process_findings_for_fixes(filtered_findings, config)

    # 5. Search for web fixes if requested
    if config.enable_web_search:
        console.print("🌐 Searching for web fixes...")
        web_search.process_findings_for_web_fixes(filtered_findings, config)

    scan_duration = time.time() - start_time

    # 6. Prepare the final result object
    result = schema.ScanResult(
        config=config,
        findings=filtered_findings,
        entry_points=[ep.path for ep in entry_points],
        scanned_files=len(list(config.target_path.rglob("*.*"))), # A simple file count
        scan_duration=scan_duration,
    )

    # 7. Render the output
    renderer.display_results_in_terminal(result, console)

    if sarif_output:
        console.print(f"📄 Exporting results to SARIF file: [cyan]{sarif_output}[/cyan]")
        renderer.export_to_sarif(result, sarif_output)

    if html_output:
        console.print(f"📝 Generating beautiful HTML report: [cyan]{html_output}[/cyan]")
        export_to_html(result, html_output)

    console.print("\n[bold green]✅ Scan complete.[/bold green]")


@app.command()
def setup_local_llm():
    """
    Downloads and configures a local LLM for offline fix generation.
    (This is a placeholder for the actual implementation).
    """
    console.print("🚧 This feature is under construction.")
    console.print("To use local AI fixes, manually download a GGUF model and place it at:")
    console.print("~/.impact-scan/models/codellama-7b.Q4_K_M.gguf")
    raise typer.Exit()


if __name__ == "__main__":
    app()
