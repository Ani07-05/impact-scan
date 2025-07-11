import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from impact_scan.core import (
    entrypoint, aggregator, fix_ai, renderer, web_search
)
from impact_scan.core.html_report import save_report
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


@app.command("scan")
def scan_command(
    root_path: Path = typer.Argument(
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
    web_search_limit: int = typer.Option(
        100,
        "--web-limit",
        help="Maximum number of web searches to perform (default: 100).",
    ),
    web_search_batch_size: int = typer.Option(
        10,
        "--web-batch-size",
        help="Batch size for web searches (default: 10).",
    ),
    web_search_delay: float = typer.Option(
        2.0,
        "--web-delay",
        help="Delay in seconds between web search requests (default: 2.0).",
    ),
    prioritize_high_severity: bool = typer.Option(
        True,
        "--prioritize-high",
        help="Prioritize high/critical severity findings for web search (default: True).",
    ),
    ai_provider: Optional[schema.AIProvider] = typer.Option(
        None,
        "--ai-provider",
        case_sensitive=False,
        help="The AI provider to use for generating fixes.",
    ),
    openai_key: Optional[str] = typer.Option(None, envvar="OPENAI_API_KEY"),
    anthropic_key: Optional[str] = typer.Option(None, envvar="ANTHROPIC_API_KEY"),
    gemini_key: Optional[str] = typer.Option(
        None,
        "--gemini-key",
        help="Google Gemini API key.",
        envvar="GOOGLE_API_KEY"
    ),
    stackoverflow_key: Optional[str] = typer.Option(
        None,
        "--stackoverflow-key",
        help="Stack Overflow API key.",
        envvar="STACKOVERFLOW_API_KEY"
    ),
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
    Scans a codebase for vulnerabilities and provides AI-powered analysis and fixes.
    """
    start_time = time.time()

    # Configuration setup
    config = schema.ScanConfig(
        root_path=root_path,
        min_severity=min_severity,
        ai_provider=ai_provider,
        enable_ai_fixes=enable_ai_fixes,
        enable_web_search=enable_web_search,
        web_search_limit=web_search_limit,
        web_search_batch_size=web_search_batch_size,
        web_search_delay=web_search_delay,
        prioritize_high_severity=prioritize_high_severity,
        api_keys=schema.APIKeys(
            openai=openai_key,
            anthropic=anthropic_key,
            gemini=gemini_key,
            stackoverflow=stackoverflow_key,
        ),
    )

    console.print(f"Initiating scan on [cyan]{config.root_path}[/cyan]...")

    # Core scanning logic
    scan_result = entrypoint.run_scan(config)

    # Web search for additional context
    if config.enable_web_search:
        console.print("Starting web search for vulnerability context...")
        web_search.process_findings_for_web_fixes(scan_result.findings, config)

    # AI-powered fix generation
    if config.enable_ai_fixes:
        if not config.ai_provider:
            console.print("[bold red]Error: AI provider must be specified for AI fixes.[/bold red]")
            raise typer.Exit(code=1)
        
        console.print(f"Generating AI fixes using [bold green]{config.ai_provider.value}[/bold green]...")
        fix_ai.generate_fixes(scan_result.findings, config)

    # Render results
    console.print("\n[bold]Scan Results:[/bold]")
    renderer.print_findings(scan_result, min_severity)

    # Save to SARIF if requested
    if sarif_output:
        console.print(f"\nSaving SARIF report to [cyan]{sarif_output}[/cyan]...")
        aggregator.save_to_sarif(scan_result, sarif_output)

    # Save to HTML if requested
    if html_output:
        console.print(f"\nGenerating HTML report at [cyan]{html_output}[/cyan]...")
        save_report(scan_result, html_output)

    end_time = time.time()
    console.print(f"\nScan completed in [yellow]{end_time - start_time:.2f}s[/yellow].")


@app.command()
def setup_local_llm():
    """
    Downloads and configures a local LLM for offline fix generation.
    (This is a placeholder for the actual implementation).
    """
    console.print("This feature is under construction.")
    console.print("To use local AI fixes, manually download a GGUF model and place it at:")
    console.print("~/.impact-scan/models/codellama-7b.Q4_K_M.gguf")
    raise typer.Exit()


@app.callback()
def main_callback():
    """
    Impact Scan CLI.
    """
    pass

if __name__ == "__main__":
    app()
