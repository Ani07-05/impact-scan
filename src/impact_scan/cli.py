"""
Simplified CLI interface for Impact Scan with smart defaults and profiles.
"""
import time
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from impact_scan.core import entrypoint, aggregator, fix_ai, renderer, web_search
from impact_scan.core.html_report import save_report
from impact_scan.utils import schema, logging_config, profiles, config_file
from impact_scan.agents import AgentOrchestrator, ReconAgent, VulnAgent, ExploitAgent, FixAgent, ComplianceAgent

# Set up logger
logger = logging.getLogger(__name__)

# Main Typer application instance
app = typer.Typer(
    name="impact-scan",
    help="AI-powered security scanner for codebases with interactive TUI",
    add_completion=False,
    no_args_is_help=True,
)

# Rich console for consistent output styling
console = Console()


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(
        ".",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
        help="Path to scan (default: current directory)",
    ),
    profile: str = typer.Option(
        "standard",
        "--profile", "-p",
        help="Scan profile: quick, standard, comprehensive, ci",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file (HTML report). Format detected from extension.",
    ),
    ai_provider: Optional[str] = typer.Option(
        None,
        "--ai",
        help="AI provider: openai, anthropic, gemini",
    ),
    min_severity: Optional[str] = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity: low, medium, high, critical",
    ),
    no_web_search: bool = typer.Option(
        False,
        "--no-web-search",
        help="Disable web search and Stack Overflow scraping",
    ),
    no_stackoverflow: bool = typer.Option(
        False,
        "--no-stackoverflow",
        help="Disable Stack Overflow scraper only",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable detailed logging",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config", "-c",
        help="Configuration file path (auto-detected if not specified)",
    ),
):
    """
    Scan your codebase for security vulnerabilities.
    
    Examples:
      impact-scan scan                          # Quick scan of current directory
      impact-scan scan /path/to/project -p comprehensive -o report.html
      impact-scan scan . --ai gemini           # Use Gemini AI for fixes
    """
    start_time = time.time()
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    logging_config.setup_logging(level=log_level)
    
    logger.info(f"Starting Impact Scan v0.1.0")

    try:
        # Load configuration file if available
        file_config = {}
        config_path = config
        
        if not config_path:
            # Auto-detect config file
            config_path = config_file.find_config_file(path)
        
        if config_path:
            console.print(f"Loading config from: [cyan]{config_path}[/cyan]")
            raw_config = config_file.load_config_file(config_path)
            file_config = config_file.validate_config(raw_config)
        
        # CLI arguments override file config
        cli_overrides = {}
        if profile != "standard":  # Only override if explicitly set
            cli_overrides['profile'] = profile
        if output:
            cli_overrides['output'] = output
        if ai_provider:
            cli_overrides['ai_provider'] = ai_provider
        if min_severity:
            cli_overrides['min_severity'] = min_severity
        if no_web_search:
            cli_overrides['enable_web_search'] = False
            cli_overrides['enable_stackoverflow_scraper'] = False
        if no_stackoverflow:
            cli_overrides['enable_stackoverflow_scraper'] = False
        
        # Merge configurations
        merged_config = config_file.merge_config(file_config, cli_overrides)
        
        # Get final profile (from merged config or default)
        profile_name = merged_config.get('profile', profile)
        scan_profile = profiles.get_profile(profile_name)
        console.print(f"Using scan profile: [bold cyan]{profile_name}[/bold cyan] - {scan_profile.description}")
        
        # Auto-detect API keys from environment
        api_keys = schema.APIKeys()
        
        # Override AI provider from merged config or CLI
        final_ai_provider = merged_config.get('ai_provider')
        if final_ai_provider:
            scan_profile.ai_provider = final_ai_provider
        
        # Build overrides dict for config
        config_overrides = {}

        # Apply merged config overrides
        if 'enable_web_search' in merged_config:
            config_overrides['enable_web_search'] = merged_config['enable_web_search']
        if 'enable_stackoverflow_scraper' in merged_config:
            config_overrides['enable_stackoverflow_scraper'] = merged_config['enable_stackoverflow_scraper']
        if 'min_severity' in merged_config:
            # Convert string to Severity enum
            sev_str = merged_config['min_severity'].upper()
            config_overrides['min_severity'] = schema.Severity[sev_str]

        # Create config from profile
        config = profiles.create_config_from_profile(
            root_path=path,
            profile=scan_profile,
            api_keys=api_keys,
            overrides=config_overrides
        )
        
        # Show scan configuration
        console.print(f"Scanning: [cyan]{config.root_path}[/cyan]")
        console.print(f"Min severity: [yellow]{config.min_severity.value.upper()}[/yellow]")
        
        if config.enable_ai_fixes:
            if config.ai_provider:
                console.print(f"AI fixes: [green]Enabled[/green] ({config.ai_provider.value})")
            else:
                console.print("[yellow]WARNING: AI fixes requested but no API key found in environment[/yellow]")
                config.enable_ai_fixes = False
        
        if config.enable_web_search:
            console.print(f"Web search: [green]Enabled[/green] (limit: {config.web_search_limit})")

        if config.enable_stackoverflow_scraper:
            console.print(f"Stack Overflow scraper: [green]Enabled[/green] (max: {config.stackoverflow_max_answers} answers)")
        elif no_stackoverflow:
            console.print("Stack Overflow scraper: [yellow]Disabled[/yellow] (--no-stackoverflow flag)")
        elif no_web_search:
            console.print("Stack Overflow scraper: [yellow]Disabled[/yellow] (--no-web-search flag)")

        # Core scanning
        scan_result = entrypoint.run_scan(config)

        # Enhanced features if enabled  
        if config.enable_web_search or config.enable_ai_fixes:
            try:
                console.print("\nEnriching findings with modern intelligence...")
                import asyncio
                asyncio.run(entrypoint.enrich_findings_async(scan_result.findings, config))
            except Exception as e:
                logger.warning(f"Intelligence enrichment failed: {e}")
                console.print(f"[yellow]WARNING: Intelligence enrichment failed: {e}[/yellow]")


        # Show results
        console.print("\n" + "="*80)
        console.print("[bold green]SCAN RESULTS[/bold green]")
        console.print("="*80)
        
        # Create summary table
        summary_table = Table.grid(padding=1)
        summary_table.add_column(style="cyan", min_width=25)
        summary_table.add_column(style="bold white")
        
        summary_table.add_row("Total Findings:", str(scan_result.total_findings))
        summary_table.add_row("Files Scanned:", str(scan_result.scanned_files))
        summary_table.add_row("[TIME] Duration:", f"{scan_result.scan_duration:.1f}s")
        
        # Show findings by severity
        for severity in [schema.Severity.CRITICAL, schema.Severity.HIGH, schema.Severity.MEDIUM, schema.Severity.LOW]:
            count = len([f for f in scan_result.findings if f.severity == severity])
            if count > 0:
                icon = {"critical": "[red]●[/red]", "high": "[yellow]●[/yellow]", "medium": "[orange1]●[/orange1]", "low": "[blue]●[/blue]"}[severity.value]
                summary_table.add_row(f"{icon} {severity.value.title()}:", str(count))
        
        console.print(summary_table)
        
        # Save output if requested
        if output:
            try:
                output_path = Path(output)
                if output_path.suffix.lower() == '.html':
                    console.print(f"\nSaving HTML report to [cyan]{output_path}[/cyan]...")
                    save_report(scan_result, output_path)
                elif output_path.suffix.lower() == '.sarif':
                    console.print(f"\nSaving SARIF report to [cyan]{output_path}[/cyan]...")
                    aggregator.save_to_sarif(scan_result, output_path)
                else:
                    # Default to HTML
                    console.print(f"\nSaving HTML report to [cyan]{output_path}[/cyan]...")
                    save_report(scan_result, output_path)
                console.print("[bold green]Report saved successfully![/bold green]")
            except Exception as e:
                logger.error(f"Failed to save report: {e}")
                console.print(f"[bold red]ERROR: Failed to save report: {e}[/bold red]")
                raise typer.Exit(code=1)

        # Show detailed findings only if there are any and not too many
        if scan_result.findings and len(scan_result.findings) <= 10:
            console.print(f"\nShowing {len(scan_result.findings)} findings:")
            renderer.print_findings(scan_result, config.min_severity)
        elif len(scan_result.findings) > 10:
            console.print(f"\nFound {len(scan_result.findings)} findings (use --output to save full report)")

        # Final status
        end_time = time.time()
        console.print(f"\nScan completed in [yellow]{end_time - start_time:.1f}s[/yellow]")
        
        # Exit with appropriate code
        critical_count = len([f for f in scan_result.findings if f.severity == schema.Severity.CRITICAL])
        if critical_count > 0:
            console.print(f"[bold red]WARNING: Found {critical_count} CRITICAL vulnerabilities![/bold red]")
            raise typer.Exit(code=2)  # Exit code 2 for critical findings
        
        high_count = len([f for f in scan_result.findings if f.severity == schema.Severity.HIGH])
        if high_count > 0 and profile == "ci":
            console.print(f"[bold yellow]WARNING: Found {high_count} HIGH vulnerabilities in CI mode![/bold yellow]")
            raise typer.Exit(code=1)  # Exit code 1 for high findings in CI mode

    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        console.print(f"[bold red]FATAL ERROR: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command("profiles")
def list_profiles():
    """List available scan profiles."""
    console.print("\n[bold]Available Scan Profiles:[/bold]\n")
    
    table = Table()
    table.add_column("Profile", style="cyan", width=15)
    table.add_column("Description", style="white")
    table.add_column("Min Severity", style="yellow")
    table.add_column("AI Fixes", style="green")
    table.add_column("Web Search", style="blue")
    
    for name, profile in profiles.SCAN_PROFILES.items():
        ai_fixes = "Yes" if profile.enable_ai_fixes else "No"
        web_search = "Yes" if profile.enable_web_search else "No"
        
        table.add_row(
            name,
            profile.description,
            profile.min_severity.value.upper(),
            ai_fixes,
            web_search
        )
    
    console.print(table)
    console.print("\n[dim]Use: impact-scan scan --profile <name>[/dim]")


@app.command("config")
def check_config():
    """Check configuration and API keys."""
    console.print("\n[bold]Configuration Status:[/bold]\n")
    
    # Check API keys
    api_keys = schema.APIKeys()
    
    table = Table()
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Details")
    
    providers = [
        ("OpenAI", api_keys.openai, "OPENAI_API_KEY"),
        ("Anthropic", api_keys.anthropic, "ANTHROPIC_API_KEY"), 
        ("Gemini", api_keys.gemini, "GOOGLE_API_KEY"),
        ("Stack Overflow", api_keys.stackoverflow, "STACKOVERFLOW_API_KEY"),
    ]
    
    for name, key, env_var in providers:
        if key:
            status = "[green]Configured[/green]"
            details = f"Set via {env_var}"
        else:
            status = "[red]Missing[/red]"
            details = f"Set {env_var} environment variable"
        
        table.add_row(name, status, details)
    
    console.print(table)
    
    # Show recommended provider
    auto_provider = profiles.auto_detect_ai_provider(api_keys)
    if auto_provider:
        console.print(f"\nAuto-detected AI provider: [green]{auto_provider.value}[/green]")
    else:
        console.print("\n[yellow]WARNING: No AI provider configured. AI fixes will be disabled.[/yellow]")
    
    console.print("\n[dim]Set API keys as environment variables to enable AI features.[/dim]")


@app.command("init")
def init_config(
    config_type: str = typer.Option(
        "yaml",
        "--type", "-t",
        help="Configuration file type: yaml, toml"
    )
):
    """Initialize a configuration file for your project."""
    
    if config_type.lower() == "yaml":
        config_path = Path(".impact-scan.yml")
        if config_path.exists():
            console.print(f"[yellow]WARNING: Configuration file already exists: {config_path}[/yellow]")
            if not typer.confirm("Overwrite existing file?"):
                console.print("Cancelled")
                return
        
        config_file.save_sample_config(config_path)
        console.print(f"[bold green]Created configuration file: {config_path}[/bold green]")
        console.print("\nEdit the file to customize your scan settings.")
        
    elif config_type.lower() == "toml":
        console.print("For TOML configuration, add this section to your pyproject.toml:")
        console.print(config_file.PYPROJECT_TOML_EXAMPLE)
        
    else:
        console.print(f"[bold red]Error: Invalid config type '{config_type}'. Use 'yaml' or 'toml'.[/bold red]")
        raise typer.Exit(code=1)


@app.command("agent-scan")
def agent_scan_command(
    path: Path = typer.Argument(
        ".",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
        help="Path to scan (default: current directory)",
    ),
    strategy: str = typer.Option(
        "adaptive",
        "--strategy", "-s",
        help="Orchestration strategy: sequential, parallel, pipeline, adaptive"
    ),
    agents: Optional[str] = typer.Option(
        None,
        "--agents", "-a",
        help="Comma-separated list of agents to run (e.g., recon,vuln,exploit)"
    ),
    ai_provider: str = typer.Option(
        "auto",
        "--ai", 
        help="AI provider: auto, openai, anthropic, gemini, none"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Save results to file (.html or .json)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output"
    )
):
    """Revolutionary Multi-Agent Security Scanning - The Future of Cybersecurity Testing"""
    
    import asyncio
    from impact_scan.agents.orchestrator import OrchestrationStrategy
    
    console.print("\n[bold cyan]IMPACT SCAN - MULTI-AGENT SECURITY PLATFORM[/bold cyan]")
    console.print("[dim]Revolutionary AI-powered security testing with specialized agents[/dim]\n")
    
    start_time = time.time()
    
    try:
        # Set up logging
        if verbose:
            logging_config.setup_logging(logging.DEBUG)
        else:
            logging_config.setup_logging(logging.INFO)
        
        # Create scan configuration
        api_keys = schema.APIKeys()
        config = schema.ScanConfig(
            root_path=path,
            min_severity=schema.Severity.MEDIUM,
            enable_ai_fixes=True,
            enable_web_search=True,
            ai_provider=schema.AIProvider(ai_provider) if ai_provider in ["openai", "anthropic", "gemini", "local"] else None,
            openai_api_key=api_keys.openai,
            anthropic_api_key=api_keys.anthropic,
            gemini_api_key=api_keys.gemini
        )
        
        # Create orchestrator and register agents
        orchestrator = AgentOrchestrator()
        
        console.print("[bold]Initializing Security Agents...[/bold]")
        
        # Register all available agents (lazy creation)
        agents_classes = {
            "recon": ReconAgent,
            "vuln": VulnAgent,
            "exploit": ExploitAgent, 
            "fix": FixAgent,
            "compliance": ComplianceAgent
        }
        
        # Determine which agents to run
        if agents:
            agent_names = [name.strip() for name in agents.split(",")]
            agent_names = [name for name in agent_names if name in agents_classes]
        else:
            agent_names = list(agents_classes.keys())
        
        if not agent_names:
            console.print("[bold red]ERROR: No valid agents specified[/bold red]")
            raise typer.Exit(code=1)
        
        # Create and register selected agents
        for agent_name in agent_names:
            try:
                agent_class = agents_classes[agent_name]
                agent_instance = agent_class(config)
                orchestrator.register_agent(agent_instance)
                console.print(f"  Agent {agent_name.upper()} registered")
            except Exception as e:
                console.print(f"  Failed to register {agent_name}: {e}")
                import traceback
                console.print(f"  {traceback.format_exc()}")
                raise
        
        console.print(f"\n[bold green]Target:[/bold green] {path}")
        console.print(f"[bold green]Strategy:[/bold green] {strategy}")
        console.print(f"[bold green]Agents:[/bold green] {', '.join(agent_names)}")
        console.print(f"[bold green]AI Provider:[/bold green] {ai_provider}")
        
        console.print("\n[bold cyan]LAUNCHING MULTI-AGENT SECURITY SCAN...[/bold cyan]\n")
        
        # Map strategy string to enum
        strategy_map = {
            "sequential": OrchestrationStrategy.SEQUENTIAL,
            "parallel": OrchestrationStrategy.PARALLEL, 
            "pipeline": OrchestrationStrategy.PIPELINE,
            "adaptive": OrchestrationStrategy.ADAPTIVE
        }
        
        strategy_enum = strategy_map.get(strategy, OrchestrationStrategy.ADAPTIVE)
        
        # Execute comprehensive scan
        results = asyncio.run(orchestrator.execute_comprehensive_scan(
            target=path,
            strategy=strategy_enum,
            include_agents=agent_names
        ))
        
        # Display results summary
        console.print("\n[bold cyan]MULTI-AGENT SCAN RESULTS[/bold cyan]\n")
        
        summary_table = Table()
        summary_table.add_column("Agent", style="cyan", width=12)
        summary_table.add_column("Status", style="white", width=10) 
        summary_table.add_column("Findings", style="yellow", width=8)
        summary_table.add_column("Time", style="green", width=8)
        summary_table.add_column("Details", style="dim", width=40)
        
        total_findings = 0
        successful_agents = 0
        
        for agent_name, result in results.items():
            status = "SUCCESS" if result.success else "FAILED"
            findings_count = len(result.findings)
            total_findings += findings_count
            
            if result.success:
                successful_agents += 1
            
            details = f"Found {findings_count} findings" if result.success else result.error_message[:35] + "..." if result.error_message and len(result.error_message) > 35 else result.error_message or "Unknown error"
            
            summary_table.add_row(
                agent_name.upper(),
                status,
                str(findings_count),
                f"{result.execution_time:.1f}s",
                details
            )
        
        console.print(summary_table)
        
        # Overall summary
        console.print(f"\n[bold green]SCAN COMPLETE![/bold green]")
        console.print(f"  {successful_agents}/{len(results)} agents succeeded")
        console.print(f"  {total_findings} total findings across all agents") 
        console.print(f"  Completed in {time.time() - start_time:.1f}s")
        
        # Get orchestration performance summary
        perf_summary = orchestrator.get_orchestration_summary()
        if perf_summary.get("failed_agents"):
            console.print(f"  [red]Failed agents: {', '.join(perf_summary['failed_agents'])}[/red]")
        
        # Save results if requested
        if output:
            try:
                console.print(f"\n[bold]Saving results to {output}...[/bold]")
                
                # Compile all agent results
                compiled_results = {
                    "scan_summary": {
                        "target": str(path),
                        "strategy": strategy,
                        "agents_executed": agent_names,
                        "total_findings": total_findings,
                        "execution_time": time.time() - start_time,
                        "successful_agents": successful_agents,
                        "failed_agents": len(results) - successful_agents
                    },
                    "agent_results": {
                        name: {
                            "status": result.status.value,
                            "execution_time": result.execution_time,
                            "findings": result.findings,
                            "data": result.data,
                            "error": result.error_message
                        }
                        for name, result in results.items()
                    },
                    "orchestration_summary": perf_summary
                }
                
                if output.suffix.lower() == ".html":
                    # Create HTML report from agent results
                    console.print("[dim]HTML export for multi-agent results coming soon...[/dim]")
                    
                else:
                    # Save as JSON
                    import json
                    with open(output, "w") as f:
                        json.dump(compiled_results, f, indent=2, default=str)
                
                console.print(f"[bold green]Results saved to {output}[/bold green]")
                
            except Exception as e:
                console.print(f"[bold red]ERROR: Failed to save results: {e}[/bold red]")
        
        # Success message
        console.print(f"\n[bold green]MULTI-AGENT SECURITY SCAN COMPLETED SUCCESSFULLY![/bold green]")
        
        if total_findings > 0:
            console.print(f"[bold yellow]Review {total_findings} security findings across all agents[/bold yellow]")
        
    except Exception as e:
        import traceback
        console.print(f"\n[bold red]MULTI-AGENT SCAN FAILED: {e}[/bold red]")
        console.print(f"[dim]Traceback:\n{traceback.format_exc()}[/dim]")
        logger.error(f"Agent scan failed: {e}")
        raise typer.Exit(code=1)


@app.command("tui")
def tui_command():
    """Launch the interactive Terminal User Interface with file browser."""
    try:
        from impact_scan.tui import run_tui
        console.print("[bold blue]🚀 Launching Impact Scan TUI...[/bold blue]")
        console.print("[cyan]✨ Interactive interface with file browser and real-time scanning![/cyan]")
        run_tui()
    except ImportError as e:
        console.print(f"[bold red]ERROR: TUI dependencies not installed: {e}[/bold red]")
        console.print("[yellow]Install with: pip install textual[/yellow]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]ERROR: Failed to launch TUI: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command("web")
def web_command(
    port: int = typer.Option(5000, help="Port to run web interface on"),
    no_browser: bool = typer.Option(False, help="Don't auto-open browser")
):
    """Launch the modern Web-based User Interface."""
    try:
        from impact_scan.web_ui import run_web_ui
        console.print("[bold blue]🌐 Launching Impact Scan Web Interface...[/bold blue]")
        console.print(f"[cyan]🚀 Starting server on http://localhost:{port}[/cyan]")
        console.print("[green]✨ Modern web UI with real-time updates[/green]")
        console.print(f"[yellow]Press Ctrl+C to stop the server[/yellow]")
        run_web_ui(port=port, auto_open=not no_browser)
    except ImportError as e:
        console.print(f"[bold red]ERROR: Web UI dependencies not installed: {e}[/bold red]")
        console.print("[yellow]Install with: pip install flask[/yellow]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]ERROR: Failed to launch Web UI: {e}[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()