"""
Simplified CLI interface for Impact Scan with smart defaults and profiles.
"""

import asyncio
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import typer
from rich.console import Console
from rich.table import Table

from impact_scan.agents import (
    AgentOrchestrator,
    ComplianceAgent,
    ExploitAgent,
    FixAgent,
    ReconAgent,
    VulnAgent,
)
from impact_scan.core import aggregator, entrypoint, renderer
from impact_scan.core.html_report import save_report

# Conditional imports for optional report formats
try:
    from impact_scan.core.markdown_report import save_markdown_report
except ImportError:
    save_markdown_report = None

try:
    from impact_scan.core.sarif_report import save_sarif_report
except ImportError:
    save_sarif_report = None
from impact_scan.utils import config_file, logging_config, profiles, schema
from impact_scan.utils.auto_installer import ensure_scanning_tools, get_installer

# Import new UI components
try:
    from impact_scan.ui import print_logo, LiveKnowledgeGraphTree, ScanProgressTracker
    UI_AVAILABLE = True
except ImportError:
    UI_AVAILABLE = False

# Set up logger
logger = logging.getLogger(__name__)

# Rich console for consistent output styling
console = Console()

# Version
__version__ = "0.3.0"

# Main Typer application instance
app = typer.Typer(
    name="impact-scan",
    help="AI-powered security scanner for codebases with interactive TUI",
    add_completion=False,
    no_args_is_help=True,
)


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        console.print(f"Impact-Scan version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
):
    """Impact-Scan: AI-powered security vulnerability scanner"""
    pass


def _generate_ignore_rules_yaml(findings: list, limit: int = 50) -> str:
    """Generate deduplicated YAML ignore rules from findings."""
    from typing import Dict, Set

    seen_rules: Set[str] = set()
    rules: list[Dict[str, str]] = []

    for finding in findings[:limit]:
        # Normalize path for cross-platform compatibility
        norm_path = str(finding.file_path).replace("\\", "/")

        # Extract CWE ID if present
        cwe_match = re.search(r"CWE-\d+", finding.vuln_id or "")

        # Create unique key for deduplication
        if cwe_match:
            rule_key = f"cwe:{cwe_match.group()}"
            rule_type = "cwe"
            rule_value = cwe_match.group()
        else:
            rule_key = f"rule:{finding.rule_id}"
            rule_type = "rule_id"
            rule_value = finding.rule_id

        # Only add if not seen before
        if rule_key not in seen_rules:
            seen_rules.add(rule_key)
            rules.append(
                {
                    "type": rule_type,
                    "value": rule_value,
                    "severity": finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity),
                    "title": finding.title,
                    "example_path": norm_path,
                    "line": finding.line_number
                    if hasattr(finding, "line_number")
                    else 0,
                }
            )

    # Generate YAML output
    yaml_output = "# Impact-Scan Ignore Rules\n"
    yaml_output += "# Generated automatically - please review and add reasons\n\n"
    yaml_output += "ignore_rules:\n"

    for rule in rules:
        yaml_output += f"  # {rule['title']}\n"
        yaml_output += f"  # Severity: {rule['severity']} | Example: {rule['example_path']}:{rule['line']}\n"
        yaml_output += f'  - {rule["type"]}: "{rule["value"]}"\n'
        yaml_output += f'    reason: "TODO: Add reason for ignoring {rule["title"]}"\n'
        yaml_output += '    # expires: "2025-12-31"  # Optional: set expiration date\n'
        yaml_output += "\n"

    return yaml_output


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(
        ".",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
        help="Path to scan (default: current directory)",
    ),
    profile: str = typer.Option(
        "standard",
        "--profile",
        "-p",
        help="Scan profile: quick, standard, comprehensive, ci",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path. Format auto-detected from extension (.html/.json/.md/.sarif)",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output-format",
        "-f",
        help="Output format(s): json, html, markdown, sarif, all (comma-separated for multiple)",
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
    ai_validation: bool = typer.Option(
        False,
        "--ai-validation",
        help="Enable AI-powered false positive reduction (requires AI provider)",
    ),
    ai_validation_provider: Optional[str] = typer.Option(
        None,
        "--ai-validation-provider",
        help="AI provider for validation: openai, anthropic, gemini, groq (auto-detect if not specified)",
    ),
    ai_validation_limit: Optional[int] = typer.Option(
        None,
        "--ai-validation-limit",
        help="Max findings to validate (cost control)",
    ),
    save_false_positives: bool = typer.Option(
        False,
        "--save-false-positives",
        help="Save false positives to file for review",
    ),
    ai_deep_scan: bool = typer.Option(
        False,
        "--ai-deep-scan",
        help="Enable AI-powered deep security audit to find logic/config vulnerabilities (requires AI provider)",
    ),
    ai_audit_max_files: Optional[int] = typer.Option(
        20,
        "--ai-audit-max-files",
        help="Maximum files to audit with AI deep scan (cost control)",
    ),
    no_semgrep: bool = typer.Option(
        False,
        "--no-semgrep",
        help="Skip Semgrep and use only AST-based scanning (faster, self-contained)",
    ),
    ai_flow: bool = typer.Option(
        False,
        "--ai-flow",
        help="Enable AI-powered code flow analysis (finds logic bugs & auth issues)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable detailed logging",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path (auto-detected if not specified)",
    ),
    generate_ignore: bool = typer.Option(
        False,
        "--generate-ignore",
        help="Generate ignore rules YAML from findings",
    ),
    ignore_output: Optional[Path] = typer.Option(
        None,
        "--ignore-output",
        help="Write ignore rules to file (default: stdout)",
    ),
    ignore_limit: int = typer.Option(
        50,
        "--ignore-limit",
        help="Maximum findings to generate rules for",
    ),
    show_ignored: bool = typer.Option(
        False,
        "--show-ignored",
        help="Include ignored findings in output reports",
    ),
    enable_ai_fixes: bool = typer.Option(
        False,
        "--enable-ai-fixes",
        help="Enable AI-powered fix generation",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Automatically apply AI-generated fixes (interactive, requires confirmation)",
    ),
    fix_auto: bool = typer.Option(
        False,
        "--fix-auto",
        help="Apply fixes automatically without confirmation (for CI/CD)",
    ),
    fix_strategy: str = typer.Option(
        "conservative",
        "--fix-strategy",
        help="Fix strategy: conservative (high confidence only) or aggressive (medium+)",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Auto-confirm prompts (use with --fix-auto)",
    ),
):
    """
    Scan your codebase for security vulnerabilities.

    Examples:
      impact-scan scan                          # Quick scan of current directory
      impact-scan scan /path/to/project -p comprehensive -o report.html
      impact-scan scan . --ai gemini           # Use Gemini AI for fixes
      impact-scan scan . --fix                 # Interactive fix application
      impact-scan scan . --fix-auto --yes      # Automated fixing for CI/CD
    """
    start_time = time.time()

    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    logging_config.setup_logging(level=log_level)


    # Detect JSON output mode (VS Code extension)
    json_stdout = False
    if output_format and "json" in output_format.lower().split(","):
        json_stdout = True
        # Redirect all decorative output to stderr to keep stdout clean for JSON
        import sys
        # Save original stdout for the actual JSON output
        original_stdout = sys.stdout
        # Redirect standard stdout to stderr so all stray prints (including rich) go there
        sys.stdout = sys.stderr
        console.file = sys.stderr

    logger.info("Starting Impact Scan v0.3.0")

    # Display minimal ASCII logo
    if UI_AVAILABLE and not json_stdout:
        console.print()  # Blank line
        print_logo(style="minimal")
        console.print()  # Blank line

    # Auto-install missing tools (seamless experience like Claude Code)
    auto_install = not yes  # If --yes flag, skip prompts and auto-install
    tools_ok = ensure_scanning_tools(auto_install=auto_install, silent=False)

    if not tools_ok:
        console.print(
            "\n[bold red]ERROR: Required security scanning tools are missing[/bold red]"
        )
        console.print("\n[yellow]Fix:[/yellow]")
        console.print("  1. Run: [cyan]impact-scan doctor[/cyan] to check installation")
        console.print("  2. Install manually: [cyan]pip install semgrep[/cyan]")
        console.print(
            "  3. Or use Docker: [cyan]docker run -v $(pwd):/workspace impact-scan scan /workspace[/cyan]"
        )
        raise typer.Exit(code=1)

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
            cli_overrides["profile"] = profile
        if output:
            cli_overrides["output"] = output
        if ai_provider:
            cli_overrides["ai_provider"] = ai_provider
        if min_severity:
            cli_overrides["min_severity"] = min_severity
        if no_web_search:
            cli_overrides["enable_web_search"] = False
            cli_overrides["enable_stackoverflow_scraper"] = False
        if no_stackoverflow:
            cli_overrides["enable_stackoverflow_scraper"] = False

        # Merge configurations
        merged_config = config_file.merge_config(file_config, cli_overrides)

        # Get final profile (from merged config or default)
        profile_name = merged_config.get("profile", profile)
        scan_profile = profiles.get_profile(profile_name)
        console.print(
            f"Using scan profile: [bold cyan]{profile_name}[/bold cyan] - {scan_profile.description}"
        )

        # Auto-detect API keys from environment
        api_keys = schema.APIKeys()

        # Override AI provider from merged config or CLI
        final_ai_provider = merged_config.get("ai_provider")
        if final_ai_provider:
            scan_profile.ai_provider = final_ai_provider

        # Build overrides dict for config
        config_overrides = {}

        # Apply merged config overrides
        if "enable_web_search" in merged_config:
            config_overrides["enable_web_search"] = merged_config["enable_web_search"]
        if "enable_stackoverflow_scraper" in merged_config:
            config_overrides["enable_stackoverflow_scraper"] = merged_config[
                "enable_stackoverflow_scraper"
            ]
        if "min_severity" in merged_config:
            # Convert string to Severity enum
            sev_str = merged_config["min_severity"].upper()
            config_overrides["min_severity"] = schema.Severity[sev_str]

        # NEW: AI validation overrides
        if ai_validation:
            config_overrides["enable_ai_validation"] = True
            if ai_validation_provider:
                config_overrides["ai_validation_provider"] = ai_validation_provider
            if ai_validation_limit:
                config_overrides["ai_validation_max_findings"] = ai_validation_limit
            if save_false_positives:
                config_overrides["save_false_positives"] = True

        # NEW: AI deep scan overrides
        if ai_deep_scan:
            config_overrides["enable_ai_deep_scan"] = True
            if ai_audit_max_files:
                config_overrides["ai_audit_max_files"] = ai_audit_max_files

        # NEW: Pass ignore rules from merged config
        if "ignore_rules" in merged_config:
            config_overrides["ignore_rules"] = merged_config["ignore_rules"]

        # Create config from profile
        config = profiles.create_config_from_profile(
            root_path=path,
            profile=scan_profile,
            api_keys=api_keys,
            overrides=config_overrides,
        )

        # Show scan configuration
        console.print(f"Scanning: [cyan]{config.root_path}[/cyan]")
        console.print(
            f"Min severity: [yellow]{config.min_severity.value.upper()}[/yellow]"
        )

        if config.enable_ai_fixes:
            if config.ai_provider:
                console.print(
                    f"AI fixes: [green]Enabled[/green] ({config.ai_provider.value})"
                )
            else:
                console.print(
                    "[yellow]WARNING: AI fixes requested but no API key found in environment[/yellow]"
                )
                config.enable_ai_fixes = False

        if config.enable_web_search:
            console.print(
                f"Web search: [green]Enabled[/green] (limit: {config.web_search_limit})"
            )

        if config.enable_stackoverflow_scraper:
            console.print(
                f"Stack Overflow scraper: [green]Enabled[/green] (max: {config.stackoverflow_max_answers} answers)"
            )

        if config.enable_ai_validation:
            validation_provider = config.ai_validation_provider or (
                config.ai_provider.value if config.ai_provider else "auto-detect"
            )
            console.print(
                f"AI validation: [green]Enabled[/green] (provider: {validation_provider})"
            )
            if config.ai_validation_max_findings:
                console.print(
                    f"  Validation limit: {config.ai_validation_max_findings} findings"
                )
            if config.save_false_positives:
                console.print("  False positives will be saved to file")

        if config.enable_ai_deep_scan:
            deep_scan_provider = (
                config.ai_provider.value if config.ai_provider else "auto-detect"
            )
            console.print(
                f"AI deep scan: [green]Enabled[/green] (provider: {deep_scan_provider}, max: {config.ai_audit_max_files} files)"
            )
            console.print(
                "  [cyan]Discovering logic/config vulnerabilities that Semgrep misses...[/cyan]"
            )
        elif no_stackoverflow:
            console.print(
                "Stack Overflow scraper: [yellow]Disabled[/yellow] (--no-stackoverflow flag)"
            )
        elif no_web_search:
            console.print(
                "Stack Overflow scraper: [yellow]Disabled[/yellow] (--no-web-search flag)"
            )

        # Core scanning
        if no_semgrep or ai_flow:
            all_findings = []

            if no_semgrep:
                # AST-only scanning mode
                console.print("[cyan]Running AST-based scan (Semgrep bypassed)...[/cyan]")
                from impact_scan.core.ast_scanner import scan_directory_with_ast

                ast_findings = scan_directory_with_ast(config.root_path)
                all_findings.extend(ast_findings)
                console.print(f"[green]AST scan:[/green] {len(ast_findings)} findings")

            if ai_flow:
                # AI flow analysis mode
                console.print("[bold cyan]Running AI-powered flow analysis...[/bold cyan]")
                console.print("[dim]Using Groq to find logic bugs & auth vulnerabilities[/dim]")
                from impact_scan.core.ai_flow_analyzer import AIFlowAnalyzer

                analyzer = AIFlowAnalyzer(api_key=config.api_keys.groq)
                ai_findings = analyzer.analyze_auth_flow(config.root_path)
                all_findings.extend(ai_findings)
                console.print(f"[green]AI flow analysis:[/green] {len(ai_findings)} vulnerabilities found")

            # Create scan result
            scan_result = schema.ScanResult(
                config=config,
                findings=all_findings,
                entry_points=[],  # AST/AI scan doesn't analyze entry points
                timestamp=time.time(),
                scan_duration=time.time() - start_time,
                scanned_files=len(set(f.file_path for f in all_findings)) if all_findings else 0,
            )
        else:
            # Normal Semgrep-based scanning
            scan_result = entrypoint.run_scan(config)


        # Display knowledge graph tree visualization (post-scan summary)
        if UI_AVAILABLE and scan_result.findings:
            try:
                from impact_scan.ui import KnowledgeGraphTree

                # Get all scanned files
                scanned_files = list(set(f.file_path for f in scan_result.findings))

                # Build tree visualization
                kg_tree = KnowledgeGraphTree(root_path=Path(config.root_path), total_files=len(scanned_files))

                # Mark all files as analyzed with finding counts
                file_finding_counts = {}
                for finding in scan_result.findings:
                    file_finding_counts[finding.file_path] = file_finding_counts.get(finding.file_path, 0) + 1

                for file_path in scanned_files:
                    finding_count = file_finding_counts.get(file_path, 0)
                    # Convert to Path object if it's a string
                    path_obj = Path(file_path) if isinstance(file_path, str) else file_path
                    kg_tree.mark_analyzed(path_obj, finding_count=finding_count)

                # Display the tree
                console.print("\n[bold cyan]Knowledge Graph - Scanned Files:[/bold cyan]")
                tree_display = kg_tree.build_tree()
                console.print(tree_display)
                console.print()

            except Exception as e:
                logger.warning(f"Knowledge graph tree visualization failed: {e}", exc_info=True)

        # Enhanced features if enabled
        if config.enable_web_search or config.enable_ai_fixes:
            try:
                console.print("\nEnriching findings with modern intelligence...")
                import asyncio

                asyncio.run(
                    entrypoint.enrich_findings_async(scan_result.findings, config)
                )
            except Exception as e:
                logger.warning(f"Intelligence enrichment failed: {e}")
                console.print(
                    f"[yellow]WARNING: Intelligence enrichment failed: {e}[/yellow]"
                )

        # NEW: Apply ignore rules if configured
        ignored_findings = []
        if config.ignore_rules:
            console.print(
                f"\n[cyan]Applying {len(config.ignore_rules)} ignore rule(s)...[/cyan]"
            )
            original_count = len(scan_result.findings)
            kept_findings, ignored_findings = aggregator.apply_ignore_rules(
                scan_result.findings, config.ignore_rules
            )
            scan_result.findings = kept_findings

            # If show_ignored is enabled, add ignored findings back to results
            # but keep them marked as ignored in metadata
            if show_ignored and ignored_findings:
                console.print(
                    f"[cyan]Including {len(ignored_findings)} ignored finding(s) in output (--show-ignored)[/cyan]"
                )
                scan_result.findings = kept_findings + ignored_findings

            if ignored_findings:
                console.print(
                    f"[yellow]Ignored {len(ignored_findings)} finding(s) based on ignore rules[/yellow]"
                )
                if verbose or show_ignored:
                    for f in ignored_findings[:5]:  # Show first 5
                        reason = f.metadata.get("ignore_reason", "Unknown")
                        console.print(
                            f"  - {f.title} [{f.file_path}:{f.line_number}] - {reason}"
                        )
                    if len(ignored_findings) > 5:
                        console.print(f"  ... and {len(ignored_findings) - 5} more")

        # NEW: Generate ignore rules if requested
        if generate_ignore:
            yaml_rules = _generate_ignore_rules_yaml(scan_result.findings, ignore_limit)

            if ignore_output:
                # Write to file
                ignore_output.write_text(yaml_rules, encoding="utf-8")
                console.print(
                    f"\n[green]OK:[/green] Ignore rules written to [cyan]{ignore_output}[/cyan]"
                )
                console.print(
                    f"  Generated {len(scan_result.findings[:ignore_limit])} ignore rules"
                )
                console.print("\n[yellow]Next steps:[/yellow]")
                console.print(f"  1. Review and edit {ignore_output}")
                console.print("  2. Add reasons for each ignore rule")
                console.print("  3. Re-run scan to verify rules work")
            else:
                # Print to stdout
                console.print("\n[bold cyan]Generated Ignore Rules:[/bold cyan]\n")
                console.print(yaml_rules)
                console.print(
                    f"\n[dim]# Total: {len(scan_result.findings[:ignore_limit])} rules generated[/dim]"
                )
                console.print("[dim]# Copy to .impact-scan.yml and edit reasons[/dim]")

            # Exit after generating ignore rules
            raise typer.Exit(code=0)

        # NEW: Auto-fix feature
        if fix or fix_auto:
            from impact_scan.core.auto_fixer import AutoFixer, GitHelper, run_tests

            console.print("\n[bold cyan]Auto-Fix Mode Activated[/bold cyan]")

            # Safety checks
            if not config.enable_ai_fixes:
                console.print(
                    "[yellow]AI fixes not enabled! Use --ai provider or enable in config[/yellow]"
                )
                raise typer.Exit(code=1)

            # Collect fixable findings
            fixable_findings = [f for f in scan_result.findings if f.ai_fix]

            if not fixable_findings:
                console.print(
                    "[yellow]No AI fixes available. Run with --ai provider first.[/yellow]"
                )
                raise typer.Exit(code=0)

            console.print(f"Found {len(fixable_findings)} fixable vulnerabilities\n")

            # Determine confidence threshold
            confidence_map = {"conservative": "high", "aggressive": "medium"}
            confidence_threshold = confidence_map.get(fix_strategy, "high")

            # Create AutoFixer
            dry_run = False  # Could add --fix-dry-run flag later
            fixer = AutoFixer(dry_run=dry_run, require_clean_git=True)

            # Check git status
            git_path = path if path.is_dir() else path.parent
            if GitHelper.is_git_repo(git_path):
                current_branch = GitHelper.get_current_branch(git_path)
                console.print(f"Git repository detected: {current_branch}")

                if not GitHelper.is_working_directory_clean(git_path):
                    console.print(
                        "[bold red]ERROR: Git working directory not clean![/bold red]"
                    )
                    console.print(
                        "[yellow]Commit or stash your changes before using --fix[/yellow]"
                    )
                    raise typer.Exit(code=1)

                # Offer to create branch
                if not fix_auto and not yes:
                    create_branch = typer.confirm(
                        "Create new branch for fixes?", default=True
                    )
                    if create_branch:
                        branch_name = f"impact-scan-fixes-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                        if GitHelper.create_branch(branch_name, git_path):
                            console.print(
                                f"[green]Created branch: {branch_name}[/green]"
                            )
                        else:
                            console.print("[red]ERROR: Failed to create branch![/red]")

                            # Check if on protected branch
                            current_branch = GitHelper.get_current_branch(git_path)
                            if current_branch in ["main", "master", "develop"]:
                                console.print(
                                    f"[red]Cannot apply fixes on protected branch '{current_branch}'[/red]"
                                )
                                console.print(
                                    "Please ensure git is working properly and try again."
                                )
                                raise typer.Exit(1)
                            else:
                                # Ask user if they want to continue on current branch
                                if not yes:
                                    if not typer.confirm(
                                        f"Continue on current branch '{current_branch}'?",
                                        default=False,
                                    ):
                                        raise typer.Exit(0)
                                else:
                                    console.print(
                                        f"[yellow]Warning: Continuing on current branch '{current_branch}' (--yes mode)[/yellow]"
                                    )
            else:
                console.print(
                    "[yellow]Not a git repository, proceeding without version control[/yellow]"
                )

            # Prepare fixes for application
            fixes_to_apply = []
            for finding in fixable_findings:
                fixes_to_apply.append(
                    {
                        "file_path": str(finding.file_path),
                        "fix_diff": finding.ai_fix,
                        "vuln_id": finding.vuln_id,
                        "rule_id": finding.rule_id,
                        "confidence": finding.metadata.get("fix_confidence", "medium"),
                        "title": finding.title,
                    }
                )

            # Show summary
            console.print("[bold]Fixes to apply:[/bold]")
            for i, fix_data in enumerate(fixes_to_apply[:10], 1):
                console.print(f"  {i}. {fix_data['title']} ({fix_data['file_path']})")
            if len(fixes_to_apply) > 10:
                console.print(f"  ... and {len(fixes_to_apply) - 10} more")

            console.print(
                f"\n[bold]Strategy:[/bold] {fix_strategy} (confidence >= {confidence_threshold})"
            )

            # Confirmation prompt (unless --fix-auto --yes)
            if not fix_auto or not yes:
                proceed = typer.confirm("\nApply these fixes?", default=False)
                if not proceed:
                    console.print("[yellow]Aborted by user[/yellow]")
                    raise typer.Exit(code=0)

            # Apply fixes
            console.print("\n[bold cyan]Applying fixes...[/bold cyan]")
            try:
                results, success_count, fail_count = fixer.apply_fixes(
                    fixes_to_apply,
                    project_root=path,
                    confidence_threshold=confidence_threshold,
                )

                # Show results
                console.print(
                    f"\n[bold green]Applied {success_count} fixes successfully[/bold green]"
                )
                if fail_count > 0:
                    console.print(
                        f"[bold red]Failed to apply {fail_count} fixes[/bold red]"
                    )
                    for result in results:
                        if not result.success:
                            console.print(f"  - {result.file_path}: {result.error}")

                # Run tests if available (optional)
                if not fix_auto or not yes:
                    run_tests_opt = typer.confirm(
                        "\nRun tests to validate fixes?", default=True
                    )
                else:
                    run_tests_opt = False  # Skip in automated mode

                if run_tests_opt:
                    console.print("\n[cyan]Running tests...[/cyan]")
                    test_success, test_output = run_tests(path)
                    if test_success:
                        console.print("[bold green]Tests passed![/bold green]")
                    else:
                        console.print("[bold red]Tests failed![/bold red]")
                        console.print(test_output[:500])  # Show first 500 chars

                        # Auto-rollback in --yes mode, otherwise ask user
                        if yes:
                            fixer.rollback_all()
                            console.print(
                                "[yellow]Auto-rollback: Rolled back all fixes (tests failed)[/yellow]"
                            )
                            raise typer.Exit(code=1)
                        else:
                            rollback = typer.confirm("\nRollback fixes?", default=True)
                            if rollback:
                                fixer.rollback_all()
                                console.print("[yellow]Rolled back all fixes[/yellow]")
                                raise typer.Exit(code=1)

                # Commit changes if git repo
                if GitHelper.is_git_repo(git_path) and success_count > 0:
                    if not fix_auto or not yes:
                        commit = typer.confirm("\nCommit fixes to git?", default=True)
                    else:
                        commit = True

                    if commit:
                        commit_msg = f"Auto-fix: Apply {success_count} AI-generated security fixes\n\n"
                        commit_msg += "Fixed vulnerabilities:\n"
                        for result in results[:10]:
                            if result.success:
                                commit_msg += (
                                    f"- {result.vuln_id} in {result.file_path}\n"
                                )
                        if len([r for r in results if r.success]) > 10:
                            commit_msg += f"... and {len([r for r in results if r.success]) - 10} more\n"

                        if GitHelper.commit_changes(commit_msg, git_path):
                            console.print("[green]Changes committed to git[/green]")
                        else:
                            console.print(
                                "[yellow]Failed to commit (check git status)[/yellow]"
                            )

                # Cleanup
                fixer.cleanup_backups()

                console.print("\n[bold green]Auto-fix complete![/bold green]")

            except RuntimeError as e:
                console.print(f"[bold red]ERROR: {e}[/bold red]")
                raise typer.Exit(code=1)
            except Exception as e:
                logger.exception("Auto-fix failed")
                console.print(f"[bold red]ERROR: Auto-fix failed: {e}[/bold red]")

                # Attempt rollback
                try:
                    fixer.rollback_all()
                    console.print("[yellow]Rolled back all changes[/yellow]")
                except:
                    pass

                raise typer.Exit(code=1)

        # Show results
        if not json_stdout:
            console.print("\n" + "=" * 80)
            console.print("[bold green]SCAN RESULTS[/bold green]")
            console.print("=" * 80)

            # Create summary table
            summary_table = Table.grid(padding=1)
            summary_table.add_column(style="cyan", min_width=25)
            summary_table.add_column(style="bold white")

            summary_table.add_row("Total Findings:", str(scan_result.total_findings))
            summary_table.add_row("Files Scanned:", str(scan_result.scanned_files))
            summary_table.add_row("[TIME] Duration:", f"{scan_result.scan_duration:.1f}s")

            # Show findings by severity
            for severity in [
                schema.Severity.CRITICAL,
                schema.Severity.HIGH,
                schema.Severity.MEDIUM,
                schema.Severity.LOW,
            ]:
                count = len([f for f in scan_result.findings if f.severity == severity])
                if count > 0:
                    icon = {
                        "critical": "[red]*[/red]",
                        "high": "[yellow]*[/yellow]",
                        "medium": "[orange1]*[/orange1]",
                        "low": "[blue]*[/blue]",
                    }[severity.value]
                    summary_table.add_row(f"{icon} {severity.value.title()}:", str(count))

            console.print(summary_table)

        # Save output if requested
        if output or output_format:
            try:
                # Determine output formats
                formats_to_generate = []

                if output_format:
                    # Parse comma-separated formats
                    if output_format.lower() == "all":
                        formats_to_generate = ["json", "html", "markdown", "sarif"]
                    else:
                        formats_to_generate = [
                            f.strip().lower() for f in output_format.split(",")
                        ]
                elif output:
                    # Auto-detect from extension
                    ext_map = {
                        ".html": "html",
                        ".json": "json",
                        ".md": "markdown",
                        ".markdown": "markdown",
                        ".sarif": "sarif",
                    }
                    ext = Path(output).suffix.lower()
                    formats_to_generate = [ext_map.get(ext, "html")]

                # Generate each format
                path_obj = Path(path)
                base_path = (
                    Path(output) 
                    if output 
                    else (path_obj.parent / "impact-scan-report" if path_obj.is_file() else path_obj / "impact-scan-report")
                )

                for fmt in formats_to_generate:
                    if fmt == "html":
                        output_path = (
                            base_path.with_suffix(".html")
                            if output
                            else Path(str(base_path) + ".html")
                        )
                        console.print(
                            f"\n[bold]Saving HTML report to[/bold] [cyan]{output_path}[/cyan]..."
                        )
                        save_report(scan_result, output_path)
                        console.print("   [green]OK:[/green] HTML report saved")

                    elif fmt == "json":
                        output_path = (
                            base_path.with_suffix(".json")
                            if output
                            else Path(str(base_path) + ".json")
                        )
                        if not json_stdout:
                            console.print(
                                f"\n[bold]Saving JSON report to[/bold] [cyan]{output_path}[/cyan]..."
                            )
                        aggregator.save_to_json(scan_result, output_path)
                        if not json_stdout:
                            console.print("   [green]OK:[/green] JSON report saved")
                        
                        if json_stdout:
                            # Print JSON to stdout for VS Code extension
                            print(output_path.read_text(encoding="utf-8"), file=original_stdout)

                    elif fmt == "markdown" or fmt == "md":
                        if save_markdown_report is None:
                            console.print(
                                f"\n[yellow]WARN:[/yellow] Markdown report module not available"
                            )
                            continue
                        output_path = (
                            base_path.with_suffix(".md")
                            if output
                            else Path(str(base_path) + ".md")
                        )
                        console.print(
                            f"\n[bold]Saving Markdown report to[/bold] [cyan]{output_path}[/cyan]..."
                        )
                        save_markdown_report(scan_result, output_path)
                        console.print(
                            "   [green]OK:[/green] Markdown report saved (GitHub-ready)"
                        )

                    elif fmt == "sarif":
                        if save_sarif_report is None:
                            console.print(
                                f"\n[yellow]WARN:[/yellow] SARIF report module not available"
                            )
                            continue
                        output_path = (
                            base_path.with_suffix(".sarif")
                            if output
                            else Path(str(base_path) + ".sarif")
                        )
                        console.print(
                            f"\n[bold]Saving SARIF report to[/bold] [cyan]{output_path}[/cyan]..."
                        )
                        save_sarif_report(scan_result, output_path)
                        console.print(
                            "   [green]OK:[/green] SARIF report saved (GitHub Code Scanning ready)"
                        )

                if not json_stdout:
                    console.print(
                        "\n[bold green]All reports saved successfully![/bold green]"
                    )

            except Exception as e:
                logger.error(f"Failed to save report: {e}")
                console.print(f"[bold red]ERROR: Failed to save report: {e}[/bold red]")
                raise typer.Exit(code=1)

        # Show detailed findings only if there are any and not too many
        if not json_stdout:
            if scan_result.findings and len(scan_result.findings) <= 10:
                console.print(f"\nShowing {len(scan_result.findings)} findings:")
                renderer.print_findings(scan_result, config.min_severity)
            elif len(scan_result.findings) > 10:
                console.print(
                    f"\nFound {len(scan_result.findings)} findings (use --output to save full report)"
                )

        # Final status
        end_time = time.time()
        if not json_stdout:
            console.print(
                f"\nScan completed in [yellow]{end_time - start_time:.1f}s[/yellow]"
            )

        # Exit with appropriate code
        critical_count = len(
            [f for f in scan_result.findings if f.severity == schema.Severity.CRITICAL]
        )
        if critical_count > 0:
            console.print(
                f"[bold red]WARNING: Found {critical_count} CRITICAL vulnerabilities![/bold red]"
            )
            raise typer.Exit(code=2)  # Exit code 2 for critical findings

        high_count = len(
            [f for f in scan_result.findings if f.severity == schema.Severity.HIGH]
        )
        if high_count > 0 and profile == "ci":
            console.print(
                f"[bold yellow]WARNING: Found {high_count} HIGH vulnerabilities in CI mode![/bold yellow]"
            )
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
            web_search,
        )

    console.print(table)
    console.print("\n[dim]Use: impact-scan scan --profile <name>[/dim]")


@app.command("scan-file")
def scan_file_command(
    file_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        help="Path to single file to scan",
    ),
    json_output: bool = typer.Option(
        True,
        "--json/--no-json",
        help="Output results as JSON (default: True, for VS Code extension)",
    ),
    ai_fixes: bool = typer.Option(
        False,
        "--ai-fixes",
        help="Generate AI-powered fix suggestions",
    ),
    ai_provider: Optional[str] = typer.Option(
        None,
        "--ai-provider",
        help="AI provider for fixes: groq, openai, anthropic, gemini",
    ),
):
    """
    Scan a single file (optimized for VS Code extension integration).

    This command is designed for fast, single-file scanning with JSON output
    for integration with editors and IDEs like VS Code.

    Example:
        impact-scan scan-file src/auth.py --json
    """
    import json
    from impact_scan.core import static_scan
    from impact_scan.utils import schema

    # Configure minimal scan for single file
    # Resolve AI provider if AI fixes requested
    resolved_ai_provider = None
    if ai_fixes:
        if ai_provider:
            resolved_ai_provider = schema.AIProvider(ai_provider)
        else:
            # Auto-detect from environment
            api_keys = schema.APIKeys()
            resolved_ai_provider = profiles.auto_detect_ai_provider(api_keys)

    config = schema.ScanConfig(
        root_path=str(file_path.parent),
        min_severity=schema.Severity.MEDIUM,  # Only show medium+ for editor
        enable_ai_fixes=ai_fixes,
        ai_provider=resolved_ai_provider,
        enable_web_search=False,  # Disable for speed
        enable_stackoverflow=False,
        enable_ai_audit=False,  # Disable for speed
    )

    try:
        # Run static analysis on single file
        findings = static_scan.run_scan(config, project_context=None)

        # Filter to only this file
        file_findings = [
            f for f in findings
            if Path(f.file_path).resolve() == file_path.resolve()
        ]

        if json_output:
            # Output JSON for VS Code extension
            output = {
                "file": str(file_path),
                "findings_count": len(file_findings),
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "line_number": f.line_number,
                        "description": f.description,
                        "vuln_id": f.vuln_id,
                        "rule_id": f.rule_id,
                        "fix": f.ai_fix if hasattr(f, 'ai_fix') and f.ai_fix else None,
                    }
                    for f in file_findings
                ]
            }
            console.print(json.dumps(output, indent=2))
        else:
            # Human-readable output
            if not file_findings:
                console.print(f"[green]✓ No issues found in {file_path.name}[/green]")
            else:
                console.print(f"\n[bold]Found {len(file_findings)} issue(s) in {file_path.name}:[/bold]\n")
                for finding in file_findings:
                    severity_color = {
                        "critical": "red",
                        "high": "red",
                        "medium": "yellow",
                        "low": "blue",
                    }.get(str(finding.severity).lower(), "white")

                    console.print(f"[{severity_color}]• Line {finding.line_number}: {finding.title}[/{severity_color}]")
                    console.print(f"  {finding.description}\n")

    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red]Error scanning file: {e}[/red]")
        raise typer.Exit(code=1)


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
        console.print(
            f"\nAuto-detected AI provider: [green]{auto_provider.value}[/green]"
        )
    else:
        console.print(
            "\n[yellow]WARNING: No AI provider configured. AI fixes will be disabled.[/yellow]"
        )

    console.print(
        "\n[dim]Set API keys as environment variables to enable AI features.[/dim]"
    )


@app.command("init")
def init_config(
    path: Path = typer.Argument(
        ".",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Repository path to analyze (default: current directory)",
    ),
    config_type: str = typer.Option(
        "yaml", "--type", "-t", help="Configuration file type: yaml, toml"
    ),
    analyze: bool = typer.Option(
        True,
        "--analyze/--no-analyze",
        help="Analyze repository and generate custom rules",
    ),
    github_actions: bool = typer.Option(
        False,
        "--github-actions",
        help="Also initialize GitHub Actions workflow",
    ),
):
    """
    Initialize impact-scan for your repository.

    Analyzes your codebase, detects languages, frameworks, and secrets.
    Generates custom security rules and an impact-scan.md configuration file.
    """
    from impact_scan.core.repo_analyzer import RepoAnalyzer

    path = path.resolve()
    console.print(f"\n[bold cyan]🔍 Initializing impact-scan for:[/bold cyan] {path}\n")

    # Step 1: Analyze repository
    analysis_result = None
    analyzer = None
    custom_rules = []
    
    if analyze:
        console.print("[bold]Step 1:[/bold] Analyzing repository...")

        analyzer = RepoAnalyzer(path)
        analysis_result = analyzer.analyze()

        # Display analysis results
        console.print(f"  [green]✓[/green] Detected [cyan]{len(analysis_result['languages'])}[/cyan] language(s)")
        console.print(f"  [green]✓[/green] Primary language: [cyan]{analysis_result['primary_language']}[/cyan]")

        if analysis_result['frameworks']:
            console.print(f"  [green]✓[/green] Frameworks: [cyan]{', '.join(analysis_result['frameworks'])}[/cyan]")

        console.print(f"  [green]✓[/green] Scanned [cyan]{analysis_result['total_files']}[/cyan] files")
        
        # Display secrets found
        secrets = analysis_result.get('secrets_found', [])
        if secrets:
            console.print(f"\n  [bold red]⚠️  SECRETS DETECTED: {len(secrets)} exposed secrets found![/bold red]")
            
            # Group by severity
            critical_secrets = [s for s in secrets if s['severity'] == 'CRITICAL']
            high_secrets = [s for s in secrets if s['severity'] == 'HIGH']
            
            if critical_secrets:
                console.print(f"    [red]• CRITICAL: {len(critical_secrets)}[/red]")
                for secret in critical_secrets[:5]:
                    console.print(f"      - {secret['type']} in [yellow]{secret['file']}[/yellow] line {secret['line']}")
                if len(critical_secrets) > 5:
                    console.print(f"      ... and {len(critical_secrets) - 5} more")
            
            if high_secrets:
                console.print(f"    [orange1]• HIGH: {len(high_secrets)}[/orange1]")
        else:
            console.print(f"  [green]✓[/green] No exposed secrets detected")
        
        console.print()

    # Step 2: Generate impact-scan.md
    console.print("[bold]Step 2:[/bold] Generating impact-scan.md...")
    
    if analyzer and analysis_result:
        md_path = path / "impact-scan.md"
        if md_path.exists():
            console.print(f"  [yellow]Note: impact-scan.md already exists[/yellow]")
            if typer.confirm("  Overwrite existing file?"):
                md_content = analyzer.generate_impact_scan_md(analysis_result)
                md_path.write_text(md_content, encoding="utf-8")
                console.print(f"  [green]✓[/green] Updated: [cyan]{md_path}[/cyan]")
            else:
                console.print("  Skipped impact-scan.md update")
        else:
            md_content = analyzer.generate_impact_scan_md(analysis_result)
            md_path.write_text(md_content, encoding="utf-8")
            console.print(f"  [green]✓[/green] Created: [cyan]{md_path}[/cyan]")
    
    console.print()

    # Step 3: Create .impact-scan.yml configuration file
    console.print("[bold]Step 3:[/bold] Creating configuration file...")

    if config_type.lower() == "yaml":
        config_path = path / ".impact-scan.yml"
        if config_path.exists():
            console.print(
                f"  [yellow]Note: Configuration file already exists: {config_path}[/yellow]"
            )
            if not typer.confirm("  Overwrite existing file?"):
                console.print("  Skipped config file")
            else:
                config_file.save_sample_config(config_path)
                if analysis_result:
                    _customize_config(config_path, analysis_result)
                console.print(f"  [green]✓[/green] Updated: [cyan]{config_path}[/cyan]")
        else:
            config_file.save_sample_config(config_path)
            if analysis_result:
                _customize_config(config_path, analysis_result)
            console.print(f"  [green]✓[/green] Created: [cyan]{config_path}[/cyan]")

    elif config_type.lower() == "toml":
        console.print(
            "For TOML configuration, add this section to your pyproject.toml:"
        )
        console.print(config_file.PYPROJECT_TOML_EXAMPLE)

    else:
        console.print(
            f"[bold red]Error: Invalid config type '{config_type}'. Use 'yaml' or 'toml'.[/bold red]"
        )
        raise typer.Exit(code=1)

    # Step 4: Generate custom rules with Groq AI
    if analyze and analysis_result:
        console.print("\n[bold]Step 4:[/bold] Generating custom security rules with Groq AI...")

        # Check for Groq API key
        api_keys = schema.APIKeys()
        if not api_keys.groq:
            console.print(f"  [yellow]⚠ Groq API key not found[/yellow]")
            console.print(f"  [dim]Set GROQ_API_KEY environment variable to enable AI-powered rule generation[/dim]")
            console.print(f"  [dim]Get a free key at: https://console.groq.com[/dim]")
            console.print(f"  [yellow]Skipping custom rule generation[/yellow]")
        else:
            rules_dir = path / ".impact-scan" / "rules"
            rules_dir.mkdir(parents=True, exist_ok=True)

            # Create minimal config for AI
            class AIConfig:
                def __init__(self):
                    self.api_keys = api_keys
                    self.ai_provider = 'groq'

            ai_config = AIConfig()
            custom_rules = asyncio.run(analyzer.generate_custom_rules(ai_config=ai_config))

            if custom_rules:
                rules_file = rules_dir / f"{analysis_result['primary_language']}-custom.yml"
                _save_custom_rules(rules_file, custom_rules, analysis_result)
                console.print(f"  [green]✓[/green] Generated [cyan]{len(custom_rules)}[/cyan] custom rules")
                console.print(f"  [green]✓[/green] Saved to: [cyan]{rules_file}[/cyan]")
            else:
                console.print(f"  [yellow]No custom rules generated[/yellow]")

    # Step 5: Initialize GitHub Actions if requested
    if github_actions:
        console.print("\n[bold]Step 5:[/bold] Setting up GitHub Actions...")

        workflow_dir = path / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)

        workflow_file = workflow_dir / "impact-scan.yml"
        if workflow_file.exists():
            if not typer.confirm(f"Overwrite existing workflow {workflow_file}?"):
                console.print("Skipped GitHub Actions setup")
            else:
                _create_github_workflow(workflow_file, analysis_result)
                console.print(f"  [green]✓[/green] Created: [cyan]{workflow_file}[/cyan]")
        else:
            _create_github_workflow(workflow_file, analysis_result)
            console.print(f"  [green]✓[/green] Created: [cyan]{workflow_file}[/cyan]")

    # Summary
    console.print("\n[bold green]✅ Initialization complete![/bold green]\n")
    
    # Show warnings if secrets were found
    secrets = analysis_result.get('secrets_found', []) if analysis_result else []
    if secrets:
        console.print("[bold red]⚠️  IMPORTANT: Secrets were detected in your codebase![/bold red]")
        console.print("   Review impact-scan.md for details and remediation steps.\n")
    
    console.print("[bold]Next steps:[/bold]")
    console.print("  1. Review [cyan]impact-scan.md[/cyan] for project-specific security rules")
    console.print("  2. Review [cyan].impact-scan.yml[/cyan] and customize as needed")
    if custom_rules:
        console.print("  3. Review generated custom rules in [cyan].impact-scan/rules/[/cyan]")
    if secrets:
        console.print(f"  [bold red]4. FIX {len(secrets)} exposed secrets immediately![/bold red]")
    console.print(f"\n  Run your first scan: [cyan]impact-scan scan {path}[/cyan]")
    console.print()


def _customize_config(config_path: Path, analysis: Dict):
    """Customize config file based on repository analysis."""
    # This would add language-specific settings to the config
    # For now, just add a comment with detected info
    try:
        content = config_path.read_text()
        header = f"# Auto-detected: {analysis['primary_language']} project\n"
        header += f"# Frameworks: {', '.join(analysis['frameworks']) if analysis['frameworks'] else 'None detected'}\n\n"
        config_path.write_text(header + content)
    except Exception as e:
        logger.debug(f"Could not customize config: {e}")


def _save_custom_rules(rules_file: Path, rules: List[Dict], analysis: Dict):
    """Save custom rules to YAML file."""
    import yaml

    rule_content = {
        "# Custom rules generated for this repository": None,
        "# Language": analysis['primary_language'],
        "# Frameworks": ', '.join(analysis['frameworks']) if analysis['frameworks'] else 'None',
        "rules": rules,
    }

    with open(rules_file, 'w') as f:
        f.write(f"# Custom Impact-Scan Rules\n")
        f.write(f"# Generated for: {analysis['primary_language']} project\n")
        f.write(f"# Frameworks: {', '.join(analysis['frameworks']) if analysis['frameworks'] else 'None'}\n\n")

        for rule in rules:
            f.write(f"# {rule['name']}\n")
            f.write(f"#   Severity: {rule['severity']}\n")
            f.write(f"#   Description: {rule['description']}\n")
            f.write(f"#   Pattern: {rule['pattern']}\n")
            f.write(f"#   Enabled: {rule['enabled']}\n\n")


def _create_github_workflow(workflow_file: Path, analysis: Dict):
    """Create GitHub Actions workflow file."""
    primary_lang = analysis.get('primary_language', 'python') if analysis else 'python'

    workflow = f"""name: Impact-Scan Security Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  security-scan:
    name: Run Impact-Scan
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Impact-Scan
        run: |
          pip install impact-scan

      - name: Run Security Scan
        env:
          GROQ_API_KEY: ${{{{ secrets.GROQ_API_KEY }}}}
        run: |
          impact-scan scan . \\
            --profile standard \\
            --output-format sarif,markdown \\
            --output impact-scan-results \\
            --min-severity medium

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: impact-scan-results.sarif

      - name: Comment PR with Results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            try {{
              const report = fs.readFileSync('impact-scan-results.md', 'utf8');
              await github.rest.issues.createComment({{
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: report.substring(0, 60000)
              }});
            }} catch (error) {{
              console.log('No markdown report found');
            }}
"""

    workflow_file.write_text(workflow)


@app.command("agent-scan")
def agent_scan_command(
    path: Path = typer.Argument(
        ".",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
        help="Path to scan (default: current directory)",
    ),
    strategy: str = typer.Option(
        "adaptive",
        "--strategy",
        "-s",
        help="Orchestration strategy: sequential, parallel, pipeline, adaptive",
    ),
    agents: Optional[str] = typer.Option(
        None,
        "--agents",
        "-a",
        help="Comma-separated list of agents to run (e.g., recon,vuln,exploit)",
    ),
    ai_provider: str = typer.Option(
        "auto", "--ai", help="AI provider: auto, openai, anthropic, gemini, groq, none"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save results to file (format auto-detected or use --output-format)",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output-format",
        "-f",
        help="Output format(s): json, html, markdown, sarif, all (comma-separated)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output"
    ),
):
    """Revolutionary Multi-Agent Security Scanning - The Future of Cybersecurity Testing"""

    import asyncio

    from impact_scan.agents.orchestrator import OrchestrationStrategy

    console.print(
        "\n[bold cyan]IMPACT SCAN - MULTI-AGENT SECURITY PLATFORM[/bold cyan]"
    )
    console.print(
        "[dim]Revolutionary AI-powered security testing with specialized agents[/dim]\n"
    )

    start_time = time.time()

    try:
        # Set up logging
        if verbose:
            logging_config.setup_logging(logging.DEBUG)
        else:
            logging_config.setup_logging(logging.INFO)

        # Create scan configuration
        api_keys = schema.APIKeys()
        # Enable AI fixes only if an AI provider is specified (not 'none' or 'auto')
        enable_ai = ai_provider not in ["none", "auto", None]
        ai_prov = (
            schema.AIProvider(ai_provider)
            if ai_provider in ["openai", "anthropic", "gemini", "groq", "local"]
            else None
        )

        config = schema.ScanConfig(
            root_path=path,
            min_severity=schema.Severity.MEDIUM,
            enable_ai_fixes=enable_ai,
            enable_web_search=False,  # Web search module deprecated
            ai_provider=ai_prov,
            openai_api_key=api_keys.openai if enable_ai else None,
            anthropic_api_key=api_keys.anthropic if enable_ai else None,
            gemini_api_key=api_keys.gemini if enable_ai else None,
        )

        # Create orchestrator and register agents
        orchestrator = AgentOrchestrator()

        console.print("[bold]Initializing Security Agents...[/bold]")

        # Register all available agents (lazy creation)
        from .agents.quality import CodeQualityAgent
        from .agents.review import AIReviewAgent

        agents_classes = {
            "recon": ReconAgent,
            "vuln": VulnAgent,
            "exploit": ExploitAgent,
            "fix": FixAgent,
            "compliance": ComplianceAgent,
            "codequality": CodeQualityAgent,
            "aireview": AIReviewAgent,
            # Aliases for convenience
            "quality": CodeQualityAgent,
            "review": AIReviewAgent,
        }

        # Determine which agents to run
        if agents:
            agent_names = [name.strip() for name in agents.split(",")]
            agent_names = [name for name in agent_names if name in agents_classes]
        else:
            # Default to vulnerability agent only for faster scans
            agent_names = ["vuln"]
            console.print(
                "[bold yellow]TIP: Use --agents vuln,quality,review for comprehensive scan[/bold yellow]"
            )

        if not agent_names:
            console.print("[bold red]ERROR: No valid agents specified[/bold red]")
            raise typer.Exit(code=1)

        # Create and register selected agents
        console.print(f"[bold]Registering {len(agent_names)} agents...[/bold]")
        for agent_name in agent_names:
            try:
                agent_class = agents_classes[agent_name]
                agent_instance = agent_class(config)
                orchestrator.register_agent(agent_instance)
                console.print(f"  [OK] {agent_name.upper()}")
            except Exception as e:
                console.print(f"  [FAILED] {agent_name}: {e}")
                import traceback

                console.print(f"  {traceback.format_exc()}")
                raise

        console.print(f"\n[bold green]Target:[/bold green] {path}")
        console.print(f"[bold green]Strategy:[/bold green] {strategy}")
        console.print(f"[bold green]Agents:[/bold green] {', '.join(agent_names)}")
        console.print(f"[bold green]AI Provider:[/bold green] {ai_provider}")

        console.print(
            "\n[bold cyan]LAUNCHING MULTI-AGENT SECURITY SCAN...[/bold cyan]\n"
        )

        # Map strategy string to enum
        strategy_map = {
            "sequential": OrchestrationStrategy.SEQUENTIAL,
            "parallel": OrchestrationStrategy.PARALLEL,
            "pipeline": OrchestrationStrategy.PIPELINE,
            "adaptive": OrchestrationStrategy.ADAPTIVE,
        }

        strategy_enum = strategy_map.get(strategy, OrchestrationStrategy.ADAPTIVE)

        # Execute comprehensive scan
        results = asyncio.run(
            orchestrator.execute_comprehensive_scan(
                target=path, strategy=strategy_enum, include_agents=agent_names
            )
        )

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

            details = (
                f"Found {findings_count} findings"
                if result.success
                else result.error_message[:35] + "..."
                if result.error_message and len(result.error_message) > 35
                else result.error_message or "Unknown error"
            )

            summary_table.add_row(
                agent_name.upper(),
                status,
                str(findings_count),
                f"{result.execution_time:.1f}s",
                details,
            )

        console.print(summary_table)

        # Overall summary
        console.print("\n[bold green]SCAN COMPLETE![/bold green]")
        console.print(f"  {successful_agents}/{len(results)} agents succeeded")
        console.print(f"  {total_findings} total findings across all agents")
        console.print(f"  Completed in {time.time() - start_time:.1f}s")

        # Get orchestration performance summary
        perf_summary = orchestrator.get_orchestration_summary()
        if perf_summary.get("failed_agents"):
            console.print(
                f"  [red]Failed agents: {', '.join(perf_summary['failed_agents'])}[/red]"
            )

        # Save results if requested
        if output or output_format:
            try:
                # Compile all agent results
                compiled_results = {
                    "scan_summary": {
                        "target": str(path),
                        "strategy": strategy,
                        "agents_executed": agent_names,
                        "total_findings": total_findings,
                        "execution_time": time.time() - start_time,
                        "successful_agents": successful_agents,
                        "failed_agents": len(results) - successful_agents,
                    },
                    "agent_results": {
                        name: {
                            "status": result.status.value,
                            "execution_time": result.execution_time,
                            "findings": [
                                str(f) for f in result.findings
                            ],  # Convert to strings for JSON
                            "data": result.data,
                            "error": result.error_message,
                        }
                        for name, result in results.items()
                    },
                    "orchestration_summary": perf_summary,
                }

                # Determine output formats
                formats_to_generate = []
                if output_format:
                    if output_format.lower() == "all":
                        formats_to_generate = ["json", "html", "markdown", "sarif"]
                    else:
                        formats_to_generate = [
                            f.strip().lower() for f in output_format.split(",")
                        ]
                elif output:
                    ext_map = {
                        ".html": "html",
                        ".json": "json",
                        ".md": "markdown",
                        ".sarif": "sarif",
                    }
                    ext = output.suffix.lower()
                    formats_to_generate = [ext_map.get(ext, "json")]

                base_path = output if output else Path(path) / "agent-scan-results"

                for fmt in formats_to_generate:
                    if fmt == "json":
                        import json

                        output_path = base_path.with_suffix(".json")
                        console.print(
                            f"\n[bold]Saving JSON report to[/bold] [cyan]{output_path}[/cyan]..."
                        )
                        with open(output_path, "w") as f:
                            json.dump(compiled_results, f, indent=2, default=str)
                        console.print("   [OK] JSON report saved")
                    else:
                        console.print(
                            f"   [WARNING] {fmt.upper()} format not yet supported for agent-scan (use regular scan command)"
                        )

                console.print(
                    "\n[bold green][SUCCESS] Results saved successfully![/bold green]"
                )

            except Exception as e:
                console.print(
                    f"[bold red]ERROR: Failed to save results: {e}[/bold red]"
                )

        # Success message
        console.print(
            "\n[bold green]MULTI-AGENT SECURITY SCAN COMPLETED SUCCESSFULLY![/bold green]"
        )

        if total_findings > 0:
            console.print(
                f"[bold yellow]Review {total_findings} security findings across all agents[/bold yellow]"
            )

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

        console.print("[bold blue]Launching Impact Scan TUI...[/bold blue]")
        console.print(
            "[cyan]Interactive interface with file browser and real-time scanning[/cyan]"
        )
        run_tui()
    except ImportError as e:
        console.print(
            f"[bold red]ERROR: TUI dependencies not installed: {e}[/bold red]"
        )
        console.print("[yellow]Install with: pip install textual[/yellow]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]ERROR: Failed to launch TUI: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command("web")
def web_command(
    port: int = typer.Option(5000, help="Port to run web interface on"),
    no_browser: bool = typer.Option(False, help="Don't auto-open browser"),
):
    """Launch the modern Web-based User Interface."""
    try:
        from impact_scan.web_ui import run_web_ui

        console.print("[bold blue]Launching Impact Scan Web Interface...[/bold blue]")
        console.print(f"[cyan]Starting server on http://localhost:{port}[/cyan]")
        console.print("[green]Modern web UI with real-time updates[/green]")
        console.print("[yellow]Press Ctrl+C to stop the server[/yellow]")
        run_web_ui(port=port, auto_open=not no_browser)
    except ImportError as e:
        console.print(
            f"[bold red]ERROR: Web UI dependencies not installed: {e}[/bold red]"
        )
        console.print("[yellow]Install with: pip install flask[/yellow]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]ERROR: Failed to launch Web UI: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command("init-github-action")
def init_github_action_command(
    enable_autofix: bool = typer.Option(
        False,
        "--autofix",
        help="Also create auto-fix workflow that creates PRs with fixes",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite existing workflow files"
    ),
):
    """
    Initialize GitHub Actions workflow for CI/CD security scanning.

    Creates .github/workflows/impact-scan.yml with:
      - Automated security scanning on push/PR
      - SARIF upload to GitHub Security tab
      - PR comments with findings
      - Weekly scheduled scans

    Examples:
      impact-scan init-github-action
      impact-scan init-github-action --autofix  # Also add auto-fix workflow
    """
    import shutil


    console.print("[bold blue]Initializing GitHub Actions Integration...[/bold blue]\n")

    # Get current working directory
    project_root = Path.cwd()
    workflows_dir = project_root / ".github" / "workflows"

    # Create .github/workflows directory if it doesn't exist
    workflows_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"✓ Created directory: {workflows_dir}")

    # Copy main workflow template
    template_path = Path(__file__).parent / "templates" / "github_action_template.yml"
    workflow_path = workflows_dir / "impact-scan.yml"

    # Validate template exists
    if not template_path.exists():
        console.print("[red]Error: Template file not found![/red]")
        console.print(f"Expected: {template_path}")
        console.print("\nThis may indicate an incomplete installation.")
        console.print("Please reinstall impact-scan:")
        console.print("  pip install --force-reinstall impact-scan")
        console.print("\nOr report this issue at:")
        console.print("  https://github.com/Ani07-05/impact-scan/issues")
        raise typer.Exit(1)

    if workflow_path.exists() and not force:
        console.print(
            f"\n[yellow]Warning: Workflow already exists: {workflow_path}[/yellow]"
        )
        console.print("[yellow]  Use --force to overwrite[/yellow]")
    else:
        shutil.copy(template_path, workflow_path)
        console.print(
            f"[green]OK:[/green] Created workflow: [cyan]{workflow_path}[/cyan]"
        )

    # Copy auto-fix workflow if requested
    if enable_autofix:
        autofix_template = (
            Path(__file__).parent / "templates" / "github_action_autofix.yml"
        )
        autofix_path = workflows_dir / "impact-scan-autofix.yml"

        # Validate auto-fix template exists
        if not autofix_template.exists():
            console.print("[red]Error: Auto-fix template file not found![/red]")
            console.print(f"Expected: {autofix_template}")
            console.print("\nSkipping auto-fix workflow creation.")
            console.print("Please reinstall impact-scan or report this issue.")
        elif autofix_path.exists() and not force:
            console.print(
                f"\n[yellow]Warning: Auto-fix workflow already exists: {autofix_path}[/yellow]"
            )
        else:
            shutil.copy(autofix_template, autofix_path)
            console.print(
                f"[green]OK:[/green] Created auto-fix workflow: [cyan]{autofix_path}[/cyan]"
            )

    # Success message with next steps
    console.print(
        "\n[bold green]GitHub Actions integration initialized![/bold green]\n"
    )

    console.print("[bold cyan]Next Steps:[/bold cyan]")
    console.print("\n1. [cyan]Add API keys as GitHub secrets:[/cyan]")
    console.print("   Go to: Settings → Secrets and variables → Actions")
    console.print("   Add: [yellow]GROQ_API_KEY[/yellow] (required)")
    console.print("   Add: [yellow]ANTHROPIC_API_KEY[/yellow] (optional)")

    console.print("\n2. [cyan]Commit the workflow:[/cyan]")
    console.print(f"   git add {workflows_dir}")
    console.print('   git commit -m "Add Impact-Scan security workflow"')
    console.print("   git push")

    console.print("\n3. [cyan]Trigger your first scan:[/cyan]")
    console.print("   - Push a commit to main/develop branch")
    console.print("   - Open a Pull Request")
    console.print("   - Go to Actions tab → Run workflow manually")

    console.print("\n4. [cyan]View results:[/cyan]")
    console.print("   - Security tab: SARIF results with code scanning alerts")
    console.print("   - PR comments: Inline vulnerability findings")
    console.print("   - Artifacts: HTML/Markdown reports (90-day retention)")

    if enable_autofix:
        console.print("\n[bold yellow]Auto-Fix Workflow Enabled![/bold yellow]")
        console.print("   Runs weekly on Mondays at 2 AM")
        console.print("   Creates PRs with AI-generated security fixes")
        console.print("   Review PRs before merging!")

    console.print(
        "\n[dim]Documentation: https://github.com/Ani07-05/impact-scan#github-actions[/dim]"
    )


@app.command("doctor")
def doctor_command():
    """Check Impact-Scan installation health and dependencies."""
    import shutil
    import subprocess
    import sys

    console.print("\n[bold cyan]Impact-Scan Installation Health Check[/bold cyan]\n")

    # Track overall health
    issues = []
    warnings = []

    # 1. Python version
    console.print("[bold]1. Python Environment[/bold]")
    py_version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    if sys.version_info >= (3, 9):
        console.print(f"   [green]OK[/green] Python {py_version}")
    else:
        console.print(f"   [red]FAIL[/red] Python {py_version} (Requires 3.9+)")
        issues.append("Python version too old (requires 3.9+)")

    # 2. Core dependencies
    console.print("\n[bold]2. Core Dependencies[/bold]")
    core_deps = [
        ("rich", "Rich library"),
        ("textual", "Textual TUI framework"),
        ("typer", "CLI framework"),
        ("pydantic", "Data validation"),
    ]

    for module_name, display_name in core_deps:
        try:
            __import__(module_name)
            console.print(f"   [green]OK[/green] {display_name}")
        except ImportError:
            console.print(f"   [red]FAIL[/red] {display_name}")
            issues.append(f"{display_name} not installed")

    # 3. Security scanning tools
    console.print("\n[bold]3. Security Scanning Tools[/bold]")

    # Semgrep
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin:
        try:
            result = subprocess.run(
                ["semgrep", "--version"], capture_output=True, text=True, timeout=5
            )
            version = (
                result.stdout.strip().split("\n")[0]
                if result.returncode == 0
                else "unknown"
            )
            console.print(f"   [green]OK[/green] Semgrep {version}")
            console.print(f"     Path: {semgrep_bin}")
        except Exception as e:
            console.print(
                "   [yellow]WARN[/yellow] Semgrep found but can't get version"
            )
            warnings.append(f"Semgrep version check failed: {e}")
    else:
        console.print("   [red]FAIL[/red] Semgrep (Not found)")
        issues.append("Semgrep not installed - install with: pip install semgrep")

    # pip-audit
    pip_audit_bin = shutil.which("pip-audit")
    if pip_audit_bin:
        console.print("   [green]OK[/green] pip-audit")
        console.print(f"     Path: {pip_audit_bin}")
    else:
        console.print("   [yellow]WARN[/yellow] pip-audit (optional)")
        warnings.append("pip-audit not installed - install with: pip install pip-audit")

    # safety
    try:
        __import__("safety")
        console.print("   [green]OK[/green] Safety")
    except ImportError:
        console.print("   [yellow]WARN[/yellow] Safety (optional)")
        warnings.append("safety not installed - install with: pip install safety")

    # 4. AI providers
    console.print("\n[bold]4. AI Provider Configuration[/bold]")

    api_keys = schema.APIKeys()
    providers_found = []

    if api_keys.openai:
        console.print("   [green]OK[/green] OpenAI API key")
        providers_found.append("OpenAI")
    else:
        console.print("   [dim]--[/dim] OpenAI API key (Not configured)")

    if api_keys.anthropic:
        console.print("   [green]OK[/green] Anthropic API key")
        providers_found.append("Anthropic")
    else:
        console.print("   [dim]--[/dim] Anthropic API key (Not configured)")

    if api_keys.gemini:
        console.print("   [green]OK[/green] Google Gemini API key")
        providers_found.append("Gemini")
    else:
        console.print("   [dim]--[/dim] Google Gemini API key (Not configured)")

    if api_keys.groq:
        console.print("   [green]OK[/green] Groq API key")
        providers_found.append("Groq")
    else:
        console.print("   [dim]--[/dim] Groq API key (Not configured)")

    if not providers_found:
        console.print("\n   [yellow]WARN[/yellow] No AI providers configured")
        console.print("   AI-powered fixes will be disabled")
        console.print(
            "   Set environment variables: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or GROQ_API_KEY"
        )
        warnings.append("No AI providers configured - AI fixes disabled")
    else:
        console.print(f"\n   Available providers: {', '.join(providers_found)}")

    # 5. Optional features
    console.print("\n[bold]5. Optional Features[/bold]")

    # Flask (web UI)
    try:
        __import__("flask")
        console.print("   [green]OK[/green] Flask (Web UI available)")
    except ImportError:
        console.print("   [yellow]WARN[/yellow] Flask (Web UI unavailable)")
        warnings.append("Flask not installed - install with: pip install flask")

    # Playwright (web intelligence)
    try:
        __import__("playwright")
        console.print("   [green]OK[/green] Playwright (Web intelligence available)")
    except ImportError:
        console.print(
            "   [yellow]WARN[/yellow] Playwright (Web intelligence unavailable)"
        )
        warnings.append(
            "Playwright not installed - install with: pip install playwright"
        )

    # 6. Write permissions
    console.print("\n[bold]6. File System[/bold]")
    test_file = Path.cwd() / ".impact-scan-test"
    try:
        test_file.write_text("test")
        test_file.unlink()
        console.print("   [green]OK[/green] Write permissions")
        console.print(f"     Working directory: {Path.cwd()}")
    except Exception as e:
        console.print("   [red]FAIL[/red] Write permissions")
        issues.append(f"Cannot write to current directory: {e}")

    # Summary
    console.print("\n" + "=" * 60)
    if not issues:
        console.print("[bold green]SUCCESS - All critical checks passed![/bold green]")
        if warnings:
            console.print(f"\n[yellow]{len(warnings)} warning(s):[/yellow]")
            for warning in warnings:
                console.print(f"  - {warning}")
        else:
            console.print(
                "\n[bold green]Impact-Scan is fully operational![/bold green]"
            )

        console.print("\n[cyan]Quick Start:[/cyan]")
        console.print("  impact-scan scan .              # Scan current directory")
        console.print("  impact-scan tui                  # Launch interactive TUI")
        console.print("  impact-scan web                  # Launch web interface")
        console.print("  impact-scan profiles             # List scan profiles")
    else:
        console.print(
            f"[bold red]FAILED - {len(issues)} critical issue(s) found:[/bold red]"
        )
        for issue in issues:
            console.print(f"  - {issue}")

        if warnings:
            console.print(f"\n[yellow]{len(warnings)} warning(s):[/yellow]")
            for warning in warnings:
                console.print(f"  - {warning}")

        console.print("\n[bold]Fix Issues:[/bold]")
        console.print("  pip install impact-scan[all]    # Install all dependencies")
        console.print("  pip install semgrep              # Install Semgrep")

        raise typer.Exit(code=1)


@app.command("start")
def start_command():
    """
    Interactive mode - modern UX like Claude Code.

    Shows welcome screen, prompts for folder, then starts scan.
    Perfect for first-time users!
    """
    try:
        from impact_scan.ui.welcome import (
            show_welcome, prompt_scan_path, prompt_ai_provider,
            prompt_output_format, prompt_severity_level
        )
    except ImportError:
        console.print("[red]UI modules not available. Use: impact-scan scan <path>[/red]")
        raise typer.Exit(code=1)

    # 1. Show welcome screen
    show_welcome()

    # 2. Interactive folder picker
    scan_path = prompt_scan_path()
    if not scan_path:
        console.print("\n[dim]Scan cancelled.[/dim]")
        raise typer.Exit(code=0)

    # 3. Prompt for severity level
    severity = prompt_severity_level()

    # 4. Prompt for AI provider with API key validation
    ai_provider = prompt_ai_provider()

    # 5. Prompt for output format
    output_format, output_path = prompt_output_format()

    # Build configuration
    from impact_scan.utils import profiles
    profile = profiles.get_profile("standard")
    api_keys = schema.APIKeys()

    # Apply user choices
    profile.min_severity = schema.Severity[severity.upper()]

    if ai_provider:
        profile.enable_ai_fixes = True
        profile.enable_ai_validation = True
        # Convert string to AIProvider enum
        profile.ai_provider = schema.AIProvider[ai_provider.upper()]
    else:
        profile.enable_ai_fixes = False
        profile.enable_ai_validation = False

    config = profiles.create_config_from_profile(
        root_path=scan_path,
        profile=profile,
        api_keys=api_keys
    )

    # Ensure AI validation settings are applied to config
    if ai_provider:
        config.enable_ai_validation = True
        config.enable_ai_fixes = True

    # Show final configuration
    console.print("\n[bold cyan]Ready to scan![/bold cyan]\n")
    console.print(f"  Target:   [white]{scan_path}[/white]")
    console.print(f"  Severity: [white]{severity.upper()}[/white]+")
    if ai_provider:
        console.print(f"  AI:       [green]{ai_provider.upper()}[/green]")
    if output_path:
        console.print(f"  Output:   [white]{output_path}[/white]")
    console.print()

    # Start scan with Claude-style live status
    try:
        from impact_scan.ui.live_status import live_scan_status

        with live_scan_status("Scanning", console=console) as status:
            # Suppress INFO logs during scan
            import logging
            logging.getLogger("impact_scan").setLevel(logging.WARNING)

            status.update("Classifying project", "Detecting frameworks...")
            scan_result = entrypoint.run_scan(config)

            # Restore logging
            logging.getLogger("impact_scan").setLevel(logging.INFO)

        # Show results
        if scan_result.findings:
            console.print(f"\n[green]Scan complete![/green] Found {len(scan_result.findings)} security issues.\n")
            renderer.print_findings(scan_result, config.min_severity or schema.Severity.LOW)
        else:
            console.print("\n[green]Scan complete![/green] No vulnerabilities found.")

        # Save output if requested
        if output_path and output_format:
            from pathlib import Path
            console.print(f"\n[cyan]Saving report to {output_path}...[/cyan]")

            if output_format == "html":
                save_report(scan_result, Path(output_path))
            elif output_format == "json":
                import json
                Path(output_path).write_text(json.dumps([f.model_dump() for f in scan_result.findings], indent=2))
            elif output_format == "markdown":
                if save_markdown_report:
                    save_markdown_report(scan_result, Path(output_path))
                else:
                    console.print("[yellow]Markdown report module not available[/yellow]")
            elif output_format == "sarif":
                if save_sarif_report:
                    save_sarif_report(scan_result, Path(output_path))
                else:
                    console.print("[yellow]SARIF report module not available[/yellow]")
            elif output_format == "all":
                save_report(scan_result, Path(f"{output_path}.html"))
                if save_markdown_report:
                    save_markdown_report(scan_result, Path(f"{output_path}.md"))
                if save_sarif_report:
                    save_sarif_report(scan_result, Path(f"{output_path}.sarif"))

            console.print(f"[green]Report saved![/green]")

    except KeyboardInterrupt:
        console.print("\n\n[yellow]Scan interrupted by user.[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"\n[red]Scan failed:[/red] {e}")
        raise typer.Exit(code=1)


@app.command("onboard")
def onboard_command():
    """
    Run the beautiful TUI onboarding experience.

    Interactive setup wizard to configure API keys and get started.
    """
    try:
        from impact_scan.tui.onboarding import run_onboarding
        run_onboarding()
    except ImportError as e:
        console.print(f"[red]Error: TUI dependencies not available: {e}[/red]")
        console.print("[yellow]Install with: pip install impact-scan[/yellow]")
    except Exception as e:
        console.print(f"[red]Error running onboarding: {e}[/red]")


@app.command("setup")
def init_command(
    skip_install: bool = typer.Option(
        False, "--skip-install", help="Skip dependency installation"
    ),
    skip_test: bool = typer.Option(False, "--skip-test", help="Skip test scan"),
):
    """
    Interactive first-run setup wizard.

    Checks installation, configures API keys, and runs a test scan.
    Makes Impact-Scan setup as easy as Claude Code!
    """
    console.print("\n[bold cyan]Welcome to Impact-Scan![/bold cyan]")
    console.print("Let's get you set up in 3 quick steps.\n")

    # Step 1: Check dependencies
    console.print("[bold]Step 1/3: Checking Dependencies[/bold]")

    if not skip_install:
        installer = get_installer(silent=False)
        results = installer.ensure_all_tools(auto_install=True)

        # Check if all required tools are available
        required_ok = all(
            result["available"]
            for tool, result in results.items()
            if result["required"]
        )

        if not required_ok:
            console.print("\n[red]Some required tools could not be installed.[/red]")
            console.print("Please run: [cyan]impact-scan doctor[/cyan] for details")
            raise typer.Exit(code=1)

        console.print("[green]All dependencies OK![/green]\n")
    else:
        console.print("[dim]Skipping dependency check...[/dim]\n")

    # Step 2: Configure API keys (optional)
    console.print("[bold]Step 2/3: Configure AI Providers (Optional)[/bold]")
    console.print("AI providers enable smart fix suggestions.\n")

    api_keys = schema.APIKeys()
    providers_found = []

    if api_keys.openai:
        providers_found.append("OpenAI")
    if api_keys.anthropic:
        providers_found.append("Anthropic")
    if api_keys.gemini:
        providers_found.append("Gemini")
    if api_keys.groq:
        providers_found.append("Groq")

    if providers_found:
        console.print(f"[green]Found:[/green] {', '.join(providers_found)}")
        console.print("[dim]API keys detected from environment variables[/dim]\n")
    else:
        console.print("[yellow]No AI providers configured[/yellow]")
        console.print("\nTo enable AI-powered fixes, set environment variables:")
        console.print("  [cyan]OPENAI_API_KEY[/cyan]     - OpenAI GPT models")
        console.print("  [cyan]ANTHROPIC_API_KEY[/cyan]  - Anthropic Claude models")
        console.print(
            "  [cyan]GOOGLE_API_KEY[/cyan]     - Google Gemini models (free tier!)"
        )
        console.print(
            "  [cyan]GROQ_API_KEY[/cyan]       - Groq fast inference (free tier!)\n"
        )

        console.print(
            "[dim]You can add these later and re-run 'impact-scan init'[/dim]\n"
        )

    # Step 3: Run test scan
    if not skip_test:
        console.print("[bold]Step 3/3: Running Test Scan[/bold]")
        console.print("Testing on a small sample...\n")

        try:

            # Create a minimal test file for scanning
            test_dir = Path.cwd() / ".impact-scan-test"
            test_dir.mkdir(exist_ok=True)

            test_file = test_dir / "test_vuln.py"
            test_file.write_text("""
# Test file with intentional vulnerabilities for scanning demo
import os
import subprocess

# CWE-78: OS Command Injection
def run_command(user_input):
    os.system(f"ls {user_input}")  # Vulnerable!

# CWE-798: Hardcoded Credentials
API_KEY = "sk-1234567890abcdef"  # Never hardcode secrets!

# CWE-259: Use of Hard-coded Password
password = "admin123"
""")

            # Quick scan
            console.print(f"Scanning test directory: [cyan]{test_dir}[/cyan]")

            from impact_scan.core import entrypoint
            from impact_scan.utils import profiles

            profile = profiles.get_profile("quick")
            config = profiles.create_config_from_profile(
                root_path=test_dir, profile=profile, api_keys=schema.APIKeys()
            )

            console.print("[dim]Running security scan...[/dim]")
            scan_result = entrypoint.run_scan(config)

            # Show results
            if scan_result.findings:
                console.print(
                    f"\n[green]Success![/green] Found {len(scan_result.findings)} test vulnerabilities:"
                )

                # Show first 3 findings
                for i, finding in enumerate(scan_result.findings[:3], 1):
                    severity_color = {
                        "critical": "red",
                        "high": "yellow",
                        "medium": "blue",
                        "low": "cyan",
                    }.get(finding.severity.value.lower(), "white")

                    console.print(
                        f"  {i}. [{severity_color}]{finding.severity.value.upper()}[/{severity_color}] {finding.title}"
                    )

                if len(scan_result.findings) > 3:
                    console.print(f"  ... and {len(scan_result.findings) - 3} more\n")
            else:
                console.print("[yellow]No findings (this is just a test)[/yellow]\n")

            # Cleanup
            import shutil

            shutil.rmtree(test_dir, ignore_errors=True)

            console.print("[green]Test scan complete![/green]\n")

        except Exception as e:
            console.print(f"[yellow]Test scan failed: {e}[/yellow]")
            console.print("[dim]This is OK - you can still use Impact-Scan[/dim]\n")
    else:
        console.print("[dim]Skipping test scan...[/dim]\n")

    # All done!
    console.print("=" * 60)
    console.print("[bold green]Setup Complete![/bold green]\n")

    console.print("[cyan]Quick Start Commands:[/cyan]")
    console.print(
        "  [bold]impact-scan scan .[/bold]              # Scan current directory"
    )
    console.print("  [bold]impact-scan scan . --ai gemini[/bold]  # Scan with AI fixes")
    console.print(
        "  [bold]impact-scan tui[/bold]                 # Launch interactive TUI"
    )
    console.print(
        "  [bold]impact-scan web[/bold]                 # Launch web interface"
    )
    console.print("  [bold]impact-scan doctor[/bold]              # Health check\n")

    console.print(
        "[dim]Documentation: https://github.com/Ani07-05/impact-scan#readme[/dim]"
    )


@app.command()
def init_repo(
    path: Path = typer.Argument(
        ".",
        exists=True,
        dir_okay=True,
        file_okay=False,
        readable=True,
        resolve_path=True,
        help="Repository path to analyze",
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--groq-key",
        envvar="GROQ_API_KEY",
        help="Groq API key (or set GROQ_API_KEY env var)",
    ),
):
    """
    Initialize repository analysis with Groq AI.
    
    Analyzes your codebase and generates:
    - impact-scan.md: Detailed security analysis
    - .impact-scan/custom-rules.yml: Custom security rules for your repo
    
    These custom rules are then used by `impact-scan scan` for targeted detection.
    """
    from impact_scan.core.groq_repo_analyzer import GroqRepoAnalyzer
    
    try:
        console.print("\n[bold cyan]Impact-Scan Repository Analyzer[/bold cyan]")
        console.print(f"[dim]Analyzing repository at: {path}[/dim]\n")
        
        if not api_key and not schema.APIKeys().groq:
            console.print("[red]Error:[/red] Groq API key not found")
            console.print("\nSet your Groq API key:")
            console.print("  [cyan]export GROQ_API_KEY=your-key[/cyan]")
            console.print("\nOr pass it via option:")
            console.print("  [cyan]impact-scan init-repo --groq-key your-key[/cyan]")
            console.print("\nGet a free API key at: [cyan]https://console.groq.com[/cyan]\n")
            raise typer.Exit(code=1)
        
        analyzer = GroqRepoAnalyzer(path, api_key=api_key)
        
        console.print("[bold]Step 1/3:[/bold] Collecting codebase information...")
        with console.status("[bold cyan]Scanning repository...", spinner="dots"):
            codebase_info = analyzer.collect_codebase_info()
        
        console.print("[green]✓[/green] Codebase information collected\n")
        
        console.print("[bold]Step 2/3:[/bold] Analyzing with Groq AI...")
        with console.status("[bold cyan]Analyzing security patterns...", spinner="dots"):
            analysis = analyzer.analyze_with_groq(codebase_info)
        
        console.print("[green]✓[/green] Security analysis complete\n")
        
        console.print("[bold]Step 3/3:[/bold] Generating custom security rules...")
        with console.status("[bold cyan]Generating rules...", spinner="dots"):
            rules = analyzer.generate_custom_rules(analysis)
        
        console.print("[green]✓[/green] Custom rules generated\n")
        
        # Save files
        analysis_file = path / "impact-scan.md"
        rules_file = path / ".impact-scan" / "custom-rules.yml"
        
        analyzer._save_analysis_md(analysis_file, codebase_info, analysis)
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        with open(rules_file, 'w') as f:
            f.write(rules)
        
        # Show results
        console.print("[bold cyan]Files Created:[/bold cyan]")
        console.print(f"  [green]✓[/green] {analysis_file.relative_to(path)}")
        console.print(f"      Detailed codebase security analysis")
        console.print(f"  [green]✓[/green] {rules_file.relative_to(path)}")
        console.print(f"      Custom Semgrep rules for your codebase\n")
        
        console.print("[bold cyan]Next Steps:[/bold cyan]")
        console.print("[dim]1. Review the analysis in:[/dim]")
        console.print(f"   [cyan]cat {analysis_file}[/cyan]")
        console.print("[dim]2. Run scan with custom rules:[/dim]")
        console.print(f"   [cyan]impact-scan scan {path}[/cyan]")
        console.print("[dim]3. View findings:[/dim]")
        console.print("   [cyan]impact-scan scan . -o findings.html[/cyan]\n")
        
        # Show preview of analysis
        console.print("[bold]Analysis Preview:[/bold]")
        console.print("[dim]" + "─" * 60 + "[/dim]")
        console.print(analysis[:800])
        console.print("[dim]..." + "─" * 60 + "[/dim]\n")
        
        console.print("[green]✓ Repository initialization complete![/green]")
        
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)
    except ImportError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("\nInstall Groq client:")
        console.print("  [cyan]pip install groq[/cyan]\n")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.exception("Analysis failed")
        console.print(f"[red]Error:[/red] Analysis failed: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
