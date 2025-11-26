"""
Welcome screen and interactive prompts for Impact-Scan.

Modern, clean UX inspired by Claude Code.
"""

from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table


def show_welcome() -> None:
    """
    Display beautiful welcome screen.

    Clean, modern design - no error-like red colors.
    """
    console = Console()

    # Clear screen for clean start
    console.clear()

    # Create welcome text
    welcome = Text()
    welcome.append("IMPACT SCAN\n", style="bold cyan")
    welcome.append("AI-Powered Security Scanner\n\n", style="dim white")
    welcome.append("Scan your codebase for vulnerabilities with AI-powered fixes\n", style="white")

    # Create feature list
    features = Table.grid(padding=(0, 2))
    features.add_column(style="cyan")
    features.add_column(style="white")

    features.add_row("[+]", "Static Analysis (Semgrep + Bandit)")
    features.add_row("[+]", "Dependency Scanning (OSV + Safety)")
    features.add_row("[+]", "AI Fix Generation (GPT-4, Claude, Gemini)")
    features.add_row("[+]", "False Positive Reduction (91% accuracy)")

    # Combine into panel
    welcome.append("\n")

    panel = Panel(
        welcome,
        border_style="cyan",
        padding=(1, 2),
        title="[bold white]Welcome[/bold white]",
        subtitle="[dim]v0.3.0[/dim]"
    )

    console.print(panel)
    console.print(features)
    console.print()


def prompt_scan_path() -> Optional[Path]:
    """
    Interactive file picker for scan target.

    Returns:
        Path to scan or None if cancelled
    """
    console = Console()

    console.print("[bold cyan]Select folder to scan[/bold cyan]\n")

    # Show current directory
    cwd = Path.cwd()
    console.print(f"Current directory: [white]{cwd}[/white]\n")

    # Prompt options
    console.print("[dim]Options:[/dim]")
    console.print("  [cyan].[/cyan]     - Scan current directory")
    console.print("  [cyan]path[/cyan]  - Enter custom path")
    console.print("  [cyan]q[/cyan]     - Quit\n")

    while True:
        path_input = Prompt.ask(
            "[cyan]Path to scan[/cyan]",
            default=".",
            show_default=False
        )

        if path_input.lower() in ['q', 'quit', 'exit']:
            return None

        target = Path(path_input).resolve()

        if not target.exists():
            console.print(f"[yellow]Path does not exist:[/yellow] {target}\n")
            continue

        if not target.is_dir():
            console.print(f"[yellow]Path is not a directory:[/yellow] {target}\n")
            continue

        # Confirm selection
        console.print(f"\n[green]Selected:[/green] {target}")

        # Count files
        try:
            py_files = len(list(target.rglob("*.py")))
            js_files = len(list(target.rglob("*.js"))) + len(list(target.rglob("*.ts")))

            if py_files + js_files == 0:
                console.print("[yellow]Warning: No Python or JavaScript files found[/yellow]")
            else:
                console.print(f"[dim]Found: {py_files} Python files, {js_files} JS/TS files[/dim]")
        except Exception:
            pass

        confirm = Confirm.ask("\n[cyan]Start scan?[/cyan]", default=True)

        if confirm:
            return target
        else:
            console.print()


def prompt_ai_provider() -> Optional[str]:
    """
    Prompt for AI provider selection with API key validation.

    Returns:
        Provider name or None to skip
    """
    console = Console()

    console.print("\n[bold cyan]AI Provider Selection[/bold cyan]")
    console.print("[dim]Choose AI provider for fix generation and validation[/dim]\n")

    console.print("[cyan]Available providers:[/cyan]")
    console.print("  [white]1.[/white] Groq (fastest, free tier)")
    console.print("  [white]2.[/white] Gemini (cheapest, $0.01/scan)")
    console.print("  [white]3.[/white] OpenAI (GPT-4)")
    console.print("  [white]4.[/white] Anthropic (Claude)")
    console.print("  [white]5.[/white] Skip AI features\n")

    choice = Prompt.ask("[cyan]Select provider[/cyan]", choices=["1", "2", "3", "4", "5"], default="1")

    provider_map = {
        "1": ("groq", "GROQ_API_KEY"),
        "2": ("gemini", "GOOGLE_API_KEY"),
        "3": ("openai", "OPENAI_API_KEY"),
        "4": ("anthropic", "ANTHROPIC_API_KEY"),
        "5": (None, None)
    }

    provider, env_key = provider_map[choice]

    if not provider:
        return None

    # Check for API key
    import os
    api_key = os.getenv(env_key)

    if not api_key:
        console.print(f"\n[yellow]No {env_key} found in environment[/yellow]")
        api_key = Prompt.ask(f"Enter {provider.upper()} API key (or press Enter to skip)", default="")

        if api_key:
            os.environ[env_key] = api_key
            console.print(f"[green]API key set for this session[/green]")
        else:
            console.print("[yellow]Skipping AI features[/yellow]")
            return None
    else:
        console.print(f"[green]Using {provider.upper()} API key from environment[/green]")

    return provider


def prompt_output_format() -> tuple[Optional[str], Optional[str]]:
    """
    Prompt for output format and file path.

    Returns:
        (format, file_path) tuple
    """
    console = Console()

    console.print("\n[bold cyan]Output Format[/bold cyan]")
    console.print("[dim]Choose report format[/dim]\n")

    console.print("[cyan]Available formats:[/cyan]")
    console.print("  [white]1.[/white] HTML (interactive, best for sharing)")
    console.print("  [white]2.[/white] JSON (machine-readable)")
    console.print("  [white]3.[/white] Markdown (GitHub-friendly)")
    console.print("  [white]4.[/white] SARIF (GitHub Security tab)")
    console.print("  [white]5.[/white] All formats")
    console.print("  [white]6.[/white] Terminal only (no file)\n")

    choice = Prompt.ask("[cyan]Select format[/cyan]", choices=["1", "2", "3", "4", "5", "6"], default="1")

    format_map = {
        "1": ("html", "scan-report.html"),
        "2": ("json", "scan-report.json"),
        "3": ("markdown", "scan-report.md"),
        "4": ("sarif", "scan-report.sarif"),
        "5": ("all", "scan-report"),
        "6": (None, None)
    }

    fmt, default_path = format_map[choice]

    if not fmt:
        return None, None

    # Prompt for custom path
    use_default = Confirm.ask(f"\nSave as [cyan]{default_path}[/cyan]?", default=True)

    if use_default:
        return fmt, default_path
    else:
        custom_path = Prompt.ask("Enter output path")
        return fmt, custom_path


def prompt_severity_level() -> str:
    """
    Prompt for minimum severity level.

    Returns:
        Severity level string
    """
    console = Console()

    console.print("\n[bold cyan]Severity Filter[/bold cyan]")
    console.print("[dim]Show only findings above this severity[/dim]\n")

    console.print("[cyan]Severity levels:[/cyan]")
    console.print("  [white]1.[/white] LOW (show all)")
    console.print("  [white]2.[/white] MEDIUM (recommended)")
    console.print("  [white]3.[/white] HIGH (critical only)")
    console.print("  [white]4.[/white] CRITICAL (urgent fixes)\n")

    choice = Prompt.ask("[cyan]Select severity[/cyan]", choices=["1", "2", "3", "4"], default="2")

    severity_map = {
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical"
    }

    return severity_map[choice]


def show_scan_config(config) -> None:
    """
    Display scan configuration in clean format.

    Args:
        config: ScanConfig object
    """
    console = Console()

    console.print("\n[bold cyan]Scan Configuration[/bold cyan]\n")

    config_table = Table.grid(padding=(0, 2))
    config_table.add_column(style="dim white", justify="right")
    config_table.add_column(style="white")

    config_table.add_row("Target:", str(config.root_path))
    config_table.add_row("Severity:", str(config.min_severity.value if config.min_severity else "ALL"))

    if config.enable_ai_fixes:
        ai_provider = getattr(config, 'ai_provider', 'auto-detect')
        config_table.add_row("AI Fixes:", f"[green]Enabled[/green] ({ai_provider})")

    if config.enable_ai_validation:
        config_table.add_row("AI Validation:", "[green]Enabled[/green] (91% FP reduction)")

    console.print(config_table)
    console.print()
