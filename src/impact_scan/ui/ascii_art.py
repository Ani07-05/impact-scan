"""
ASCII Art and Visual Elements for Impact-Scan CLI.

Provides minimal, professional branding and visual elements following
the Arguably design philosophy: barely noticeable, doesn't get in the way.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Version will be imported from package metadata
try:
    from importlib.metadata import version
    __version__ = version("impact-scan")
except Exception:
    __version__ = "0.2.0"


def get_logo(style="minimal") -> Panel:
    """
    Get the Impact-Scan logo as a Rich Panel.

    Args:
        style: Logo style - "minimal" (default), "box", or "simple"

    Returns:
        Rich Panel with logo
    """
    if style == "box":
        logo_text = Text()
        logo_text.append("  IMPACT SCAN", style="bold cyan")
        logo_text.append("\n")
        logo_text.append("  AI Security Scanner • 100% Precision", style="dim white")
        logo_text.append("\n")
        logo_text.append(f"  v{__version__}", style="dim cyan")

        return Panel(
            logo_text,
            border_style="cyan",
            padding=(0, 1),
            expand=False
        )

    elif style == "simple":
        logo_text = Text()
        logo_text.append("━" * 50, style="cyan")
        logo_text.append("\n")
        logo_text.append(f"  IMPACT SCAN v{__version__}", style="bold cyan")
        logo_text.append("\n")
        logo_text.append("  AI Security • 0% False Positives", style="dim white")
        logo_text.append("\n")
        logo_text.append("━" * 50, style="cyan")

        return Panel(logo_text, border_style="", padding=(0, 0), expand=False)

    else:  # minimal (default)
        logo_text = Text()
        logo_text.append(f"IMPACT SCAN v{__version__}", style="bold cyan")
        logo_text.append(" • ", style="dim white")
        logo_text.append("AI Security Scanner", style="dim white")

        return Panel(logo_text, border_style="", padding=(0, 1), expand=False)


def print_logo(console: Console | None = None, style="minimal", show_banner=True):
    """
    Print the Impact-Scan logo to console.

    Args:
        console: Rich Console instance (creates new if None)
        style: Logo style - "minimal", "box", or "simple"
        show_banner: If False, skips printing (for --no-banner flag)
    """
    if not show_banner:
        return

    if console is None:
        console = Console()

    logo = get_logo(style)
    console.print(logo)
    console.print()  # Add spacing
