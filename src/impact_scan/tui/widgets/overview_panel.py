"""
Overview Panel Widget
Dashboard view with codebase tree, config, and scan info.
"""

from pathlib import Path
from typing import Dict, Set

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Static, Tree
from textual.widgets.tree import TreeNode

from .config_panel import ConfigPanel


# Colors
COLORS = {
    "cyan": "#00D4FF",
    "green": "#50FA7B",
    "orange": "#FFB86C",
    "purple": "#BD93F9",
    "pink": "#FF6EC7",
    "yellow": "#F1FA8C",
    "red": "#FF5555",
    "muted": "#7D8590",
}


class AnimatedBanner(Static):
    """Animated ASCII banner with flowing effect."""

    frame_index = reactive(0)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.animation_active = True

        # Define animation frames
        self.frames = [
            # Frame 0 - Empty
            f"\n\n\n\n\n\n\n\n\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n[{COLORS['green']}]         Security Analysis Platform         [/]\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n\n[{COLORS['yellow']}]          Press 'b' to browse a codebase[/]",

            # Frame 1 - First line appears
            f"[bold {COLORS['cyan']}]██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗[/]    [bold {COLORS['purple']}]███████╗ ██████╗ █████╗ ███╗   ██╗[/]\n\n\n\n\n\n\n\n\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n[{COLORS['green']}]         Security Analysis Platform         [/]\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n\n[{COLORS['yellow']}]          Press 'b' to browse a codebase[/]",

            # Frame 2
            f"[bold {COLORS['cyan']}]██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗[/]    [bold {COLORS['purple']}]███████╗ ██████╗ █████╗ ███╗   ██╗[/]\n[bold {COLORS['cyan']}]██║████╗ ████║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝[/]    [bold {COLORS['purple']}]██╔════╝██╔════╝██╔══██╗████╗  ██║[/]\n[bold {COLORS['cyan']}]██║██╔████╔██║██████╔╝███████║██║        ██║[/]       [bold {COLORS['purple']}]███████╗██║     ███████║██╔██╗ ██║[/]\n\n\n\n\n\n\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n[{COLORS['green']}]         Security Analysis Platform         [/]\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n\n[{COLORS['yellow']}]          Press 'b' to browse a codebase[/]",

            # Frame 3 - IMPACT complete
            f"[bold {COLORS['cyan']}]██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗[/]    [bold {COLORS['purple']}]███████╗ ██████╗ █████╗ ███╗   ██╗[/]\n[bold {COLORS['cyan']}]██║████╗ ████║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝[/]    [bold {COLORS['purple']}]██╔════╝██╔════╝██╔══██╗████╗  ██║[/]\n[bold {COLORS['cyan']}]██║██╔████╔██║██████╔╝███████║██║        ██║[/]       [bold {COLORS['purple']}]███████╗██║     ███████║██╔██╗ ██║[/]\n[bold {COLORS['cyan']}]██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║        ██║[/]       [bold {COLORS['purple']}]╚════██║██║     ██╔══██║██║╚██╗██║[/]\n[bold {COLORS['cyan']}]██║██║ ╚═╝ ██║██║     ██║  ██║╚██████╗   ██║[/]       [bold {COLORS['purple']}]███████║╚██████╗██║  ██║██║ ╚████║[/]\n[bold {COLORS['cyan']}]╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝[/]       [bold {COLORS['purple']}]╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/]\n\n\n\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n[{COLORS['green']}]         Security Analysis Platform         [/]\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n\n[{COLORS['yellow']}]          Press 'b' to browse a codebase[/]",

            # Frame 4 - SCAN starts
            f"[bold {COLORS['cyan']}]██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗[/]    [bold {COLORS['purple']}]███████╗ ██████╗ █████╗ ███╗   ██╗[/]\n[bold {COLORS['cyan']}]██║████╗ ████║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝[/]    [bold {COLORS['purple']}]██╔════╝██╔════╝██╔══██╗████╗  ██║[/]\n[bold {COLORS['cyan']}]██║██╔████╔██║██████╔╝███████║██║        ██║[/]       [bold {COLORS['purple']}]███████╗██║     ███████║██╔██╗ ██║[/]\n[bold {COLORS['cyan']}]██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║        ██║[/]       [bold {COLORS['purple']}]╚════██║██║     ██╔══██║██║╚██╗██║[/]\n[bold {COLORS['cyan']}]██║██║ ╚═╝ ██║██║     ██║  ██║╚██████╗   ██║[/]       [bold {COLORS['purple']}]███████║╚██████╗██║  ██║██║ ╚████║[/]\n[bold {COLORS['cyan']}]╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝[/]       [bold {COLORS['purple']}]╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/]\n\n\n\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n[{COLORS['green']}]         Security Analysis Platform         [/]\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n\n[{COLORS['yellow']}]          Press 'b' to browse a codebase[/]",

            # Frame 5
            f"[bold {COLORS['cyan']}]██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗[/]    [bold {COLORS['purple']}]███████╗ ██████╗ █████╗ ███╗   ██╗[/]\n[bold {COLORS['cyan']}]██║████╗ ████║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝[/]    [bold {COLORS['purple']}]██╔════╝██╔════╝██╔══██╗████╗  ██║[/]\n[bold {COLORS['cyan']}]██║██╔████╔██║██████╔╝███████║██║        ██║[/]       [bold {COLORS['purple']}]███████╗██║     ███████║██╔██╗ ██║[/]\n[bold {COLORS['cyan']}]██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║        ██║[/]       [bold {COLORS['purple']}]╚════██║██║     ██╔══██║██║╚██╗██║[/]\n[bold {COLORS['cyan']}]██║██║ ╚═╝ ██║██║     ██║  ██║╚██████╗   ██║[/]       [bold {COLORS['purple']}]███████║╚██████╗██║  ██║██║ ╚████║[/]\n[bold {COLORS['cyan']}]╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝[/]       [bold {COLORS['purple']}]╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/]\n\n\n\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n[{COLORS['green']}]         Security Analysis Platform         [/]\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n\n[{COLORS['yellow']}]          Press 'b' to browse a codebase[/]",

            # Frame 6 - Final
            f"[bold {COLORS['cyan']}]██╗███╗   ███╗██████╗  █████╗  ██████╗████████╗[/]    [bold {COLORS['purple']}]███████╗ ██████╗ █████╗ ███╗   ██╗[/]\n[bold {COLORS['cyan']}]██║████╗ ████║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝[/]    [bold {COLORS['purple']}]██╔════╝██╔════╝██╔══██╗████╗  ██║[/]\n[bold {COLORS['cyan']}]██║██╔████╔██║██████╔╝███████║██║        ██║[/]       [bold {COLORS['purple']}]███████╗██║     ███████║██╔██╗ ██║[/]\n[bold {COLORS['cyan']}]██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║        ██║[/]       [bold {COLORS['purple']}]╚════██║██║     ██╔══██║██║╚██╗██║[/]\n[bold {COLORS['cyan']}]██║██║ ╚═╝ ██║██║     ██║  ██║╚██████╗   ██║[/]       [bold {COLORS['purple']}]███████║╚██████╗██║  ██║██║ ╚████║[/]\n[bold {COLORS['cyan']}]╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝[/]       [bold {COLORS['purple']}]╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/]\n\n\n\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n[{COLORS['green']}]         Security Analysis Platform         [/]\n[{COLORS['muted']}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n\n[{COLORS['yellow']}]          Press 'b' to browse a codebase[/]",
        ]

    def on_mount(self) -> None:
        """Start animation when mounted."""
        self.update(self.frames[0])
        self.set_interval(0.1, self.animate_frame)  # 100ms for smoother 60fps animation

    def animate_frame(self) -> None:
        """Animate to next frame."""
        if not self.animation_active:
            return

        if self.frame_index < len(self.frames) - 1:
            self.frame_index += 1
            self.update(self.frames[self.frame_index])
        else:
            # Animation complete, stop
            self.animation_active = False

    def stop_animation(self) -> None:
        """Stop the animation."""
        self.animation_active = False


class CodebaseTree(Container):
    """Codebase file tree with language detection."""

    DEFAULT_CSS = """
    CodebaseTree {
        height: 1fr;
        background: #0D1117;
        border: round #30363D;
    }

    CodebaseTree Tree {
        height: 100%;
        background: #0D1117;
        scrollbar-size: 1 1;
    }

    CodebaseTree .empty-state {
        height: 100%;
        content-align: center middle;
        text-align: center;
        color: #7D8590;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.current_path = None
        self.stats: Dict = {}

    def compose(self) -> ComposeResult:
        yield AnimatedBanner(classes="empty-state", id="tree-empty")

    def load_path(self, path: Path) -> Dict:
        """Load codebase and return stats."""
        # If already loaded for this path, just return cached stats
        if self.current_path == path and self.stats:
            return self.stats

        self.current_path = path
        stats = self._analyze_codebase(path)
        self.stats = stats

        # Remove empty state
        try:
            empty = self.query_one("#tree-empty")
            empty.remove()
        except Exception:
            pass

        # Remove existing tree if it exists
        try:
            old_tree = self.query_one("#code-tree", Tree)
            old_tree.remove()
        except Exception:
            pass

        # Create new tree
        tree = Tree(f"[{COLORS['cyan']}]{path.name}[/]", id="code-tree")
        tree.root.expand()
        self._build_tree(tree.root, path, max_depth=3)
        self.mount(tree)

        return stats

    def _analyze_codebase(self, path: Path) -> Dict:
        """Analyze codebase and return statistics."""
        stats = {
            'total_files': 0,
            'code_files': 0,
            'total_size': 0,
            'languages': set(),
            'by_language': {},
        }

        code_ext = {
            '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
            '.jsx': 'React', '.tsx': 'React', '.java': 'Java',
            '.go': 'Go', '.rs': 'Rust', '.c': 'C', '.cpp': 'C++',
            '.cs': 'C#', '.rb': 'Ruby', '.php': 'PHP', '.swift': 'Swift',
            '.kt': 'Kotlin', '.scala': 'Scala', '.sql': 'SQL',
        }

        try:
            for f in path.rglob('*'):
                if f.is_file() and not any(p.startswith('.') for p in f.parts):
                    stats['total_files'] += 1
                    try:
                        stats['total_size'] += f.stat().st_size
                    except:
                        pass

                    ext = f.suffix.lower()
                    if ext in code_ext:
                        stats['code_files'] += 1
                        lang = code_ext[ext]
                        stats['languages'].add(lang)
                        stats['by_language'][lang] = stats['by_language'].get(lang, 0) + 1
        except:
            pass

        return stats

    def _build_tree(self, node: TreeNode, path: Path, max_depth: int, depth: int = 0) -> None:
        """Build tree structure."""
        if depth >= max_depth:
            return

        try:
            items = sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
            dirs = [i for i in items if i.is_dir() and not i.name.startswith('.')]
            files = [i for i in items if i.is_file() and not i.name.startswith('.')]

            # Add directories first
            for d in dirs[:10]:  # Limit
                color = COLORS['purple']
                child = node.add(f"[{color}]📁 {d.name}[/]", expand=False)
                self._build_tree(child, d, max_depth, depth + 1)

            # Add files
            for f in files[:15]:  # Limit
                color = self._get_file_color(f.suffix)
                node.add_leaf(f"[{color}]{f.name}[/]")

            if len(dirs) > 10 or len(files) > 15:
                node.add_leaf(f"[{COLORS['muted']}]... more files[/]")
        except:
            pass

    def _get_file_color(self, ext: str) -> str:
        """Get color based on file extension."""
        ext = ext.lower()
        if ext in ['.py', '.js', '.ts', '.java', '.go', '.rs']:
            return COLORS['green']
        elif ext in ['.json', '.yml', '.yaml', '.toml']:
            return COLORS['orange']
        elif ext in ['.md', '.txt', '.rst']:
            return COLORS['yellow']
        elif ext in ['.html', '.css', '.jsx', '.tsx']:
            return COLORS['pink']
        return COLORS['muted']


class ScanInfo(Container):
    """Scan configuration and rules info."""

    DEFAULT_CSS = """
    ScanInfo {
        height: auto;
        background: #161B22;
        border: round #30363D;
        padding: 1;
        margin: 0 0 1 0;
    }

    ScanInfo .info-title {
        color: #00D4FF;
        text-style: bold;
        margin: 0 0 1 0;
    }

    ScanInfo .info-row {
        height: 2;
    }

    ScanInfo .stats-row {
        height: 2;
        layout: horizontal;
    }

    ScanInfo .stat-item {
        width: 1fr;
        text-align: center;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("◈ Scan Configuration", classes="info-title")
        
        with Horizontal(classes="stats-row"):
            yield Static(f"[{COLORS['cyan']}]--[/] files", classes="stat-item", id="info-files")
            yield Static(f"[{COLORS['green']}]--[/] code", classes="stat-item", id="info-code")
            yield Static(f"[{COLORS['orange']}]--[/] MB", classes="stat-item", id="info-size")

        yield Static(f"[{COLORS['muted']}]Languages:[/] [#7D8590]--[/]", classes="info-row", id="info-langs")
        yield Static(f"[{COLORS['muted']}]Semgrep:[/] [{COLORS['green']}]● Ready[/]", classes="info-row", id="info-semgrep")
        yield Static(f"[{COLORS['muted']}]AI Valid:[/] [{COLORS['orange']}]○ Not configured[/]", classes="info-row", id="info-ai")

    def update_stats(self, stats: Dict) -> None:
        """Update stats display."""
        try:
            self.query_one("#info-files", Static).update(
                f"[{COLORS['cyan']}]{stats.get('total_files', '--')}[/] files"
            )
            self.query_one("#info-code", Static).update(
                f"[{COLORS['green']}]{stats.get('code_files', '--')}[/] code"
            )
            size_mb = stats.get('total_size', 0) / (1024 * 1024)
            self.query_one("#info-size", Static).update(
                f"[{COLORS['orange']}]{size_mb:.1f}[/] MB"
            )

            langs = list(stats.get('languages', []))[:4]
            lang_str = ", ".join(langs) if langs else "--"
            self.query_one("#info-langs", Static).update(
                f"[{COLORS['muted']}]Languages:[/] [{COLORS['purple']}]{lang_str}[/]"
            )
        except:
            pass

    def update_ai_status(self, provider: str, enabled: bool) -> None:
        """Update AI status."""
        try:
            if provider and provider != "none":
                self.query_one("#info-ai", Static).update(
                    f"[{COLORS['muted']}]AI Valid:[/] [{COLORS['green']}]● {provider}[/]"
                )
            else:
                self.query_one("#info-ai", Static).update(
                    f"[{COLORS['muted']}]AI Valid:[/] [{COLORS['orange']}]○ Disabled[/]"
                )
        except:
            pass


class ProgressLog(Container):
    """Minimal progress log."""

    DEFAULT_CSS = """
    ProgressLog {
        height: 1fr;
        background: #0D1117;
        border: round #30363D;
        padding: 1;
    }

    ProgressLog .log-title {
        color: #00D4FF;
        text-style: bold;
        margin: 0 0 1 0;
    }

    ProgressLog .log-content {
        height: 1fr;
        background: #0D1117;
        overflow-y: auto;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.messages = []

    def compose(self) -> ComposeResult:
        yield Static("◈ Activity", classes="log-title")
        yield Static(f"[{COLORS['muted']}]Ready to scan...[/]", classes="log-content", id="log-content")

    def log(self, message: str, style: str = "cyan") -> None:
        """Add a log message with real-time update."""
        import time
        ts = time.strftime("%H:%M:%S")
        
        # Parse style from message if it contains markup
        if message.startswith("[") and "]" in message:
            self.messages.append(f"[{COLORS['muted']}]{ts}[/] {message}")
        else:
            color = COLORS.get(style, COLORS["cyan"])
            self.messages.append(f"[{COLORS['muted']}]{ts}[/] [{color}]{message}[/]")
        
        # Keep last 30 messages
        if len(self.messages) > 30:
            self.messages = self.messages[-30:]

        try:
            content = "\n".join(self.messages) if self.messages else f"[{COLORS['muted']}]Ready...[/]"
            log_widget = self.query_one("#log-content", Static)
            log_widget.update(content)
            # Force refresh
            log_widget.refresh()
        except:
            pass
    
    def clear(self) -> None:
        """Clear all log messages."""
        self.messages = []
        try:
            self.query_one("#log-content", Static).update(f"[{COLORS['muted']}]Ready to scan...[/]")
        except:
            pass


class OverviewPanel(Container):
    """Overview panel - codebase tree and config."""

    DEFAULT_CSS = """
    OverviewPanel {
        height: 100%;
        width: 100%;
        background: #0D1117;
        layout: horizontal;
    }

    OverviewPanel .left-column {
        width: 50;
        min-width: 45;
        height: 100%;
        layout: vertical;
        background: #161B22;
        border-right: heavy #30363D;
        padding: 1;
    }

    OverviewPanel .right-column {
        width: 1fr;
        height: 100%;
        layout: vertical;
        background: #0D1117;
        padding: 1;
    }

    OverviewPanel .tree-section {
        height: 1fr;
    }

    OverviewPanel .log-section {
        height: 1fr;
        margin: 1 0 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        # Left: Config & Info
        with Vertical(classes="left-column"):
            yield ConfigPanel()
            yield ScanInfo()

        # Right: Codebase Tree + Activity Log
        with Vertical(classes="right-column"):
            with Container(classes="tree-section"):
                yield CodebaseTree()
            with Container(classes="log-section"):
                yield ProgressLog()
