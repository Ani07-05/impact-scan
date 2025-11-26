"""
Interactive Knowledge Graph Visualization.

Shows relationships between files, functions, and vulnerabilities
as they're discovered during scanning.
"""

from pathlib import Path
from typing import Dict, List, Set, Optional
from rich.console import Console
from rich.tree import Tree
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout


class KnowledgeGraphViz:
    """
    Visualize knowledge graph relationships.

    Shows:
    - File dependencies (imports)
    - Function call graph
    - Vulnerability connections
    - Entry points and data flow
    """

    def __init__(self, root_path: Path):
        self.root_path = root_path
        self.files: Set[str] = set()
        self.imports: Dict[str, List[str]] = {}  # file -> [imported files]
        self.functions: Dict[str, List[str]] = {}  # file -> [functions]
        self.vulnerabilities: Dict[str, int] = {}  # file -> count
        self.entry_points: List[str] = []
        self.console = Console()

    def add_file(self, file_path: str):
        """Add a file to the graph."""
        self.files.add(file_path)

    def add_import(self, file_path: str, imported_file: str):
        """Add an import relationship."""
        if file_path not in self.imports:
            self.imports[file_path] = []
        self.imports[file_path].append(imported_file)

    def add_function(self, file_path: str, function_name: str):
        """Add a function to a file."""
        if file_path not in self.functions:
            self.functions[file_path] = []
        self.functions[file_path].append(function_name)

    def add_vulnerability(self, file_path: str):
        """Add a vulnerability to a file."""
        self.vulnerabilities[file_path] = self.vulnerabilities.get(file_path, 0) + 1

    def mark_entry_point(self, file_path: str):
        """Mark a file as an entry point."""
        if file_path not in self.entry_points:
            self.entry_points.append(file_path)

    def build_graph_tree(self) -> Tree:
        """Build a visual tree showing relationships."""
        # Root node
        tree = Tree(
            f"[bold cyan]Knowledge Graph[/bold cyan] [dim]({len(self.files)} files)[/dim]",
            guide_style="cyan dim"
        )

        # Entry points section
        if self.entry_points:
            entry_node = tree.add("[bold yellow]Entry Points[/bold yellow]", guide_style="yellow dim")
            for ep in self.entry_points:
                ep_display = Path(ep).name
                ep_node = entry_node.add(f"[yellow]{ep_display}[/yellow]")

                # Show what this entry point imports
                if ep in self.imports:
                    imports_node = ep_node.add("[dim]imports:[/dim]")
                    for imp in self.imports[ep][:3]:  # Show first 3
                        imports_node.add(f"[cyan]└─ {Path(imp).name}[/cyan]")

                # Show functions
                if ep in self.functions:
                    func_count = len(self.functions[ep])
                    ep_node.add(f"[dim]{func_count} functions[/dim]")

        # Files with vulnerabilities
        if self.vulnerabilities:
            vuln_node = tree.add(
                f"[bold red]Vulnerable Files[/bold red] [dim]({len(self.vulnerabilities)})[/dim]",
                guide_style="red dim"
            )
            for file_path, count in sorted(self.vulnerabilities.items(), key=lambda x: -x[1]):
                file_name = Path(file_path).name
                vuln_node.add(f"[red]{file_name}[/red] [dim]({count} issues)[/dim]")

        # Dependency graph
        if self.imports:
            dep_node = tree.add(
                f"[bold cyan]Dependencies[/bold cyan] [dim]({len(self.imports)} files)[/dim]",
                guide_style="cyan dim"
            )
            # Show files with most imports (highly connected)
            most_connected = sorted(self.imports.items(), key=lambda x: -len(x[1]))[:5]
            for file_path, imports in most_connected:
                file_name = Path(file_path).name
                file_node = dep_node.add(f"[cyan]{file_name}[/cyan] [dim]({len(imports)} imports)[/dim]")
                for imp in imports[:2]:  # Show first 2
                    file_node.add(f"[dim]└─ {Path(imp).name}[/dim]")

        return tree

    def build_stats_table(self) -> Table:
        """Build statistics table."""
        stats = Table.grid(padding=(0, 2))
        stats.add_column(style="dim cyan", justify="right")
        stats.add_column(style="white")

        stats.add_row("Files:", str(len(self.files)))
        stats.add_row("Entry Points:", str(len(self.entry_points)))
        stats.add_row("Dependencies:", str(sum(len(v) for v in self.imports.values())))
        stats.add_row("Functions:", str(sum(len(v) for v in self.functions.values())))
        stats.add_row("Vulnerabilities:", str(sum(self.vulnerabilities.values())))

        return stats

    def display(self):
        """Display the knowledge graph."""
        self.console.print("\n")

        # Stats panel
        stats_panel = Panel(
            self.build_stats_table(),
            title="[bold cyan]Knowledge Graph Stats[/bold cyan]",
            border_style="cyan dim",
            padding=(1, 2)
        )
        self.console.print(stats_panel)

        # Graph tree
        self.console.print()
        graph_tree = self.build_graph_tree()
        self.console.print(graph_tree)
        self.console.print()


class LiveKnowledgeGraph:
    """
    Live-updating knowledge graph that builds as scan progresses.

    Shows relationships being discovered in real-time.
    """

    def __init__(self, root_path: Path):
        self.graph = KnowledgeGraphViz(root_path)
        self.live = None
        self.console = Console()

    def _build_display(self) -> Panel:
        """Build the live display."""
        layout = Layout()
        layout.split_column(
            Layout(self.graph.build_stats_table(), size=7),
            Layout(self.graph.build_graph_tree())
        )

        return Panel(
            layout,
            title="[bold cyan]Building Knowledge Graph[/bold cyan]",
            border_style="cyan dim",
            padding=(1, 2)
        )

    def start(self):
        """Start live display."""
        self.live = Live(
            self._build_display(),
            console=self.console,
            refresh_per_second=2,
            transient=True
        )
        self.live.start()

    def update(self):
        """Update the display."""
        if self.live:
            self.live.update(self._build_display())

    def stop(self):
        """Stop live display."""
        if self.live:
            self.live.stop()
        # Show final graph
        self.graph.display()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
