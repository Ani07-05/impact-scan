"""
Codebase Explorer Widget
Shows directory tree visualization and codebase statistics.
Vibrant cyberpunk styling.
"""

from pathlib import Path
from typing import Dict, List, Optional

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Tree
from textual.widgets.tree import TreeNode

# Vibrant color palette
COLORS = {
    "pink": "#FF6EC7",
    "cyan": "#00D4FF",
    "green": "#50FA7B",
    "orange": "#FFB86C",
    "purple": "#BD93F9",
    "yellow": "#F1FA8C",
    "red": "#FF5555",
    "muted": "#7D8590",
    "text": "#E6EDF3",
}


class CodebaseStats(Container):
    """Display minimal codebase statistics."""

    DEFAULT_CSS = """
    CodebaseStats {
        height: auto;
        padding: 0 1;
        background: #161B22;
        margin: 0;
    }

    CodebaseStats .stats-row {
        height: 2;
        layout: horizontal;
    }

    CodebaseStats .stat-item {
        width: 1fr;
        height: 2;
        text-align: center;
        content-align: center middle;
    }
    """

    def __init__(self) -> None:
        """Initialize codebase stats."""
        super().__init__()
        self.stats: Dict[str, int] = {}

    def compose(self) -> ComposeResult:
        """Compose the minimal stats display."""
        with Horizontal(classes="stats-row"):
            yield Static(f"[{COLORS['muted']}]-- files[/]", classes="stat-item", id="stat-files")
            yield Static(f"[{COLORS['muted']}]-- code[/]", classes="stat-item", id="stat-code")
            yield Static(f"[{COLORS['muted']}]-- MB[/]", classes="stat-item", id="stat-size")

    def update_stats(self, path: Path) -> None:
        """Calculate and update statistics for the codebase."""
        stats = self._calculate_stats(path)
        self.stats = stats

        size_mb = stats['total_size'] / (1024 * 1024)
        
        self.query_one("#stat-files", Static).update(
            f"[{COLORS['cyan']}]{stats['total_files']}[/] [{COLORS['muted']}]files[/]"
        )
        self.query_one("#stat-code", Static).update(
            f"[{COLORS['green']}]{stats['code_files']}[/] [{COLORS['muted']}]code[/]"
        )
        self.query_one("#stat-size", Static).update(
            f"[{COLORS['orange']}]{size_mb:.1f}[/] [{COLORS['muted']}]MB[/]"
        )

    def _calculate_stats(self, path: Path) -> Dict[str, int]:
        """Calculate statistics for the codebase."""
        stats = {
            'total_files': 0,
            'total_dirs': 0,
            'code_files': 0,
            'total_size': 0,
            'file_types': 0,
            'avg_file_size': 0,
        }

        file_extensions = set()
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
            '.c', '.cpp', '.h', '.hpp', '.cs', '.php', '.rb', '.swift',
            '.kt', '.scala', '.r', '.m', '.sql', '.sh', '.bash'
        }

        try:
            for item in path.rglob('*'):
                # Skip hidden files and common ignore patterns
                if any(part.startswith('.') for part in item.parts):
                    continue
                if any(skip in str(item) for skip in ['node_modules', '__pycache__', 'venv', '.git']):
                    continue

                if item.is_file():
                    stats['total_files'] += 1
                    try:
                        size = item.stat().st_size
                        stats['total_size'] += size

                        ext = item.suffix.lower()
                        if ext:
                            file_extensions.add(ext)

                        if ext in code_extensions:
                            stats['code_files'] += 1
                    except (OSError, PermissionError):
                        pass

                elif item.is_dir():
                    stats['total_dirs'] += 1

            stats['file_types'] = len(file_extensions)
            if stats['total_files'] > 0:
                stats['avg_file_size'] = stats['total_size'] // stats['total_files']

        except (OSError, PermissionError):
            pass

        return stats


class CodebaseExplorer(Container):
    """Codebase explorer with tree visualization and statistics."""

    DEFAULT_CSS = """
    CodebaseExplorer {
        height: 100%;
        background: #161B22;
    }

    CodebaseExplorer .tree-container {
        height: 1fr;
        padding: 0;
        background: #0D1117;
        border: solid #30363D;
        margin: 1;
    }

    CodebaseExplorer Tree {
        height: 100%;
        background: #0D1117;
        scrollbar-size: 1 1;
    }

    CodebaseExplorer .empty-state {
        height: 100%;
        align: center middle;
        text-align: center;
        color: #7D8590;
        padding: 2;
    }
    """

    def __init__(self) -> None:
        """Initialize codebase explorer."""
        super().__init__()
        self.current_path: Optional[Path] = None

    def compose(self) -> ComposeResult:
        """Compose the codebase explorer."""
        yield CodebaseStats()

        with Container(classes="tree-container"):
            yield Static(
                f"[{COLORS['muted']}]No codebase loaded[/]\n\n"
                f"[{COLORS['cyan']}]Press 'b' to browse[/]",
                classes="empty-state",
                id="empty-state"
            )

    def load_codebase(self, path: Path) -> None:
        """Load and display codebase tree."""
        self.current_path = path

        try:
            # Update stats
            stats_widget = self.query_one(CodebaseStats)
            stats_widget.update_stats(path)

            # Remove empty state if present
            try:
                empty_state = self.query_one("#empty-state")
                empty_state.remove()
            except Exception:
                pass

            # Remove existing tree if present
            try:
                existing_tree = self.query_one("#codebase-tree", Tree)
                existing_tree.remove()
            except Exception:
                pass

            # Create new tree
            tree_container = self.query_one(".tree-container")
            tree = Tree(str(path.name), id="codebase-tree")
            tree.root.expand()

            # Build tree structure
            self._build_tree(tree.root, path, max_depth=4)

            # Mount and refresh
            tree_container.mount(tree)
            self.refresh()

        except Exception as e:
            # Log error but don't crash
            import logging
            logging.error(f"Error loading codebase: {e}", exc_info=True)
            self.app.notify(f"Error loading codebase: {str(e)}", severity="error")

    def _build_tree(
        self,
        node: TreeNode,
        path: Path,
        max_depth: int = 4,
        current_depth: int = 0
    ) -> None:
        """Recursively build directory tree with colorful labels."""
        if current_depth >= max_depth:
            return

        # Skip patterns
        skip_patterns = {
            'node_modules', '__pycache__', 'venv', '.venv', 'env',
            '.git', '.idea', '.vscode', 'dist', 'build', '.pytest_cache',
            '.ruff_cache', '.mypy_cache', 'coverage'
        }

        try:
            # Get all items and sort (directories first, then files)
            items = list(path.iterdir())
            dirs = sorted([item for item in items if item.is_dir() and item.name not in skip_patterns and not item.name.startswith('.')])
            files = sorted([item for item in items if item.is_file() and not item.name.startswith('.')])

            # Add directories with cyan/purple colors
            for dir_item in dirs[:20]:  # Limit to 20 per level
                label = Text()
                label.append("▸ ", style=COLORS["purple"])
                label.append(dir_item.name, style=f"bold {COLORS['cyan']}")

                dir_node = node.add(label, expand=False)
                dir_node.data = dir_item

                # Recursively add subdirectories
                if current_depth < max_depth - 1:
                    try:
                        if any(dir_item.iterdir()):  # Has children
                            self._build_tree(dir_node, dir_item, max_depth, current_depth + 1)
                    except (OSError, PermissionError):
                        pass

            # Add files with colorful styling
            for file_item in files[:30]:  # Limit to 30 files per directory
                color = self._get_file_color(file_item.suffix)
                label = Text()
                label.append("  ", style="dim")
                label.append(file_item.name, style=color)

                file_node = node.add_leaf(label)
                file_node.data = file_item

            # If there are more items, add indicator
            total_hidden = max(0, len(dirs) - 20) + max(0, len(files) - 30)
            if total_hidden > 0:
                label = Text(f"  ... +{total_hidden} more", style=COLORS["muted"])
                node.add_leaf(label)

        except (OSError, PermissionError):
            pass

    def _get_file_color(self, ext: str) -> str:
        """Get color for file based on extension."""
        ext_lower = ext.lower()
        
        # Code files - green
        code_exts = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.c', '.cpp', '.h'}
        if ext_lower in code_exts:
            return COLORS["green"]
        
        # Config files - orange
        config_exts = {'.json', '.yml', '.yaml', '.toml', '.ini', '.env'}
        if ext_lower in config_exts:
            return COLORS["orange"]
        
        # Doc files - yellow
        doc_exts = {'.md', '.txt', '.rst', '.doc'}
        if ext_lower in doc_exts:
            return COLORS["yellow"]
        
        # Web files - pink
        web_exts = {'.html', '.css', '.scss', '.sass'}
        if ext_lower in web_exts:
            return COLORS["pink"]
        
        return COLORS["text"]

    @on(Tree.NodeSelected, "#codebase-tree")
    def on_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle tree node selection."""
        if event.node.data:
            path = event.node.data
            if isinstance(path, Path):
                self.app.notify(f"[{COLORS['cyan']}]{path.name}[/]")
