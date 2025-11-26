"""
Animated Knowledge Graph Tree Visualization.

Shows the repository structure being scanned in real-time using Rich Tree + Live.
This is a unique differentiator - no other security scanner visualizes the scan like this!
"""

from pathlib import Path
from typing import Dict, Set
from rich.live import Live
from rich.tree import Tree
from rich.text import Text
from rich.console import Console


class KnowledgeGraphTree:
    """
    Live-updating tree visualization of repository being scanned.

    Shows real-time progress:
    - [OK] Files analyzed (with finding count)
    - [>>] Files in progress
    - [DIR] Directories
    - [X] Errors
    - [-] Skipped (tutorial/test code)
    """

    def __init__(self, root_path: Path, total_files: int = 0):
        """
        Initialize knowledge graph tree.

        Args:
            root_path: Root directory being scanned
            total_files: Total number of files to scan
        """
        self.root_path = root_path
        self.total_files = total_files
        self.analyzed_count = 0
        self.finding_count = 0

        # Track file states
        self.analyzed_files: Set[str] = set()
        self.in_progress_files: Set[str] = set()
        self.skipped_files: Set[str] = set()
        self.error_files: Set[str] = set()
        self.file_findings: Dict[str, int] = {}

        # Build initial tree
        self.tree = Tree(
            f"[DIR] Repository: {root_path.name} ({total_files} files)",
            guide_style="cyan dim"
        )

        # Directory nodes cache
        self._dir_nodes: Dict[str, Tree] = {}

    def mark_analyzing(self, file_path: Path):
        """Mark a file as currently being analyzed."""
        rel_path = str(file_path.relative_to(self.root_path))
        self.in_progress_files.add(rel_path)

    def mark_analyzed(self, file_path: Path, finding_count: int = 0):
        """Mark a file as analyzed with finding count."""
        try:
            rel_path = str(file_path.relative_to(self.root_path))
        except ValueError:
            # File is not relative to root_path, use absolute path
            rel_path = str(file_path)
        self.in_progress_files.discard(rel_path)
        self.analyzed_files.add(rel_path)
        self.file_findings[rel_path] = finding_count
        self.analyzed_count += 1
        self.finding_count += finding_count

    def mark_skipped(self, file_path: Path, reason: str = ""):
        """Mark a file as skipped (tutorial/test code)."""
        rel_path = str(file_path.relative_to(self.root_path))
        self.in_progress_files.discard(rel_path)
        self.skipped_files.add(rel_path)

    def mark_error(self, file_path: Path, error: str = ""):
        """Mark a file as having an error."""
        rel_path = str(file_path.relative_to(self.root_path))
        self.in_progress_files.discard(rel_path)
        self.error_files.add(rel_path)

    def _get_dir_node(self, dir_path: str) -> Tree:
        """Get or create a directory node in the tree."""
        if dir_path in self._dir_nodes:
            return self._dir_nodes[dir_path]

        parts = Path(dir_path).parts
        current_path = ""
        parent_node = self.tree

        for part in parts:
            current_path = str(Path(current_path) / part) if current_path else part

            if current_path not in self._dir_nodes:
                dir_node = parent_node.add(f"[DIR] {part}/", guide_style="cyan dim")
                self._dir_nodes[current_path] = dir_node

            parent_node = self._dir_nodes[current_path]

        return parent_node

    def build_tree(self, max_files_shown: int = 50) -> Tree:
        """
        Build the current tree view.

        Args:
            max_files_shown: Maximum files to show (to avoid clutter)

        Returns:
            Updated Rich Tree
        """
        # Rebuild tree
        self.tree = Tree(
            f"[DIR] Repository: {self.root_path.name} ({self.total_files} files)",
            guide_style="cyan dim"
        )
        self._dir_nodes = {}

        # Group files by directory
        files_by_dir: Dict[str, list] = {}

        all_files = (
            list(self.analyzed_files)[:max_files_shown]
            + list(self.in_progress_files)
            + list(self.skipped_files)[:10]  # Limit skipped
            + list(self.error_files)
        )

        for file_path in all_files:
            dir_path = str(Path(file_path).parent) if "/" in file_path else ""
            if dir_path not in files_by_dir:
                files_by_dir[dir_path] = []
            files_by_dir[dir_path].append(file_path)

        # Add files to tree
        for dir_path, files in sorted(files_by_dir.items()):
            if dir_path:
                parent_node = self._get_dir_node(dir_path)
            else:
                parent_node = self.tree

            for file_path in sorted(files):
                filename = Path(file_path).name

                if file_path in self.analyzed_files:
                    findings = self.file_findings.get(file_path, 0)
                    if findings > 0:
                        label = Text()
                        label.append("[OK] ", style="green")
                        label.append(filename, style="white")
                        label.append(f" ({findings} findings)", style="yellow")
                        parent_node.add(label)
                    else:
                        parent_node.add(f"[OK] {filename} (clean)", style="green dim")

                elif file_path in self.in_progress_files:
                    label = Text()
                    label.append("[>>] ", style="yellow")
                    label.append(filename, style="yellow")
                    label.append(" (analyzing...)", style="dim")
                    parent_node.add(label)

                elif file_path in self.skipped_files:
                    parent_node.add(f"[-] {filename} (skipped)", style="dim")

                elif file_path in self.error_files:
                    parent_node.add(f"[X] {filename} (error)", style="red")

        return self.tree

    def get_summary_text(self) -> Text:
        """Get summary statistics text."""
        summary = Text()
        summary.append("\nKnowledge Graph: ", style="bold cyan")
        summary.append(f"{self.total_files} files indexed", style="white")
        summary.append(" • ", style="dim")
        summary.append(f"{self.analyzed_count} analyzed", style="green")
        summary.append(" • ", style="dim")
        summary.append(f"{self.finding_count} findings", style="yellow" if self.finding_count > 0 else "green")

        if len(self.in_progress_files) > 0:
            summary.append(" • ", style="dim")
            summary.append(f"{len(self.in_progress_files)} in progress", style="cyan")

        return summary


class LiveKnowledgeGraphTree:
    """
    Context manager for live-updating knowledge graph tree.

    Usage:
        with LiveKnowledgeGraphTree(root_path, total_files) as kg_tree:
            kg_tree.mark_analyzing(file1)
            kg_tree.mark_analyzed(file1, finding_count=2)
            kg_tree.update()  # Refresh display
    """

    def __init__(self, root_path: Path, total_files: int = 0, console: Console | None = None):
        """
        Initialize live tree.

        Args:
            root_path: Root directory being scanned
            total_files: Total number of files
            console: Rich Console (creates new if None)
        """
        self.kg_tree = KnowledgeGraphTree(root_path, total_files)
        self.console = console or Console()
        self.live = None

    def __enter__(self):
        """Start live display."""
        self.live = Live(
            self.kg_tree.build_tree(),
            console=self.console,
            refresh_per_second=4,  # 4 FPS for smooth animation
            vertical_overflow="visible"
        )
        self.live.__enter__()
        return self.kg_tree

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop live display and show final summary."""
        if self.live:
            # Update with final tree
            self.live.update(self.kg_tree.build_tree())
            self.live.__exit__(exc_type, exc_val, exc_tb)

            # Print summary
            self.console.print(self.kg_tree.get_summary_text())
            self.console.print()

    def update(self):
        """Manually update the live display (call after marking files)."""
        if self.live:
            self.live.update(self.kg_tree.build_tree())
