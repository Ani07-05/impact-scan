"""Path Browser Modal Screen"""

import platform
from pathlib import Path

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Static

from ..theme import MODAL_CSS


class PathBrowserModal(ModalScreen[str]):
    """Minimalist path browser for selecting scan directories."""

    DEFAULT_CSS = MODAL_CSS

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
        Binding("enter", "select_path", "Select"),
        Binding("backspace", "go_back", "Go Back"),
        Binding("h", "go_home", "Home"),
        Binding("r", "go_root", "Root"),
    ]

    def __init__(self, current_path: Path = None) -> None:
        """
        Initialize path browser.

        Args:
            current_path: Initial directory to show
        """
        super().__init__()
        self.current_path = current_path or Path.cwd()
        self.selected_path = self.current_path

    def compose(self) -> ComposeResult:
        """Compose path browser UI."""
        with Container(classes="browser-container"):
            yield Static("Select Target Directory", classes="browser-header")

            # Quick access shortcuts
            with Horizontal(classes="browser-shortcuts"):
                yield Button("Home", variant="default", classes="shortcut-btn", id="go-home-btn")
                yield Button("Root (/)", variant="default", classes="shortcut-btn", id="go-root-btn")
                if platform.system() == "Windows":
                    yield Button("C:\\", variant="default", classes="shortcut-btn", id="go-c-drive")
                    yield Button("D:\\", variant="default", classes="shortcut-btn", id="go-d-drive")
                else:
                    yield Button("/tmp", variant="default", classes="shortcut-btn", id="go-tmp")
                    yield Button("/var", variant="default", classes="shortcut-btn", id="go-var")

            with Vertical(classes="browser-content"):
                yield DirectoryTree(
                    str(self.current_path), classes="path-tree", id="path-tree"
                )

            with Horizontal(classes="browser-actions"):
                yield Button(
                    "Select", variant="success", classes="action-btn", id="select-path"
                )
                yield Button(
                    "Parent Dir", variant="primary", classes="action-btn", id="go-back"
                )
                yield Button(
                    "Cancel", variant="default", classes="action-btn", id="cancel-path"
                )

    @on(DirectoryTree.DirectorySelected)
    def on_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        """Handle directory selection."""
        self.selected_path = Path(event.path)

    @on(Button.Pressed, "#select-path")
    def select_path(self) -> None:
        """Select current path and close modal."""
        self.dismiss(str(self.selected_path))

    @on(Button.Pressed, "#go-back")
    def go_back(self) -> None:
        """Navigate to parent directory."""
        tree = self.query_one("#path-tree", DirectoryTree)
        current = Path(tree.path)

        # Navigate to parent if not already at root
        if current.parent != current:  # Not at filesystem root
            parent_path = current.parent
            tree.path = str(parent_path)
            tree.reload()
            self.selected_path = parent_path

    @on(Button.Pressed, "#go-home-btn")
    def go_home_btn(self) -> None:
        """Navigate to home directory via button."""
        self._navigate_to(Path.home())

    @on(Button.Pressed, "#go-root-btn")
    def go_root_btn(self) -> None:
        """Navigate to root directory via button."""
        self._navigate_to(Path("/"))

    @on(Button.Pressed, "#go-c-drive")
    def go_c_drive(self) -> None:
        """Navigate to C: drive (Windows)."""
        self._navigate_to(Path("C:\\"))

    @on(Button.Pressed, "#go-d-drive")
    def go_d_drive(self) -> None:
        """Navigate to D: drive (Windows)."""
        self._navigate_to(Path("D:\\"))

    @on(Button.Pressed, "#go-tmp")
    def go_tmp(self) -> None:
        """Navigate to /tmp directory."""
        self._navigate_to(Path("/tmp"))

    @on(Button.Pressed, "#go-var")
    def go_var(self) -> None:
        """Navigate to /var directory."""
        self._navigate_to(Path("/var"))

    def _navigate_to(self, path: Path) -> None:
        """Navigate to a specific directory."""
        if path.exists() and path.is_dir():
            tree = self.query_one("#path-tree", DirectoryTree)
            tree.path = str(path)
            tree.reload()
            self.selected_path = path

    @on(Button.Pressed, "#cancel-path")
    def cancel_path(self) -> None:
        """Cancel and close modal."""
        self.dismiss(None)

    def action_dismiss(self) -> None:
        """Cancel via Esc key."""
        self.dismiss(None)

    def action_select_path(self) -> None:
        """Select via Enter key."""
        self.dismiss(str(self.selected_path))

    def action_go_back(self) -> None:
        """Go back to parent directory via Backspace key."""
        self.go_back()

    def action_go_home(self) -> None:
        """Navigate to home directory via 'h' key."""
        self._navigate_to(Path.home())

    def action_go_root(self) -> None:
        """Navigate to root directory via 'r' key."""
        self._navigate_to(Path("/"))
