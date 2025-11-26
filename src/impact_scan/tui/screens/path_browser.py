"""Path Browser Modal Screen"""

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

            with Vertical(classes="browser-content"):
                yield DirectoryTree(
                    str(self.current_path), classes="path-tree", id="path-tree"
                )

            with Horizontal(classes="browser-actions"):
                yield Button(
                    "Select", variant="success", classes="action-btn", id="select-path"
                )
                yield Button(
                    "Home", variant="primary", classes="action-btn", id="go-home"
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

    @on(Button.Pressed, "#go-home")
    def go_home(self) -> None:
        """Navigate to home directory."""
        home_path = Path.home()
        tree = self.query_one("#path-tree", DirectoryTree)
        tree.path = str(home_path)
        tree.reload()
        self.selected_path = home_path

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
