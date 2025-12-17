"""
Finding Detail Modal Screen
Shows detailed information about a security finding with syntax highlighting and markdown rendering.
"""

from pathlib import Path
from typing import Optional

from rich.markdown import Markdown
from rich.syntax import Syntax
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from impact_scan.utils.schema import Finding


class FindingDetailModal(ModalScreen[None]):
    """Modal screen showing detailed finding information."""

    DEFAULT_CSS = """
    FindingDetailModal {
        align: center middle;
        background: $background 90%;
    }

    .detail-container {
        width: 120;
        height: 50;
        background: $surface;
        border: thick $primary;
    }

    .detail-header {
        height: 4;
        background: $primary;
        color: white;
        padding: 1 2;
        border-bottom: solid white;
    }

    .header-title {
        text-style: bold;
        height: 1;
    }

    .header-subtitle {
        text-style: italic;
        color: $accent;
        height: 1;
    }

    .detail-content {
        height: 1fr;
        padding: 2;
        background: $surface;
    }

    .info-section {
        height: auto;
        margin: 0 0 2 0;
        padding: 1;
        border: solid $primary-darken-2;
        background: $surface-darken-1;
    }

    .section-title {
        text-style: bold underline;
        color: $primary;
        margin: 0 0 1 0;
    }

    .code-section {
        height: auto;
        margin: 1 0;
        border: solid $accent;
        background: $background;
    }

    .markdown-section {
        height: auto;
        margin: 1 0;
        padding: 1;
        border: solid $primary-darken-2;
        background: $surface-lighten-1;
    }

    .detail-actions {
        height: 5;
        background: $surface-darken-1;
        padding: 1 2;
        border-top: thick $primary;
        align: center middle;
    }

    .action-btn {
        min-width: 16;
        height: 3;
        margin: 0 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
    ]

    def __init__(self, finding: Finding, code_snippet: Optional[str] = None) -> None:
        """
        Initialize finding detail modal.

        Args:
            finding: The security finding to display
            code_snippet: Optional code snippet to show with syntax highlighting
        """
        super().__init__()
        self.finding = finding
        self.code_snippet = code_snippet

    def compose(self) -> ComposeResult:
        """Compose the finding detail modal."""
        with Vertical(classes="detail-container"):
            # Header with finding title and severity
            with Container(classes="detail-header"):
                severity_icon = self._get_severity_icon(self.finding.severity.value)
                title = self.finding.title or "Security Finding"
                yield Static(
                    f"{severity_icon} {title}",
                    classes="header-title"
                )
                yield Static(
                    f"{self.finding.severity.value.upper()} | {self.finding.file_path}:{self.finding.line_number or '?'}",
                    classes="header-subtitle"
                )

            # Scrollable content
            with VerticalScroll(classes="detail-content"):
                # Basic information section
                with Container(classes="info-section"):
                    yield Static("📋 Finding Information", classes="section-title")
                    yield Static(f"Vulnerability ID: {self.finding.vuln_id or self.finding.rule_id or 'N/A'}")
                    yield Static(f"Severity: {self.finding.severity.value.upper()}")
                    yield Static(f"File: {self.finding.file_path}")
                    if self.finding.line_number:
                        yield Static(f"Line: {self.finding.line_number}")
                    if self.finding.confidence:
                        yield Static(f"Confidence: {self.finding.confidence}")

                # Description as markdown
                if self.finding.description:
                    with Container(classes="markdown-section"):
                        yield Static("📝 Description", classes="section-title")
                        # Render description as markdown
                        markdown_content = Markdown(self.finding.description)
                        yield Static(markdown_content)

                # Recommendation as markdown
                if self.finding.recommendation:
                    with Container(classes="markdown-section"):
                        yield Static("💡 Recommendation", classes="section-title")
                        markdown_content = Markdown(self.finding.recommendation)
                        yield Static(markdown_content)

                # Code snippet with syntax highlighting
                if self.code_snippet:
                    with Container(classes="code-section"):
                        yield Static("🔍 Code Snippet", classes="section-title")
                        # Detect file extension for syntax highlighting
                        file_ext = Path(str(self.finding.file_path)).suffix.lstrip(".")
                        lexer = self._get_lexer(file_ext)

                        syntax = Syntax(
                            self.code_snippet,
                            lexer,
                            theme="monokai",
                            line_numbers=True,
                            start_line=max(1, (self.finding.line_number or 1) - 5),
                            highlight_lines={self.finding.line_number} if self.finding.line_number else set(),
                        )
                        yield Static(syntax)

                # CWE/OWASP information
                if self.finding.cwe or self.finding.owasp:
                    with Container(classes="info-section"):
                        yield Static("🔐 Security Standards", classes="section-title")
                        if self.finding.cwe:
                            yield Static(f"CWE: {self.finding.cwe}")
                        if self.finding.owasp:
                            yield Static(f"OWASP: {self.finding.owasp}")

                # References
                if self.finding.references:
                    with Container(classes="info-section"):
                        yield Static("🔗 References", classes="section-title")
                        for ref in self.finding.references[:5]:  # Limit to 5
                            yield Static(f"  • {ref}")

            # Action buttons
            with Horizontal(classes="detail-actions"):
                yield Button(
                    "📋 Copy Path",
                    variant="primary",
                    classes="action-btn",
                    id="copy-path"
                )
                yield Button(
                    "📝 Copy Details",
                    variant="default",
                    classes="action-btn",
                    id="copy-details"
                )
                yield Button(
                    "✕ Close",
                    variant="error",
                    classes="action-btn",
                    id="close"
                )

    def _get_severity_icon(self, severity: str) -> str:
        """Get icon for severity level."""
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
        }
        return icons.get(severity.lower(), "⚪")

    def _get_lexer(self, file_ext: str) -> str:
        """Get syntax lexer based on file extension."""
        lexer_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "jsx": "jsx",
            "tsx": "tsx",
            "java": "java",
            "go": "go",
            "rs": "rust",
            "c": "c",
            "cpp": "cpp",
            "cs": "csharp",
            "php": "php",
            "rb": "ruby",
            "sh": "bash",
            "yml": "yaml",
            "yaml": "yaml",
            "json": "json",
            "xml": "xml",
            "html": "html",
            "css": "css",
            "sql": "sql",
        }
        return lexer_map.get(file_ext.lower(), "text")

    @on(Button.Pressed, "#copy-path")
    def copy_path(self) -> None:
        """Copy file path to clipboard."""
        # In a real implementation, this would use pyperclip or similar
        self.app.notify(f"Path copied: {self.finding.file_path}")

    @on(Button.Pressed, "#copy-details")
    def copy_details(self) -> None:
        """Copy finding details to clipboard."""
        details = f"""
Security Finding: {self.finding.title or 'N/A'}
Severity: {self.finding.severity.value.upper()}
File: {self.finding.file_path}
Line: {self.finding.line_number or 'N/A'}

Description:
{self.finding.description or 'N/A'}

Recommendation:
{self.finding.recommendation or 'N/A'}
"""
        self.app.notify("Finding details copied to clipboard")

    @on(Button.Pressed, "#close")
    def close_modal(self) -> None:
        """Close the modal."""
        self.dismiss()

    def action_dismiss(self) -> None:
        """Dismiss via Esc key."""
        self.dismiss()
