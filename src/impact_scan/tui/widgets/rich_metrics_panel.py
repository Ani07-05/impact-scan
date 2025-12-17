"""
Rich Metrics Panel Widget
Enhanced metrics display with sparklines, trends, and visual indicators.
Vibrant cyberpunk styling.
"""

from typing import Dict, List

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, Grid, Horizontal, Vertical
from textual.widgets import Static

from impact_scan.utils.schema import ScanResult

# Vibrant color palette
COLORS = {
    "critical": "#FF5555",
    "high": "#FFB86C", 
    "medium": "#F1FA8C",
    "low": "#8BE9FD",
    "score": "#50FA7B",
    "total": "#BD93F9",
    "muted": "#7D8590",
    "accent": "#00D4FF",
    "pink": "#FF6EC7",
}


class SparklineWidget(Static):
    """Widget that displays a colorful sparkline chart."""

    def __init__(self, values: List[int], color: str = "#50FA7B", **kwargs) -> None:
        """Initialize sparkline widget."""
        super().__init__(**kwargs)
        self.values = values
        self.color = color

    def render(self) -> Text:
        """Render sparkline using block characters."""
        if not self.values:
            return Text("▁▁▁▁▁▁▁▁▁▁", style="#30363D")

        # Normalize values to 0-7 range for block characters
        max_val = max(self.values) if self.values else 1
        min_val = min(self.values) if self.values else 0
        range_val = max_val - min_val if max_val != min_val else 1

        # Unicode block characters for sparklines
        blocks = "▁▂▃▄▅▆▇█"

        sparkline = ""
        for val in self.values:
            normalized = int(((val - min_val) / range_val) * 7)
            sparkline += blocks[normalized]

        return Text(sparkline, style=self.color)


class RichMetricsPanel(Container):
    """Minimal metrics panel with vibrant colors."""

    DEFAULT_CSS = """
    RichMetricsPanel {
        height: auto;
        background: #161B22;
        padding: 1;
        border: solid #30363D;
    }

    RichMetricsPanel .metrics-row {
        height: 3;
        layout: horizontal;
        align: center middle;
    }

    RichMetricsPanel .metric-item {
        width: 1fr;
        height: 3;
        text-align: center;
        content-align: center middle;
        text-style: bold;
        border: solid #30363D;
        margin: 0 1 0 0;
    }

    RichMetricsPanel .metric-critical {
        border: solid #FF5555;
        color: #FF5555;
        background: #FF5555 10%;
    }

    RichMetricsPanel .metric-high {
        border: solid #FFB86C;
        color: #FFB86C;
        background: #FFB86C 10%;
    }

    RichMetricsPanel .metric-medium {
        border: solid #F1FA8C;
        color: #F1FA8C;
        background: #F1FA8C 5%;
    }

    RichMetricsPanel .metric-low {
        border: solid #8BE9FD;
        color: #8BE9FD;
        background: #8BE9FD 10%;
    }

    RichMetricsPanel .metric-score {
        border: solid #50FA7B;
        color: #50FA7B;
        background: #50FA7B 10%;
        margin: 0;
    }

    RichMetricsPanel .summary-bar {
        height: 2;
        padding: 0 1;
        margin: 1 0 0 0;
        content-align: center middle;
    }
    """

    def __init__(self) -> None:
        """Initialize metrics panel."""
        super().__init__()
        self.history: List[Dict[str, int]] = []

    def compose(self) -> ComposeResult:
        """Compose the minimal metrics panel."""
        with Horizontal(classes="metrics-row"):
            yield Static("0", classes="metric-item metric-critical", id="critical-value")
            yield Static("0", classes="metric-item metric-high", id="high-value")
            yield Static("0", classes="metric-item metric-medium", id="medium-value")
            yield Static("0", classes="metric-item metric-low", id="low-value")
            yield Static("--", classes="metric-item metric-score", id="score-value")

        yield Static(f"[{COLORS['muted']}]Ready to scan...[/]", classes="summary-bar", id="summary-bar")

    def update_metrics(self, scan_result: ScanResult) -> None:
        """Update metrics from scan result with vibrant colors."""
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for finding in scan_result.findings:
            severity = finding.severity.value.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        total_findings = len(scan_result.findings)
        security_score = scan_result.security_score or 0.0

        # Update metric values with vibrant colors
        critical_value = self.query_one("#critical-value", Static)
        critical_value.update(Text(str(severity_counts["critical"]), style=f"bold {COLORS['critical']}"))

        high_value = self.query_one("#high-value", Static)
        high_value.update(Text(str(severity_counts["high"]), style=f"bold {COLORS['high']}"))

        medium_value = self.query_one("#medium-value", Static)
        medium_value.update(Text(str(severity_counts["medium"]), style=f"bold {COLORS['medium']}"))

        low_value = self.query_one("#low-value", Static)
        low_value.update(Text(str(severity_counts["low"]), style=f"bold {COLORS['low']}"))

        score_value = self.query_one("#score-value", Static)
        score_style = self._get_score_style(security_score)
        score_value.update(Text(f"{security_score:.0f}%", style=score_style))

        # Update summary bar with colorful risk level
        summary = self.query_one("#summary-bar", Static)
        risk_level = self._calculate_risk_level(severity_counts)
        files_scanned = scan_result.metadata.get('files_scanned', 0)
        
        summary.update(
            f"[{COLORS['muted']}]Risk:[/] {risk_level}  [{COLORS['muted']}]│[/]  "
            f"[{COLORS['accent']}]{total_findings}[/] [{COLORS['muted']}]issues[/]  [{COLORS['muted']}]│[/]  "
            f"[{COLORS['score']}]{files_scanned}[/] [{COLORS['muted']}]files[/]"
        )

    def _get_score_style(self, score: float) -> str:
        """Get style based on security score."""
        if score >= 80:
            return f"bold {COLORS['score']}"
        elif score >= 60:
            return f"bold {COLORS['medium']}"
        elif score >= 40:
            return f"bold {COLORS['high']}"
        else:
            return f"bold {COLORS['critical']}"

    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level with colorful display."""
        if severity_counts["critical"] > 0:
            return f"[{COLORS['critical']} bold]● CRITICAL[/]"
        elif severity_counts["high"] > 5:
            return f"[{COLORS['high']} bold]● HIGH[/]"
        elif severity_counts["high"] > 0 or severity_counts["medium"] > 10:
            return f"[{COLORS['high']}]● ELEVATED[/]"
        elif severity_counts["medium"] > 0 or severity_counts["low"] > 5:
            return f"[{COLORS['medium']}]● MODERATE[/]"
        else:
            return f"[{COLORS['score']}]● LOW[/]"
