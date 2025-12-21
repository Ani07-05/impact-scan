"""
TUI (Terminal User Interface) module for Impact Scan.
Provides interactive terminal interface for security scanning.

Available Interface:
- ModernImpactScanTUI: Beautiful TUI with animated ASCII art banner
- Full support for OpenAI, Anthropic, Gemini, and Groq AI providers
- Real-time progress tracking and immediate visual feedback
- Professional tabbed layout with overview, findings, and reports
- Animated IMPACT SCAN logo on startup
"""

from .modern_app import ModernImpactScanTUI as ImpactScanTUI
from .modern_app import run_modern_tui as run_tui

__all__ = ["ImpactScanTUI", "run_tui"]
