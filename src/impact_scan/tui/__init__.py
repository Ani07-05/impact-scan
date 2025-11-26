"""
TUI (Terminal User Interface) module for Impact Scan.
Provides interactive terminal interface for security scanning.

Available Interface:
- UltraModernTUI: Ultra-modern, minimal TUI inspired by OpenTUI
- Full support for OpenAI, Anthropic, and Gemini AI providers
- Real-time progress tracking and immediate visual feedback
- Professional grid layout with working components
- Web mode support (runs in browser!)
"""

from .app import UltraModernTUI as ImpactScanTUI
from .app import run_ultra_modern_tui as run_tui

__all__ = ["ImpactScanTUI", "run_tui"]
