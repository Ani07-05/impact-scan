"""
TUI (Terminal User Interface) module for Impact Scan.
Provides interactive terminal interface for security scanning.

Available Interface:
- CleanModernTUI: Clean, functional TUI inspired by k9s/lazygit/btop
- Full support for OpenAI, Anthropic, and Gemini AI providers
- Real-time progress tracking and immediate visual feedback
- Professional grid layout with working components
"""

from .clean_modern_tui import CleanModernTUI as ImpactScanTUI, run_clean_modern_tui as run_tui

__all__ = ["ImpactScanTUI", "run_tui"]