"""
Impact Scan - AI-powered security vulnerability scanner
"""

__version__ = "0.3.0"
__author__ = "Anirudh"

from pathlib import Path

# Package metadata
PACKAGE_ROOT = Path(__file__).parent

__all__ = ["__version__", "__author__", "PACKAGE_ROOT"]
