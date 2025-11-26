"""Ecosystem-specific dependency scanners"""

from .javascript_scanner import JavaScriptScanner
from .python_scanner import PythonScanner

__all__ = ["PythonScanner", "JavaScriptScanner"]
