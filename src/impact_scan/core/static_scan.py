"""
Static analysis scan using ripgrep.
Replaces semgrep and bandit with a ripgrep-based approach.
"""

import logging
import os
from pathlib import Path
from typing import List, Optional

from ..utils import schema
from .ripgrep_scanner import run_ripgrep_scan

# Set up logging
logger = logging.getLogger(__name__)


def run_scan(scan_config: schema.ScanConfig, project_context=None) -> List[schema.Finding]:
    """
    Runs the local static analysis scan using ripgrep.

    Args:
        scan_config: Scan configuration
        project_context: Optional ProjectContext from project_classifier

    Returns:
        List of findings from ripgrep scanner
    """
    logger.info("Starting ripgrep-based static analysis scan...")

    # Get Groq API key from environment or config
    groq_api_key = os.getenv("GROQ_API_KEY")

    if not groq_api_key:
        logger.warning("GROQ_API_KEY not set - AI validation will be skipped")
        logger.warning("Set GROQ_API_KEY environment variable to enable AI-powered validation")

    # Run ripgrep scan
    findings = run_ripgrep_scan(scan_config.root_path, groq_api_key)

    logger.info(f"Found {len(findings)} validated security issues")
    return findings


def _map_severity(severity_str: str) -> schema.Severity:
    """Maps severity string to our internal schema."""
    severity_str = severity_str.upper()
    mapping = {
        "CRITICAL": schema.Severity.CRITICAL,
        "HIGH": schema.Severity.HIGH,
        "MEDIUM": schema.Severity.MEDIUM,
        "LOW": schema.Severity.LOW,
    }
    return mapping.get(severity_str, schema.Severity.MEDIUM)
