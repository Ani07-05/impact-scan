"""
Logging configuration for Impact Scan.
"""

import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(level: str = "INFO", log_file: Path = None) -> None:
    """
    Configure logging for the application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to write logs to
    """
    # Create console for rich output
    console = Console(stderr=True)

    # Configure root logger
    root_logger = logging.getLogger()
    # Handle both string and int log levels
    if isinstance(level, int):
        root_logger.setLevel(level)
    else:
        root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear any existing handlers
    root_logger.handlers.clear()

    # Add rich handler for console output with UTF-8 encoding
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
        enable_link_path=False,
    )
    rich_handler.setFormatter(logging.Formatter(fmt="%(message)s", datefmt="[%X]"))
    root_logger.addHandler(rich_handler)

    # Add file handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root_logger.addHandler(file_handler)

    # Set specific loggers to appropriate levels
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
