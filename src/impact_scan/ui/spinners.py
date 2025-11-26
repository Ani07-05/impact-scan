"""
Modern ASCII-safe spinner animations.

Based on cli-spinners but with Windows-safe characters only.
"""

from typing import Dict, List
from dataclasses import dataclass


@dataclass
class SpinnerStyle:
    """Spinner animation style."""
    frames: List[str]
    interval: int  # milliseconds per frame


# ASCII-safe spinners (Windows-compatible)
SPINNERS: Dict[str, SpinnerStyle] = {
    "dots": SpinnerStyle(
        frames=["   ", ".  ", ".. ", "..."],
        interval=80
    ),
    "line": SpinnerStyle(
        frames=["-", "\\", "|", "/"],
        interval=130
    ),
    "box": SpinnerStyle(
        frames=["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]"],
        interval=100
    ),
    "arrow": SpinnerStyle(
        frames=["<  ", " < ", "  <", "  >", " > ", ">  "],
        interval=100
    ),
    "clock": SpinnerStyle(
        frames=["12", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
        interval=100
    ),
    "pulse": SpinnerStyle(
        frames=[".", "..", "...", "....", ".....", "......"],
        interval=120
    ),
    "bounce": SpinnerStyle(
        frames=["[    ]", "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]"],
        interval=80
    ),
}


def get_spinner(name: str = "line") -> SpinnerStyle:
    """
    Get spinner by name.

    Args:
        name: Spinner name (default: "line")

    Returns:
        SpinnerStyle object
    """
    return SPINNERS.get(name, SPINNERS["line"])
