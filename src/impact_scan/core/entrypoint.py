import abc
import re
from pathlib import Path
from typing import List, Iterator

from impact_scan.utils import paths, schema


class EntryPointDetector(abc.ABC):
    """Abstract base class for all framework entry point detectors."""

    @abc.abstractmethod
    def detect(self, root_path: Path) -> Iterator[schema.EntryPoint]:
        """
        Detects entry points for a specific framework within the codebase.

        Args:
            root_path: The root directory of the codebase to scan.

        Yields:
            An iterator of EntryPoint objects found.
        """
        raise NotImplementedError


class FlaskDetector(EntryPointDetector):
    """Detects potential Flask application entry points."""

    # Regex to find "app = Flask(__name__)" assignments
    FLASK_APP_INIT_RE = re.compile(r"app\s*=\s*Flask\(__name__\)")
    # Regex to find the common "if __name__ == '__main__':" block
    MAIN_BLOCK_RE = re.compile(r"if\s+__name__\s*==\s*['\"]__main__['\"]:")

    def detect(self, root_path: Path) -> Iterator[schema.EntryPoint]:
        """Scans .py files for Flask application patterns."""
        for py_file in paths.discover_files(root_path, paths.PYTHON_EXTENSIONS):
            try:
                content = paths.read_file_content(py_file)
                if self.FLASK_APP_INIT_RE.search(content):
                    yield schema.EntryPoint(
                        path=py_file,
                        framework="Flask",
                        confidence=0.9,
                    )
                elif self.MAIN_BLOCK_RE.search(content):
                    yield schema.EntryPoint(
                        path=py_file,
                        framework="Python Executable",
                        confidence=0.7,
                    )
            except (IOError, UnicodeDecodeError):
                # Silently skip files that cannot be read
                continue


class NextJSDetector(EntryPointDetector):
    """Detects potential Next.js application entry points based on file structure."""

    # Canonical file paths for Next.js App Router and Pages Router
    CANONICAL_PATHS = [
        "src/app/page.tsx",
        "src/app/page.js",
        "src/app/layout.tsx",
        "src/app/layout.js",
        "pages/index.tsx",
        "pages/index.js",
        "next.config.js",
        "next.config.mjs",
    ]

    def detect(self, root_path: Path) -> Iterator[schema.EntryPoint]:
        """Checks for the existence of canonical Next.js files."""
        for rel_path_str in self.CANONICAL_PATHS:
            file_path = root_path / rel_path_str
            if file_path.is_file():
                yield schema.EntryPoint(
                    path=file_path,
                    framework="Next.js",
                    confidence=1.0,
                )


def find_entry_points(root_path: Path) -> List[schema.EntryPoint]:
    """
    Aggregates findings from all available entry point detectors.

    This function is the main interface for the entrypoint detection system.
    It is designed to be easily extensible by adding new detector classes
    to the `detectors` list.

    Args:
        root_path: The root directory of the codebase.

    Returns:
        A list of all discovered EntryPoint objects.
    """
    detectors: List[EntryPointDetector] = [
        FlaskDetector(),
        NextJSDetector(),
    ]

    all_entry_points: List[schema.EntryPoint] = []
    for detector in detectors:
        all_entry_points.extend(detector.detect(root_path))

    # Future improvement: Add logic to de-duplicate or merge findings
    return all_entry_points
