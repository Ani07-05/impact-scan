import abc
import re
import time
from pathlib import Path
from typing import List, Iterator

from impact_scan.utils import paths, schema
from . import dep_audit, static_scan


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


def run_scan(config: schema.ScanConfig) -> schema.ScanResult:
    """
    Orchestrates the entire scanning process.

    This function initializes and runs all the different scanning modules,
    aggregates their findings, and returns a comprehensive scan result.
    """
    start_time = time.time()

    # 1. Find entry points
    entry_points = find_entry_points(config.root_path)

    # 2. Run scanners
    all_findings = []
    static_findings = static_scan.run_scan(config)
    dep_findings = dep_audit.run_scan(config)

    all_findings.extend(static_findings)
    all_findings.extend(dep_findings)

    # 3. Filter findings by minimum severity
    if config.min_severity:
        severity_levels = {
            schema.Severity.LOW: 0,
            schema.Severity.MEDIUM: 1,
            schema.Severity.HIGH: 2,
            schema.Severity.CRITICAL: 3,
        }
        min_level = severity_levels.get(config.min_severity, 0)
        
        filtered_findings = [
            f for f in all_findings
            if severity_levels.get(f.severity, -1) >= min_level
        ]
        all_findings = filtered_findings

    # 4. Get total number of scanned files (simple version)
    scanned_files_count = len(set(f.file_path for f in all_findings))

    scan_duration = time.time() - start_time

    # 5. Assemble final result
    result = schema.ScanResult(
        config=config,
        findings=all_findings,
        entry_points=entry_points,
        scanned_files=scanned_files_count,
        scan_duration=scan_duration,
        timestamp=start_time,
    )

    return result


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
