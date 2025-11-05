import abc
import re
import time
import logging
from pathlib import Path
from typing import List, Iterator

from impact_scan.utils import paths, schema
from . import dep_audit, static_scan, web_search, fix_ai

# Set up logging
logger = logging.getLogger(__name__)


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
            except (IOError, UnicodeDecodeError) as e:
                # Log error but continue scanning other files
                logger.warning(f"Could not read file {py_file}: {e}")
                continue
            except Exception as e:
                # Log unexpected errors but don't crash the scan
                logger.error(f"Unexpected error processing {py_file}: {e}")
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
    Orchestrates the synchronous part of the scanning process.

    This function initializes and runs synchronous scanning modules (static analysis,
    dependency audit) and returns an initial result. Asynchronous enrichment
    is handled separately.
    """
    start_time = time.time()

    try:
        # 1. Find entry points
        logger.info("Detecting entry points...")
        entry_points = find_entry_points(config.root_path)
        logger.info(f"Found {len(entry_points)} entry points")

        # 2. Run synchronous scanners
        all_findings = []
        
        try:
            logger.info("Running static analysis scan...")
            static_findings = static_scan.run_scan(config)
            all_findings.extend(static_findings)
        except Exception as e:
            logger.error(f"Static analysis scan failed: {e}")
        
        try:
            logger.info("Running dependency audit scan...")
            dep_findings = dep_audit.run_scan(config)
            all_findings.extend(dep_findings)
        except Exception as e:
            logger.error(f"Dependency audit scan failed: {e}")

        # 3. Filter findings by minimum severity
        if config.min_severity:
            logger.info(f"Filtering findings by minimum severity: {config.min_severity}")
            severity_levels = {
                schema.Severity.LOW: 0,
                schema.Severity.MEDIUM: 1,
                schema.Severity.HIGH: 2,
                schema.Severity.CRITICAL: 3,
            }
            min_level = severity_levels.get(config.min_severity, 0)
            
            original_count = len(all_findings)
            filtered_findings = [
                f for f in all_findings
                if severity_levels.get(f.severity, -1) >= min_level
            ]
            all_findings = filtered_findings
            logger.info(f"Filtered {original_count} findings to {len(all_findings)} based on severity threshold")

        # 4. Get total number of scanned files
        scanned_files_count = len(set(f.file_path for f in all_findings))

        scan_duration = time.time() - start_time

        # 5. Assemble final result (without async enrichment)
        result = schema.ScanResult(
            config=config,
            findings=all_findings,
            entry_points=entry_points,
            scanned_files=scanned_files_count,
            scan_duration=scan_duration,
            timestamp=start_time,
        )

        logger.info(f"Synchronous scan completed in {scan_duration:.2f} seconds with {len(all_findings)} findings")
        return result
        
    except Exception as e:
        logger.error(f"Critical error during synchronous scan: {e}")
        scan_duration = time.time() - start_time
        return schema.ScanResult(
            config=config,
            findings=[],
            entry_points=[],
            scanned_files=0,
            scan_duration=scan_duration,
            timestamp=start_time,
        )


async def enrich_findings_async(findings: List[schema.Finding], config: schema.ScanConfig) -> None:
    """
    Performs asynchronous enrichment of findings (web search, AI fixes).
    This function is designed to be called from an environment with a running event loop.
    """
    if not findings:
        return

    if config.enable_web_search:
        logger.info("Running web intelligence enrichment...")
        try:
            # Offload sync function to thread to avoid blocking and event loop issues
            import asyncio
            await asyncio.to_thread(web_search.process_findings_for_web_fixes, findings, config)
        except Exception as e:
            logger.error(f"Web intelligence enrichment failed: {e}")
    
    if config.enable_ai_fixes:
        logger.info("Running AI fix generation...")
        try:
            # Offload sync function to thread
            import asyncio
            await asyncio.to_thread(fix_ai.generate_fixes, findings, config)
        except Exception as e:
            logger.error(f"AI fix generation failed: {e}")


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
        try:
            detector_name = detector.__class__.__name__
            logger.debug(f"Running {detector_name}...")
            entry_points = list(detector.detect(root_path))
            all_entry_points.extend(entry_points)
            logger.debug(f"{detector_name} found {len(entry_points)} entry points")
        except Exception as e:
            logger.error(f"Entry point detector {detector.__class__.__name__} failed: {e}")
            # Continue with other detectors

    # Future improvement: Add logic to de-duplicate or merge findings
    return all_entry_points
