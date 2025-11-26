import abc
import logging
import re
import time
from pathlib import Path
from typing import Iterator, List

from ..utils import paths, schema
from . import dep_audit, fix_ai, project_classifier, static_scan, repo_graph_integration

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
        # 1. AI-powered project classification (replaces entry point detection)
        logger.info("Classifying project type with AI...")
        project_context = None
        try:
            project_context = project_classifier.classify_project(
                Path(config.root_path),
                api_keys=config.api_keys
            )
            if project_context:
                logger.info(f"Project Type: {project_context.project_type}")
                logger.info(f"Frameworks: {', '.join(project_context.frameworks) or 'None detected'}")
                logger.info(f"Languages: {', '.join(project_context.languages)}")
                logger.info(f"Description: {project_context.description}")
            else:
                logger.warning("Project classification unavailable, using default rules")
        except Exception as e:
            logger.warning(f"Project classification failed: {e}, using default rules")

        # 1.5. Build repository + semantic knowledge graphs for context-aware validation
        repo_graph = repo_graph_integration.build_repository_graph_for_scan(
            config,
            project_context=project_context,
        )
        kg = repo_graph_integration.build_knowledge_graph_for_scan(
            config,
            project_context=project_context,
        )

        # 2. Run synchronous scanners with intelligent rule selection
        all_findings = []

        try:
            logger.info("Running static analysis scan...")
            static_findings = static_scan.run_scan(config, project_context)
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
            logger.info(
                f"Filtering findings by minimum severity: {config.min_severity}"
            )
            severity_levels = {
                schema.Severity.LOW: 0,
                schema.Severity.MEDIUM: 1,
                schema.Severity.HIGH: 2,
                schema.Severity.CRITICAL: 3,
            }
            min_level = severity_levels.get(config.min_severity, 0)

            original_count = len(all_findings)
            filtered_findings = [
                f
                for f in all_findings
                if severity_levels.get(f.severity, -1) >= min_level
            ]
            all_findings = filtered_findings
            logger.info(
                f"Filtered {original_count} findings to {len(all_findings)} based on severity threshold"
            )

        # 3.25. Cheap context-aware filtering using KnowledgeGraph before AI
        if kg and all_findings:
            try:
                before = len(all_findings)
                all_findings = repo_graph_integration.filter_with_knowledge_graph(
                    kg, all_findings
                )
                dropped = before - len(all_findings)
                if dropped > 0:
                    logger.info(
                        f"Knowledge graph pre-filtered {dropped} obvious false positives "
                        f"({dropped / before * 100:.1f}% reduction before AI)"
                    )
            except Exception as e:
                logger.error(f"Knowledge graph filtering failed: {e}")

        # 3.5. AI Validation (optional) - Reduce false positives
        if config.enable_ai_validation and all_findings:
            try:
                from . import ai_validator

                logger.info("Running AI validation with repository context to reduce false positives...")
                original_count = len(all_findings)
                all_findings = ai_validator.validate_with_ai(
                    all_findings,
                    config,
                    repo_graph=repo_graph,
                    knowledge_graph=kg,
                )
                reduction = original_count - len(all_findings)
                if reduction > 0:
                    logger.info(
                        f"AI validation filtered {reduction} false positives "
                        f"({reduction / original_count * 100:.1f}% reduction)"
                    )
            except Exception as e:
                logger.error(f"AI validation failed: {e}")
                logger.warning("Continuing with all findings (AI validation skipped)")

        # 3.6. AI Deep Security Audit (optional) - Discover new vulnerabilities
        if config.enable_ai_deep_scan:
            try:
                from . import ai_security_auditor

                logger.info(
                    "Running AI deep security audit to discover logic/config vulnerabilities..."
                )
                audit_findings = ai_security_auditor.audit_with_ai(
                    target_path=Path(config.root_path),
                    config=config,
                    max_files=config.ai_audit_max_files,
                )
                if audit_findings:
                    logger.info(
                        f"AI audit discovered {len(audit_findings)} additional vulnerabilities"
                    )
                    all_findings.extend(audit_findings)
                else:
                    logger.info("AI audit: No additional vulnerabilities discovered")
            except Exception as e:
                logger.error(f"AI deep scan failed: {e}")
                logger.warning(
                    "Continuing with existing findings (AI deep scan skipped)"
                )

        # 3.7. Framework Semantic Analysis (Phase 1) - Detect missing parameters, framework misconfigurations
        if getattr(config, "enable_semantic_analysis", False):
            try:
                from . import semantic_analyzer

                logger.info("Running framework semantic analysis...")

                # Get AI provider if available
                ai_provider = None
                if config.api_keys:
                    try:
                        ai_provider = fix_ai.get_ai_fix_provider(config.api_keys)
                    except Exception:
                        logger.debug("No AI provider available for semantic analysis")

                # Find Python files in auth/config directories (high priority)
                python_files = []
                for pattern in [
                    "**/auth/*.py",
                    "**/main.py",
                    "**/app.py",
                    "**/routes/*.py",
                ]:
                    python_files.extend(config.root_path.glob(pattern))

                # Limit to reasonable number
                python_files = list(set(python_files))[:20]

                if python_files:
                    semantic_findings = semantic_analyzer.analyze_framework_semantics(
                        file_paths=python_files,
                        framework="fastapi",  # Auto-detect in future
                        ai_provider=ai_provider,
                    )

                    if semantic_findings:
                        logger.info(
                            f"Semantic analysis found {len(semantic_findings)} framework issues"
                        )
                        all_findings.extend(semantic_findings)
                    else:
                        logger.info("Semantic analysis: No framework issues found")
                else:
                    logger.debug("No Python files found for semantic analysis")

            except Exception as e:
                logger.error(f"Semantic analysis failed: {e}", exc_info=True)
                logger.warning(
                    "Continuing with existing findings (semantic analysis skipped)"
                )

        # 4. Get total number of scanned files
        scanned_files_count = len(set(f.file_path for f in all_findings))

        scan_duration = time.time() - start_time

        # 5. Assemble final result (without async enrichment)
        # Note: entry_points kept for backwards compatibility but may be empty
        result = schema.ScanResult(
            config=config,
            findings=all_findings,
            entry_points=[],  # Deprecated: replaced by project_context
            scanned_files=scanned_files_count,
            scan_duration=scan_duration,
            timestamp=start_time,
        )

        logger.info(
            f"Synchronous scan completed in {scan_duration:.2f} seconds with {len(all_findings)} findings"
        )
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


async def enrich_findings_async(
    findings: List[schema.Finding], config: schema.ScanConfig
) -> None:
    """
    Performs asynchronous enrichment of findings (web search, AI fixes).
    This function is designed to be called from an environment with a running event loop.
    """
    if not findings:
        return

    # Web search enrichment temporarily disabled (module refactoring in progress)
    # TODO: Re-enable after web intelligence module is restructured
    # if config.enable_web_search:
    #     logger.info("Running web intelligence enrichment...")
    #     try:
    #         # Offload sync function to thread to avoid blocking and event loop issues
    #         import asyncio
    #
    #         await asyncio.to_thread(
    #             web_search.process_findings_for_web_fixes, findings, config
    #         )
    #     except Exception as e:
    #         logger.error(f"Web intelligence enrichment failed: {e}")

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
            logger.error(
                f"Entry point detector {detector.__class__.__name__} failed: {e}"
            )
            # Continue with other detectors

    # Future improvement: Add logic to de-duplicate or merge findings
    return all_entry_points
