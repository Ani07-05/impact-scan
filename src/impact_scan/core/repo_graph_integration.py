from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from ..utils import schema
from . import knowledge_graph

logger = logging.getLogger(__name__)

try:  # Optional dependency – advanced context only if gh_repo_kg is installed
    from gh_repo_kg.api import RepositoryGraph, build_repository_graph  # type: ignore
    from gh_repo_kg.ingest import IngestOptions  # type: ignore
except ImportError:  # pragma: no cover - optional feature
    RepositoryGraph = None  # type: ignore
    build_repository_graph = None  # type: ignore
    IngestOptions = None  # type: ignore


def build_repository_graph_for_scan(
    config: schema.ScanConfig,
    project_context=None,
) -> Optional["RepositoryGraph"]:
    """Build a repository graph for the target codebase.

    Returns None if gh_repo_kg is not installed or graph build fails.
    """

    if build_repository_graph is None or IngestOptions is None:
        logger.debug("gh_repo_kg not available - repository graph disabled")
        return None

    root_path = Path(config.root_path).resolve()

    ingest_opts = IngestOptions()
    # Add common non-code directories to ignore
    ingest_opts.ignore_dirs.update(
        {
            "node_modules",
            "dist",
            "build",
            ".tox",
            ".idea",
            ".vscode",
        }
    )

    # Example of context-aware tuning (can be expanded later)
    if project_context and "React" in getattr(project_context, "frameworks", []):
        ingest_opts.ignore_extensions.update({".map"})

    try:
        logger.info("[KG] Building repository graph for %s", root_path)
        repo_graph: RepositoryGraph = build_repository_graph(  # type: ignore[call-arg]
            root_path,
            ingest_options=ingest_opts,
            enable_python_analysis=True,
        )
        logger.info(
            "[KG] Repository graph built: %d files, %d file nodes, %d Python files",
            len(repo_graph.manifest.files),
            len(repo_graph.file_graph.nodes),
            len(repo_graph.python_imports.nodes)
            if repo_graph.python_imports is not None
            else 0,
        )
        return repo_graph
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("[KG] Failed to build repository graph: %s", e, exc_info=True)
        return None


def _rel_id_for_finding(repo_graph: "RepositoryGraph", finding: schema.Finding) -> Optional[str]:
    """Map a Finding's file_path to the normalized ID used in the repo graph."""

    try:
        rel = finding.file_path.resolve().relative_to(repo_graph.manifest.root)
    except Exception:
        return None
    return str(rel).replace("\\", "/")


def build_graph_context_for_finding(
    repo_graph: "RepositoryGraph",
    finding: schema.Finding,
    *,
    max_imports: int = 5,
    max_imported_by: int = 5,
    max_neighbors: int = 5,
) -> str:
    """Build a short, human-readable repository context string for an LLM prompt."""

    node_id = _rel_id_for_finding(repo_graph, finding)
    if not node_id:
        return ""

    lines: List[str] = []

    # Structural neighbors (same directory)
    neighbors: List[str] = []
    for n in repo_graph.file_graph.neighbors(node_id):
        neighbors.append(n.id)
        if len(neighbors) >= max_neighbors:
            break

    if neighbors:
        lines.append(
            "Neighbor files (same directory): " + ", ".join(sorted(neighbors))
        )

    # Python import relationships
    if repo_graph.python_imports is not None:
        imports: List[str] = []
        for fi in repo_graph.python_imports.imports_of(node_id):
            imports.append(str(fi.relative_path).replace("\\", "/"))
            if len(imports) >= max_imports:
                break

        imported_by: List[str] = []
        for fi in repo_graph.python_imports.imported_by(node_id):
            imported_by.append(str(fi.relative_path).replace("\\", "/"))
            if len(imported_by) >= max_imported_by:
                break

        if imports:
            lines.append("Imports (repo modules): " + ", ".join(sorted(imports)))
        if imported_by:
            lines.append("Imported by: " + ", ".join(sorted(imported_by)))

    return "\n".join(lines)


def build_knowledge_graph_for_scan(
    config: schema.ScanConfig,
    project_context=None,
) -> Optional[knowledge_graph.KnowledgeGraph]:
    """Build impact-scan's internal KnowledgeGraph for the project."""

    try:
        kg = knowledge_graph.build_knowledge_graph(
            Path(config.root_path), project_context
        )
        return kg
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("[KG] Failed to build semantic knowledge graph: %s", e, exc_info=True)
        return None


def filter_with_knowledge_graph(
    kg: knowledge_graph.KnowledgeGraph,
    findings: List[schema.Finding],
) -> List[schema.Finding]:
    """Use KnowledgeGraph.validate_finding to drop obvious false positives."""

    kept: List[schema.Finding] = []

    for f in findings:
        try:
            result = kg.validate_finding(f, vulnerable_code=f.code_snippet)
        except Exception as e:  # pragma: no cover
            logger.debug("[KG] validate_finding failed for %s: %s", f.vuln_id, e)
            kept.append(f)
            continue

        if not result.get("is_valid") and result.get("suggested_action") == "dismiss":
            f.metadata["kg_filtered"] = True
            f.metadata["kg_reason"] = result.get("reasoning", "")
            continue

        kept.append(f)

    return kept
