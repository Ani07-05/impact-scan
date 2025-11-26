"""
CodeQualityAgent - Code Quality & Best Practices Detection

Detects code smells, complexity issues, maintainability problems.
Uses radon, pylint/eslint, and pattern-based detection.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Union

from ..utils.schema import Finding, Severity, VulnSource
from .base import Agent, AgentResult

logger = logging.getLogger(__name__)


class CodeQualityAgent(Agent):
    """
    Detect code quality issues: complexity, smells, dead code

    Capabilities:
    - Cyclomatic complexity (radon)
    - Maintainability index
    - Code smells (patterns)
    - Dead code detection
    - Best practice violations
    """

    def __init__(self, config, **kwargs):
        super().__init__(name="quality", config=config, **kwargs)
        self.complexity_threshold = kwargs.get("complexity_threshold", 10)
        self.min_severity = kwargs.get("min_severity", Severity.MEDIUM)

    async def _execute_internal(
        self, target: Union[str, Path], context: Dict[str, Any], result: AgentResult
    ) -> None:
        """Execute code quality analysis"""

        print("[QUALITY] Starting code quality analysis...")

        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        findings = []

        # Phase 1: Complexity Analysis (radon)
        print("[QUALITY] Analyzing code complexity...")
        complexity_findings = self._analyze_complexity(target_path)
        findings.extend(complexity_findings)

        # Phase 2: Maintainability Index
        print("[QUALITY] Calculating maintainability index...")
        maintainability_findings = self._analyze_maintainability(target_path)
        findings.extend(maintainability_findings)

        # Phase 3: Pattern-based code smells
        print("[QUALITY] Detecting code smells...")
        smell_findings = self._detect_code_smells(target_path)
        findings.extend(smell_findings)

        # Filter by severity
        filtered_findings = [
            f
            for f in findings
            if self._severity_order(f.severity)
            >= self._severity_order(self.min_severity)
        ]

        # Add findings to result
        for finding in filtered_findings:
            result.findings.append(finding)

        # Compile statistics
        result.data["total_issues"] = len(filtered_findings)
        result.data["by_category"] = self._categorize_findings(filtered_findings)
        result.data["by_severity"] = {
            "HIGH": len([f for f in filtered_findings if f.severity == Severity.HIGH]),
            "MEDIUM": len(
                [f for f in filtered_findings if f.severity == Severity.MEDIUM]
            ),
            "LOW": len([f for f in filtered_findings if f.severity == Severity.LOW]),
        }

        print(f"[QUALITY] Found {len(filtered_findings)} quality issues")

    def _analyze_complexity(self, target_path: Path) -> List[Finding]:
        """Analyze cyclomatic complexity using radon"""
        findings = []

        try:
            # Run radon cc (cyclomatic complexity)
            result = subprocess.run(
                ["radon", "cc", str(target_path), "-j", "--min", "B"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                logger.warning(f"Radon failed: {result.stderr}")
                return findings

            data = json.loads(result.stdout)

            for file_path, functions in data.items():
                for func in functions:
                    complexity = func.get("complexity", 0)

                    if complexity >= self.complexity_threshold:
                        severity = self._complexity_to_severity(complexity)

                        finding = Finding(
                            vuln_id=f"quality-complexity-{func['name']}",
                            rule_id="high-cyclomatic-complexity",
                            title=f"High Complexity: {func['name']}",
                            description=f"Function has cyclomatic complexity of {complexity} (threshold: {self.complexity_threshold}). "
                            f"Consider refactoring into smaller functions. "
                            f"Rank: {func.get('rank', 'Unknown')}",
                            severity=severity,
                            source=VulnSource.STATIC_ANALYSIS,
                            file_path=Path(file_path),
                            line_number=func.get("lineno", 1),
                            code_snippet=f"def {func['name']}(...): # complexity={complexity}",
                            metadata={
                                "complexity": complexity,
                                "rank": func.get("rank"),
                                "type": func.get("type"),
                                "category": "complexity",
                            },
                        )
                        findings.append(finding)

        except FileNotFoundError:
            logger.warning("Radon not installed - skipping complexity analysis")
        except Exception as e:
            logger.error(f"Complexity analysis failed: {e}")

        return findings

    def _analyze_maintainability(self, target_path: Path) -> List[Finding]:
        """Analyze maintainability index using radon"""
        findings = []

        try:
            # Run radon mi (maintainability index)
            result = subprocess.run(
                ["radon", "mi", str(target_path), "-j"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                return findings

            data = json.loads(result.stdout)

            for file_path, metrics in data.items():
                mi = metrics.get("mi", 100)
                rank = metrics.get("rank", "A")

                # Maintainability Index < 20 = bad, < 40 = moderate
                if mi < 40:
                    severity = Severity.HIGH if mi < 20 else Severity.MEDIUM

                    finding = Finding(
                        vuln_id=f"quality-maintainability-{Path(file_path).name}",
                        rule_id="low-maintainability-index",
                        title=f"Low Maintainability: {Path(file_path).name}",
                        description=f"File has maintainability index of {mi:.1f} (rank: {rank}). "
                        f"Consider refactoring to improve readability and reduce complexity. "
                        f"Target: MI > 40 for maintainable code.",
                        severity=severity,
                        source=VulnSource.STATIC_ANALYSIS,
                        file_path=Path(file_path),
                        line_number=1,
                        code_snippet=f"# MI: {mi:.1f}, Rank: {rank}",
                        metadata={
                            "maintainability_index": mi,
                            "rank": rank,
                            "category": "maintainability",
                        },
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Maintainability analysis failed: {e}")

        return findings

    def _detect_code_smells(self, target_path: Path) -> List[Finding]:
        """Detect common code smells using patterns"""
        findings = []

        # Pattern-based detection for common smells
        smell_patterns = [
            {
                "pattern": r"def\s+\w+\([^)]{100,}\)",  # Long parameter list
                "name": "long-parameter-list",
                "title": "Long Parameter List",
                "description": "Function has too many parameters. Consider using a config object or builder pattern.",
                "severity": Severity.MEDIUM,
            },
            {
                "pattern": r"if.*:\s*if.*:\s*if.*:\s*if",  # Deep nesting
                "name": "deep-nesting",
                "title": "Deeply Nested Code",
                "description": "Code has excessive nesting (4+ levels). Refactor using early returns or extraction.",
                "severity": Severity.MEDIUM,
            },
            {
                "pattern": r"(TODO|FIXME|HACK|XXX)",  # Technical debt markers
                "name": "technical-debt",
                "title": "Technical Debt Marker",
                "description": "Code contains TODO/FIXME comments indicating incomplete work.",
                "severity": Severity.LOW,
            },
        ]

        # Walk through files
        if target_path.is_file():
            files = [target_path]
        else:
            files = list(target_path.rglob("*.py")) + list(target_path.rglob("*.js"))

        import re

        for file_path in files[:50]:  # Limit to avoid performance issues
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                for pattern_def in smell_patterns:
                    matches = re.finditer(pattern_def["pattern"], content, re.MULTILINE)

                    for match in matches:
                        line_number = content[: match.start()].count("\n") + 1

                        finding = Finding(
                            vuln_id=f"quality-smell-{pattern_def['name']}-{file_path.name}-{line_number}",
                            rule_id=pattern_def["name"],
                            title=pattern_def["title"],
                            description=pattern_def["description"],
                            severity=pattern_def["severity"],
                            source=VulnSource.STATIC_ANALYSIS,
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=match.group(0)[:100],
                            metadata={"category": "code-smell"},
                        )
                        findings.append(finding)

            except Exception as e:
                logger.debug(f"Error processing {file_path}: {e}")
                continue

        return findings

    def _complexity_to_severity(self, complexity: int) -> Severity:
        """Map complexity score to severity"""
        if complexity >= 20:
            return Severity.HIGH
        elif complexity >= 10:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _severity_order(self, severity: Severity) -> int:
        """Get numeric order for severity"""
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }
        return order.get(severity, 0)

    def _categorize_findings(self, findings: List[Finding]) -> Dict[str, int]:
        """Categorize findings by type"""
        categories = {}
        for finding in findings:
            category = finding.metadata.get("category", "other")
            categories[category] = categories.get(category, 0) + 1
        return categories
