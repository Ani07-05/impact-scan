"""
SARIF Report Generator for GitHub Code Scanning Integration

Implements SARIF 2.1.0 format for:
- GitHub Code Scanning
- VS Code Problems Panel
- Azure DevOps
- Other SARIF-compatible tools

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..utils import schema


class SARIFGenerator:
    """Generate SARIF 2.1.0 compliant reports"""

    def __init__(self):
        self.tool_name = "Impact-Scan"
        self.tool_version = "1.0.0"
        self.sarif_version = "2.1.0"

    def generate_sarif(self, result: schema.ScanResult) -> Dict[str, Any]:
        """
        Generate complete SARIF report from scan result

        Args:
            result: ScanResult object from Impact-Scan

        Returns:
            SARIF 2.1.0 compliant dictionary
        """

        # Extract all findings
        all_findings = []
        for findings_list in result.findings_by_severity.values():
            all_findings.extend(findings_list)

        # Build rules from findings
        rules = self._build_rules(all_findings)

        # Build results from findings
        results = self._build_results(all_findings, result.config.root_path)

        # Build SARIF structure
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": self.sarif_version,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/Ani07-05/impact-scan",
                            "semanticVersion": self.tool_version,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "columnKind": "utf16CodeUnits",
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.fromtimestamp(
                                result.timestamp
                            ).isoformat()
                            + "Z",
                            "workingDirectory": {
                                "uri": self._path_to_uri(result.config.root_path)
                            },
                        }
                    ],
                    "automationDetails": {
                        "id": f"impact-scan/{datetime.now().strftime('%Y-%m-%d')}"
                    },
                }
            ],
        }

        return sarif

    def _build_rules(self, findings: List[schema.Finding]) -> List[Dict[str, Any]]:
        """Build SARIF rules from findings"""
        rules_dict = {}

        for finding in findings:
            rule_id = finding.rule_id

            if rule_id not in rules_dict:
                # Map severity to SARIF level
                default_level = self._severity_to_level(finding.severity)

                # Map severity to security-severity score
                security_severity = self._severity_to_score(finding.severity)

                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {
                        "text": finding.description[:1024]  # GitHub limit
                    },
                    "help": {
                        "text": finding.description,
                        "markdown": self._format_help_markdown(finding),
                    },
                    "defaultConfiguration": {"level": default_level},
                    "properties": {
                        "tags": self._get_tags(finding),
                        "precision": "high",
                        "security-severity": str(security_severity),
                        "problem.severity": default_level,
                    },
                }

        return list(rules_dict.values())

    def _build_results(
        self, findings: List[schema.Finding], root_path: Path
    ) -> List[Dict[str, Any]]:
        """Build SARIF results from findings"""
        results = []

        for finding in findings:
            # Build relative path from root
            try:
                relative_path = Path(finding.file_path).relative_to(root_path)
            except ValueError:
                # File outside root, use absolute
                relative_path = Path(finding.file_path)

            # Build result object
            result = {
                "ruleId": finding.rule_id,
                "level": self._severity_to_level(finding.severity),
                "message": {"text": finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(relative_path).replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": 1,
                                "endLine": finding.line_number,
                                "endColumn": 100,
                                "snippet": {
                                    "text": finding.code_snippet[:200]
                                    if finding.code_snippet
                                    else ""
                                },
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": self._generate_fingerprint(finding)
                },
            }

            # Add fix suggestion if available
            if finding.ai_fix or finding.fix_suggestion:
                fix_text = finding.ai_fix or finding.fix_suggestion
                result["fixes"] = [
                    {
                        "description": {"text": "Apply AI-generated fix"},
                        "artifactChanges": [
                            {
                                "artifactLocation": {
                                    "uri": str(relative_path).replace("\\", "/")
                                },
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": finding.line_number,
                                            "startColumn": 1,
                                        },
                                        "insertedContent": {"text": fix_text[:500]},
                                    }
                                ],
                            }
                        ],
                    }
                ]

            # Add related locations (Stack Overflow references)
            if finding.stackoverflow_fixes:
                result["relatedLocations"] = []
                for i, so_fix in enumerate(finding.stackoverflow_fixes[:3], 1):
                    result["relatedLocations"].append(
                        {
                            "id": i,
                            "physicalLocation": {
                                "artifactLocation": {"uri": so_fix.url}
                            },
                            "message": {
                                "text": f"Stack Overflow solution: {so_fix.title}"
                            },
                        }
                    )

            results.append(result)

        return results

    def _severity_to_level(self, severity: schema.Severity) -> str:
        """Map Impact-Scan severity to SARIF level"""
        mapping = {
            schema.Severity.CRITICAL: "error",
            schema.Severity.HIGH: "error",
            schema.Severity.MEDIUM: "warning",
            schema.Severity.LOW: "note",
        }
        return mapping.get(severity, "warning")

    def _severity_to_score(self, severity: schema.Severity) -> float:
        """Map Impact-Scan severity to security-severity score (0.0-10.0)"""
        mapping = {
            schema.Severity.CRITICAL: 9.5,
            schema.Severity.HIGH: 8.0,
            schema.Severity.MEDIUM: 5.5,
            schema.Severity.LOW: 3.0,
        }
        return mapping.get(severity, 5.0)

    def _get_tags(self, finding: schema.Finding) -> List[str]:
        """Extract tags from finding"""
        tags = ["security"]

        # Add source tag
        if finding.source == schema.VulnSource.DEPENDENCY:
            tags.append("dependency")
        elif finding.source == schema.VulnSource.AI_DETECTION:
            tags.append("ai-detected")

        # Add vulnerability type tags
        if "xss" in finding.title.lower():
            tags.extend(["xss", "injection"])
        elif "sql" in finding.title.lower():
            tags.extend(["sql-injection", "injection"])
        elif "csrf" in finding.title.lower():
            tags.append("csrf")
        elif "auth" in finding.title.lower():
            tags.append("authorization")
        elif "race" in finding.title.lower():
            tags.append("race-condition")

        return tags[:20]  # GitHub limit

    def _format_help_markdown(self, finding: schema.Finding) -> str:
        """Format help text as markdown"""
        md = f"## {finding.title}\n\n"
        md += f"{finding.description}\n\n"

        if finding.ai_explanation:
            md += f"### AI Analysis\n\n{finding.ai_explanation}\n\n"

        if finding.fix_suggestion or finding.ai_fix:
            fix = finding.ai_fix or finding.fix_suggestion
            md += f"### Remediation\n\n```python\n{fix[:500]}\n```\n\n"

        if finding.stackoverflow_fixes:
            md += "### References\n\n"
            for so_fix in finding.stackoverflow_fixes[:3]:
                md += f"- [{so_fix.title}]({so_fix.url}) ({so_fix.votes} votes)\n"

        return md

    def _generate_fingerprint(self, finding: schema.Finding) -> str:
        """Generate stable fingerprint for deduplication"""
        # Combine rule ID, file path, and line number
        fingerprint_data = (
            f"{finding.rule_id}:{finding.file_path}:{finding.line_number}"
        )
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

    def _path_to_uri(self, path: Path) -> str:
        """Convert Path to file:// URI"""
        return path.resolve().as_uri()


def save_sarif_report(result: schema.ScanResult, output_path: Path) -> None:
    """
    Generate and save SARIF report

    Args:
        result: ScanResult from Impact-Scan
        output_path: Where to save SARIF file
    """
    generator = SARIFGenerator()
    sarif_data = generator.generate_sarif(result)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
