import json
import subprocess
from pathlib import Path
from typing import List

from impact_scan.utils import schema



def scan_for_static_issues(root_path: Path) -> List[schema.Finding]:
    """
    Runs Bandit to find static analysis vulnerabilities in Python code.
    """
    if not root_path.is_dir():
        raise FileNotFoundError(f"Root path is not a directory: {root_path}")

    try:
        proc = subprocess.run(
            ["bandit", "-r", str(root_path), "-f", "json"],
            check=False,
            capture_output=True,
            text=True,
            cwd=root_path
        )
        
        # --- START DEBUG PRINTS ---
        print("\n--- Bandit STDOUT ---")
        print(proc.stdout)
        print("--- End Bandit STDOUT ---\n")
        
        print("\n--- Bandit STDERR ---")
        print(proc.stderr)
        print("--- End Bandit STDERR ---\n")
        # --- END DEBUG PRINTS ---

    except FileNotFoundError:
        raise FileNotFoundError("Bandit command not found. Ensure Bandit is installed correctly.")
    except subprocess.CalledProcessError as e:
        raise e

    if proc.stdout:
        return _parse_bandit_output(proc.stdout)
    
    return []

def _parse_bandit_output(json_output: str) -> List[schema.Finding]:
    """
    Parses the JSON output from Bandit into a list of Finding objects.
    """
    data = json.loads(json_output)

    findings: List[schema.Finding] = []
    for result in data.get("results", []):
        file_path_str = result.get("filename")
        line_number = result.get("line_number")
        code_snippet = result.get("code")

        if not file_path_str or line_number is None or not code_snippet:
            continue

        findings.append(
            schema.Finding(
                file_path=Path(file_path_str),
                line_number=line_number,
                vuln_id=result.get("test_id"),
                title=result.get("test_name"),
                severity=_map_bandit_severity(result.get("issue_severity")),
                source=schema.VulnSource.STATIC_ANALYSIS,
                code_snippet=code_snippet,
                description=result.get("issue_text"),
                metadata={
                    "confidence": result.get("issue_confidence"),
                    "cwe": result.get("cwe"),
                    "more_info": result.get("more_info"),
                }
            )
        )
    return findings


def _map_bandit_severity(severity_str: str) -> schema.Severity:
    """Maps Bandit's severity strings to our internal Severity enum."""
    severity_map = {
        "HIGH": schema.Severity.HIGH,
        "MEDIUM": schema.Severity.MEDIUM,
        "LOW": schema.Severity.LOW,
    }
    return severity_map.get(severity_str, schema.Severity.LOW)
