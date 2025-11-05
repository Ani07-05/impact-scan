import json
import subprocess
from pathlib import Path
from typing import List
import logging

from impact_scan.utils import schema

# Set up logging
logger = logging.getLogger(__name__)



def run_scan(scan_config: schema.ScanConfig) -> List[schema.Finding]:
    """
    Runs the static analysis scan using Bandit.
    """
    logger.info("Starting static analysis scan...")
    findings = scan_for_static_issues(scan_config.root_path)
    logger.info(f"Found {len(findings)} static analysis issues")
    return findings


def scan_for_static_issues(root_path: Path) -> List[schema.Finding]:
    """
    Runs Bandit to find static analysis vulnerabilities in Python code.
    """
    if not root_path.is_dir():
        raise FileNotFoundError(f"Root path is not a directory: {root_path}")

    try:
        # Validate and sanitize root path
        root_path = root_path.resolve()
        
        # Build secure command list
        cmd = ["bandit", "-r", str(root_path), "-f", "json"]
        
        # Create clean environment to avoid poetry config conflicts
        import os
        clean_env = os.environ.copy()
        # Remove Poetry-specific environment variables that might cause conflicts
        for key in list(clean_env.keys()):
            if key.startswith(('POETRY_', 'VIRTUAL_ENV')):
                clean_env.pop(key, None)
        
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            shell=False,  # Disable shell to prevent injection
            env=clean_env,  # Use clean environment
            timeout=300  # Add timeout for large codebases
        )
        
        logger.debug(f"Bandit output for {root_path}:")
        logger.debug(f"STDOUT: {proc.stdout}")
        logger.debug(f"STDERR: {proc.stderr}")
        
        # Debug: Log JSON structure overview
        if proc.stdout:
            logger.info(f"DEBUG: STDOUT length: {len(proc.stdout)} characters")
            # Check if stdout contains "results" keyword
            if '"results"' in proc.stdout:
                logger.info("DEBUG: Found 'results' key in stdout")
            else:
                logger.warning("DEBUG: No 'results' key found in stdout")
        else:
            logger.warning("DEBUG: No stdout from Bandit")

    except subprocess.TimeoutExpired:
        logger.error(f"Bandit scan timed out for {root_path}")
        return []
    except FileNotFoundError:
        logger.error("Bandit command not found. Ensure Bandit is installed correctly.")
        return []
    except subprocess.CalledProcessError as e:
        logger.warning(f"Bandit subprocess failed with return code {e.returncode}")
        # Don't raise, continue with partial results if available

    if proc.stdout:
        return _parse_bandit_output(proc.stdout)
    
    return []

def _parse_bandit_output(json_output: str) -> List[schema.Finding]:
    """
    Parses the JSON output from Bandit into a list of Finding objects.
    """
    # Clean up progress bar output that pollutes JSON
    if json_output.startswith("Working..."):
        # Find the start of actual JSON (first '{')
        json_start = json_output.find('{')
        if json_start != -1:
            json_output = json_output[json_start:]
            logger.info(f"DEBUG: Stripped progress bar, JSON now starts with: {json_output[:50]}...")
        else:
            logger.warning("DEBUG: Could not find JSON start after progress bar")
            return []
    
    try:
        data = json.loads(json_output)
        logger.info("DEBUG: JSON parsing successful")
    except json.JSONDecodeError as e:
        logger.warning(f"Bandit output was not valid JSON: {e}")
        logger.info(f"DEBUG: First 100 chars of cleaned output: {json_output[:100]}...")
        return []
    except Exception as e:
        logger.error(f"DEBUG: Unexpected error parsing JSON: {e}")
        return []

    # Debug: log raw results count
    raw_results = data.get("results", [])
    logger.info(f"DEBUG: Bandit found {len(raw_results)} raw results")
    
    # Debug: log if JSON structure looks correct
    logger.info(f"DEBUG: JSON keys present: {list(data.keys())}")
    if raw_results:
        logger.info(f"DEBUG: First result keys: {list(raw_results[0].keys())}")
    else:
        logger.warning("DEBUG: No results found in JSON output")

    findings: List[schema.Finding] = []
    for i, result in enumerate(raw_results):
        file_path_str = result.get("filename")
        line_number = result.get("line_number")
        code_snippet = result.get("code")

        # Debug: log each result processing
        logger.info(f"DEBUG: Processing result {i+1}: {result.get('test_id')} - {result.get('issue_severity')}")
        logger.info(f"DEBUG: file_path_str={bool(file_path_str)}, line_number={line_number}, code_snippet={bool(code_snippet)}")

        if not file_path_str or line_number is None or not code_snippet:
            logger.warning(f"DEBUG: Skipping result {i+1} due to missing data")
            continue

        finding = schema.Finding(
            file_path=Path(file_path_str),
            line_number=line_number,
            vuln_id=result.get("test_id"),
            rule_id=result.get("test_id"),
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
        
        logger.info(f"DEBUG: Created finding {i+1}: {finding.rule_id} - {finding.severity}")
        findings.append(finding)
        
    logger.info(f"DEBUG: Returning {len(findings)} processed findings")
    return findings


def _map_bandit_severity(severity_str: str) -> schema.Severity:
    """Maps Bandit's severity strings to our internal Severity enum."""
    severity_map = {
        "HIGH": schema.Severity.HIGH,
        "MEDIUM": schema.Severity.MEDIUM,
        "LOW": schema.Severity.LOW,
    }
    return severity_map.get(severity_str, schema.Severity.LOW)
