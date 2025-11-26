import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List

from ..utils import schema

# Set up logging
logger = logging.getLogger(__name__)


def _select_semgrep_rules(project_context, local_rules_path: Path) -> List[str]:
    """
    Intelligently select Semgrep rules based on project context.

    Args:
        project_context: ProjectContext from project_classifier (or None)
        local_rules_path: Path to local custom rules

    Returns:
        List of --config flags for Semgrep
    """
    config_flags = []

    # Always include: Common security patterns (language-agnostic)
    config_flags.append("--config=p/security-audit")

    if not project_context:
        # No context: Use comprehensive rulesets (safe default)
        logger.info("No project context - using comprehensive rulesets")
        config_flags.extend([
            "--config=p/python",
            "--config=p/javascript",
            "--config=p/nodejs",
            "--config=p/typescript",
            "--config=p/jwt",
        ])
    else:
        # Language-specific rules (always relevant)
        if "Python" in project_context.languages:
            config_flags.append("--config=p/python")

        if any(lang in project_context.languages for lang in ["JavaScript", "TypeScript"]):
            config_flags.append("--config=p/javascript")
            config_flags.append("--config=p/typescript")

        if "Node.js" in project_context.frameworks or "Express" in project_context.frameworks:
            config_flags.append("--config=p/nodejs")

        if "Rust" in project_context.languages:
            config_flags.append("--config=p/rust")

        if "Go" in project_context.languages:
            config_flags.append("--config=p/golang")

        # Security context-aware rules
        sec = project_context.security_context

        # Library-aware filtering: Skip web-specific rules for libraries
        if project_context.is_library:
            logger.info("Library detected - skipping web-specific security rules")
            logger.info("  → Skipping: JWT/OAuth, XSS, CSRF, Session Management, Path Traversal")
            logger.info("  → These vulnerabilities only apply to web applications")
            # For libraries, only language-specific rules are added (already done above)
        else:
            # Not a library - add web-specific rules based on security context

            # JWT/OAuth rules - ONLY for web apps that handle auth
            if sec.get("handles_auth", False):
                logger.info("Enabling JWT/OAuth rules (project handles authentication)")
                config_flags.append("--config=p/jwt")

            # XSS/HTML rules - ONLY for projects generating HTML
            if sec.get("generates_html", False):
                logger.info("Enabling XSS rules (project generates HTML)")
                config_flags.append("--config=p/xss")

            # SQL injection - ONLY for projects using databases
            if sec.get("uses_database", False):
                logger.info("Enabling SQL injection rules (project uses database)")
                config_flags.append("--config=p/sql-injection")

            # React/Next.js specific rules
            if "React" in project_context.frameworks or "Next.js" in project_context.frameworks:
                config_flags.append("--config=p/react")

    # Add local custom rules if they exist
    if local_rules_path.exists():
        logger.info(f"Including local custom rules from {local_rules_path}")
        config_flags.append(f"--config={local_rules_path}")

    return config_flags


def run_scan(scan_config: schema.ScanConfig, project_context=None) -> List[schema.Finding]:
    """
    Runs the local static analysis scan.
    Now defaults to Semgrep for comprehensive multi-language support.

    Args:
        scan_config: Scan configuration
        project_context: Optional ProjectContext from project_classifier
    """
    logger.info("Starting local static analysis scan...")

    # Check if Semgrep is available
    if not shutil.which("semgrep"):
        logger.warning(
            "Semgrep not found in PATH. Falling back to Bandit (Python only)."
        )
        return run_bandit_scan(scan_config.root_path)

    findings = run_semgrep_scan(scan_config.root_path, project_context)
    logger.info(f"Found {len(findings)} issues with Semgrep")
    return findings


def run_semgrep_scan(root_path: Path, project_context=None) -> List[schema.Finding]:
    """
    Runs Semgrep to find security issues with intelligent rule selection.

    Args:
        root_path: Root directory to scan
        project_context: Optional ProjectContext for smart rule selection
    """
    if not root_path.is_dir():
        raise FileNotFoundError(f"Root path is not a directory: {root_path}")

    try:
        root_path = root_path.resolve()
        local_rules_path = Path(__file__).parent.parent / "rules"

        # Smart rule selection based on project context
        config_flags = _select_semgrep_rules(project_context, local_rules_path)

        if project_context:
            logger.info(f"Using {len(config_flags)} Semgrep rulesets for {project_context.project_type} project")
        else:
            logger.info(f"Using {len(config_flags)} Semgrep rulesets (no project context)")


        cmd = (
            ["semgrep", "scan", "--json"]
            + config_flags
            + [str(root_path)]
        )

        logger.info(f"Running Semgrep on {root_path}...")

        # Show animated spinner during Semgrep scan (ASCII-only for Windows compatibility)
        from rich.console import Console
        from rich.spinner import Spinner
        from rich.live import Live
        console = Console()

        # Use ASCII-compatible spinner (line, not dots which has Unicode)
        with Live(Spinner("line", text="[cyan]Scanning with Semgrep...[/cyan]"), console=console, refresh_per_second=4):
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=600,  # 10 minute timeout for larger repos
            )

        # Handle Semgrep exit codes
        # 0 = success, no findings
        # 1 = success, findings found
        # 130 = SIGINT/user interrupt (known Semgrep issue on Windows)
        # Other = actual error
        if proc.returncode == 130:
            logger.warning("Semgrep interrupted (exit 130) - known Windows issue")
            logger.warning("Attempting to parse partial output...")
            # Try to parse any output we got before interruption
            if proc.stdout:
                return _parse_semgrep_output(proc.stdout, root_path)
            return []
        elif proc.returncode not in [0, 1, 2]:
            logger.error(f"Semgrep failed with code {proc.returncode}")
            logger.error(f"STDERR: {proc.stderr}")
            return []

        if proc.stdout:
            return _parse_semgrep_output(proc.stdout, root_path)

    except subprocess.TimeoutExpired:
        logger.error(f"Semgrep scan timed out for {root_path}")
    except Exception as e:
        logger.error(f"Semgrep scan failed: {e}")

    return []


def _parse_semgrep_output(json_output: str, root_path: Path) -> List[schema.Finding]:
    """
    Parses Semgrep JSON output into Finding objects.
    """
    try:
        data = json.loads(json_output)
        results = data.get("results", [])

        findings: List[schema.Finding] = []

        for result in results:
            path_str = result.get("path")
            # Semgrep returns relative paths usually, but let's be safe
            full_path = root_path / path_str

            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            severity = _map_semgrep_severity(extra.get("severity", "INFO"))

            finding = schema.Finding(
                file_path=full_path,
                line_number=result.get("start", {}).get("line", 1),
                vuln_id=result.get("check_id"),
                rule_id=result.get("check_id"),
                title=result.get("check_id").split(".")[-1].replace("-", " ").title(),
                severity=severity,
                source=schema.VulnSource.STATIC_ANALYSIS,
                code_snippet=extra.get("lines", ""),
                description=extra.get("message", ""),
                metadata={
                    "cwe": metadata.get("cwe"),
                    "owasp": metadata.get("owasp"),
                    "references": metadata.get("references"),
                    "confidence": metadata.get("confidence"),
                },
            )
            findings.append(finding)

        return findings

    except json.JSONDecodeError:
        logger.error("Failed to parse Semgrep JSON output")
        return []


def _map_semgrep_severity(severity_str: str) -> schema.Severity:
    """Maps Semgrep severity to our internal schema."""
    severity_str = severity_str.upper()
    if severity_str == "ERROR":
        return schema.Severity.HIGH
    elif severity_str == "WARNING":
        return schema.Severity.MEDIUM
    elif severity_str == "INFO":
        return schema.Severity.LOW
    return schema.Severity.LOW


# --- Legacy Bandit Support (Fallback) ---


def run_bandit_scan(root_path: Path) -> List[schema.Finding]:
    """
    Runs Bandit to find static analysis vulnerabilities in Python code.
    """
    logger.info("Running Bandit fallback scan...")
    try:
        root_path = root_path.resolve()
        cmd = ["bandit", "-r", str(root_path), "-f", "json"]

        # Create clean environment
        clean_env = os.environ.copy()
        for key in list(clean_env.keys()):
            if key.startswith(("POETRY_", "VIRTUAL_ENV")):
                clean_env.pop(key, None)

        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
            env=clean_env,
            timeout=300,
        )

        if proc.stdout:
            return _parse_bandit_output(proc.stdout)

    except Exception as e:
        logger.error(f"Bandit scan failed: {e}")

    return []


def _parse_bandit_output(json_output: str) -> List[schema.Finding]:
    """Parses Bandit JSON output."""
    # Clean up potential progress bar noise
    if json_output.startswith("Working..."):
        json_start = json_output.find("{")
        if json_start != -1:
            json_output = json_output[json_start:]

    try:
        data = json.loads(json_output)
        findings: List[schema.Finding] = []

        for result in data.get("results", []):
            finding = schema.Finding(
                file_path=Path(result.get("filename")),
                line_number=result.get("line_number"),
                vuln_id=result.get("test_id"),
                rule_id=result.get("test_id"),
                title=result.get("test_name"),
                severity=_map_bandit_severity(result.get("issue_severity")),
                source=schema.VulnSource.STATIC_ANALYSIS,
                code_snippet=result.get("code"),
                description=result.get("issue_text"),
                metadata={
                    "confidence": result.get("issue_confidence"),
                    "cwe": result.get("cwe"),
                },
            )
            findings.append(finding)
        return findings
    except Exception:
        return []


def _map_bandit_severity(severity_str: str) -> schema.Severity:
    mapping = {
        "HIGH": schema.Severity.HIGH,
        "MEDIUM": schema.Severity.MEDIUM,
        "LOW": schema.Severity.LOW,
    }
    return mapping.get(severity_str, schema.Severity.LOW)
