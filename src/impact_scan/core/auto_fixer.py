"""
Auto-fix module for applying AI-generated security fixes safely.

This module handles:
- Applying unified diff patches to files
- Git integration (branching, committing)
- Safety guardrails (clean working dir, backups, rollback)
- Validation (syntax checking, test running)
"""

import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FixResult:
    """Result of applying a single fix."""

    success: bool
    file_path: Path
    vuln_id: str
    rule_id: str
    error: Optional[str] = None
    backup_path: Optional[Path] = None


class GitHelper:
    """
    Git operations for auto-fix workflow.
    """

    @staticmethod
    def is_git_repo(path: Path) -> bool:
        """Check if path is in a git repository."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def is_working_directory_clean(path: Path) -> bool:
        """Check if git working directory has no uncommitted changes."""
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Empty output means clean working dir
            return result.returncode == 0 and not result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def get_current_branch(path: Path) -> Optional[str]:
        """Get current git branch name."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    @staticmethod
    def create_branch(branch_name: str, path: Path) -> bool:
        """Create and checkout a new git branch."""
        try:
            result = subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info(f"Created branch: {branch_name}")
                return True
            else:
                logger.error(f"Failed to create branch: {result.stderr}")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Git branch creation failed: {e}")
            return False

    @staticmethod
    def commit_changes(message: str, path: Path) -> bool:
        """Stage and commit all changes."""
        try:
            # Stage all changes
            subprocess.run(
                ["git", "add", "-A"],
                cwd=path,
                check=True,
                capture_output=True,
                timeout=10,
            )

            # Commit
            result = subprocess.run(
                ["git", "commit", "-m", message],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                logger.info(f"Committed changes: {message}")
                return True
            else:
                logger.warning(f"Commit may have failed: {result.stderr}")
                return False

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ) as e:
            logger.error(f"Git commit failed: {e}")
            return False

    @staticmethod
    def reset_hard(path: Path) -> bool:
        """Reset working directory to last commit (DESTRUCTIVE)."""
        try:
            subprocess.run(
                ["git", "reset", "--hard", "HEAD"],
                cwd=path,
                check=True,
                capture_output=True,
                timeout=10,
            )
            logger.info("Reset working directory to HEAD")
            return True
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ) as e:
            logger.error(f"Git reset failed: {e}")
            return False


class AutoFixer:
    """
    Safely apply AI-generated fixes to source code.
    """

    def __init__(self, dry_run: bool = False, require_clean_git: bool = True):
        """
        Initialize AutoFixer.

        Args:
            dry_run: If True, simulate changes without modifying files
            require_clean_git: If True, require clean git working dir before applying fixes
        """
        self.dry_run = dry_run
        self.require_clean_git = require_clean_git
        self.backup_dir: Optional[Path] = None
        self.applied_fixes: List[FixResult] = []

    def apply_fixes(
        self,
        fixes: List[Dict[str, Any]],
        project_root: Path,
        confidence_threshold: str = "high",
    ) -> Tuple[List[FixResult], int, int]:
        """
        Apply AI-generated fixes to files.

        Args:
            fixes: List of fix dictionaries with 'file_path', 'fix_diff', 'vuln_id', etc.
            project_root: Root directory of project
            confidence_threshold: Minimum confidence level (low, medium, high)

        Returns:
            (results, success_count, fail_count)
        """

        # Safety check: Require clean git working dir
        if self.require_clean_git and not self.dry_run:
            if GitHelper.is_git_repo(project_root):
                if not GitHelper.is_working_directory_clean(project_root):
                    raise RuntimeError(
                        "Git working directory is not clean! "
                        "Commit or stash changes before running --fix"
                    )
            else:
                logger.warning("Not a git repository, skipping clean check")

        # Create backup directory
        if not self.dry_run:
            self.backup_dir = Path(tempfile.mkdtemp(prefix="impact-scan-backup-"))
            logger.info(f"Created backup directory: {self.backup_dir}")

        # Filter by confidence
        confidence_levels = {"low": 1, "medium": 2, "high": 3}
        min_confidence = confidence_levels.get(confidence_threshold, 3)

        results = []
        success_count = 0
        fail_count = 0

        for fix in fixes:
            # Check confidence level
            fix_confidence_str = fix.get("confidence", "medium")
            fix_confidence = confidence_levels.get(fix_confidence_str, 2)

            if fix_confidence < min_confidence:
                logger.debug(
                    f"Skipping fix for {fix.get('vuln_id')} (confidence too low)"
                )
                continue

            # Apply single fix
            result = self._apply_single_fix(
                file_path=Path(fix["file_path"]),
                fix_diff=fix.get("fix_diff") or fix.get("ai_fix", ""),
                vuln_id=fix.get("vuln_id", "UNKNOWN"),
                rule_id=fix.get("rule_id", "unknown"),
            )

            results.append(result)
            self.applied_fixes.append(result)

            if result.success:
                success_count += 1
            else:
                fail_count += 1

        return results, success_count, fail_count

    def _apply_single_fix(
        self, file_path: Path, fix_diff: str, vuln_id: str, rule_id: str
    ) -> FixResult:
        """Apply a single unified diff patch to a file."""

        if not file_path.exists():
            return FixResult(
                success=False,
                file_path=file_path,
                vuln_id=vuln_id,
                rule_id=rule_id,
                error=f"File not found: {file_path}",
            )

        # Backup original file
        backup_path = None
        if not self.dry_run:
            backup_path = self.backup_dir / file_path.name
            try:
                shutil.copy2(file_path, backup_path)
            except Exception as e:
                logger.error(f"Failed to backup {file_path}: {e}")
                return FixResult(
                    success=False,
                    file_path=file_path,
                    vuln_id=vuln_id,
                    rule_id=rule_id,
                    error=f"Backup failed: {e}",
                )

        # If fix_diff is not in unified diff format, try to apply as direct replacement
        if not fix_diff.startswith("---") and not fix_diff.startswith("+++"):
            # Direct replacement (not unified diff)
            return self._apply_direct_replacement(
                file_path, fix_diff, vuln_id, rule_id, backup_path
            )

        # Apply unified diff patch
        try:
            # Write patch to temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".patch", delete=False, encoding="utf-8"
            ) as f:
                f.write(fix_diff)
                patch_file = f.name

            # Apply patch using git apply or patch command
            if self.dry_run:
                # Dry run: check if patch would apply
                result = subprocess.run(
                    ["git", "apply", "--check", patch_file],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            else:
                # Apply for real
                result = subprocess.run(
                    ["git", "apply", patch_file],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

            # Clean up temp patch file
            Path(patch_file).unlink(missing_ok=True)

            if result.returncode == 0:
                # Success! Validate syntax
                if not self.dry_run:
                    is_valid, error = self._validate_syntax(file_path)
                    if not is_valid:
                        # Rollback invalid fix
                        if backup_path:
                            shutil.copy2(backup_path, file_path)
                        return FixResult(
                            success=False,
                            file_path=file_path,
                            vuln_id=vuln_id,
                            rule_id=rule_id,
                            error=f"Syntax validation failed: {error}",
                            backup_path=backup_path,
                        )

                logger.info(f"Applied fix for {vuln_id} in {file_path}")
                return FixResult(
                    success=True,
                    file_path=file_path,
                    vuln_id=vuln_id,
                    rule_id=rule_id,
                    backup_path=backup_path,
                )
            else:
                error_msg = result.stderr or "Patch failed to apply"
                logger.error(f"Failed to apply fix for {vuln_id}: {error_msg}")

                # Restore from backup
                if backup_path and not self.dry_run:
                    shutil.copy2(backup_path, file_path)

                return FixResult(
                    success=False,
                    file_path=file_path,
                    vuln_id=vuln_id,
                    rule_id=rule_id,
                    error=error_msg,
                    backup_path=backup_path,
                )

        except Exception as e:
            logger.exception(f"Exception applying fix for {vuln_id}")

            # Restore from backup
            if backup_path and not self.dry_run:
                shutil.copy2(backup_path, file_path)

            return FixResult(
                success=False,
                file_path=file_path,
                vuln_id=vuln_id,
                rule_id=rule_id,
                error=str(e),
                backup_path=backup_path,
            )

    def _apply_direct_replacement(
        self,
        file_path: Path,
        new_content: str,
        vuln_id: str,
        rule_id: str,
        backup_path: Optional[Path],
    ) -> FixResult:
        """Apply fix as direct file content replacement."""
        try:
            if not self.dry_run:
                file_path.write_text(new_content, encoding="utf-8")

                # Validate syntax
                is_valid, error = self._validate_syntax(file_path)
                if not is_valid:
                    # Rollback
                    if backup_path:
                        shutil.copy2(backup_path, file_path)
                    return FixResult(
                        success=False,
                        file_path=file_path,
                        vuln_id=vuln_id,
                        rule_id=rule_id,
                        error=f"Syntax validation failed: {error}",
                        backup_path=backup_path,
                    )

            return FixResult(
                success=True,
                file_path=file_path,
                vuln_id=vuln_id,
                rule_id=rule_id,
                backup_path=backup_path,
            )

        except Exception as e:
            # Restore from backup
            if backup_path and not self.dry_run:
                shutil.copy2(backup_path, file_path)

            return FixResult(
                success=False,
                file_path=file_path,
                vuln_id=vuln_id,
                rule_id=rule_id,
                error=str(e),
                backup_path=backup_path,
            )

    def _validate_syntax(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        """Validate syntax after applying fix."""
        suffix = file_path.suffix.lower()

        # Python syntax check
        if suffix == ".py":
            try:
                import ast

                code = file_path.read_text(encoding="utf-8")
                ast.parse(code)
                return True, None
            except SyntaxError as e:
                return False, f"Syntax error at line {e.lineno}: {e.msg}"
            except Exception as e:
                return False, str(e)

        # JavaScript/TypeScript syntax check (requires Node.js)
        elif suffix in [".js", ".jsx", ".ts", ".tsx"]:
            try:
                result = subprocess.run(
                    ["node", "--check", str(file_path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return True, None
                else:
                    return False, result.stderr
            except FileNotFoundError:
                # Node.js not installed, skip validation
                logger.warning("Node.js not found, skipping JS/TS syntax validation")
                return True, None
            except subprocess.TimeoutExpired:
                return False, "Syntax check timed out"

        # Unknown file type, assume valid
        return True, None

    def rollback_all(self) -> int:
        """Rollback all applied fixes. Returns number of files rolled back."""
        if not self.backup_dir:
            logger.warning("No backup directory, cannot rollback")
            return 0

        logger.info("Rolling back all fixes...")
        rollback_count = 0

        for fix_result in self.applied_fixes:
            if fix_result.success and fix_result.backup_path:
                try:
                    shutil.copy2(fix_result.backup_path, fix_result.file_path)
                    logger.info(f"Rolled back {fix_result.file_path}")
                    rollback_count += 1
                except Exception as e:
                    logger.error(f"Failed to rollback {fix_result.file_path}: {e}")

        logger.info(f"Rollback complete: {rollback_count} files restored")
        return rollback_count

    def cleanup_backups(self) -> None:
        """Remove backup directory."""
        if self.backup_dir and self.backup_dir.exists():
            try:
                shutil.rmtree(self.backup_dir)
                logger.info(f"Cleaned up backup directory: {self.backup_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup backups: {e}")


def run_tests(
    project_root: Path, test_command: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Run tests to validate fixes didn't break anything.

    Args:
        project_root: Project root directory
        test_command: Custom test command (e.g., "pytest", "npm test")

    Returns:
        (success: bool, output: str)
    """
    if not test_command:
        # Auto-detect test command
        if (project_root / "pytest.ini").exists() or (
            project_root / "setup.cfg"
        ).exists():
            test_command = "pytest"
        elif (project_root / "package.json").exists():
            test_command = "npm test"
        else:
            logger.info("No test framework detected, skipping test run")
            return True, "No tests found"

    try:
        logger.info(f"Running tests: {test_command}")
        result = subprocess.run(
            test_command,
            cwd=project_root,
            capture_output=True,
            text=True,
            shell=True,
            timeout=300,  # 5 minute timeout
        )

        success = result.returncode == 0
        output = result.stdout + "\n" + result.stderr

        if success:
            logger.info("Tests passed!")
        else:
            logger.warning(f"Tests failed with exit code {result.returncode}")

        return success, output

    except subprocess.TimeoutExpired:
        return False, "Test run timed out (5 minutes)"

    except Exception as e:
        logger.error(f"Failed to run tests: {e}")
        return False, str(e)
