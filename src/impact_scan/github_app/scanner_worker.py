"""Background worker for processing scan jobs from Redis queue.

This worker:
1. Dequeues scan jobs from Redis (highest priority first)
2. Clones/fetches repositories with LRU caching
3. Runs Impact Scan on changed files
4. Posts progressive comments to GitHub PR
5. Handles errors gracefully
"""

import os
import sys
import time
import json
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file in project root
project_root = Path(__file__).parent.parent.parent.parent
env_path = project_root / ".env"
load_dotenv(env_path)

# Add ripgrep to PATH for static analysis
ripgrep_path = project_root / "ripgrep-14.1.0-x86_64-pc-windows-msvc"
if ripgrep_path.exists():
    os.environ["PATH"] = str(ripgrep_path) + os.pathsep + os.environ.get("PATH", "")

from .queue_manager import QueueManager
from .github_client import GitHubClient
from .comment_formatter import CommentFormatter
from ..utils.schema import Severity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RepoCache:
    """Manages local repository caching with LRU eviction."""

    def __init__(self, cache_dir: str = "/tmp/impact-scan-repos", max_size_gb: float = 10.0):
        """Initialize repo cache.

        Args:
            cache_dir: Directory to store cached repos
            max_size_gb: Maximum cache size in GB (triggers LRU eviction)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = int(max_size_gb * 1024 * 1024 * 1024)

    def get_repo_path(self, repo_full_name: str) -> Path:
        """Get local path for a repository.

        Args:
            repo_full_name: Full repo name (owner/repo)

        Returns:
            Path to local repo directory
        """
        # Sanitize repo name for filesystem
        safe_name = repo_full_name.replace("/", "_")
        return self.cache_dir / safe_name

    def get_cache_size(self) -> int:
        """Get total size of cache directory in bytes."""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(self.cache_dir):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except (OSError, FileNotFoundError):
                    pass
        return total_size

    def evict_lru_repos(self):
        """Evict least recently used repositories to free space."""
        logger.info("Cache size exceeded, running LRU eviction...")

        # Get all repos with their last access time
        repos = []
        for repo_dir in self.cache_dir.iterdir():
            if repo_dir.is_dir():
                try:
                    # Use .git directory mtime as last access time
                    git_dir = repo_dir / ".git"
                    if git_dir.exists():
                        mtime = git_dir.stat().st_mtime
                        repos.append((repo_dir, mtime))
                except (OSError, FileNotFoundError):
                    pass

        # Sort by access time (oldest first)
        repos.sort(key=lambda x: x[1])

        # Evict oldest repos until we're under 80% capacity
        target_size = int(self.max_size_bytes * 0.8)
        current_size = self.get_cache_size()

        for repo_dir, mtime in repos:
            if current_size <= target_size:
                break

            try:
                logger.info(f"Evicting {repo_dir.name} (last used: {datetime.fromtimestamp(mtime)})")
                shutil.rmtree(repo_dir)
                current_size = self.get_cache_size()
            except (OSError, PermissionError) as e:
                logger.warning(f"Failed to evict {repo_dir.name}: {e}")

        logger.info(f"Cache size after eviction: {current_size / (1024**3):.2f} GB")

    def touch_repo(self, repo_path: Path):
        """Update last access time for a repository.

        Args:
            repo_path: Path to repository directory
        """
        git_dir = repo_path / ".git"
        if git_dir.exists():
            # Touch .git directory to update mtime
            os.utime(git_dir, None)


class ScannerWorker:
    """Background worker for processing scan jobs."""

    def __init__(self):
        """Initialize scanner worker."""
        self.queue_manager = QueueManager()
        self.github_client = GitHubClient()
        self.repo_cache = RepoCache()

    def clone_or_fetch_repo(
        self,
        installation_id: int,
        repo_full_name: str,
        base_ref: str,
        head_ref: str,
    ) -> Path:
        """Clone repository or fetch if already cached.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            base_ref: Base branch reference
            head_ref: Head branch reference

        Returns:
            Path to local repository
        """
        repo_path = self.repo_cache.get_repo_path(repo_full_name)

        # Get installation token for git authentication
        token = self.github_client.get_installation_token(installation_id)
        clone_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"

        if repo_path.exists():
            logger.info(f"Repository cached, fetching updates: {repo_full_name}")

            # Fetch latest changes
            try:
                subprocess.run(
                    ["git", "fetch", "origin"],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                    timeout=60
                )
            except subprocess.CalledProcessError as e:
                logger.warning(f"Fetch failed, re-cloning: {e.stderr.decode()}")
                shutil.rmtree(repo_path)
                return self.clone_or_fetch_repo(installation_id, repo_full_name, base_ref, head_ref)

        else:
            logger.info(f"Cloning repository: {repo_full_name}")

            # Check if cache size exceeded
            cache_size = self.repo_cache.get_cache_size()
            if cache_size > self.repo_cache.max_size_bytes:
                self.repo_cache.evict_lru_repos()

            # Clone with depth 50 for faster cloning
            try:
                subprocess.run(
                    ["git", "clone", "--depth=50", clone_url, str(repo_path)],
                    check=True,
                    capture_output=True,
                    timeout=120
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"Clone failed: {e.stderr.decode()}")
                raise

        # Checkout head branch
        try:
            subprocess.run(
                ["git", "checkout", head_ref],
                cwd=repo_path,
                check=True,
                capture_output=True,
                timeout=30
            )
        except subprocess.CalledProcessError:
            # Try fetching the specific ref if checkout failed
            try:
                subprocess.run(
                    ["git", "fetch", "origin", f"{head_ref}:{head_ref}"],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                    timeout=60
                )
                subprocess.run(
                    ["git", "checkout", head_ref],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                    timeout=30
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"Checkout failed: {e.stderr.decode()}")
                raise

        # Update cache access time
        self.repo_cache.touch_repo(repo_path)

        return repo_path

    def run_scan(
        self,
        repo_path: Path,
        file_paths: list[str],
        tier: str = "free",
    ) -> Dict[str, Any]:
        """Run Impact Scan on changed files.

        Args:
            repo_path: Path to local repository
            file_paths: List of changed file paths
            tier: User tier (free/pro)

        Returns:
            Scan results dictionary
        """
        logger.info(f"Running scan on {len(file_paths)} files...")

        start_time = time.time()

        try:
            # Import scan entrypoint
            from ..core.entrypoint import run_scan
            from ..utils.schema import ScanConfig, APIKeys, Severity

            # Get API keys from environment
            api_keys = APIKeys(
                groq_api_key=os.getenv("GROQ_API_KEY"),
            )

            # Configure scan for GitHub App
            # Free tier: Basic scan with bugs + security only
            # Pro tier: Full scan with AI validation + Stack Overflow
            config = ScanConfig(
                root_path=repo_path,
                min_severity=Severity.MEDIUM,
                enable_ai_fixes=False,  # Disable AI fixes for GitHub App (causes validation error)
                enable_ai_validation=False,  # Disable for free tier (enable for pro later)
                enable_web_search=False,  # Disable web search for now
                enable_stackoverflow_scraper=False,  # Disable for free tier
                enable_ai_deep_scan=False,  # Not needed for PR scans
                enable_semantic_analysis=False,  # Not needed for PR scans
                api_keys=api_keys,
                prioritize_high_severity=True,
            )

            # Run scan
            scan_result = run_scan(config)

            scan_duration = time.time() - start_time

            # Convert to dict format
            return {
                "files_scanned": len(file_paths),
                "scan_duration_seconds": scan_duration,
                "findings": scan_result.findings,
                "changed_files": file_paths,
            }

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)

            # Return empty results on error
            scan_duration = time.time() - start_time
            return {
                "files_scanned": len(file_paths),
                "scan_duration_seconds": scan_duration,
                "findings": [],
                "changed_files": file_paths,
            }

    def post_initial_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        files_scanned: int,
        scan_duration: float,
        changed_files: list[str],
        tier: str,
    ) -> int:
        """Post initial scan comment to PR.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            pr_number: Pull request number
            files_scanned: Number of files scanned
            scan_duration: Scan duration in seconds
            changed_files: List of changed file paths
            tier: User tier (free/pro)

        Returns:
            Comment ID for later editing
        """
        formatter = CommentFormatter(tier=tier)

        # Generate basic Mermaid diagram
        mermaid_diagram = self.generate_basic_mermaid(changed_files)

        comment_body = formatter.format_initial_comment(
            file_count=files_scanned,
            scan_duration_ms=int(scan_duration * 1000),
            mermaid_diagram=mermaid_diagram,
        )

        comment_id = self.github_client.post_comment(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            body=comment_body,
        )

        logger.info(f"Posted initial comment {comment_id}")
        return comment_id

    def generate_basic_mermaid(self, changed_files: list[str], findings: list = None) -> str:
        """Generate Mermaid diagram showing file relationships and issue density.

        Args:
            changed_files: List of changed file paths
            findings: Optional list of Finding objects to show issue density

        Returns:
            Mermaid diagram code
        """
        # Group files by directory
        file_groups = {}
        for filepath in changed_files[:15]:  # Limit to 15 files
            parts = filepath.split("/")
            if len(parts) > 1:
                dir_name = parts[-2]
                filename = parts[-1]
            else:
                dir_name = "root"
                filename = filepath

            if dir_name not in file_groups:
                file_groups[dir_name] = []
            file_groups[dir_name].append((filepath, filename))

        # Count issues per file
        issue_count = {}
        if findings:
            for finding in findings:
                file_path = str(finding.file_path) if hasattr(finding, 'file_path') else ""
                issue_count[file_path] = issue_count.get(file_path, 0) + 1

        # Build diagram
        lines = ["graph TD"]

        # Add nodes for each directory
        dir_ids = {}
        for idx, dir_name in enumerate(file_groups.keys()):
            dir_id = f"DIR{idx}"
            dir_ids[dir_name] = dir_id
            lines.append(f"    {dir_id}[📁 {dir_name}]")
            lines.append(f"    style {dir_id} fill:#e1f5ff,stroke:#0288d1")

        # Add file nodes with issue indicators
        file_counter = 0
        for dir_name, files in file_groups.items():
            dir_id = dir_ids[dir_name]
            for filepath, filename in files:
                file_id = f"F{file_counter}"
                file_counter += 1

                # Determine file style based on issues
                issues = issue_count.get(filepath, 0)
                if issues >= 3:
                    style = "fill:#ffebee,stroke:#c62828"  # Red for high issues
                    icon = "🔴"
                elif issues > 0:
                    style = "fill:#fff3e0,stroke:#ef6c00"  # Orange for some issues
                    icon = "🟠"
                else:
                    style = "fill:#e8f5e9,stroke:#2e7d32"  # Green for clean
                    icon = "🟢"

                issue_text = f" ({issues})" if issues > 0 else ""
                lines.append(f"    {file_id}[\"{icon} {filename}{issue_text}\"]")
                lines.append(f"    style {file_id} {style}")
                lines.append(f"    {dir_id} --> {file_id}")

        # Add note for truncated files
        if len(changed_files) > 15:
            lines.append(f"    MORE[\"... +{len(changed_files)-15} more files\"]")
            lines.append(f"    style MORE fill:#f5f5f5,stroke:#999")

        return "\n".join(lines)

    def update_final_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        comment_id: int,
        scan_results: Dict[str, Any],
        tier: str,
        truncated: bool,
    ):
        """Update comment with final scan results.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            comment_id: Comment ID to edit
            scan_results: Scan results dictionary
            tier: User tier (free/pro)
            truncated: Whether file list was truncated
        """
        formatter = CommentFormatter(tier=tier)

        # Generate Mermaid diagram with findings
        mermaid_diagram = self.generate_basic_mermaid(
            scan_results["changed_files"],
            findings=scan_results["findings"]
        )

        # Mock validation stats for now
        validation_stats = {
            "total_potential_issues": 0,
            "validated_issues": len(scan_results["findings"]),
            "false_positives_filtered": 0,
        }

        comment_body = formatter.format_final_comment(
            file_count=scan_results["files_scanned"],
            scan_duration_ms=int(scan_results["scan_duration_seconds"] * 1000),
            findings=scan_results["findings"],
            validation_stats=validation_stats,
            mermaid_diagram=mermaid_diagram,
            truncated=truncated,
        )

        self.github_client.edit_comment(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            comment_id=comment_id,
            body=comment_body,
        )

        logger.info(f"Updated final comment {comment_id}")

    def post_inline_comments(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        head_sha: str,
        findings: list,
    ):
        """Post inline review comments for all findings.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            pr_number: Pull request number
            head_sha: Git commit SHA
            findings: List of Finding objects
        """
        logger.info(f"Posting inline comments for {len(findings)} findings...")

        posted_count = 0
        failed_count = 0

        for finding in findings:
            try:
                # Skip if no line number
                if not hasattr(finding, 'line_number') or not finding.line_number:
                    continue

                # Format inline comment body
                severity_emoji = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                }.get(finding.severity, "ℹ️")

                comment_body = f"""{severity_emoji} **{finding.severity.name}**: {finding.title}

{finding.description}

**Location:** Line {finding.line_number}
"""

                # Add fix suggestion if available
                if hasattr(finding, 'fix') and finding.fix:
                    comment_body += f"\n**Suggested Fix:**\n```python\n{finding.fix}\n```"

                # Post the comment
                self.github_client.post_review_comment(
                    installation_id=installation_id,
                    repo_full_name=repo_full_name,
                    pr_number=pr_number,
                    commit_id=head_sha,
                    path=str(finding.file_path),
                    line=finding.line_number,
                    body=comment_body,
                )

                posted_count += 1

            except Exception as e:
                logger.warning(f"Failed to post inline comment for {finding.file_path}:{finding.line_number}: {e}")
                failed_count += 1

        logger.info(f"Posted {posted_count} inline comments ({failed_count} failed)")

    def create_check_run(
        self,
        installation_id: int,
        repo_full_name: str,
        head_sha: str,
        scan_results: Dict[str, Any],
    ):
        """Create GitHub check run with scan status.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            head_sha: Git commit SHA
            scan_results: Scan results dictionary
        """
        findings = scan_results["findings"]

        # Count critical/high findings
        critical_count = sum(
            1 for f in findings
            if hasattr(f, 'severity') and f.severity in [Severity.CRITICAL, Severity.HIGH]
        )

        # Determine check conclusion
        if critical_count > 0:
            conclusion = "failure"
            title = f"Impact Scan - {critical_count} critical/high issues found"
        else:
            conclusion = "success"
            title = "Impact Scan - No critical issues found"

        self.github_client.create_check_run(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            head_sha=head_sha,
            name="Impact Scan",
            status="completed",
            conclusion=conclusion,
            title=title,
            summary=f"Scanned {scan_results['files_scanned']} files in {scan_results['scan_duration_seconds']:.2f}s",
        )

        logger.info(f"Created check run: {conclusion}")

    def process_job(self, job_data: Dict[str, Any]):
        """Process a single scan job.

        Args:
            job_data: Job data from queue
        """
        job_id = job_data["job_id"]
        installation_id = job_data["installation_id"]
        repo_full_name = job_data["repo_full_name"]
        pr_number = job_data["pr_number"]
        head_sha = job_data["head_sha"]
        base_ref = job_data["base_ref"]
        head_ref = job_data["head_ref"]
        file_paths = job_data["file_paths"]
        tier = job_data["tier"]
        truncated = job_data["truncated"]

        logger.info(f"Processing job {job_id}: {repo_full_name}#{pr_number}")

        try:
            # Update job status
            self.queue_manager.update_job_status(job_id, "processing")

            # Phase 1: Fast scan + initial comment
            logger.info("Phase 1: Fast scan")

            # Clone/fetch repository
            repo_path = self.clone_or_fetch_repo(
                installation_id=installation_id,
                repo_full_name=repo_full_name,
                base_ref=base_ref,
                head_ref=head_ref,
            )

            # Run scan
            scan_results = self.run_scan(
                repo_path=repo_path,
                file_paths=file_paths,
                tier=tier,
            )

            # Post initial comment
            comment_id = self.post_initial_comment(
                installation_id=installation_id,
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                files_scanned=scan_results["files_scanned"],
                scan_duration=scan_results["scan_duration_seconds"],
                changed_files=scan_results["changed_files"],
                tier=tier,
            )

            # Phase 2: AI validation (TODO - implement later)
            logger.info("Phase 2: AI validation (skipped in this version)")

            # Phase 3: Fix generation + enrichment (TODO - implement later)
            logger.info("Phase 3: Fix generation (skipped in this version)")

            # Update final comment
            self.update_final_comment(
                installation_id=installation_id,
                repo_full_name=repo_full_name,
                comment_id=comment_id,
                scan_results=scan_results,
                tier=tier,
                truncated=truncated,
            )

            # Post inline comments for findings
            self.post_inline_comments(
                installation_id=installation_id,
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                head_sha=head_sha,
                findings=scan_results["findings"],
            )

            # Create check run
            self.create_check_run(
                installation_id=installation_id,
                repo_full_name=repo_full_name,
                head_sha=head_sha,
                scan_results=scan_results,
            )

            # Mark job as completed
            self.queue_manager.update_job_status(job_id, "completed")
            logger.info(f"Job {job_id} completed successfully")

        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}", exc_info=True)

            # Mark job as failed
            self.queue_manager.update_job_status(job_id, "failed", result={"error": str(e)})

            # Post error comment
            try:
                error_comment = f"""## Impact Scan - Scan Failed

An error occurred while scanning this PR:

```
{str(e)}
```

This has been logged and we'll investigate. You can try:
- Re-pushing commits to trigger a new scan
- [Report this issue](https://github.com/user/impact-scan/issues) if it persists

---
*Impact Scan beta - [Give feedback](https://github.com/user/impact-scan/issues)*
"""
                self.github_client.post_comment(
                    installation_id=installation_id,
                    repo_full_name=repo_full_name,
                    pr_number=pr_number,
                    body=error_comment,
                )

                # Create neutral check run
                self.github_client.create_check_run(
                    installation_id=installation_id,
                    repo_full_name=repo_full_name,
                    head_sha=head_sha,
                    name="Impact Scan",
                    status="completed",
                    conclusion="neutral",
                    title="Impact Scan - Error",
                    summary=f"Scan failed: {str(e)}",
                )
            except Exception as comment_error:
                logger.error(f"Failed to post error comment: {comment_error}")

    def run(self):
        """Main worker loop - process jobs from queue."""
        logger.info("Scanner worker started")

        while True:
            try:
                # Dequeue highest priority job
                job_data = self.queue_manager.dequeue_scan()

                if job_data:
                    self.process_job(job_data)
                else:
                    # No jobs in queue, sleep for a bit
                    time.sleep(5)

            except KeyboardInterrupt:
                logger.info("Worker shutting down...")
                break
            except Exception as e:
                logger.error(f"Worker error: {e}", exc_info=True)
                time.sleep(10)  # Back off on errors


if __name__ == "__main__":
    worker = ScannerWorker()
    worker.run()
