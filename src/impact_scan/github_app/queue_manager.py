"""Redis-based queue manager with smart scheduling."""

import os
import uuid
import json
from typing import Optional, Dict, Any, List
import redis
from datetime import datetime, timezone


class QueueManager:
    """Manages scan job queue with priority scheduling."""

    def __init__(self, redis_url: Optional[str] = None):
        """Initialize queue manager.

        Args:
            redis_url: Redis connection URL. Defaults to env var REDIS_URL.
        """
        url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = redis.from_url(url, decode_responses=True)

        # Queue keys
        self.QUEUE_KEY = "scan_queue"
        self.JOB_PREFIX = "job:"

    def enqueue_scan(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        head_sha: str,
        base_ref: str,
        head_ref: str,
        file_paths: List[str],
        tier: str,
        truncated: bool = False,
    ) -> str:
        """Enqueue a scan job with smart priority.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            pr_number: Pull request number
            head_sha: Git commit SHA
            base_ref: Base branch reference
            head_ref: Head branch reference
            file_paths: List of changed file paths
            tier: Installation tier ("free" or "pro")
            truncated: Whether file list was truncated

        Returns:
            Job ID
        """
        job_id = str(uuid.uuid4())

        # Create job data
        job_data = {
            "job_id": job_id,
            "installation_id": installation_id,
            "repo_full_name": repo_full_name,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "base_ref": base_ref,
            "head_ref": head_ref,
            "file_paths": file_paths,
            "file_count": len(file_paths),
            "tier": tier,
            "truncated": truncated,
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "status": "queued",
        }

        # Store job data
        job_key = f"{self.JOB_PREFIX}{job_id}"
        self.redis_client.setex(
            job_key,
            60 * 60 * 24,  # Expire after 24 hours
            json.dumps(job_data),
        )

        # Calculate priority score for smart scheduling
        # Priority = (tier_weight * 100) - file_count
        # This means:
        # - Pro tier gets priority (200 - file_count)
        # - Free tier (100 - file_count)
        # - Within same tier, smaller PRs go first
        tier_weight = 2 if tier == "pro" else 1
        priority_score = (tier_weight * 100) - len(file_paths)

        # Add to sorted set (higher score = higher priority)
        self.redis_client.zadd(
            self.QUEUE_KEY,
            {job_id: priority_score},
        )

        return job_id

    def dequeue_scan(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        """Dequeue next scan job (blocking).

        Args:
            timeout: Block timeout in seconds

        Returns:
            Job data dict or None if timeout
        """
        # Get highest priority job (ZREVRANGE returns highest scores first)
        # This is non-blocking - for production, consider using BZPOPMAX
        result = self.redis_client.zrevrange(
            self.QUEUE_KEY,
            0,
            0,  # Get only the first (highest priority) item
            withscores=False,
        )

        if not result:
            return None

        job_id = result[0]

        # Remove from queue
        self.redis_client.zrem(self.QUEUE_KEY, job_id)

        # Get job data
        job_key = f"{self.JOB_PREFIX}{job_id}"
        job_data_json = self.redis_client.get(job_key)

        if not job_data_json:
            # Job expired or deleted
            return None

        job_data = json.loads(job_data_json)
        job_data["status"] = "processing"

        # Update job status
        self.redis_client.setex(
            job_key,
            60 * 60 * 24,  # Extend expiry
            json.dumps(job_data),
        )

        return job_data

    def update_job_status(
        self,
        job_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update job status.

        Args:
            job_id: Job ID
            status: New status ("processing", "completed", "failed")
            result: Optional result data
        """
        job_key = f"{self.JOB_PREFIX}{job_id}"
        job_data_json = self.redis_client.get(job_key)

        if not job_data_json:
            return

        job_data = json.loads(job_data_json)
        job_data["status"] = status

        if status == "completed":
            job_data["completed_at"] = datetime.now(timezone.utc).isoformat()
        elif status == "failed":
            job_data["failed_at"] = datetime.now(timezone.utc).isoformat()

        if result:
            job_data["result"] = result

        # Update job data
        self.redis_client.setex(
            job_key,
            60 * 60 * 24,  # Keep for 24 hours
            json.dumps(job_data),
        )

    def get_queue_depth(self) -> int:
        """Get current queue depth.

        Returns:
            Number of jobs in queue
        """
        return self.redis_client.zcard(self.QUEUE_KEY)

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status and data.

        Args:
            job_id: Job ID

        Returns:
            Job data dict or None if not found
        """
        job_key = f"{self.JOB_PREFIX}{job_id}"
        job_data_json = self.redis_client.get(job_key)

        if not job_data_json:
            return None

        return json.loads(job_data_json)

    def get_installation_queue_depth(self, installation_id: int) -> int:
        """Get queue depth for a specific installation.

        Args:
            installation_id: GitHub App installation ID

        Returns:
            Number of pending jobs for this installation
        """
        # Get all job IDs in queue
        all_job_ids = self.redis_client.zrange(self.QUEUE_KEY, 0, -1)

        # Count jobs for this installation
        count = 0
        for job_id in all_job_ids:
            job_data = self.get_job_status(job_id)
            if job_data and job_data.get("installation_id") == installation_id:
                count += 1

        return count
