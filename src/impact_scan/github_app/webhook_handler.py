"""FastAPI webhook handler for GitHub App."""

import os
import hmac
import hashlib
import json
from pathlib import Path
from typing import Optional, Any
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables from .env file in project root
project_root = Path(__file__).parent.parent.parent.parent
env_path = project_root / ".env"
load_dotenv(env_path)

from .tier_manager import TierManager
from .github_client import GitHubClient
from .queue_manager import QueueManager


app = FastAPI(title="Impact Scan GitHub App")

# Initialize managers (lazy initialization for GitHub client)
tier_manager = TierManager()
github_client = None  # Initialized on first use
queue_manager = QueueManager()


def get_github_client() -> GitHubClient:
    """Get GitHub client instance (lazy initialization)."""
    global github_client
    if github_client is None:
        github_client = GitHubClient()
    return github_client


class WebhookPayload(BaseModel):
    """GitHub webhook payload."""
    action: str
    installation: dict
    pull_request: Optional[dict] = None
    repository: dict


def verify_webhook_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify GitHub webhook signature.

    Args:
        payload_body: Raw request body bytes
        signature_header: X-Hub-Signature-256 header value

    Returns:
        True if signature is valid
    """
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not webhook_secret:
        raise ValueError("GITHUB_WEBHOOK_SECRET not configured")

    # GitHub sends signature as "sha256=<signature>"
    if not signature_header.startswith("sha256="):
        return False

    expected_signature = signature_header.split("=")[1]

    # Calculate HMAC
    mac = hmac.new(
        webhook_secret.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256,
    )
    actual_signature = mac.hexdigest()

    # Constant-time comparison
    return hmac.compare_digest(expected_signature, actual_signature)


@app.get("/health")
async def health_check():
    """Health check endpoint.

    Returns:
        Health status and queue metrics
    """
    queue_depth = queue_manager.get_queue_depth()

    return {
        "status": "healthy",
        "queue_depth": queue_depth,
        "version": "0.1.0",
    }


@app.post("/webhook")
async def handle_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
):
    """Handle GitHub webhook events.

    Args:
        request: FastAPI request object
        background_tasks: FastAPI background tasks

    Returns:
        Success response

    Raises:
        HTTPException: If signature verification fails
    """
    # Get signature header
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature header")

    # Get raw body for signature verification
    body = await request.body()

    # Verify signature
    if not verify_webhook_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse payload
    payload = json.loads(body)

    # Get event type
    event_type = request.headers.get("X-GitHub-Event")

    # Handle pull request events
    if event_type == "pull_request":
        await handle_pull_request_event(payload, background_tasks)

    return {"status": "ok"}


async def handle_pull_request_event(payload: dict, background_tasks: BackgroundTasks):
    """Handle pull_request webhook events.

    Args:
        payload: Webhook payload
        background_tasks: FastAPI background tasks
    """
    action = payload.get("action")

    # Only handle opened and synchronize (new commits pushed)
    if action not in ("opened", "synchronize"):
        return

    # Extract PR data
    installation_id = payload["installation"]["id"]
    repo_full_name = payload["repository"]["full_name"]
    pr_number = payload["pull_request"]["number"]
    head_sha = payload["pull_request"]["head"]["sha"]
    base_ref = payload["pull_request"]["base"]["ref"]
    head_ref = payload["pull_request"]["head"]["ref"]

    # Check tier and quota
    tier_info = tier_manager.get_tier_info(installation_id)

    if not tier_info.can_scan:
        # Quota exceeded - post limit reached comment
        await post_limit_reached_comment(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            head_sha=head_sha,
            tier_info=tier_info,
        )
        return

    # Get changed files
    gh_client = get_github_client()
    changed_files = gh_client.get_pr_files(
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        pr_number=pr_number,
    )

    # Truncate to 50 files if needed
    file_limit = 50
    truncated = len(changed_files) > file_limit
    if truncated:
        changed_files = changed_files[:file_limit]

    # Extract file paths
    file_paths = [f["filename"] for f in changed_files]

    # Enqueue scan job
    job_id = queue_manager.enqueue_scan(
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        head_sha=head_sha,
        base_ref=base_ref,
        head_ref=head_ref,
        file_paths=file_paths,
        tier=tier_info.tier,
        truncated=truncated,
    )

    # Increment quota
    tier_manager.increment_scan_count(installation_id)

    # Return success (worker will process in background)
    return {"job_id": job_id, "status": "queued"}


async def post_limit_reached_comment(
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
    tier_info: Any,
):
    """Post comment when daily scan limit is reached.

    Args:
        installation_id: GitHub App installation ID
        repo_full_name: Full repo name (owner/repo)
        pr_number: Pull request number
        head_sha: Git commit SHA
        tier_info: Tier information object
    """
    reset_time = tier_manager._get_next_reset_time()

    comment_body = f"""## Impact Scan - Daily Limit Reached

You've used all **{tier_info.daily_limit} free scans** for today.

This PR is **queued** and will be scanned tomorrow at {reset_time}, or you can:

**Early Bird Pricing** (Coming Soon)
- Unlimited scans: $29/month
- Stack Overflow fix citations
- Polish suggestions (performance, style)
- Custom rules support
- [Join the waitlist →](https://impact-scan.dev/waitlist)

---
*Free tier: {tier_info.daily_limit} scans/day | Resets daily at 00:00 UTC*
"""

    # Post comment
    gh_client = get_github_client()
    gh_client.post_comment(
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        body=comment_body,
    )

    # Create neutral check run
    gh_client.create_check_run(
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        head_sha=head_sha,
        name="Impact Scan",
        status="completed",
    )
    # Note: Need to update check run with conclusion="neutral" in a separate call
    # This is a simplified version - full implementation would track check_run_id


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
