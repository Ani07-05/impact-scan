"""GitHub API client for posting comments and managing checks."""

import os
import time
import jwt
import requests
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone


class GitHubClient:
    """GitHub API client for GitHub App operations."""

    def __init__(
        self,
        app_id: Optional[str] = None,
        private_key: Optional[str] = None,
    ):
        """Initialize GitHub client.

        Args:
            app_id: GitHub App ID. Defaults to env var GITHUB_APP_ID.
            private_key: GitHub App private key (PEM format). Defaults to env var GITHUB_APP_PRIVATE_KEY.
        """
        self.app_id = app_id or os.getenv("GITHUB_APP_ID")
        raw_private_key = private_key or os.getenv("GITHUB_APP_PRIVATE_KEY")

        # Replace literal \n with actual newlines
        self.private_key = raw_private_key.replace("\\n", "\n") if raw_private_key else None

        if not self.app_id or not self.private_key:
            raise ValueError(
                "GitHub App credentials not configured. "
                "Set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY environment variables."
            )

        self.base_url = "https://api.github.com"
        self._installation_tokens: Dict[int, tuple[str, datetime]] = {}

    def _generate_jwt(self) -> str:
        """Generate JWT for GitHub App authentication.

        Returns:
            JWT token string
        """
        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued 60 seconds in the past to account for clock drift
            "exp": now + (10 * 60),  # Expires in 10 minutes
            "iss": self.app_id,
        }

        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def get_installation_token(self, installation_id: int) -> str:
        """Get installation access token (cached for 1 hour).

        Args:
            installation_id: GitHub App installation ID

        Returns:
            Installation access token
        """
        # Check if we have a cached token that's still valid
        if installation_id in self._installation_tokens:
            token, expires_at = self._installation_tokens[installation_id]
            if datetime.now(timezone.utc) < expires_at - timedelta(minutes=5):
                return token

        # Generate new installation token
        jwt_token = self._generate_jwt()
        url = f"{self.base_url}/app/installations/{installation_id}/access_tokens"

        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10,
        )

        # Better error message
        if response.status_code == 401:
            raise ValueError(
                f"GitHub App authentication failed (401 Unauthorized). "
                f"Please check:\n"
                f"1. GITHUB_APP_ID is correct: {self.app_id}\n"
                f"2. Private key matches the GitHub App\n"
                f"3. App is installed for installation_id: {installation_id}\n"
                f"Response: {response.text}"
            )

        response.raise_for_status()

        data = response.json()
        token = data["token"]
        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))

        # Cache token
        self._installation_tokens[installation_id] = (token, expires_at)

        return token

    def post_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        body: str,
    ) -> int:
        """Post a comment on a PR.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            pr_number: Pull request number
            body: Comment body (markdown)

        Returns:
            Comment ID
        """
        token = self.get_installation_token(installation_id)
        url = f"{self.base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"

        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json={"body": body},
            timeout=10,
        )
        response.raise_for_status()

        return response.json()["id"]

    def edit_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        comment_id: int,
        body: str,
    ) -> Dict[str, Any]:
        """Edit an existing comment.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            comment_id: Comment ID to edit
            body: New comment body (markdown)

        Returns:
            API response
        """
        token = self.get_installation_token(installation_id)
        url = f"{self.base_url}/repos/{repo_full_name}/issues/comments/{comment_id}"

        response = requests.patch(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json={"body": body},
            timeout=10,
        )
        response.raise_for_status()

        return response.json()

    def create_check_run(
        self,
        installation_id: int,
        repo_full_name: str,
        head_sha: str,
        name: str = "Impact Scan",
        status: str = "queued",
        conclusion: Optional[str] = None,
        title: Optional[str] = None,
        summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a GitHub check run.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            head_sha: Git commit SHA
            name: Check run name
            status: Check status ("queued", "in_progress", "completed")
            conclusion: Check conclusion ("success", "failure", "neutral", "cancelled")
            title: Check title
            summary: Check summary (markdown)

        Returns:
            API response with check run ID
        """
        token = self.get_installation_token(installation_id)
        url = f"{self.base_url}/repos/{repo_full_name}/check-runs"

        data: Dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }

        if conclusion:
            data["conclusion"] = conclusion

        if title or summary:
            data["output"] = {}
            if title:
                data["output"]["title"] = title
            if summary:
                data["output"]["summary"] = summary

        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json=data,
            timeout=10,
        )
        response.raise_for_status()

        return response.json()

    def update_check_run(
        self,
        installation_id: int,
        repo_full_name: str,
        check_run_id: int,
        status: str = "completed",
        conclusion: Optional[str] = None,
        title: Optional[str] = None,
        summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a GitHub check run.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            check_run_id: Check run ID
            status: Check status ("queued", "in_progress", "completed")
            conclusion: Check conclusion ("success", "failure", "neutral", "cancelled")
            title: Check title
            summary: Check summary (markdown)

        Returns:
            API response
        """
        token = self.get_installation_token(installation_id)
        url = f"{self.base_url}/repos/{repo_full_name}/check-runs/{check_run_id}"

        data: Dict[str, Any] = {"status": status}

        if conclusion:
            data["conclusion"] = conclusion

        if title or summary:
            data["output"] = {}
            if title:
                data["output"]["title"] = title
            if summary:
                data["output"]["summary"] = summary

        response = requests.patch(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json=data,
            timeout=10,
        )
        response.raise_for_status()

        return response.json()

    def post_review_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        commit_id: str,
        path: str,
        line: int,
        body: str,
    ) -> Dict[str, Any]:
        """Post an inline review comment on a specific line.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            pr_number: Pull request number
            commit_id: Git commit SHA
            path: File path relative to repo root
            line: Line number
            body: Comment body (markdown)

        Returns:
            API response
        """
        token = self.get_installation_token(installation_id)
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}/comments"

        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json={
                "body": body,
                "commit_id": commit_id,
                "path": path,
                "line": line,
            },
            timeout=10,
        )
        response.raise_for_status()

        return response.json()

    def get_pr_files(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
    ) -> List[Dict[str, Any]]:
        """Get list of changed files in a PR.

        Args:
            installation_id: GitHub App installation ID
            repo_full_name: Full repo name (owner/repo)
            pr_number: Pull request number

        Returns:
            List of file objects with filename, status, changes
        """
        token = self.get_installation_token(installation_id)
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}/files"

        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10,
        )
        response.raise_for_status()

        return response.json()
