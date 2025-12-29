"""GitHub App integration for Impact Scan.

Provides webhook handling, background scanning, and PR comment generation
for automated code review on GitHub Pull Requests.
"""

from .webhook_handler import app as webhook_app
from .tier_manager import TierManager
from .github_client import GitHubClient

__all__ = ["webhook_app", "TierManager", "GitHubClient"]
