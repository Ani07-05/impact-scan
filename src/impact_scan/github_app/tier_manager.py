"""Tier management and quota tracking for GitHub App."""

import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import redis
from pydantic import BaseModel


class TierInfo(BaseModel):
    """Installation tier information."""
    installation_id: int
    tier: str  # "free" | "pro"
    scans_today: int
    daily_limit: int
    can_scan: bool
    features: Dict[str, bool]


class TierManager:
    """Manages installation tiers and quota tracking."""

    def __init__(self, redis_url: Optional[str] = None):
        """Initialize tier manager with Redis connection.

        Args:
            redis_url: Redis connection URL. Defaults to env var REDIS_URL.
        """
        url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = redis.from_url(url, decode_responses=True)

        # Tier limits
        self.FREE_TIER_DAILY_LIMIT = 25
        self.PRO_TIER_DAILY_LIMIT = -1  # Unlimited

    def get_tier_info(self, installation_id: int) -> TierInfo:
        """Get tier information for an installation.

        Args:
            installation_id: GitHub App installation ID

        Returns:
            TierInfo with quota status and features
        """
        # Get tier (default to free)
        tier_key = f"installation_tier:{installation_id}"
        tier = self.redis_client.get(tier_key) or "free"

        # Get today's scan count
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        count_key = f"scan_count:{installation_id}:{today}"
        scans_today = int(self.redis_client.get(count_key) or 0)

        # Determine limits and features
        if tier == "pro":
            daily_limit = self.PRO_TIER_DAILY_LIMIT
            can_scan = True  # Unlimited
            features = {
                "stackoverflow_citations": True,
                "polish_suggestions": True,
                "custom_rules": True,
                "priority_queue": True,
            }
        else:  # free tier
            daily_limit = self.FREE_TIER_DAILY_LIMIT
            can_scan = scans_today < daily_limit
            features = {
                "stackoverflow_citations": False,
                "polish_suggestions": False,
                "custom_rules": False,
                "priority_queue": False,
            }

        return TierInfo(
            installation_id=installation_id,
            tier=tier,
            scans_today=scans_today,
            daily_limit=daily_limit,
            can_scan=can_scan,
            features=features,
        )

    def increment_scan_count(self, installation_id: int) -> int:
        """Increment scan count for today.

        Args:
            installation_id: GitHub App installation ID

        Returns:
            New scan count for today
        """
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        count_key = f"scan_count:{installation_id}:{today}"

        # Increment and set expiry for automatic cleanup (expire after 2 days)
        new_count = self.redis_client.incr(count_key)
        self.redis_client.expire(count_key, 60 * 60 * 24 * 2)  # 2 days

        return new_count

    def set_tier(self, installation_id: int, tier: str) -> None:
        """Set tier for an installation (admin use).

        Args:
            installation_id: GitHub App installation ID
            tier: Tier name ("free" or "pro")
        """
        if tier not in ("free", "pro"):
            raise ValueError(f"Invalid tier: {tier}. Must be 'free' or 'pro'")

        tier_key = f"installation_tier:{installation_id}"
        self.redis_client.set(tier_key, tier)

    def get_quota_usage(self, installation_id: int) -> Dict[str, Any]:
        """Get detailed quota usage for dashboard.

        Args:
            installation_id: GitHub App installation ID

        Returns:
            Dict with usage stats
        """
        tier_info = self.get_tier_info(installation_id)

        return {
            "installation_id": installation_id,
            "tier": tier_info.tier,
            "scans_today": tier_info.scans_today,
            "daily_limit": tier_info.daily_limit,
            "scans_remaining": (
                tier_info.daily_limit - tier_info.scans_today
                if tier_info.daily_limit > 0
                else -1  # Unlimited
            ),
            "can_scan": tier_info.can_scan,
            "reset_time": self._get_next_reset_time(),
        }

    def _get_next_reset_time(self) -> str:
        """Get next quota reset time (midnight UTC).

        Returns:
            ISO timestamp of next reset
        """
        now = datetime.now(timezone.utc)
        tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # If it's already past midnight, add a day
        if tomorrow <= now:
            from datetime import timedelta
            tomorrow = tomorrow + timedelta(days=1)

        return tomorrow.isoformat()
