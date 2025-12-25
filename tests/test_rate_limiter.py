"""
Tests for the advanced rate limiting system.

Tests token bucket, exponential backoff, circuit breaker, and persistent cache.
"""

import asyncio
import time
from pathlib import Path
import tempfile

import pytest

from src.impact_scan.utils.rate_limiter import (
    AdaptiveRateLimiter,
    CircuitBreaker,
    CircuitState,
    TokenBucket,
    RateLimitStats,
)
from src.impact_scan.utils.persistent_cache import PersistentCache


class TestTokenBucket:
    """Test token bucket algorithm."""

    def test_initialization(self):
        """Test token bucket initializes with full capacity."""
        bucket = TokenBucket(max_tokens=5, refill_rate=1.0)
        assert bucket.current_tokens == 5
        assert bucket.max_tokens == 5

    def test_consume_tokens(self):
        """Test consuming tokens."""
        bucket = TokenBucket(max_tokens=5, refill_rate=1.0)

        # Can consume when tokens available
        assert bucket.consume(2.0) is True
        assert abs(bucket.current_tokens - 3.0) < 0.01

        # Can consume remaining tokens
        assert bucket.consume(3.0) is True
        assert abs(bucket.current_tokens - 0.0) < 0.01

        # Cannot consume when bucket is empty
        assert bucket.consume(1.0) is False

    def test_refill(self):
        """Test token refill over time."""
        bucket = TokenBucket(max_tokens=5, refill_rate=2.0)  # 2 tokens per second

        # Consume all tokens
        bucket.consume(5.0)
        assert bucket.current_tokens == 0.0

        # Wait and refill
        time.sleep(1.0)
        bucket._refill()

        # Should have refilled ~2 tokens
        assert bucket.current_tokens >= 1.8
        assert bucket.current_tokens <= 2.2

    def test_max_capacity(self):
        """Test bucket doesn't exceed max capacity."""
        bucket = TokenBucket(max_tokens=5, refill_rate=10.0)

        # Wait for refill
        time.sleep(2.0)
        bucket._refill()

        # Should not exceed max capacity
        assert bucket.current_tokens <= 5.0

    def test_wait_time_calculation(self):
        """Test wait time calculation."""
        bucket = TokenBucket(max_tokens=5, refill_rate=2.0)

        # Consume all tokens
        bucket.consume(5.0)

        # Should need to wait for tokens
        wait_time = bucket.get_wait_time(2.0)
        assert wait_time > 0.0
        assert wait_time <= 1.5  # Need 2 tokens at 2/sec = ~1 second


class TestCircuitBreaker:
    """Test circuit breaker pattern."""

    def test_initialization(self):
        """Test circuit breaker initializes in CLOSED state."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_closed_state(self):
        """Test requests allowed in CLOSED state."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)
        assert cb.can_proceed() is True

    def test_open_after_failures(self):
        """Test circuit opens after threshold failures."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)

        # Record failures
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.can_proceed() is False

    def test_half_open_recovery(self):
        """Test circuit enters HALF_OPEN after timeout."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)

        # Open the circuit
        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(1.1)

        # Should allow testing
        assert cb.can_proceed() is True
        assert cb.state == CircuitState.HALF_OPEN

    def test_recovery_on_success(self):
        """Test circuit closes on successful half-open request."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)

        # Open the circuit
        for _ in range(3):
            cb.record_failure()

        # Wait and transition to half-open
        time.sleep(1.1)
        cb.can_proceed()

        # Record success
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_reset(self):
        """Test circuit breaker reset."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)

        # Open the circuit
        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN

        # Reset
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0


class TestAdaptiveRateLimiter:
    """Test adaptive rate limiter."""

    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test rate limiter initializes correctly."""
        limiter = AdaptiveRateLimiter(
            requests_per_minute=60.0,
            max_burst=3,
            initial_backoff=1.0,
            max_backoff=60.0,
        )

        assert limiter.token_bucket.max_tokens == 3
        assert limiter.current_backoff == 1.0
        assert limiter.circuit_breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_acquire_tokens(self):
        """Test acquiring tokens."""
        limiter = AdaptiveRateLimiter(
            requests_per_minute=60.0,
            max_burst=3,
        )

        # Should allow burst requests
        assert await limiter.acquire() is True
        assert await limiter.acquire() is True
        assert await limiter.acquire() is True

    @pytest.mark.asyncio
    async def test_record_success(self):
        """Test recording successful requests."""
        limiter = AdaptiveRateLimiter()

        limiter.record_success()

        assert limiter.stats.successful_requests == 1
        assert limiter.current_backoff == limiter.initial_backoff

    @pytest.mark.asyncio
    async def test_record_rate_limit(self):
        """Test recording rate limit hits."""
        limiter = AdaptiveRateLimiter(
            initial_backoff=0.1,  # Small backoff for testing
            max_backoff=1.0,
        )

        initial_backoff = limiter.current_backoff

        # Record rate limit (with small timeout for testing)
        await limiter.record_rate_limit()

        assert limiter.stats.rate_limited_requests == 1
        assert limiter.current_backoff > initial_backoff  # Exponential increase

    @pytest.mark.asyncio
    async def test_retry_after_header(self):
        """Test respecting Retry-After header."""
        limiter = AdaptiveRateLimiter()

        # Record rate limit with Retry-After
        await limiter.record_rate_limit(retry_after=1)

        # Should set retry_after_until
        assert limiter.retry_after_until is not None
        assert limiter.retry_after_until > time.time()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        """Test circuit breaker opens after repeated failures."""
        limiter = AdaptiveRateLimiter(
            circuit_breaker_threshold=2,
            initial_backoff=0.1,
        )

        # Record failures to open circuit
        await limiter.record_rate_limit()
        await limiter.record_rate_limit()

        assert limiter.circuit_breaker.state == CircuitState.OPEN
        assert await limiter.acquire() is False

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Test statistics tracking."""
        limiter = AdaptiveRateLimiter()

        await limiter.acquire()
        limiter.record_success()

        stats = limiter.get_stats()
        assert stats.total_requests == 1
        assert stats.successful_requests == 1
        assert stats.get_success_rate() == 100.0


class TestPersistentCache:
    """Test persistent SQLite cache."""

    def test_initialization(self):
        """Test cache initializes with database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")

            assert cache.db_path.exists()
            assert cache.default_ttl == 86400

    def test_set_and_get(self):
        """Test setting and getting cached values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")

            key_data = {"vuln_id": "CWE-89", "title": "SQL Injection"}
            value = {"solution": "Use parameterized queries"}

            cache.set(key_data, value, ttl=60)
            retrieved = cache.get(key_data)

            assert retrieved == value

    def test_cache_miss(self):
        """Test cache miss returns None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")

            result = cache.get({"nonexistent": "key"})
            assert result is None

    def test_expiration(self):
        """Test cache entries expire after TTL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")

            key_data = {"test": "key"}
            value = {"data": "value"}

            # Set with 1 second TTL
            cache.set(key_data, value, ttl=1)

            # Should be available immediately
            assert cache.get(key_data) == value

            # Wait for expiration (with buffer)
            time.sleep(2.0)

            # Should be expired
            assert cache.get(key_data) is None

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")

            # Add expired entry
            cache.set({"key": "1"}, {"data": "1"}, ttl=1)
            time.sleep(2.0)  # Wait longer to ensure expiration

            # Add active entry
            cache.set({"key": "2"}, {"data": "2"}, ttl=60)

            # Cleanup
            deleted = cache.cleanup_expired()

            assert deleted == 1
            stats = cache.get_stats()
            assert stats["total_entries"] == 1

    def test_cache_stats(self):
        """Test cache statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")

            # Add some entries
            cache.set({"key": "1"}, {"data": "1"})
            cache.set({"key": "2"}, {"data": "2"})

            # Get to increment hit count
            cache.get({"key": "1"})
            cache.get({"key": "1"})

            stats = cache.get_stats()
            assert stats["total_entries"] == 2
            assert stats["active_entries"] == 2
            assert stats["total_cache_hits"] == 2
            assert stats["db_size_mb"] > 0

    def test_clear_cache(self):
        """Test clearing all cache entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")

            # Add entries
            cache.set({"key": "1"}, {"data": "1"})
            cache.set({"key": "2"}, {"data": "2"})

            # Clear
            cache.clear()

            stats = cache.get_stats()
            assert stats["total_entries"] == 0

    def test_persistence_across_instances(self):
        """Test cache persists across different instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # First instance
            cache1 = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")
            cache1.set({"key": "persist"}, {"data": "value"})

            # Second instance (simulates restart)
            cache2 = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")
            retrieved = cache2.get({"key": "persist"})

            assert retrieved == {"data": "value"}

    def test_context_manager(self):
        """Test cache as context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with PersistentCache(cache_dir=Path(tmpdir), db_name="test.db") as cache:
                cache.set({"key": "1"}, {"data": "1"}, ttl=1)
                time.sleep(2.0)  # Wait longer to ensure expiration
                # Context manager should cleanup on exit

            # Verify cleanup happened
            cache2 = PersistentCache(cache_dir=Path(tmpdir), db_name="test.db")
            stats = cache2.get_stats()
            assert stats["total_entries"] == 0
