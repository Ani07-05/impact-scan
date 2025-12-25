"""
Advanced rate limiting utilities with modern 2025 best practices.

Implements:
- Token Bucket Algorithm: Allows controlled bursts while maintaining average rate
- Exponential Backoff with Jitter: Progressive delays on rate limit hits
- Circuit Breaker Pattern: Auto-disable on repeated failures, auto-recover
- Retry-After Header Support: Respects server-specified wait times
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from rich.console import Console

console = Console()


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Too many failures, blocking requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class RateLimitStats:
    """Statistics for rate limiting behavior."""
    total_requests: int = 0
    rate_limited_requests: int = 0
    circuit_breaks: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_wait_time: float = 0.0
    last_request_time: Optional[float] = None

    def get_success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_requests == 0:
            return 100.0
        return (self.successful_requests / self.total_requests) * 100.0


@dataclass
class TokenBucket:
    """
    Token bucket rate limiter.

    Tokens are added at a fixed rate (refill_rate).
    Each request consumes tokens.
    Allows bursts up to max_tokens.
    """
    max_tokens: float
    refill_rate: float  # tokens per second
    current_tokens: float = field(init=False)
    last_refill_time: float = field(init=False)

    def __post_init__(self):
        """Initialize bucket as full."""
        self.current_tokens = self.max_tokens
        self.last_refill_time = time.time()

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill_time

        # Add tokens based on elapsed time
        tokens_to_add = elapsed * self.refill_rate
        self.current_tokens = min(self.max_tokens, self.current_tokens + tokens_to_add)
        self.last_refill_time = now

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens.

        Returns:
            True if tokens were available and consumed, False otherwise
        """
        self._refill()

        if self.current_tokens >= tokens:
            self.current_tokens -= tokens
            return True
        return False

    def get_wait_time(self, tokens: float = 1.0) -> float:
        """
        Calculate how long to wait until tokens are available.

        Returns:
            Wait time in seconds
        """
        self._refill()

        if self.current_tokens >= tokens:
            return 0.0

        tokens_needed = tokens - self.current_tokens
        wait_time = tokens_needed / self.refill_rate
        return wait_time


class CircuitBreaker:
    """
    Circuit breaker pattern for rate limiting.

    - CLOSED: Normal operation
    - OPEN: Too many failures, block all requests
    - HALF_OPEN: Testing if service recovered
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 300.0,  # 5 minutes
        half_open_max_calls: int = 1,
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of consecutive failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            half_open_max_calls: Max calls allowed in half-open state
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.half_open_calls = 0

    def can_proceed(self) -> bool:
        """Check if request can proceed based on circuit state."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if self.last_failure_time and time.time() - self.last_failure_time >= self.recovery_timeout:
                console.log("[yellow]Circuit breaker entering HALF_OPEN state (testing recovery)[/yellow]")
                self.state = CircuitState.HALF_OPEN
                self.half_open_calls = 0
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            # Allow limited calls in half-open state
            if self.half_open_calls < self.half_open_max_calls:
                self.half_open_calls += 1
                return True
            return False

        return False

    def record_success(self):
        """Record successful request."""
        if self.state == CircuitState.HALF_OPEN:
            console.log("[green]Circuit breaker recovered - returning to CLOSED state[/green]")
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None

    def record_failure(self):
        """Record failed request (rate limit hit)."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            # Failed during recovery test - back to OPEN
            console.log("[red]Circuit breaker recovery failed - returning to OPEN state[/red]")
            self.state = CircuitState.OPEN
        elif self.failure_count >= self.failure_threshold:
            # Too many failures - open circuit
            console.log(
                f"[red]Circuit breaker OPEN - too many rate limit failures "
                f"({self.failure_count}/{self.failure_threshold}). "
                f"Waiting {self.recovery_timeout}s before retry[/red]"
            )
            self.state = CircuitState.OPEN

    def reset(self):
        """Reset circuit breaker to closed state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None


class AdaptiveRateLimiter:
    """
    Advanced rate limiter combining multiple strategies.

    Features:
    - Token bucket algorithm for smooth rate limiting
    - Exponential backoff with jitter on rate limit hits
    - Circuit breaker to prevent cascading failures
    - Retry-After header support
    - Adaptive rate adjustment based on success/failure patterns
    """

    def __init__(
        self,
        requests_per_minute: float = 10.0,
        max_burst: int = 3,
        initial_backoff: float = 1.0,
        max_backoff: float = 60.0,
        backoff_multiplier: float = 2.0,
        circuit_breaker_threshold: int = 3,
        circuit_breaker_timeout: float = 300.0,
    ):
        """
        Initialize adaptive rate limiter.

        Args:
            requests_per_minute: Target request rate
            max_burst: Maximum burst size (token bucket capacity)
            initial_backoff: Initial backoff delay in seconds
            max_backoff: Maximum backoff delay in seconds
            backoff_multiplier: Multiplier for exponential backoff
            circuit_breaker_threshold: Failures before circuit opens
            circuit_breaker_timeout: Seconds before circuit recovery attempt
        """
        # Token bucket for smooth rate limiting
        refill_rate = requests_per_minute / 60.0  # tokens per second
        self.token_bucket = TokenBucket(
            max_tokens=max_burst,
            refill_rate=refill_rate
        )

        # Circuit breaker for failure protection
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_breaker_threshold,
            recovery_timeout=circuit_breaker_timeout
        )

        # Exponential backoff settings
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self.backoff_multiplier = backoff_multiplier
        self.current_backoff = initial_backoff

        # Retry-After tracking
        self.retry_after_until: Optional[float] = None

        # Statistics
        self.stats = RateLimitStats()

    async def acquire(self) -> bool:
        """
        Acquire permission to make a request.

        Returns:
            True if request can proceed, False if circuit is open
        """
        self.stats.total_requests += 1

        # Check circuit breaker first
        if not self.circuit_breaker.can_proceed():
            console.log("[yellow]Circuit breaker OPEN - request blocked[/yellow]")
            return False

        # Check Retry-After constraint
        if self.retry_after_until:
            wait_until = self.retry_after_until - time.time()
            if wait_until > 0:
                console.log(
                    f"[dim]Waiting {wait_until:.1f}s due to Retry-After header[/dim]"
                )
                await asyncio.sleep(wait_until)
                self.stats.total_wait_time += wait_until
            self.retry_after_until = None

        # Try to consume token
        if not self.token_bucket.consume():
            # Need to wait for tokens
            wait_time = self.token_bucket.get_wait_time()
            console.log(f"[dim]Rate limit: waiting {wait_time:.1f}s for token[/dim]")
            await asyncio.sleep(wait_time)
            self.stats.total_wait_time += wait_time
            self.token_bucket.consume()  # Consume after waiting
            self.stats.rate_limited_requests += 1

        self.stats.last_request_time = time.time()
        return True

    def record_success(self):
        """Record successful request - reset backoff."""
        self.stats.successful_requests += 1
        self.circuit_breaker.record_success()
        self.current_backoff = self.initial_backoff  # Reset backoff

    async def record_rate_limit(
        self,
        retry_after: Optional[int] = None,
        retry_after_header: Optional[str] = None
    ):
        """
        Record rate limit hit with exponential backoff.

        Args:
            retry_after: Retry-After value in seconds
            retry_after_header: Raw Retry-After header value
        """
        self.stats.rate_limited_requests += 1
        self.stats.failed_requests += 1
        self.circuit_breaker.record_failure()

        # Parse Retry-After header
        if retry_after_header:
            try:
                retry_after = int(retry_after_header)
            except ValueError:
                # Might be HTTP-date format, ignore for now
                pass

        # Use Retry-After if provided, otherwise use exponential backoff
        if retry_after:
            wait_time = float(retry_after)
            self.retry_after_until = time.time() + wait_time
            console.log(
                f"[yellow]Rate limit hit - Server says retry after {wait_time}s[/yellow]"
            )
        else:
            # Exponential backoff with jitter
            jitter = random.uniform(0, self.current_backoff * 0.3)
            wait_time = min(self.current_backoff + jitter, self.max_backoff)

            console.log(
                f"[yellow]Rate limit hit - Backing off {wait_time:.1f}s "
                f"(attempt {self.stats.rate_limited_requests})[/yellow]"
            )

            # Increase backoff for next time
            self.current_backoff = min(
                self.current_backoff * self.backoff_multiplier,
                self.max_backoff
            )

            await asyncio.sleep(wait_time)
            self.stats.total_wait_time += wait_time

    def record_failure(self):
        """Record general failure (not rate limit)."""
        self.stats.failed_requests += 1

    def get_stats(self) -> RateLimitStats:
        """Get current statistics."""
        return self.stats

    def reset(self):
        """Reset rate limiter state."""
        self.current_backoff = self.initial_backoff
        self.retry_after_until = None
        self.circuit_breaker.reset()
