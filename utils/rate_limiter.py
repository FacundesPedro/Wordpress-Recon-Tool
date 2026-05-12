# recon_wp/utils/rate_limiter.py
"""Async rate limiter with exponential backoff for brute-force protection.

This module provides rate limiting utilities to prevent:
- Account lockouts during credential brute-forcing
- Detection by WAF/IPS systems
- Excessive load on target servers

Usage:
    from utils.rate_limiter import RateLimiter

    limiter = RateLimiter(max_requests=5, per_seconds=1.0)
    async with limiter:
        await http_client.post(url, content=data)
"""

import asyncio
import time
from typing import Optional


class RateLimiter:
    """Async rate limiter using token bucket algorithm.

    SECURITY:
    - Prevents excessive requests that could cause account lockouts
    - Implements exponential backoff on failures
    - Thread-safe for concurrent access

    Args:
        max_requests: Maximum requests allowed per interval
        per_seconds: Time interval in seconds
        backoff_factor: Multiplier for exponential backoff
        max_retries: Maximum retry attempts with backoff
    """

    def __init__(
        self,
        max_requests: int = 5,
        per_seconds: float = 1.0,
        backoff_factor: float = 2.0,
        max_retries: int = 3,
    ):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.backoff_factor = backoff_factor
        self.max_retries = max_retries

        self._tokens = float(max_requests)
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def _acquire(self):
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._tokens = min(
                self.max_requests,
                self._tokens + elapsed * (self.max_requests / self.per_seconds),
            )
            self._last_update = now

            if self._tokens < 1:
                wait_time = (1 - self._tokens) * (self.per_seconds / self.max_requests)
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1

    async def __aenter__(self):
        """Context manager entry - acquire token."""
        await self._acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - no action needed."""
        pass


class RetryLimiter:
    """Rate limiter with retry logic and exponential backoff.

    SECURITY:
    - Implements exponential backoff to avoid overwhelming servers
    - Skips after max consecutive failures to prevent lockouts
    - Tracks consecutive failures for lockout detection
    """

    def __init__(
        self,
        max_requests: int = 5,
        per_seconds: float = 1.0,
        backoff_factor: float = 2.0,
        max_retries: int = 3,
        max_consecutive_failures: int = 3,
    ):
        self.rate_limiter = RateLimiter(
            max_requests=max_requests,
            per_seconds=per_seconds,
            backoff_factor=backoff_factor,
            max_retries=max_retries,
        )
        self.max_consecutive_failures = max_consecutive_failures
        self._consecutive_failures = 0
        self._backoff_time = 1.0
        self._lock = asyncio.Lock()

    @property
    def consecutive_failures(self) -> int:
        """Number of consecutive failures."""
        return self._consecutive_failures

    def should_skip(self) -> bool:
        """Check if we should skip due to too many failures."""
        return self._consecutive_failures >= self.max_consecutive_failures

    async def execute_with_retry(
        self,
        coro,
        on_success: Optional[callable] = None,
        on_failure: Optional[callable] = None,
    ):
        """Execute a coroutine with rate limiting and retry.

        Args:
            coro: The coroutine to execute
            on_success: Optional callback on success (receives result)
            on_failure: Optional callback on failure (receives exception)

        Returns:
            Result of coroutine if successful, None if skipped or failed
        """
        if self.should_skip():
            return None

        async with self.rate_limiter:
            for attempt in range(self.rate_limiter.max_retries):
                try:
                    result = await coro
                    async with self._lock:
                        self._consecutive_failures = 0
                        self._backoff_time = 1.0

                    if on_success:
                        on_success(result)
                    return result

                except Exception as e:
                    async with self._lock:
                        self._consecutive_failures += 1

                    if on_failure:
                        on_failure(e)

                    if self._consecutive_failures >= self.max_consecutive_failures:
                        break

                    if attempt < self.rate_limiter.max_retries - 1:
                        await asyncio.sleep(self._backoff_time)
                        self._backoff_time *= self.rate_limiter.backoff_factor

        return None

    def reset(self):
        """Reset failure counter and backoff."""
        self._consecutive_failures = 0
        self._backoff_time = 1.0
