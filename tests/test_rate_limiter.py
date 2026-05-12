# tests/test_rate_limiter.py
"""Tests for rate limiter module."""

import asyncio
import time

import pytest

from utils.rate_limiter import RateLimiter, RetryLimiter


class TestRateLimiter:
    """Tests for the basic RateLimiter."""

    @pytest.mark.asyncio
    async def test_rate_limiter_allows_initial_requests(self):
        """Test that initial requests are allowed."""
        limiter = RateLimiter(max_requests=5, per_seconds=1.0)
        start = time.monotonic()

        async with limiter:
            pass

        elapsed = time.monotonic() - start
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_rate_limiter_enforces_limit(self):
        """Test that rate limiter enforces request limits."""
        limiter = RateLimiter(max_requests=2, per_seconds=1.0)

        start = time.monotonic()

        async with limiter:
            pass
        async with limiter:
            pass

        elapsed = time.monotonic() - start
        assert elapsed < 0.2

    @pytest.mark.asyncio
    async def test_rate_limiter_waits_when_exhausted(self):
        """Test that limiter waits when rate limit is exhausted."""
        limiter = RateLimiter(max_requests=1, per_seconds=0.5)

        start = time.monotonic()
        async with limiter:
            pass
        async with limiter:
            pass
        elapsed = time.monotonic() - start

        assert elapsed >= 0.4

    @pytest.mark.asyncio
    async def test_rate_limiter_refills_over_time(self):
        """Test that rate limit tokens refill over time."""
        limiter = RateLimiter(max_requests=2, per_seconds=1.0)

        async with limiter:
            pass
        async with limiter:
            pass

        await asyncio.sleep(1.5)

        start = time.monotonic()
        async with limiter:
            pass
        elapsed = time.monotonic() - start

        assert elapsed < 0.2

    @pytest.mark.asyncio
    async def test_rate_limiter_high_throughput(self):
        """Test high throughput scenario."""
        limiter = RateLimiter(max_requests=100, per_seconds=10.0)

        for _ in range(10):
            async with limiter:
                pass

        await asyncio.sleep(0.5)


class TestRetryLimiter:
    """Tests for the RetryLimiter with exponential backoff."""

    @pytest.mark.asyncio
    async def test_retry_limiter_initialization(self):
        """Test RetryLimiter initializes correctly."""
        limiter = RetryLimiter(max_requests=5, per_seconds=1.0)

        assert limiter.rate_limiter.max_requests == 5
        assert limiter.rate_limiter.per_seconds == 1.0
        assert limiter.consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_retry_limiter_success_resets_failures(self):
        """Test that successful execution resets failure counter."""
        limiter = RetryLimiter(
            max_requests=5,
            per_seconds=1.0,
            max_consecutive_failures=3,
        )

        limiter._consecutive_failures = 2

        async def success_coro():
            return "success"

        result = await limiter.execute_with_retry(success_coro())

        assert result == "success"
        assert limiter.consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_retry_limiter_failure_increments_counter(self):
        """Test that failures increment the counter."""
        limiter = RetryLimiter(
            max_requests=5,
            per_seconds=1.0,
            max_consecutive_failures=3,
            max_retries=1,
        )

        async def failing_coro():
            raise ValueError("Test error")

        await limiter.execute_with_retry(failing_coro())

        assert limiter.consecutive_failures >= 1

    @pytest.mark.asyncio
    async def test_retry_limiter_skips_when_max_failures(self):
        """Test that limiter skips when max failures reached."""
        limiter = RetryLimiter(
            max_requests=5,
            per_seconds=1.0,
            max_consecutive_failures=2,
        )

        limiter._consecutive_failures = 3

        async def failing_coro():
            return "should not run"

        result = await limiter.execute_with_retry(failing_coro())

        assert result is None
        assert limiter.should_skip() is True

    @pytest.mark.asyncio
    async def test_retry_limiter_with_exponential_backoff(self):
        """Test exponential backoff on failures."""
        limiter = RetryLimiter(
            max_requests=5,
            per_seconds=1.0,
            backoff_factor=2.0,
            max_retries=2,
        )

        failure_times = []
        attempt_count = 0

        async def failing_coro():
            nonlocal attempt_count
            attempt_count += 1
            failure_times.append(time.monotonic())
            raise ValueError("Test error")

        start = time.monotonic()
        result = await limiter.execute_with_retry(failing_coro())
        total_time = time.monotonic() - start

        assert result is None
        assert attempt_count >= 1
        assert total_time > 0

    @pytest.mark.asyncio
    async def test_retry_limiter_reset(self):
        """Test reset method."""
        limiter = RetryLimiter(
            max_requests=5,
            per_seconds=1.0,
            max_consecutive_failures=3,
        )

        limiter._consecutive_failures = 5
        limiter._backoff_time = 10.0

        limiter.reset()

        assert limiter.consecutive_failures == 0
        assert limiter._backoff_time == 1.0

    @pytest.mark.asyncio
    async def test_retry_limiter_callbacks(self):
        """Test success and failure callbacks."""
        limiter = RetryLimiter(
            max_requests=5,
            per_seconds=1.0,
            max_retries=1,
        )

        success_results = []
        failure_count = 0

        def on_success(result):
            success_results.append(result)

        def on_failure(exc):
            nonlocal failure_count
            failure_count += 1

        async def success_coro():
            return "success"

        result = await limiter.execute_with_retry(
            success_coro(),
            on_success=on_success,
            on_failure=on_failure,
        )

        assert result == "success"
        assert success_results == ["success"]

        success_results.clear()

        async def failing_coro():
            raise ValueError("fail")

        result = await limiter.execute_with_retry(
            failing_coro(),
            on_success=on_success,
            on_failure=on_failure,
        )

        assert result is None
        assert failure_count >= 1


class TestRateLimiterEdgeCases:
    """Edge case tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_small_max_requests(self):
        """Test behavior with small max requests."""
        limiter = RateLimiter(max_requests=1, per_seconds=1.0)

        start = time.monotonic()
        async with limiter:
            pass
        async with limiter:
            pass
        elapsed = time.monotonic() - start

        assert elapsed >= 0.9

    @pytest.mark.asyncio
    async def test_very_high_rate(self):
        """Test with very high rate limit."""
        limiter = RateLimiter(max_requests=1000, per_seconds=0.1)

        for _ in range(10):
            async with limiter:
                pass

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test concurrent access to rate limiter."""
        limiter = RateLimiter(max_requests=5, per_seconds=1.0)

        async def use_limiter():
            async with limiter:
                await asyncio.sleep(0.01)

        tasks = [use_limiter() for _ in range(5)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_context_manager_exception(self):
        """Test context manager handles exceptions."""
        limiter = RateLimiter(max_requests=5, per_seconds=1.0)

        with pytest.raises(ValueError):
            async with limiter:
                raise ValueError("test")

        async with limiter:
            pass
