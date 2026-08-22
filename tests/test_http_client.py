# tests/test_http_client.py
"""Tests for HttpClient — context manager, UA rotation, request delegation, stealth mode."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from core.http_client import (
    ACCEPT_LANGUAGES,
    COMMON_USER_AGENTS,
    REFERERS,
    STEALTH_USER_AGENTS,
    HttpClient,
    friendly_network_error,
)


class TestHttpClientLifecycle:
    """Tests for context manager behavior."""

    @pytest.mark.asyncio
    async def test_enter_creates_client(self):
        client = HttpClient(timeout=15, insecure=False)
        async with client:
            assert client._client is not None
            assert isinstance(client._client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_exit_closes_client(self):
        client = HttpClient()
        async with client:
            mock_close = AsyncMock()
            client._client.aclose = mock_close
        mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_exit_handles_no_client(self):
        client = HttpClient()
        assert client._client is None
        await client.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_timeout_passed_to_client(self):
        client = HttpClient(timeout=30)
        async with client:
            assert client._client.timeout.connect == 30

    @pytest.mark.asyncio
    async def test_insecure_sets_verify_false(self):
        client = HttpClient(insecure=True)
        async with client:
            assert client._client._transport._pool._ssl_context is not None


class TestUserAgentRotation:
    """Tests for User-Agent rotation."""

    @pytest.mark.asyncio
    async def test_initial_ua_is_first_in_list(self):
        client = HttpClient()
        async with client:
            initial_ua = client._client.headers["User-Agent"]
            assert initial_ua == COMMON_USER_AGENTS[0]

    def test_get_next_user_agent_cycles(self):
        client = HttpClient()
        # First call returns index 0, advances to 1
        ua0 = client._get_next_user_agent()
        assert ua0 == COMMON_USER_AGENTS[0]
        # Second call returns index 1, advances to 2
        ua1 = client._get_next_user_agent()
        assert ua1 == COMMON_USER_AGENTS[1]
        assert ua0 != ua1

    def test_ua_cycles_back_to_start(self):
        client = HttpClient()
        n = len(COMMON_USER_AGENTS)
        for _ in range(n):
            client._get_next_user_agent()
        next_ua = client._get_next_user_agent()
        assert next_ua == COMMON_USER_AGENTS[0]

    def test_single_ua_wraps_to_zero(self):
        client = HttpClient()
        client._user_agents = ["single-agent"]
        client._get_next_user_agent()
        # (0 + 1) % 1 = 0, so index wraps back to 0
        assert client._current_ua_index == 0

    def test_set_user_agents_replaces_list_and_resets_index(self):
        client = HttpClient()
        client._current_ua_index = 3
        client.set_user_agents(["custom-agent-1", "custom-agent-2"])
        assert client._user_agents == ["custom-agent-1", "custom-agent-2"]
        assert client._current_ua_index == 0

    def test_set_user_agents_empty_list_ignored(self):
        client = HttpClient()
        original = client._user_agents
        client.set_user_agents([])
        assert client._user_agents is original

    def test_set_user_agents_none_ignored(self):
        client = HttpClient()
        original = client._user_agents
        client.set_user_agents(None)
        assert client._user_agents is original

    def _make_mock_client(self):
        """Create an AsyncMock client that can be awaited on aclose."""
        mock = AsyncMock()
        mock.headers = {}
        return mock

    @pytest.mark.asyncio
    async def test_ua_refreshes_before_get(self):
        client = HttpClient()
        async with client:
            client._client = self._make_mock_client()
            client._current_ua_index = 0
            await client.get("https://example.com")
            assert client._client.headers["User-Agent"] == COMMON_USER_AGENTS[0]

    @pytest.mark.asyncio
    async def test_ua_refreshes_before_post(self):
        client = HttpClient()
        async with client:
            client._client = self._make_mock_client()
            client._current_ua_index = 0
            await client.post("https://example.com")
            assert client._client.headers["User-Agent"] == COMMON_USER_AGENTS[0]

    @pytest.mark.asyncio
    async def test_ua_changes_between_requests(self):
        client = HttpClient()
        async with client:
            client._client = self._make_mock_client()
            client._current_ua_index = 0
            await client.get("https://example.com")
            ua_first = client._client.headers["User-Agent"]
            await client.get("https://example.com")
            ua_second = client._client.headers["User-Agent"]
            assert ua_first != ua_second


class TestHttpClientMethods:
    """Tests for request methods."""

    @pytest.mark.asyncio
    async def test_get_delegates_to_client(self):
        client = HttpClient()
        async with client:
            mock_response = MagicMock(spec=httpx.Response)
            client._client.get = AsyncMock(return_value=mock_response)
            result = await client.get("https://example.com/page")
            assert result is mock_response
            client._client.get.assert_called_once_with("https://example.com/page")

    @pytest.mark.asyncio
    async def test_post_delegates_to_client(self):
        client = HttpClient()
        async with client:
            mock_response = MagicMock(spec=httpx.Response)
            client._client.post = AsyncMock(return_value=mock_response)
            result = await client.post(
                "https://example.com/api", json={"key": "value"}
            )
            assert result is mock_response
            client._client.post.assert_called_once_with(
                "https://example.com/api", json={"key": "value"}
            )

    @pytest.mark.asyncio
    async def test_head_delegates_to_client(self):
        client = HttpClient()
        async with client:
            mock_response = MagicMock(spec=httpx.Response)
            client._client.head = AsyncMock(return_value=mock_response)
            result = await client.head("https://example.com")
            assert result is mock_response

    @pytest.mark.asyncio
    async def test_request_delegates_to_client(self):
        client = HttpClient()
        async with client:
            mock_response = MagicMock(spec=httpx.Response)
            client._client.request = AsyncMock(return_value=mock_response)
            result = await client.request(
                "PATCH", "https://example.com/api", content=b"data"
            )
            assert result is mock_response
            client._client.request.assert_called_once_with(
                "PATCH", "https://example.com/api", content=b"data"
            )

    @pytest.mark.asyncio
    async def test_get_outside_context_raises(self):
        client = HttpClient()
        with pytest.raises(RuntimeError, match="async context manager"):
            await client.get("https://example.com")

    @pytest.mark.asyncio
    async def test_post_outside_context_raises(self):
        client = HttpClient()
        with pytest.raises(RuntimeError, match="async context manager"):
            await client.post("https://example.com")

    @pytest.mark.asyncio
    async def test_head_outside_context_raises(self):
        client = HttpClient()
        with pytest.raises(RuntimeError, match="async context manager"):
            await client.head("https://example.com")

    @pytest.mark.asyncio
    async def test_request_outside_context_raises(self):
        client = HttpClient()
        with pytest.raises(RuntimeError, match="async context manager"):
            await client.request("GET", "https://example.com")


class TestHttpClientInit:
    """Tests for initialization defaults."""

    def test_default_timeout(self):
        client = HttpClient()
        assert client.timeout == 10

    def test_default_insecure(self):
        client = HttpClient()
        assert client.insecure is False

    def test_custom_timeout(self):
        client = HttpClient(timeout=60)
        assert client.timeout == 60

    def test_custom_insecure(self):
        client = HttpClient(insecure=True)
        assert client.insecure is True

    def test_client_starts_none(self):
        client = HttpClient()
        assert client._client is None

    def test_ua_index_starts_at_zero(self):
        client = HttpClient()
        assert client._current_ua_index == 0

    def test_user_agents_is_common_list(self):
        client = HttpClient()
        assert client._user_agents == list(COMMON_USER_AGENTS)


class TestStealthMode:
    """Tests for stealth mode (jitter, referer, dedup, expanded UA pool)."""

    def _stealth_config(self, **overrides):
        """Create a minimal stealth config."""
        from config import ScanConfig
        params = {
            "stealth_enabled": True,
            "stealth_min_delay": 0.01,
            "stealth_max_delay": 0.05,
            "stealth_rotate_ua": True,
            "stealth_rotate_referer": True,
            "stealth_dedup_requests": True,
            "stealth_rate_limit": 0.0,
        }
        params.update(overrides)
        return ScanConfig(**params)

    def test_stealth_uses_expanded_ua_pool(self):
        client = HttpClient(config=self._stealth_config())
        assert len(client._user_agents) >= 50
        assert client._user_agents == STEALTH_USER_AGENTS

    def test_non_stealth_uses_common_ua_pool(self):
        client = HttpClient()
        assert client._user_agents == list(COMMON_USER_AGENTS)
        assert len(client._user_agents) == 5

    def test_stealth_has_referers(self):
        client = HttpClient(config=self._stealth_config())
        assert len(client._referers) > 0
        assert client._referers == REFERERS

    def test_non_stealth_no_referers(self):
        client = HttpClient()
        assert client._referers == []

    def test_stealth_has_accept_languages(self):
        client = HttpClient(config=self._stealth_config())
        assert len(client._accept_languages) > 0
        assert client._accept_languages == ACCEPT_LANGUAGES

    def test_non_stealth_no_accept_languages(self):
        client = HttpClient()
        assert client._accept_languages == []

    def test_stealth_dedup_enabled(self):
        client = HttpClient(config=self._stealth_config())
        assert client.dedup_enabled is True

    def test_non_stealth_dedup_disabled(self):
        client = HttpClient()
        assert client.dedup_enabled is False

    def test_stealth_rotate_ua_default_true(self):
        client = HttpClient(config=self._stealth_config(stealth_rotate_ua=False))
        assert client.rotate_ua is False

    def test_stealth_rotate_referer_default_true(self):
        client = HttpClient(config=self._stealth_config(stealth_rotate_referer=False))
        assert client.rotate_referer is False

    def _make_mock_client(self):
        mock = AsyncMock()
        mock.headers = {}
        return mock

    @pytest.mark.asyncio
    async def test_referer_set_on_request_in_stealth(self):
        client = HttpClient(config=self._stealth_config())
        async with client:
            client._client = self._make_mock_client()
            await client.get("https://example.com")
            assert "Referer" in client._client.headers
            assert client._client.headers["Referer"] in REFERERS

    @pytest.mark.asyncio
    async def test_accept_language_set_on_request_in_stealth(self):
        client = HttpClient(config=self._stealth_config())
        async with client:
            client._client = self._make_mock_client()
            await client.get("https://example.com")
            assert "Accept-Language" in client._client.headers
            assert client._client.headers["Accept-Language"] in ACCEPT_LANGUAGES

    @pytest.mark.asyncio
    async def test_no_referer_when_non_stealth(self):
        client = HttpClient()
        async with client:
            client._client = self._make_mock_client()
            await client.get("https://example.com")
            assert "Referer" not in client._client.headers

    @pytest.mark.asyncio
    async def test_request_unique_skips_duplicate(self):
        client = HttpClient(config=self._stealth_config())
        async with client:
            client._client = self._make_mock_client()
            r1 = await client.request_unique("GET", "https://example.com/")
            assert r1 is not None
            r2 = await client.request_unique("GET", "https://example.com/")
            assert r2 is None

    @pytest.mark.asyncio
    async def test_request_unique_force_bypasses_dedup(self):
        client = HttpClient(config=self._stealth_config())
        async with client:
            mock = MagicMock(spec=httpx.Response)
            client._client = self._make_mock_client()
            client._client.request = AsyncMock(return_value=mock)
            r1 = await client.request_unique("GET", "https://example.com/", force=True)
            assert r1 is not None
            r2 = await client.request_unique("GET", "https://example.com/", force=True)
            assert r2 is not None

    @pytest.mark.asyncio
    async def test_different_methods_not_deduplicated(self):
        client = HttpClient(config=self._stealth_config())
        async with client:
            client._client = self._make_mock_client()
            r1 = await client.request_unique("GET", "https://example.com/")
            assert r1 is not None
            r2 = await client.request_unique("POST", "https://example.com/")
            assert r2 is not None

    @pytest.mark.asyncio
    async def test_jitter_applies_delay_in_stealth(self):
        client = HttpClient(config=self._stealth_config())
        async with client:
            client._client = self._make_mock_client()
            with patch("core.http_client.asyncio.sleep", AsyncMock()) as mock_sleep:
                await client.get("https://example.com")
                mock_sleep.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_jitter_when_non_stealth(self):
        client = HttpClient()
        async with client:
            client._client = self._make_mock_client()
            with patch("core.http_client.asyncio.sleep", AsyncMock()) as mock_sleep:
                await client.get("https://example.com")
                mock_sleep.assert_not_awaited()

    def test_stealth_disabled_by_default(self):
        client = HttpClient()
        assert client.stealth_enabled is False

    def test_stealth_enabled_flag(self):
        client = HttpClient(config=self._stealth_config())
        assert client.stealth_enabled is True

    @pytest.mark.asyncio
    async def test_rate_limiter_created_when_rate_set(self):
        cfg = self._stealth_config(stealth_rate_limit=5.0)
        client = HttpClient(config=cfg)
        assert client._rate_limiter is not None

    def test_no_rate_limiter_by_default(self):
        client = HttpClient()
        assert client._rate_limiter is None

    @pytest.mark.asyncio
    async def test_ua_rotation_uses_stealth_pool(self):
        client = HttpClient(config=self._stealth_config())
        first = client._get_next_user_agent()
        second = client._get_next_user_agent()
        assert first in STEALTH_USER_AGENTS
        assert second in STEALTH_USER_AGENTS
        assert first != second

    def test_stealth_pool_size_at_least_50(self):
        assert len(STEALTH_USER_AGENTS) >= 50


class TestCircuitBreaker:
    """Tests for the circuit breaker (consecutive error tracking)."""

    def test_starts_reachable(self):
        client = HttpClient()
        assert client.unreachable is False
        assert client._consecutive_errors == 0

    def test_threshold_defaults_to_five(self):
        client = HttpClient()
        assert client.unreachable_threshold == 5

    def test_threshold_from_config(self):
        from config import ScanConfig
        cfg = ScanConfig(unreachable_threshold=3)
        client = HttpClient(config=cfg)
        assert client.unreachable_threshold == 3

    @pytest.mark.asyncio
    async def test_success_resets_error_counter(self):
        client = HttpClient()
        client._consecutive_errors = 2
        async with client:
            mock_response = MagicMock(spec=httpx.Response)
            client._client.get = AsyncMock(return_value=mock_response)
            await client.get("https://example.com")
        assert client._consecutive_errors == 0
        assert client.unreachable is False

    @pytest.mark.asyncio
    async def test_transport_error_increments_counter(self):
        client = HttpClient()
        async with client:
            client._client.get = AsyncMock(
                side_effect=httpx.ConnectError("boom")
            )
            with pytest.raises(httpx.ConnectError):
                await client.get("https://example.com")
        assert client._consecutive_errors == 1
        assert client.unreachable is False

    @pytest.mark.asyncio
    async def test_threshold_reached_marks_unreachable(self):
        client = HttpClient()
        client.unreachable_threshold = 2
        async with client:
            client._client.get = AsyncMock(
                side_effect=httpx.ConnectError("boom")
            )
            with pytest.raises(httpx.ConnectError):
                await client.get("https://example.com")
            with pytest.raises(httpx.ConnectError):
                await client.get("https://example.com")
        assert client.unreachable is True
        assert client._consecutive_errors == 2

    @pytest.mark.asyncio
    async def test_unreachable_short_circuits_requests(self):
        client = HttpClient()
        client.unreachable = True
        async with client:
            client._client.get = AsyncMock()
            with pytest.raises(RuntimeError, match="unreachable"):
                await client.get("https://example.com")
        client._client.get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unreachable_closes_created_coroutine(self):
        client = HttpClient()
        client.unreachable = True

        async def dummy():
            return None

        coro = dummy()
        with pytest.raises(RuntimeError, match="unreachable"):
            await client._execute(coro)
        assert coro.cr_frame is None

    @pytest.mark.asyncio
    async def test_http_status_errors_do_not_trip_breaker(self):
        client = HttpClient()
        async with client:
            mock_response = MagicMock(spec=httpx.Response, status_code=500)
            client._client.get = AsyncMock(return_value=mock_response)
            await client.get("https://example.com")
        assert client._consecutive_errors == 0
        assert client.unreachable is False


class TestFriendlyNetworkError:
    """Tests for friendly_network_error helper."""

    def test_dns_resolution_error(self):
        exc = httpx.ConnectError(
            "[Errno 8] nodename nor servname provided, or not known"
        )
        msg = friendly_network_error(exc)
        assert "DNS resolution failed" in msg

    def test_tls_expired_certificate(self):
        exc = httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "certificate has expired"
        )
        msg = friendly_network_error(exc)
        assert "TLS certificate" in msg
        assert "expired" in msg.lower()

    def test_connection_refused(self):
        exc = httpx.ConnectError("[Errno 61] Connection refused")
        msg = friendly_network_error(exc)
        assert "Connection refused" in msg

    def test_timeout(self):
        exc = httpx.ConnectTimeout("timed out")
        msg = friendly_network_error(exc)
        assert "timed out" in msg.lower()

    def test_generic_transport_error(self):
        exc = httpx.RemoteProtocolError("server disconnected")
        msg = friendly_network_error(exc)
        assert "Network error" in msg

    def test_unknown_exception(self):
        exc = ValueError("weird")
        msg = friendly_network_error(exc)
        assert "Network error" in msg
        assert "ValueError" in msg
