# tests/test_http_client.py
"""Tests for HttpClient — context manager, UA rotation, request delegation."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from core.http_client import COMMON_USER_AGENTS, HttpClient


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
        assert client._user_agents is COMMON_USER_AGENTS
