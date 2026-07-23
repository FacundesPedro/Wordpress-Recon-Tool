# tests/test_http_step.py
"""Unit tests for base/http_step.py — BaseHttpStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from base.http_step import BaseHttpStep
from core.http_client import HttpClient


# ---------------------------------------------------------------------------
# Concrete subclass for testing
# ---------------------------------------------------------------------------
class ConcreteHttpStep(BaseHttpStep):
    name = "http_step"
    description = "An HTTP step for testing"
    MODULE = "http"

    async def run(self):
        return list(self.findings)


# ---------------------------------------------------------------------------
# BaseHttpStep
# ---------------------------------------------------------------------------
class TestBaseHttpStepInit:
    def test_stores_references(self):
        target = MagicMock()
        config = MagicMock()
        http = MagicMock(spec=HttpClient)
        step = ConcreteHttpStep(target=target, config=config, http=http)
        assert step.http is http
        assert step.target is target
        assert step.config is config


class TestFetch:
    @pytest.fixture
    def step(self):
        target = MagicMock()
        target.url = "https://example.com"
        return ConcreteHttpStep(target=target, config=MagicMock(), http=MagicMock())

    @pytest.mark.asyncio
    async def test_url_joining_strips_trailing_slash_from_target(self, step):
        step.http.request = AsyncMock()
        await step.fetch("/path")
        _, kwargs = step.http.request.call_args
        url = step.http.request.call_args[0][1]
        assert url == "https://example.com/path"

    @pytest.mark.asyncio
    async def test_url_joining_strips_leading_slash_from_path(self, step):
        step.http.request = AsyncMock()
        await step.fetch("path")
        url = step.http.request.call_args[0][1]
        assert url == "https://example.com/path"

    @pytest.mark.asyncio
    async def test_passes_kwargs_to_request(self, step):
        step.http.request = AsyncMock()
        await step.fetch("/path", "GET", follow_redirects=True)
        _, kwargs = step.http.request.call_args
        assert kwargs.get("follow_redirects") is True

    @pytest.mark.asyncio
    async def test_returns_response(self, step):
        expected = MagicMock()
        step.http.request = AsyncMock(return_value=expected)
        result = await step.fetch("/path")
        assert result is expected

    @pytest.mark.asyncio
    async def test_delegates_to_http_request(self, step):
        step.http.request = AsyncMock()
        await step.fetch("/path")
        step.http.request.assert_called_once()


class TestGet:
    @pytest.mark.asyncio
    async def test_calls_fetch_with_get(self):
        target = MagicMock()
        target.url = "https://example.com"
        step = ConcreteHttpStep(target=target, config=MagicMock(), http=MagicMock())
        step.fetch = AsyncMock()
        await step.get("/path")
        step.fetch.assert_called_once_with("/path", "GET")


class TestPost:
    @pytest.mark.asyncio
    async def test_calls_fetch_with_post(self):
        target = MagicMock()
        target.url = "https://example.com"
        step = ConcreteHttpStep(target=target, config=MagicMock(), http=MagicMock())
        step.fetch = AsyncMock()
        await step.post("/path")
        step.fetch.assert_called_once_with("/path", "POST")


class TestHead:
    @pytest.mark.asyncio
    async def test_calls_fetch_with_head(self):
        target = MagicMock()
        target.url = "https://example.com"
        step = ConcreteHttpStep(target=target, config=MagicMock(), http=MagicMock())
        step.fetch = AsyncMock()
        await step.head("/path")
        step.fetch.assert_called_once_with("/path", "HEAD")


class TestUrljoin:
    def test_joins_path(self):
        target = MagicMock()
        target.url = "https://example.com"
        step = ConcreteHttpStep(target=target, config=MagicMock(), http=MagicMock())
        result = step.urljoin("subdir/file.txt")
        assert result == "https://example.com/subdir/file.txt"

    def test_handles_trailing_slash(self):
        target = MagicMock()
        target.url = "https://example.com/"
        step = ConcreteHttpStep(target=target, config=MagicMock(), http=MagicMock())
        result = step.urljoin("file.txt")
        assert result == "https://example.com/file.txt"

    def test_handles_leading_slash(self):
        target = MagicMock()
        target.url = "https://example.com"
        step = ConcreteHttpStep(target=target, config=MagicMock(), http=MagicMock())
        result = step.urljoin("/file.txt")
        assert result == "https://example.com/file.txt"
