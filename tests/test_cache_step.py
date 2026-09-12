"""Tests for CacheAnalysisStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.cache_step import (
    CacheAnalysisStep,
    cache_layer,
    cacheable,
)


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)


class TestHelpers:
    def test_cache_layer_detection(self):
        assert cache_layer(HeaderDict({"Age": "12"})) == "age"
        assert cache_layer(HeaderDict({"CF-Cache-Status": "HIT"})) == "cf-cache-status"
        assert cache_layer(HeaderDict({})) is None

    def test_cacheable(self):
        assert cacheable(HeaderDict({"Cache-Control": "public, max-age=60"}))
        assert not cacheable(HeaderDict({"Cache-Control": "private, no-store"}))
        assert not cacheable(HeaderDict({}))


class TestCacheAnalysisStep:
    async def test_cache_layer_info_finding(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "/account" in url or "/profile" in url or "/api" in url or "/dashboard" in url or "/me" in url:
                return MagicMock(status_code=404, text="nope")
            return MagicMock(status_code=200, headers=HeaderDict(
                {"X-Cache": "HIT", "Cache-Control": "no-store"}), text="ok")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = CacheAnalysisStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("Caching layer" in f.title for f in findings)

    async def test_cacheable_homepage_low(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if url.rstrip("/") != "https://example.com" and "/" in url[8:]:
                return MagicMock(status_code=404, text="nope")
            return MagicMock(status_code=200, headers=HeaderDict(
                {"Cache-Control": "public, max-age=300"}), text="ok")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = CacheAnalysisStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("publicly cacheable" in f.title for f in findings)

    async def test_deception_surface_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "canary7q4" in url and "/account" in url:
                return MagicMock(status_code=200, headers=HeaderDict(
                    {"X-Cache": "MISS", "Cache-Control": "public, max-age=60"}),
                    text="account page")
            return MagicMock(status_code=404, text="nope")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = CacheAnalysisStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("cache deception" in f.title.lower() for f in findings)

    async def test_fetch_failure_clean(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = CacheAnalysisStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []

    async def test_catch_all_shell_not_reported(self, mock_http, mock_target, mock_config):
        """A cacheable catch-all shell on the canary path is not cache deception."""
        shell = (
            "<!doctype html><html><head><title>App</title></head>"
            "<body>" + "x" * 500 + "</body></html>"
        )

        async def requestor(method, url, **kwargs):
            return MagicMock(
                status_code=200,
                text=shell,
                headers=HeaderDict(
                    {"X-Cache": "MISS", "Cache-Control": "public, max-age=60"}
                ),
            )

        mock_http.request = AsyncMock(side_effect=requestor)
        step = CacheAnalysisStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert not any("cache deception" in f.title.lower() for f in findings)
