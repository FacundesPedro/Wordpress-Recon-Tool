# tests/test_scan_context.py
"""Tests for core/scan_context.py — ScanContext and WebArtifacts."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.scan_context import ScanContext, WebArtifacts


class HeaderDict(dict):
    """Case-insensitive header lookup like httpx.Headers."""

    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


def make_response(status=200, text="", headers=None, json_data=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = HeaderDict(headers or {})
    if json_data is not None:
        resp.json = MagicMock(return_value=json_data)
    else:
        resp.json = MagicMock(side_effect=ValueError("no json"))
    return resp


def make_http(handler):
    http = MagicMock()
    http.request = AsyncMock(side_effect=handler)
    return http


class TestWebArtifactsMemoization:
    @pytest.mark.asyncio
    async def test_homepage_is_memoized(self):
        calls = []

        async def handler(method, url, **kwargs):
            calls.append(url)
            return make_response(200, "home")

        http = make_http(handler)
        web = WebArtifacts(http, "https://example.com")

        first = await web.homepage()
        second = await web.homepage()

        assert first is second
        assert calls == ["https://example.com/"]
        assert web.requests_made == 1
        assert web.requests_saved == 1

    @pytest.mark.asyncio
    async def test_single_flight_under_concurrency(self):
        calls = []

        async def handler(method, url, **kwargs):
            calls.append(url)
            await asyncio.sleep(0.01)
            return make_response(200, "home")

        http = make_http(handler)
        web = WebArtifacts(http, "https://example.com")

        results = await asyncio.gather(*[web.homepage() for _ in range(5)])

        assert len(calls) == 1
        assert all(r is results[0] for r in results)
        assert web.requests_made == 1
        assert web.requests_saved == 4

    @pytest.mark.asyncio
    async def test_named_endpoints(self):
        calls = []

        async def handler(method, url, **kwargs):
            calls.append(url)
            return make_response(200)

        http = make_http(handler)
        web = WebArtifacts(http, "https://example.com/")

        await web.wp_json()
        await web.robots()

        assert "https://example.com/wp-json/" in calls
        assert "https://example.com/robots.txt" in calls

    @pytest.mark.asyncio
    async def test_auth_headers_bypass_cache(self):
        calls = []

        async def handler(method, url, **kwargs):
            calls.append(url)
            return make_response(200)

        http = make_http(handler)
        web = WebArtifacts(http, "https://example.com")

        await web.get("/admin", headers={"Authorization": "Basic abc"})
        await web.get("/admin", headers={"Authorization": "Basic abc"})

        assert len(calls) == 2
        assert web.requests_made == 0

    @pytest.mark.asyncio
    async def test_invalidate_clears_cache(self):
        calls = []

        async def handler(method, url, **kwargs):
            calls.append(url)
            return make_response(200)

        http = make_http(handler)
        web = WebArtifacts(http, "https://example.com")

        await web.homepage()
        web.invalidate()
        await web.homepage()

        assert len(calls) == 2


class TestWebArtifactsWordpress:
    @pytest.mark.asyncio
    async def test_detects_via_rest_namespaces(self):
        async def handler(method, url, **kwargs):
            return make_response(
                200,
                "",
                {"Content-Type": "application/json"},
                json_data={"namespaces": ["wp/v2"]},
            )

        web = WebArtifacts(make_http(handler), "https://wp.example")
        assert await web.wordpress() is True

    @pytest.mark.asyncio
    async def test_detects_via_homepage_marker(self):
        async def handler(method, url, **kwargs):
            if url.endswith("/wp-json/"):
                return make_response(404, "Not Found")
            return make_response(200, '<link href="/wp-content/themes/x/style.css">')

        web = WebArtifacts(make_http(handler), "https://wp.example")
        assert await web.wordpress() is True

    @pytest.mark.asyncio
    async def test_spa_shell_is_not_wordpress(self):
        async def handler(method, url, **kwargs):
            if url.endswith("/wp-json/"):
                return make_response(404, "Not Found")
            return make_response(200, "<html><body>SPA</body></html>")

        web = WebArtifacts(make_http(handler), "https://spa.example")
        assert await web.wordpress() is False

    @pytest.mark.asyncio
    async def test_fail_closed_on_network_error(self):
        async def handler(method, url, **kwargs):
            raise ConnectionError("boom")

        web = WebArtifacts(make_http(handler), "https://down.example")
        assert await web.wordpress() is False


class TestScanContextArtifacts:
    @pytest.mark.asyncio
    async def test_set_get_has(self):
        ctx = ScanContext()
        assert ctx.has("x") is False
        ctx.set("x", 1)
        assert ctx.has("x") is True
        assert ctx.get("x") == 1
        assert ctx.get("missing", "d") == "d"

    @pytest.mark.asyncio
    async def test_wait_resolves_when_set(self):
        ctx = ScanContext()

        async def producer():
            await asyncio.sleep(0.01)
            ctx.set("token", "abc")

        task = asyncio.create_task(producer())
        assert await ctx.wait("token", timeout=1) == "abc"
        await task

    @pytest.mark.asyncio
    async def test_wait_returns_none_on_missing(self):
        ctx = ScanContext()
        ctx.mark_missing("gone")
        assert await ctx.wait("gone", timeout=0.1) is None

    @pytest.mark.asyncio
    async def test_wait_times_out(self):
        ctx = ScanContext()
        assert await ctx.wait("never", timeout=0.01) is None

    @pytest.mark.asyncio
    async def test_stats_without_http(self):
        ctx = ScanContext()
        assert ctx.stats == {"requests_made": 0, "requests_saved": 0}


class TestScanContextSoft404:
    @pytest.mark.asyncio
    async def test_detects_catch_all_and_sets_flag(self):
        calls = []

        async def handler(method, url, **kwargs):
            calls.append(url)
            return make_response(200, "<html><head><title>Shell</title></head></html>")

        ctx = ScanContext(
            http=make_http(handler), target_url="https://spa.example"
        )
        assert ctx.enumeration_is_unreliable is False
        detector = await ctx.soft404_detector()
        assert detector.calibrated is True
        assert ctx.enumeration_is_unreliable is True
        assert ctx.enumeration_unreliable is True
        assert len(calls) >= 1

    @pytest.mark.asyncio
    async def test_detector_is_memoized_per_base_url(self):
        calls = []

        async def handler(method, url, **kwargs):
            calls.append(url)
            return make_response(200, "<html><title>Shell</title></html>")

        ctx = ScanContext(http=make_http(handler), target_url="https://spa.example")
        d1 = await ctx.soft404_detector()
        count = len(calls)
        d2 = await ctx.soft404_detector()
        assert d1 is d2
        assert len(calls) == count  # no second calibration

    @pytest.mark.asyncio
    async def test_calibration_failure_is_safe(self):
        async def handler(method, url, **kwargs):
            raise ConnectionError("down")

        ctx = ScanContext(http=make_http(handler), target_url="https://x.example")
        detector = await ctx.soft404_detector()
        assert detector.calibrated is False
        assert ctx.enumeration_is_unreliable is False
