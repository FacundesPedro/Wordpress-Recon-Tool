"""Tests for the pinned (split-horizon) httpx transport."""

import httpx

from core.pinned_transport import PinnedTransport


async def _capture(transport, url):
    """Call handle_async_request, capturing the rewritten request."""
    captured = {}

    async def fake_handle(self, request):
        captured["url"] = request.url
        captured["host"] = request.headers.get("host")
        captured["sni"] = request.extensions.get("sni_hostname")
        captured["extensions_before"] = dict(request.extensions)
        return httpx.Response(200, request=request)

    original = httpx.AsyncHTTPTransport.handle_async_request
    httpx.AsyncHTTPTransport.handle_async_request = fake_handle
    try:
        await transport.handle_async_request(httpx.Request("GET", url))
    finally:
        httpx.AsyncHTTPTransport.handle_async_request = original
    return captured


class TestPinnedTransport:
    async def test_rewrites_url_and_sets_host_and_sni(self):
        transport = PinnedTransport("10.0.0.5", "app.example.com")
        captured = await _capture(transport, "https://app.example.com/path?q=1")
        assert captured["url"].host == "10.0.0.5"
        assert captured["url"].path == "/path"
        assert captured["url"].query == b"q=1"
        assert captured["host"] == "app.example.com"
        assert captured["sni"] == "app.example.com"

    async def test_keeps_non_standard_port_in_host_header(self):
        transport = PinnedTransport("10.0.0.5", "app.example.com")
        captured = await _capture(transport, "http://app.example.com:8080/x")
        assert captured["url"].host == "10.0.0.5"
        assert captured["url"].port == 8080
        assert captured["host"] == "app.example.com:8080"

    async def test_other_hosts_untouched(self):
        transport = PinnedTransport("10.0.0.5", "app.example.com")
        captured = await _capture(transport, "https://cdn.other.com/a.js")
        assert captured["url"].host == "cdn.other.com"
        assert captured["sni"] is None

    async def test_case_insensitive_host_match(self):
        transport = PinnedTransport("10.0.0.5", "APP.example.com")
        captured = await _capture(transport, "https://app.example.com/x")
        assert captured["url"].host == "10.0.0.5"
