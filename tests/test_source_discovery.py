"""Tests for utils.source_discovery helpers."""

from unittest.mock import AsyncMock, MagicMock

from utils.source_discovery import (
    extract_asset_urls,
    extract_link_urls,
    fetch_assets,
    fuzz_common_assets,
    normalize_url,
    strip_query,
)

BASE = "https://example.com"


class TestNormalizeUrl:
    def test_relative_resolves_to_absolute(self):
        assert normalize_url("/app.js", BASE) == "https://example.com/app.js"

    def test_root_relative(self):
        assert normalize_url("static/app.js", BASE) == "https://example.com/static/app.js"

    def test_external_blocked(self):
        assert normalize_url("https://evil.com/app.js", BASE) is None

    def test_different_port_blocked(self):
        assert normalize_url("http://example.com:8080/app.js", "https://example.com:8443") is None

    def test_data_scheme_blocked(self):
        assert normalize_url("data:text/javascript,alert(1)", BASE) is None

    def test_javascript_scheme_blocked(self):
        assert normalize_url("javascript:void(0)", BASE) is None

    def test_fragment_only_blocked(self):
        assert normalize_url("#section", BASE) is None

    def test_empty_blocked(self):
        assert normalize_url("", BASE) is None

    def test_quotes_stripped(self):
        assert normalize_url('"/app.js"', BASE) == "https://example.com/app.js"

    def test_absolute_same_origin_kept(self):
        assert normalize_url("https://example.com/app.js", BASE) == "https://example.com/app.js"


class TestStripQuery:
    def test_removes_query(self):
        assert strip_query("https://example.com/app.js?v=1.2") == "https://example.com/app.js"

    def test_no_query(self):
        assert strip_query("https://example.com/app.js") == "https://example.com/app.js"


class TestExtractAssetUrls:
    def test_script_src(self):
        html = '<script src="/static/app.js"></script>'
        assert extract_asset_urls(html, BASE) == ["https://example.com/static/app.js"]

    def test_link_stylesheet(self):
        html = '<link rel="stylesheet" href="/style.css">'
        assert extract_asset_urls(html, BASE) == ["https://example.com/style.css"]

    def test_link_import(self):
        html = '<link rel="import" href="/module.js">'
        assert extract_asset_urls(html, BASE) == ["https://example.com/module.js"]

    def test_css_url(self):
        html = "<style>body { background: url('/img/logo.png') }</style>"
        # logo.png is not in ASSET_EXTENSIONS but css url() is captured
        urls = extract_asset_urls(html, BASE)
        assert "https://example.com/img/logo.png" in urls

    def test_inline_js_asset_reference(self):
        html = '<script>fetch("/api/data.js?v=2")</script>'
        urls = extract_asset_urls(html, BASE)
        assert "https://example.com/api/data.js" in urls

    def test_external_assets_excluded(self):
        html = '<script src="https://cdn.example.net/lib.js"></script>'
        assert extract_asset_urls(html, BASE) == []

    def test_deduplication(self):
        html = (
            '<script src="/app.js"></script>'
            '<script src="/app.js"></script>'
            '<script src="/app.js"></script>'
        )
        assert extract_asset_urls(html, BASE) == ["https://example.com/app.js"]

    def test_empty_html(self):
        assert extract_asset_urls("", BASE) == []


class TestExtractLinkUrls:
    def test_internal_links(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        urls = extract_link_urls(html, BASE)
        assert urls == ["https://example.com/about", "https://example.com/contact"]

    def test_external_and_mailto_excluded(self):
        html = '<a href="https://other.com">X</a><a href="mailto:a@b.com">M</a>'
        assert extract_link_urls(html, BASE) == []

    def test_fragment_excluded(self):
        html = '<a href="#top">Top</a>'
        assert extract_link_urls(html, BASE) == []


def _responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, response in routes.items():
            if url.endswith(suffix) or url == suffix:
                return response
        return MagicMock(status_code=404, text="Not Found")

    return _respond


class TestFetchAssets:
    async def test_fetches_200_assets(self):
        http = MagicMock()
        http.request = AsyncMock(
            side_effect=_responder(
                {
                    "/app.js": MagicMock(status_code=200, text="var a=1;"),
                    "/style.css": MagicMock(status_code=200, text="body{}"),
                }
            )
        )
        fetched = await fetch_assets(http, BASE, ["/app.js", "/style.css"])
        assert len(fetched) == 2
        assert fetched[0] == ("https://example.com/app.js", "var a=1;")

    async def test_skips_404(self):
        http = MagicMock()
        http.request = AsyncMock(return_value=MagicMock(status_code=404, text="Nope"))
        fetched = await fetch_assets(http, BASE, ["/missing.js"])
        assert fetched == []

    async def test_max_files_cap(self):
        http = MagicMock()
        http.request = AsyncMock(return_value=MagicMock(status_code=200, text="x"))
        fetched = await fetch_assets(
            http, BASE, [f"/a{i}.js" for i in range(10)], max_files=3
        )
        assert len(fetched) == 3

    async def test_truncates_to_max_bytes(self):
        http = MagicMock()
        http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="A" * 5000)
        )
        fetched = await fetch_assets(http, BASE, ["/big.js"], max_bytes=1000)
        assert len(fetched[0][1]) == 1000

    async def test_external_urls_skipped(self):
        http = MagicMock()
        http.request = AsyncMock()
        await fetch_assets(http, BASE, ["https://evil.com/app.js"])
        http.request.assert_not_called()

    async def test_exception_tolerated(self):
        http = MagicMock()
        http.request = AsyncMock(side_effect=ConnectionError("boom"))
        fetched = await fetch_assets(http, BASE, ["/app.js"])
        assert fetched == []


class TestFuzzCommonAssets:
    async def test_finds_existing_paths(self):
        http = MagicMock()
        http.request = AsyncMock(
            side_effect=_responder(
                {
                    "/app.js": MagicMock(status_code=200, text="var a=1;"),
                }
            )
        )
        found = await fuzz_common_assets(http, BASE, ["app.js", "nope.js", "bundle.js"])
        assert found == ["https://example.com/app.js"]

    async def test_max_probes_cap(self):
        http = MagicMock()
        http.request = AsyncMock(return_value=MagicMock(status_code=404, text="Nope"))
        await fuzz_common_assets(
            http, BASE, [f"/p{i}.js" for i in range(20)], max_probes=5
        )
        assert http.request.call_count == 5

    async def test_exception_tolerated(self):
        http = MagicMock()
        http.request = AsyncMock(side_effect=ConnectionError("boom"))
        found = await fuzz_common_assets(http, BASE, ["app.js"])
        assert found == []
