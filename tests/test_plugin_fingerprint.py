"""Tests for utils/plugin_fingerprint.py (asset-hash version lookup)."""

import hashlib
from datetime import datetime, timezone

import pytest

from utils.plugin_fingerprint import (
    API_INFO,
    PluginFingerprinter,
    assets_from_html,
    clear_cache,
    parse_tags,
    _versions_before,
)


class FakeResponse:
    def __init__(self, content: bytes = b"", status_code: int = 200, json_data=None):
        self.content = content
        self.status_code = status_code
        self._json = json_data

    def json(self):
        return self._json


class FakeClient:
    """Maps ``url`` -> bytes; the plugin API returns a changelog JSON body."""

    def __init__(self, routes, changelog: str = ""):
        self.routes = routes
        self.changelog = changelog

    async def get(self, url, params=None):
        if url == API_INFO:
            return FakeResponse(
                json_data={"sections": {"changelog": self.changelog}}
            )
        body = self.routes.get(url)
        if body is None:
            return FakeResponse(status_code=404)
        return FakeResponse(content=body)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tags_page(*versions):
    links = "".join(f'<a href="{v}/">{v}/</a>' for v in versions)
    return f"<html><body>{links}</body></html>".encode()


def upstream_url(slug, version, asset):
    return f"https://plugins.svn.wordpress.org/{slug}/tags/{version}/{asset}"


@pytest.fixture(autouse=True)
def _clear():
    clear_cache()
    yield
    clear_cache()


class TestParseTags:
    def test_numeric_only_sorted(self):
        html = '<a href="1.9/">1.9/</a><a href="1.10/">1.10/</a><a href="trunk/">t</a>'
        assert parse_tags(html) == ["1.9", "1.10"]

    def test_empty(self):
        assert parse_tags("") == []


class TestAssetsFromHtml:
    def test_extracts_css_and_js(self):
        html = (
            '<link href="/wp-content/plugins/cf7/includes/css/x.css?ver=1">'
            '<script src="/wp-content/plugins/cf7/includes/js/y.js"></script>'
            '<link href="/wp-content/plugins/other/a.css">'
        )
        assert assets_from_html(html, "cf7") == [
            "includes/css/x.css",
            "includes/js/y.js",
        ]

    def test_respects_limit(self):
        html = "".join(
            f'<link href="/wp-content/plugins/p/a{i}.css">' for i in range(5)
        )
        assert len(assets_from_html(html, "p", limit=2)) == 2


class TestFingerprint:
    @pytest.mark.asyncio
    async def test_single_exact_intersection_is_high(self):
        slug = "cf7"
        asset1, asset2 = "a.css", "b.js"
        target = {asset1: b"v2css", asset2: b"v2js"}
        routes = {
            f"https://plugins.svn.wordpress.org/{slug}/tags/": tags_page(
                "1.0", "1.1", "1.2"
            ),
            upstream_url(slug, "1.0", asset1): b"v1css",
            upstream_url(slug, "1.1", asset1): b"v2css",
            upstream_url(slug, "1.2", asset1): b"v2css",
            upstream_url(slug, "1.0", asset2): b"v1js",
            upstream_url(slug, "1.1", asset2): b"v2js",
            upstream_url(slug, "1.2", asset2): b"v3js",
        }

        async def fetch_target(path):
            return target.get(path)

        fp = await PluginFingerprinter(client=FakeClient(routes)).fingerprint(
            slug, asset_paths=[asset1, asset2], fetch_target=fetch_target
        )
        assert fp.version == "1.1"
        assert fp.confidence == "high"
        assert fp.candidates == ["1.1"]
        assert fp.matched_assets[asset1] == ["1.1", "1.2"]

    @pytest.mark.asyncio
    async def test_range_is_medium_latest(self):
        slug = "p"
        asset = "x.css"
        routes = {
            f"https://plugins.svn.wordpress.org/{slug}/tags/": tags_page(
                "1.0", "2.0"
            ),
            upstream_url(slug, "1.0", asset): b"same",
            upstream_url(slug, "2.0", asset): b"same",
        }

        async def fetch_target(path):
            return b"same"

        fp = await PluginFingerprinter(client=FakeClient(routes)).fingerprint(
            slug, asset_paths=[asset], fetch_target=fetch_target
        )
        assert fp.candidates == ["1.0", "2.0"]
        assert fp.version == "2.0"
        assert fp.confidence == "medium"

    @pytest.mark.asyncio
    async def test_no_upstream_tags(self):
        slug = "p"
        routes = {f"https://plugins.svn.wordpress.org/{slug}/tags/": b"<html></html>"}

        async def fetch_target(path):
            return b"x"

        fp = await PluginFingerprinter(client=FakeClient(routes)).fingerprint(
            slug, asset_paths=["x.css"], fetch_target=fetch_target
        )
        assert fp.version is None
        assert "no numeric upstream tags" in fp.error

    @pytest.mark.asyncio
    async def test_soft404_html_is_not_hashed(self):
        slug = "p"
        routes = {
            f"https://plugins.svn.wordpress.org/{slug}/tags/": tags_page("1.0"),
            upstream_url(slug, "1.0", "x.css"): b"real",
        }

        async def fetch_target(path):
            return b"<!DOCTYPE html><html>shell</html>"

        fp = await PluginFingerprinter(client=FakeClient(routes)).fingerprint(
            slug, asset_paths=["x.css"], fetch_target=fetch_target
        )
        assert fp.version is None
        assert "did not match" in fp.error

    @pytest.mark.asyncio
    async def test_target_modified_filters_candidates(self):
        slug = "p"
        asset = "x.css"
        routes = {
            f"https://plugins.svn.wordpress.org/{slug}/tags/": tags_page(
                "1.0", "1.1", "1.2"
            ),
            upstream_url(slug, "1.0", asset): b"same",
            upstream_url(slug, "1.1", asset): b"same",
            upstream_url(slug, "1.2", asset): b"same",
        }
        changelog = (
            "= 1.2 =\n* 10 Oct 2026\n\n"
            "= 1.1 =\n* 01 Sep 2026\n\n"
            "= 1.0 =\n* 01 Jan 2026\n"
        )
        client = FakeClient(routes, changelog=changelog)

        async def fetch_target(path):
            return b"same"

        fp = await PluginFingerprinter(client=client).fingerprint(
            slug,
            asset_paths=[asset],
            fetch_target=fetch_target,
            target_modified=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )
        assert fp.version == "1.1"  # 1.2 released after the install date
        assert fp.release_dates["1.1"].startswith("01 Sep")
        assert fp.target_modified.startswith("2026-09-25")

    @pytest.mark.asyncio
    async def test_requests_are_capped(self):
        slug = "p"
        routes = {
            f"https://plugins.svn.wordpress.org/{slug}/tags/": tags_page(
                "1.0", "2.0", "3.0"
            ),
        }

        async def fetch_target(path):
            return b"x"

        fp = await PluginFingerprinter(
            client=FakeClient(routes), max_requests=2
        ).fingerprint(slug, asset_paths=["x.css"], fetch_target=fetch_target)
        # One tags request + one upstream request, the rest capped.
        assert fp.requests_made == 2


class TestVersionsBefore:
    def test_filters_dates(self):
        dates = {"1.0": "01 Jan 2026", "1.1": "01 Sep 2026", "1.2": "10 Oct 2026"}
        kept = _versions_before(dates, datetime(2026, 9, 25, tzinfo=timezone.utc))
        assert kept == ["1.0", "1.1"]
