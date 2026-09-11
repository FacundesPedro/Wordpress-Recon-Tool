"""Tests for SourcemapStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from steps.webapp.sourcemap_step import SourcemapStep

pytestmark = pytest.mark.asyncio


VALID_MAP = '{"version":3,"sources":["app.ts"],"mappings":"AAAA"}'
SPA_SHELL = (
    "<!doctype html><html><head><title>App</title></head>"
    "<body><app-root></app-root></body></html>"
)


def make_step(mock_http, mock_target, mock_config, enabled=True, max_js=10):
    mock_config.source_scan_sourcemaps = enabled
    mock_config.source_scan_max_js = max_js
    return SourcemapStep(target=mock_target, config=mock_config, http=mock_http)


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, response in routes.items():
            if url.endswith(suffix) or url == suffix:
                return response
        return MagicMock(status_code=404, text="Not Found")

    return _respond


class TestIsSourcemapContent:
    async def test_valid_v3_map(self):
        from steps.webapp.sourcemap_step import is_sourcemap_content
        assert is_sourcemap_content(VALID_MAP) is True

    async def test_version_and_sources_only(self):
        from steps.webapp.sourcemap_step import is_sourcemap_content
        assert is_sourcemap_content('{"version":3,"sources":["a.ts"]}') is True

    async def test_html_rejected(self):
        from steps.webapp.sourcemap_step import is_sourcemap_content
        assert is_sourcemap_content(SPA_SHELL) is False

    async def test_unrelated_json_rejected(self):
        from steps.webapp.sourcemap_step import is_sourcemap_content
        assert is_sourcemap_content('{"error": "not found"}') is False

    async def test_non_json_rejected(self):
        from steps.webapp.sourcemap_step import is_sourcemap_content
        assert is_sourcemap_content("//# sourceMappingURL=x.map") is False


class TestSourcemapStep:
    async def test_exposed_map_detected(self, mock_http, mock_target, mock_config):
        html = '<html><head><script src="/static/app.js"></script></head><body></body></html>'
        map_body = '{"version":3,"sources":["app.ts"],"names":[],"mappings":"AAAA"}'
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": MagicMock(status_code=200, text=html),
                    "/static/app.js.map": MagicMock(status_code=200, text=map_body),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "Exposed JavaScript sourcemap"
        assert "/static/app.js.map" in findings[0].evidence
        assert findings[0].raw["source_lines"] == 1

    async def test_no_map_found(self, mock_http, mock_target, mock_config):
        html = '<html><head><script src="/static/app.js"></script></head><body></body></html>'
        mock_http.request = AsyncMock(
            side_effect=responder({"/": MagicMock(status_code=200, text=html)})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_multiple_maps(self, mock_http, mock_target, mock_config):
        html = (
            "<html><head>"
            '<script src="/static/app.js"></script>'
            '<script src="/static/vendor.js"></script>'
            "</head><body></body></html>"
        )
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": MagicMock(status_code=200, text=html),
                    "/static/app.js.map": MagicMock(status_code=200, text=VALID_MAP),
                    "/static/vendor.js.map": MagicMock(status_code=200, text=VALID_MAP),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert len(findings) == 2

    async def test_spa_shell_at_map_path_ignored(self, mock_http, mock_target, mock_config):
        html = '<html><head><script src="/main.js"></script></head><body></body></html>'
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": MagicMock(status_code=200, text=html),
                    "/main.js": MagicMock(status_code=200, text="console.log(1)"),
                    "/main.js.map": MagicMock(status_code=200, text=SPA_SHELL),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_non_sourcemap_json_ignored(self, mock_http, mock_target, mock_config):
        html = '<html><head><script src="/app.js"></script></head><body></body></html>'
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": MagicMock(status_code=200, text=html),
                    "/app.js.map": MagicMock(
                        status_code=200, text='{"error": "not found"}'
                    ),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_sourcemap_url_comment_detected(self, mock_http, mock_target, mock_config):
        html = '<html><head><script src="/static/app.js"></script></head><body></body></html>'
        js = "console.log('app');\n//# sourceMappingURL=app.a1b2c3.js.map\n"
        map_body = '{"version":3,"sources":["app.ts"]}'
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": MagicMock(status_code=200, text=html),
                    "/static/app.js": MagicMock(status_code=200, text=js),
                    "/static/app.a1b2c3.js.map": MagicMock(
                        status_code=200, text=map_body
                    ),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert len(findings) == 1
        assert "/static/app.a1b2c3.js.map" in findings[0].evidence
        assert findings[0].raw["discovery"] == "source_mapping_url"

    async def test_disabled_by_config(self, mock_http, mock_target, mock_config):
        step = make_step(mock_http, mock_target, mock_config, enabled=False)
        findings = await step.run()
        assert findings == []
        mock_http.request.assert_not_called()

    async def test_non_js_assets_ignored(self, mock_http, mock_target, mock_config):
        html = '<html><head><link rel="stylesheet" href="/style.css"></head><body></body></html>'
        mock_http.request = AsyncMock(
            side_effect=responder({"/": MagicMock(status_code=200, text=html)})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
