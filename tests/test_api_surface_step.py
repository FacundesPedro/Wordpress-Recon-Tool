"""Tests for ApiSurfaceStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.api_surface_step import (
    ApiSurfaceStep,
    parse_robots,
    parse_sitemap,
)

DEFAULT_PATHS = [
    "robots.txt",
    "sitemap.xml",
    "api",
    "graphql",
    "swagger.json",
]


def make_step(mock_http, mock_target, mock_config, paths=None):
    mock_config.webapp_max_api_paths = 30
    step = ApiSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
    step.resolve_wordlist_or_fallback = MagicMock(
        return_value=paths if paths is not None else DEFAULT_PATHS
    )
    return step


def response(status, text=""):
    return MagicMock(status_code=status, text=text)


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix) or url == suffix:
                return resp
        return response(404, "Not Found")

    return _respond


class TestParsers:
    def test_parse_robots(self):
        text = (
            "User-agent: *\nDisallow: /admin\nDisallow:\n"
            "Sitemap: https://example.com/sitemap.xml\n"
        )
        parsed = parse_robots(text)
        assert parsed["disallowed"] == ["/admin"]
        assert parsed["sitemaps"] == ["https://example.com/sitemap.xml"]

    def test_parse_sitemap(self):
        text = (
            "<?xml><urlset>"
            "<url><loc>https://a.example</loc></url>"
            "<url><loc>https://b.example</loc></url>"
            "</urlset>"
        )
        assert parse_sitemap(text) == ["https://a.example", "https://b.example"]


class TestApiSurfaceStep:
    async def test_robots_disallowed_reported(self, mock_http, mock_target, mock_config):
        robots = "User-agent: *\nDisallow: /internal\nDisallow: /admin/export\n"
        mock_http.request = AsyncMock(
            side_effect=responder({"robots.txt": response(200, robots)})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "robots.txt" in f.title][0]
        assert finding.severity == "info"
        assert finding.evidence == "https://example.com/robots.txt"
        assert finding.raw["url"] == "https://example.com/robots.txt"
        assert "/admin/export" in finding.raw["disallowed"]

    async def test_sitemap_inventory_reported(self, mock_http, mock_target, mock_config):
        sitemap = (
            "<urlset>"
            "<url><loc>https://example.com/a</loc></url>"
            "<url><loc>https://example.com/b</loc></url>"
            "</urlset>"
        )
        mock_http.request = AsyncMock(
            side_effect=responder({"sitemap.xml": response(200, sitemap)})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "Sitemap" in f.title][0]
        assert finding.severity == "info"
        assert finding.raw["url_count"] == 2

    async def test_openapi_json_high(self, mock_http, mock_target, mock_config):
        spec = (
            '{"openapi":"3.0.0","paths":{'
            '"/users":{"get":{},"post":{}},'
            '"/admin/export":{"get":{}},'
            '"/login":{"post":{}}}}'
        )
        mock_http.request = AsyncMock(
            side_effect=responder({"swagger.json": response(200, spec)})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "OpenAPI" in f.title][0]
        assert finding.severity == "high"
        assert finding.raw["endpoint_count"] == 4
        assert "/admin/export" in finding.raw["sensitive_paths"]
        assert "/login" in finding.raw["sensitive_paths"]

    async def test_swagger_ui_medium(self, mock_http, mock_target, mock_config):
        html = (
            "<html><div id='swagger-ui'></div>"
            "<script src='/swagger-ui-bundle.js'></script></html>"
        )
        mock_http.request = AsyncMock(
            side_effect=responder({"swagger-ui.html": response(200, html)})
        )
        step = make_step(mock_http, mock_target, mock_config, paths=["swagger-ui.html"])
        findings = await step.run()
        finding = [f for f in findings if "Swagger UI" in f.title][0]
        assert finding.severity == "medium"

    async def test_graphql_introspection_high(self, mock_http, mock_target, mock_config):
        gql = '{"data":{"types":[{"name":"User"},{"name":"Query"},{"name":"Mutation"}]}}'
        mock_http.request = AsyncMock(
            side_effect=responder({"graphql": response(200, gql)})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "GraphQL introspection" in f.title][0]
        assert finding.severity == "high"
        assert finding.raw["type_count"] == 3
        assert finding.raw["types"] == ["User", "Query", "Mutation"]
        post_calls = [
            c for c in mock_http.request.call_args_list if c.args[0] == "POST"
        ]
        assert len(post_calls) == 1
        assert post_calls[0].kwargs["json"]["query"].startswith("{__schema")

    async def test_graphql_no_introspection_info(self, mock_http, mock_target, mock_config):
        gql = '{"errors":[{"message":"Introspection is not allowed"}]}'
        mock_http.request = AsyncMock(
            side_effect=responder({"graphql": response(400, gql)})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("GraphQL endpoint present" in f.title for f in findings)

    async def test_api_endpoints_info(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder({"api": response(200, '["ok"]')})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "API endpoints discovered" in f.title][0]
        assert finding.severity == "info"
        assert "api" in finding.raw["paths"]

    async def test_404s_ignored(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(404, "Not Found"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_spa_shell_paths_not_reported(self, mock_http, mock_target, mock_config):
        """Catch-all 200 shells must not produce API/robots/sitemap findings."""
        shell = (
            "<!doctype html><html><head><title>App</title></head>"
            "<body>" + "x" * 500 + "</body></html>"
        )

        async def shell_responder(method, url, **kwargs):
            return response(200, shell)

        mock_http.request = AsyncMock(side_effect=shell_responder)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_exceptions_tolerated(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_wordlist_none_disables(self, mock_http, mock_target, mock_config):
        step = make_step(mock_http, mock_target, mock_config)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)
        findings = await step.run()
        assert findings == []
        mock_http.request.assert_not_called()
