"""Tests for API module steps (3 step classes)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# AppPasswordsStep
# ---------------------------------------------------------------------------

class TestAppPasswordsStep:
    """AppPasswordsStep — GET app-password endpoints, JSON 200/401 detection."""

    async def test_both_endpoints_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=[
            MagicMock(
                status_code=200,
                headers={"content-type": "application/json"},
                text='[{"id": 1}]',
            ),
            MagicMock(
                status_code=401,
                headers={"content-type": "application/json"},
                text='{"code": "rest_forbidden"}',
            ),
        ])
        from steps.api.app_passwords_step import AppPasswordsStep
        step = AppPasswordsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "Application Passwords API detected" in findings[0].title
        assert "1 endpoint(s) publicly accessible" in findings[0].description
        assert "1 endpoint(s) exist but require authentication" in findings[0].description

    async def test_public_access_detected(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                headers={"content-type": "application/json"},
                text='[{"id": 1}]',
            )
        )
        from steps.api.app_passwords_step import AppPasswordsStep
        step = AppPasswordsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "publicly accessible" in findings[0].description

    async def test_no_endpoints_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=404,
                headers={"content-type": "application/json"},
                text='{"code": "rest_no_route"}',
            )
        )
        from steps.api.app_passwords_step import AppPasswordsStep
        step = AppPasswordsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_html_shell_ignored(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                headers={"content-type": "text/html"},
                text="<!doctype html><html><body>homepage</body></html>",
            )
        )
        from steps.api.app_passwords_step import AppPasswordsStep
        step = AppPasswordsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_plain_permalink_fallback(self, mock_http, mock_target, mock_config):
        async def requestor(url, **kwargs):
            if "rest_route=" in url:
                return MagicMock(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text='[{"id": 1}]',
                )
            return MagicMock(status_code=200, text="<html>homepage</html>")

        mock_http.get = AsyncMock(side_effect=requestor)
        from steps.api.app_passwords_step import AppPasswordsStep
        step = AppPasswordsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1

    async def test_no_endpoints_found_different_codes(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=[
            MagicMock(status_code=403, text="forbidden"),
            MagicMock(status_code=500, text="error"),
        ])
        from steps.api.app_passwords_step import AppPasswordsStep
        step = AppPasswordsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=ConnectionError("network error"))
        from steps.api.app_passwords_step import AppPasswordsStep
        step = AppPasswordsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PagesIpLeakStep
# ---------------------------------------------------------------------------

class TestPagesIpLeakStep:
    """PagesIpLeakStep — GET wp/v2/pages, JSON-parsed, IP regex scan."""

    PAGES_WITH_IP = {
        "id": 1,
        "title": "Hello World",
        "_links": {"author": "http://192.168.1.1/wp-json/"},
    }

    PAGES_WITH_MULTIPLE_IPS = {
        "id": 2,
        "modified_by": {"ip": "10.0.0.5"},
        "revisions": [
            {"author_ip": "192.168.1.100"},
        ],
    }

    PAGES_PUBLIC_ONLY = {
        "id": 3,
        "link": "https://example.com/page",
    }

    async def test_private_ip_leaked(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                json=lambda: self.PAGES_WITH_IP,
                text='{"_links": {"author": "http://192.168.1.1/wp-json/"}}',
            )
        )
        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        step = PagesIpLeakStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "Internal IP addresses leaked" in findings[0].title
        assert "192.168.1.1" in findings[0].evidence

    async def test_multiple_private_ips(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                json=lambda: self.PAGES_WITH_MULTIPLE_IPS,
                text='{"ip": "10.0.0.5, 192.168.1.100"}',
            )
        )
        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        step = PagesIpLeakStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "10.0.0.5" in findings[0].evidence or "192.168.1.100" in findings[0].evidence

    async def test_public_ips_not_flagged(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                json=lambda: self.PAGES_PUBLIC_ONLY,
                text='{"ip": "8.8.8.8"}',
            )
        )
        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        step = PagesIpLeakStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_no_ips_detected(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                json=lambda: {"no": "ips", "here": True},
                text='{"no": "ips"}',
            )
        )
        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        step = PagesIpLeakStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_endpoint_not_accessible(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=403, text="Forbidden")
        )
        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        step = PagesIpLeakStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_invalid_json(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text="not json")
        )
        mock_http.get.return_value.json.side_effect = ValueError("bad json")

        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        step = PagesIpLeakStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=ConnectionError("network error"))
        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        step = PagesIpLeakStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# RestSurfaceStep
# ---------------------------------------------------------------------------

class TestRestSurfaceStep:
    """RestSurfaceStep — GET on REST routes, JSON-only detection."""

    @staticmethod
    def json_response(status, body):
        return MagicMock(
            status_code=status,
            headers={"content-type": "application/json"},
            text=body,
        )

    async def test_endpoints_found_multiple(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if url.endswith("/wp-json/") or url.endswith("/wp-json/wp/v2/"):
                return self.json_response(200, "{}")
            return self.json_response(404, '{"code": "rest_no_route"}')

        mock_http.request = AsyncMock(side_effect=requestor)
        from steps.api.rest_surface_step import RestSurfaceStep
        step = RestSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "REST API surface detected" in findings[0].title
        assert "2 accessible" in findings[0].description

    async def test_no_endpoints_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=self.json_response(404, '{"code": "rest_no_route"}')
        )
        from steps.api.rest_surface_step import RestSurfaceStep
        step = RestSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_some_endpoints_found(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "/wp-json/wp/v2/users" in url:
                return self.json_response(401, '{"code": "rest_forbidden"}')
            if "/wp-json/wp/v2/posts" in url:
                return self.json_response(200, "[]")
            return self.json_response(404, '{"code": "rest_no_route"}')

        mock_http.request = AsyncMock(side_effect=requestor)
        from steps.api.rest_surface_step import RestSurfaceStep
        step = RestSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1
        assert "2 accessible" in findings[0].description

    async def test_html_shell_ignored(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                headers={"content-type": "text/html"},
                text="<!doctype html><html><body>homepage</body></html>",
            )
        )
        from steps.api.rest_surface_step import RestSurfaceStep
        step = RestSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_plain_permalink_fallback(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "rest_route=" in url:
                return self.json_response(200, "{}")
            return MagicMock(
                status_code=200,
                headers={"content-type": "text/html"},
                text="<html>homepage</html>",
            )

        mock_http.request = AsyncMock(side_effect=requestor)
        from steps.api.rest_surface_step import RestSurfaceStep
        step = RestSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].raw["endpoints"][0]["path"].startswith("?rest_route=")

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("network error"))
        from steps.api.rest_surface_step import RestSurfaceStep
        step = RestSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_content_type_captured(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=self.json_response(200, "{}")
        )
        from steps.api.rest_surface_step import RestSurfaceStep
        step = RestSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        raw = findings[0].raw
        endpoints = raw["endpoints"]
        assert any(e["content_type"] == "application/json" for e in endpoints)
