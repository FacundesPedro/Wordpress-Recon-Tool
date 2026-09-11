"""Tests for ssrf module steps."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestOembedProxyStep:
    """Tests for OembedProxyStep — GET to /oembed/1.0/proxy, JSON validation."""

    OEMBED_JSON = (
        '{"type": "rich", "provider_name": "Example", '
        '"html": "<blockquote>hi</blockquote>"}'
    )

    async def test_vulnerable_json_oembed_response(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                headers={"content-type": "application/json"},
                text=self.OEMBED_JSON,
            )
        )

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "ssrf"
        assert f.severity == "medium"
        assert "oEmbed proxy" in f.title

    async def test_auth_required_not_reported(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=401,
                headers={"content-type": "application/json"},
                text='{"code": "rest_forbidden"}',
            )
        )

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_html_shell_ignored(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                headers={"content-type": "text/html"},
                text="<!doctype html><html><body>WordPress homepage</body></html>",
            )
        )

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_error_json_not_reported(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                headers={"content-type": "application/json"},
                text='{"code": "rest_no_route", "message": "No route"}',
            )
        )

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_plain_permalink_fallback(self, mock_http, mock_target, mock_config):
        async def requestor(url, **kwargs):
            if "rest_route=" in url:
                return MagicMock(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=self.OEMBED_JSON,
                )
            return MagicMock(status_code=200, text="<html>homepage</html>")

        mock_http.get = AsyncMock(side_effect=requestor)

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "rest_route=" in findings[0].raw["url"]

    async def test_non_200_status(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404, text=""))

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_exception_returns_empty(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = Exception("Connection error")

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []


class TestPingbackSsrfStep:
    """Tests for PingbackSsrfStep — single POST to xmlrpc.php."""

    async def test_available_via_pingback_ping_string(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text="pingback.ping")
        )

        from steps.ssrf.pingback_ssrf_step import PingbackSsrfStep
        step = PingbackSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "ssrf"
        assert f.severity == "medium"
        assert "pingback.ping" in f.title

    async def test_available_via_fault_code_zero(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="<faultCode>0</faultCode>"
            )
        )

        from steps.ssrf.pingback_ssrf_step import PingbackSsrfStep
        step = PingbackSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1

    async def test_not_available(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text="<faultCode>404</faultCode>")
        )

        from steps.ssrf.pingback_ssrf_step import PingbackSsrfStep
        step = PingbackSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_exception_returns_empty(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(side_effect=Exception("Connection refused"))

        from steps.ssrf.pingback_ssrf_step import PingbackSsrfStep
        step = PingbackSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []
