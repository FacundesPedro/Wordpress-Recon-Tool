"""Tests for ssrf module steps."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestOembedProxyStep:
    """Tests for OembedProxyStep — single GET to /oembed/1.0/proxy."""

    async def test_vulnerable_via_wordpress_keyword(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(
            status_code=200, text="WordPress oEmbed response"
        )

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "ssrf"
        assert f.severity == "medium"
        assert "oEmbed proxy" in f.title

    async def test_vulnerable_via_html_keyword(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(
            status_code=200, text="<html><body>proxy response</body></html>"
        )

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1

    async def test_not_vulnerable_no_keywords(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(
            status_code=200, text="some other response"
        )

        from steps.ssrf.oembed_proxy_step import OembedProxyStep
        step = OembedProxyStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_non_200_status(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(status_code=404, text="")

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
