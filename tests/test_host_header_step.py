"""Tests for HostHeaderStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.host_header_step import HostHeaderStep, build_canary, extract_title


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)

    def items(self):
        return self._data.items()


def response(status, headers: dict, text=""):
    return MagicMock(status_code=status, headers=HeaderDict(headers), text=text)


def make_step(mock_http, mock_target, mock_config, enabled=True):
    mock_config.webapp_host_probe = enabled
    return HostHeaderStep(target=mock_target, config=mock_config, http=mock_http)


class TestHelpers:
    def test_canary_format(self):
        canary = build_canary()
        assert canary.startswith("canary-host-")
        assert canary.endswith(".example")

    def test_extract_title(self):
        assert extract_title("<title>App</title>") == "App"
        assert extract_title("no title here") == ""


class TestHostHeaderStep:
    async def test_no_reflection_no_findings(self, mock_http, mock_target, mock_config):
        async def _respond(method, url, **kwargs):
            return response(200, {}, "<html><body>home</body></html>")

        mock_http.request = AsyncMock(side_effect=_respond)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_host_reflected_in_body_low(self, mock_http, mock_target, mock_config):
        async def _respond(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if "Host" in headers:
                return response(200, {}, f"<html>contact@{headers['Host']}</html>")
            return response(200, {}, "<html>home</html>")

        mock_http.request = AsyncMock(side_effect=_respond)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "Host header reflected" in f.title][0]
        assert finding.severity == "low"

    async def test_unknown_vhost_200_vs_404_baseline(self, mock_http, mock_target, mock_config):
        async def _respond(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if "Host" in headers:
                return response(200, {}, "<html><title>other</title></html>")
            if "X-Forwarded-Host" in headers:
                return response(404, {}, "not found")
            return response(404, {}, "not found")

        mock_http.request = AsyncMock(side_effect=_respond)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [
            f for f in findings if "valid virtual host" in f.title
        ][0]
        assert finding.severity == "low"

    async def test_different_vhost_content_low(self, mock_http, mock_target, mock_config):
        async def _respond(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if "Host" in headers:
                return response(200, {}, "<html><title>other site</title></html>")
            return response(200, {}, "<html><title>home</title></html>")

        mock_http.request = AsyncMock(side_effect=_respond)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "Different virtual host" in f.title][0]
        assert finding.severity == "low"
        assert finding.raw["title"] == "other site"

    async def test_xfh_reflected_medium(self, mock_http, mock_target, mock_config):
        async def _respond(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if "X-Forwarded-Host" in headers:
                return response(
                    200,
                    {"set-cookie": f"session=x; Domain={headers['X-Forwarded-Host']}"},
                    "<html>home</html>",
                )
            return response(200, {}, "<html>home</html>")

        mock_http.request = AsyncMock(side_effect=_respond)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "X-Forwarded-Host" in f.title][0]
        assert finding.severity == "medium"

    async def test_disabled_by_config(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(200, {}, "home"))
        step = make_step(mock_http, mock_target, mock_config, enabled=False)
        findings = await step.run()
        assert findings == []
        mock_http.request.assert_not_called()

    async def test_baseline_failure(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
        assert mock_http.request.call_count == 1
