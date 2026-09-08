"""Tests for OpenRedirectStep."""

from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, quote, unquote

from steps.webapp.open_redirect_step import (
    OpenRedirectStep,
    build_canary,
    canary_in_location,
)


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)

    def items(self):
        return self._data.items()


def response(status, headers: dict = None, text=""):
    return MagicMock(
        status_code=status, headers=HeaderDict(headers or {}), text=text
    )


def make_step(mock_http, mock_target, mock_config, enabled=True, max_requests=60):
    mock_config.webapp_open_redirect = enabled
    mock_config.webapp_redirect_max_requests = max_requests
    return OpenRedirectStep(target=mock_target, config=mock_config, http=mock_http)


class TestCanaryHelpers:
    def test_canary_format(self):
        canary = build_canary()
        assert canary.startswith("https://redirect-canary-")
        assert canary.endswith(".example")

    def test_canary_in_location(self):
        canary = build_canary()
        host = canary.split("//", 1)[1].split("/", 1)[0]
        assert canary_in_location(canary, canary)
        assert canary_in_location(canary + "/next", canary)
        assert canary_in_location("https://x.example/?u=" + quote(host, safe=""), canary)
        assert not canary_in_location("https://other.example/", canary)
        assert not canary_in_location("", canary)


class TestOpenRedirectStep:
    async def test_open_redirect_on_login_high(self, mock_http, mock_target, mock_config):
        async def redirector(method, url, **kwargs):
            if "/login" in url and "url=" in url:
                target = unquote(parse_qs(url.split("?", 1)[1])["url"][0])
                return response(302, {"location": target})
            return response(200, text="ok")

        mock_http.request = AsyncMock(side_effect=redirector)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert findings
        finding = findings[0]
        assert finding.severity == "high"
        assert finding.raw["path"] == "/login"
        assert finding.raw["param"] == "url"

    async def test_non_auth_path_medium(self, mock_http, mock_target, mock_config):
        async def redirector(method, url, **kwargs):
            if "/redirect?" in url and "next=" in url:
                target = unquote(parse_qs(url.split("?", 1)[1])["next"][0])
                return response(302, {"location": target})
            return response(200, text="ok")

        mock_http.request = AsyncMock(side_effect=redirector)
        step = make_step(mock_http, mock_target, mock_config, max_requests=120)
        findings = await step.run()

        assert findings
        assert findings[0].severity == "medium"
        assert findings[0].raw["path"] == "/redirect"
        assert findings[0].raw["param"] == "next"

    async def test_encoded_location_detected(self, mock_http, mock_target, mock_config):
        async def redirector(method, url, **kwargs):
            if "/go" in url and "to=" in url:
                target = unquote(parse_qs(url.split("?", 1)[1])["to"][0])
                return response(
                    302,
                    {"location": "https://evil.example/?r=" + quote(target, safe="")},
                )
            return response(200, text="ok")

        mock_http.request = AsyncMock(side_effect=redirector)
        step = make_step(mock_http, mock_target, mock_config, max_requests=150)
        findings = await step.run()
        assert any(f.raw["path"] == "/go" for f in findings)

    async def test_no_redirects_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(200, text="ok"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_redirect_to_other_host_ignored(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(302, {"location": "https://other.example/"})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_disabled_by_config(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(200, text="ok"))
        step = make_step(mock_http, mock_target, mock_config, enabled=False)
        findings = await step.run()
        assert findings == []
        mock_http.request.assert_not_called()

    async def test_max_requests_respected(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(200, text="ok"))
        step = make_step(mock_http, mock_target, mock_config, max_requests=10)
        await step.run()
        assert mock_http.request.call_count <= 10

    async def test_probes_use_no_redirect_following(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(200, text="ok"))
        step = make_step(mock_http, mock_target, mock_config, max_requests=10)
        await step.run()
        for call in mock_http.request.call_args_list:
            assert call.kwargs.get("follow_redirects") is False
