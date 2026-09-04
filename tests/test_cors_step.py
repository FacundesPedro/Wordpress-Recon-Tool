"""Tests for CorsStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from steps.webapp.cors_step import CorsStep

pytestmark = pytest.mark.asyncio


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key: str, default=None):
        return self._data.get(key.lower(), default)

    def items(self):
        return self._data.items()


def response(status, headers: dict, text=""):
    return MagicMock(status_code=status, headers=HeaderDict(headers), text=text)


def make_step(mock_http, mock_target, mock_config):
    return CorsStep(target=mock_target, config=mock_config, http=mock_http)


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp
        return response(404, {})

    return _respond


class TestCorsStep:
    async def test_origin_reflection_with_credentials(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200,
                        {
                            "access-control-allow-origin": "https://evil.attacker.example",
                            "access-control-allow-credentials": "true",
                        },
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = [f.title for f in findings]
        assert "CORS origin reflection with credentials" in titles
        finding = [f for f in findings if "reflection" in f.title][0]
        assert finding.severity == "high"

    async def test_origin_reflection_no_credentials(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200,
                        {"access-control-allow-origin": "https://evil.attacker.example"},
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        finding = [f for f in findings if "reflection" in f.title][0]
        assert finding.severity == "medium"

    async def test_wildcard_info(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(200, {"access-control-allow-origin": "*"}),
                    "/api": response(200, {}),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any(f.title == "Wildcard CORS policy" for f in findings)

    async def test_wildcard_with_credentials_medium(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200,
                        {
                            "access-control-allow-origin": "*",
                            "access-control-allow-credentials": "true",
                        },
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        finding = [f for f in findings if "Wildcard" in f.title][0]
        assert finding.severity == "medium"

    async def test_trusted_origin_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200, {"access-control-allow-origin": "https://app.example.com"}
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_no_cors_headers_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=responder({"/": response(200, {})}))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_exceptions_tolerated(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
