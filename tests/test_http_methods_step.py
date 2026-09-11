"""Tests for HttpMethodsStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from steps.webapp.http_methods_step import HttpMethodsStep

pytestmark = pytest.mark.asyncio


def make_step(mock_http, mock_target, mock_config):
    return HttpMethodsStep(target=mock_target, config=mock_config, http=mock_http)


def response(status, headers=None, text=""):
    return MagicMock(status_code=status, headers=headers or {}, text=text)


def responder_by_method(routes: dict):
    async def _respond(method, url, **kwargs):
        return routes.get(method, response(405))

    return _respond


class TestHttpMethodsStep:
    async def test_trace_enabled(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder_by_method(
                {
                    "OPTIONS": response(200, {"allow": "GET, HEAD, POST"}),
                    "TRACE": response(200, text="<pre>TRACE / HTTP/1.1 200 OK</pre>"),
                    "PUT": response(405),
                    "DELETE": response(405),
                    "PROPFIND": response(405),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = [f.title for f in findings]
        assert "TRACE method enabled" in titles
        trace = [f for f in findings if f.title == "TRACE method enabled"][0]
        assert trace.severity == "medium"
        assert "200" in trace.evidence

    async def test_put_delete_propfind_flagged(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder_by_method(
                {
                    "OPTIONS": response(200, {"allow": "GET, PUT, DELETE, PROPFIND"}),
                    "TRACE": response(405),
                    "PUT": response(200),
                    "DELETE": response(204),
                    "PROPFIND": response(207),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = [f.title for f in findings]
        assert "PUT method allowed" in titles
        assert "DELETE method allowed" in titles
        assert "WebDAV PROPFIND method enabled" in titles

    async def test_all_blocked_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder_by_method(
                {"OPTIONS": response(200, {"allow": "GET, HEAD, POST, OPTIONS"})}
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_missing_allow_header(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder_by_method({"OPTIONS": response(200, {})})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = [f.title for f in findings]
        assert "Missing Allow header on OPTIONS" in titles

    async def test_request_exceptions_tolerated(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_403_not_flagged_as_allowed(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder_by_method(
                {
                    "OPTIONS": response(200, {"allow": "GET"}),
                    "TRACE": response(403),
                    "PUT": response(403),
                    "DELETE": response(403),
                    "PROPFIND": response(403),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_spa_catchall_methods_suppressed(self, mock_http, mock_target, mock_config):
        """SPA shell served for every method = methods not actually enabled."""
        shell = ("<!-- license -->\n<!doctype html><html><head>"
                 "<title>OWASP Juice Shop</title></head></html>")

        async def catch_all(method, url, **kwargs):
            return response(200, text=shell)

        mock_http.request = AsyncMock(side_effect=catch_all)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = [f.title for f in findings]
        assert "TRACE method enabled" not in titles
        assert "PUT method allowed" not in titles
        assert "DELETE method allowed" not in titles
        assert "WebDAV PROPFIND method enabled" not in titles

    async def test_method_processed_differently_reported(self, mock_http, mock_target, mock_config):
        """A method answered differently from the GET baseline is a real signal."""
        shell = "<!doctype html><html><title>App</title></html>"

        async def responder(method, url, **kwargs):
            if method == "PUT":
                return response(201, text='{"created": true}')
            if method == "DELETE":
                return response(204, text="")
            return response(200, text=shell)

        mock_http.request = AsyncMock(side_effect=responder)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = [f.title for f in findings]
        assert "PUT method allowed" in titles
        assert "DELETE method allowed" in titles
        assert "TRACE method enabled" not in titles
