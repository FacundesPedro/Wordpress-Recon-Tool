"""Tests for StackTraceStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from steps.webapp.stack_trace_step import StackTraceStep

pytestmark = pytest.mark.asyncio


def make_step(mock_http, mock_target, mock_config):
    return StackTraceStep(target=mock_target, config=mock_config, http=mock_http)


def response(status, text=""):
    return MagicMock(status_code=status, text=text)


class TestStackTraceStep:
    async def test_python_traceback_detected(self, mock_http, mock_target, mock_config):
        body = (
            "<html><body><h1>500 Internal Server Error</h1><pre>"
            "Traceback (most recent call last):\n"
            '  File "/app/views.py", line 42, in index\n'
            "    raise ValueError('bad input')\n"
            "</pre></body></html>"
        )
        mock_http.request = AsyncMock(return_value=response(500, body))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert any("Python traceback" in f.title for f in findings)
        finding = [f for f in findings if "Python traceback" in f.title][0]
        assert finding.severity == "medium"
        assert "views.py" in finding.evidence

    async def test_php_fatal_error(self, mock_http, mock_target, mock_config):
        body = (
            "<b>Fatal error</b>:  Uncaught Error: Call to undefined function "
            "in /var/www/html/index.php on line 10"
        )
        mock_http.request = AsyncMock(return_value=response(500, body))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("PHP fatal error" in f.title for f in findings)

    async def test_django_error(self, mock_http, mock_target, mock_config):
        body = "<pre>django.core.exceptions.ImproperlyConfigured: no static files</pre>"
        mock_http.request = AsyncMock(return_value=response(500, body))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Django error" in f.title for f in findings)

    async def test_signatures_reported_once(self, mock_http, mock_target, mock_config):
        body = "Traceback (most recent call last):\nTraceback (most recent call last):"
        mock_http.request = AsyncMock(return_value=response(500, body))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        python_hits = [f for f in findings if "Python traceback" in f.title]
        assert len(python_hits) == 1

    async def test_clean_responses_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(200, "<html>ok</html>"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_500_without_details_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(500, "<html><body>Server Error</body></html>")
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_post_malformed_json_detected(self, mock_http, mock_target, mock_config):
        body = (
            "<pre>org.springframework.http.converter.HttpMessageNotReadableException: "
            "JSON parse error</pre>"
        )

        def responder(method, url, **kwargs):
            if method == "POST":
                return response(400, body)
            return response(200, "<html>ok</html>")

        mock_http.request = AsyncMock(side_effect=responder)
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert any("Spring exception" in f.title for f in findings)
        post_calls = [
            c for c in mock_http.request.call_args_list if c.args[0] == "POST"
        ]
        assert len(post_calls) == 2

    async def test_exceptions_tolerated(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
