"""Tests for CsrfStep and DefaultCredentialsStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.csrf_step import CsrfStep, has_token, parse_forms
from steps.active.default_credentials_step import DefaultCredentialsStep


class TestCsrfHelpers:
    def test_parse_forms(self):
        forms = parse_forms(
            '<form action="/register" method="POST">'
            '<input name="user"><input name="pass"></form>'
        )
        assert forms[0]["method"] == "POST"
        assert "user" in forms[0]["fields"]

    def test_has_token(self):
        assert has_token(["csrf_token", "user"])
        assert has_token(["_wpnonce"])
        assert not has_token(["user", "pass"])


class TestCsrfStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 50
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return CsrfStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_missing_token_reported(self, mock_http, mock_target, mock_config):
        html = ('<form action="/register" method="POST">'
                '<input name="user"><input name="password">'
                '<input type="submit" name="submit"></form>')
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("without CSRF token" in f.title for f in findings)

    async def test_token_present_clean(self, mock_http, mock_target, mock_config):
        html = ('<form action="/register" method="POST">'
                '<input name="csrf_token" type="hidden" value="x">'
                '<input name="user"><input name="password"></form>')
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []


class TestDefaultCredentialsStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 30
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return DefaultCredentialsStep(
            target=mock_target, config=mock_config, http=mock_http
        )

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_default_creds_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if method == "POST":
                data = kwargs.get("data") or {}
                if data.get("log") == "admin" and data.get("pwd") == "admin":
                    return MagicMock(status_code=302,
                                     headers={"location": "/wp-admin/"})
                return MagicMock(status_code=200, text="wrong")
            return MagicMock(status_code=200, text="<form>login</form>")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Default credentials" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)

    async def test_no_login_endpoints(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="nope")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
