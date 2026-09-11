"""Tests for FormSecurityStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.form_security_step import FormSecurityStep, parse_form


class TestParseForm:
    def test_parses_method_action_inputs(self):
        form = parse_form(
            '<form action="/login" method="POST">',
            '<input type="text" name="user"><input type="password" name="pass" autocomplete="on">'
        )
        assert form["method"] == "POST"
        assert form["action"] == "/login"
        assert {"type": "password", "name": "pass", "autocomplete": "on"} in form["inputs"]

    def test_defaults(self):
        form = parse_form("<form>", "<input type='password'>")
        assert form["method"] == "GET"
        assert form["action"] == ""


class TestFormSecurityStep:
    async def test_http_password_form_high(self, mock_http, mock_target, mock_config):
        html = ('<form action="http://insecure.example/login" method="POST">'
                '<input type="password" name="pass"></form>')
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = FormSecurityStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("plaintext" in f.title.lower() for f in findings)
        assert any(f.severity == "high" for f in findings)

    async def test_autocomplete_flagged(self, mock_http, mock_target, mock_config):
        html = ('<form action="/login" method="POST">'
                '<input type="password" name="pass" autocomplete="on"></form>')
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = FormSecurityStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("autocomplete" in f.title.lower() for f in findings)

    async def test_https_form_clean(self, mock_http, mock_target, mock_config):
        html = ('<form action="/login" method="POST">'
                '<input type="password" name="pass" autocomplete="off"></form>')
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = FormSecurityStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []

    async def test_no_forms(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<p>no forms</p>")
        )
        step = FormSecurityStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []
