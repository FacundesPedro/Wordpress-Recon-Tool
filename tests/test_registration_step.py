"""Tests for RegistrationStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.users.registration_step import (
    RegistrationStep,
    looks_like_registration,
)

REGISTRATION_MARKERS = [
    "registration confirmation will be emailed",
    "id=\"user_login\"",
    "name=\"user_login\"",
    "action=register",
    "create a new account",
    "registerform",
]

SIGNUP_MARKERS = [
    "create a new site",
    "sitesetup",
    "signup_for",
    "signup_user",
]


class TestLooksLikeRegistration:
    def test_registration_page(self):
        html = ('<form id="registerform">Registration confirmation will be emailed'
                '<input name="user_login"></form>')
        assert looks_like_registration(html, REGISTRATION_MARKERS)

    def test_login_page_not_registration(self):
        html = '<form id="loginform"><input name="log"></form>'
        assert not looks_like_registration(html, REGISTRATION_MARKERS)

    def test_signup_page(self):
        html = "Create a new site! signup_for=blog signup_user=1"
        assert looks_like_registration(html, SIGNUP_MARKERS)


class TestRegistrationStep:
    async def test_open_registration_reported(self, mock_http, mock_target, mock_config):
        html = ('<form id="registerform">Registration confirmation will be emailed'
                '<input name="user_login"></form>')
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = RegistrationStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("Open user registration" in f.title for f in findings)

    async def test_registration_disabled(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<p>registration closed</p>")
        )
        step = RegistrationStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []

    async def test_multisite_signup_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "action=register" in url:
                return MagicMock(status_code=200, text="<p>closed</p>")
            return MagicMock(status_code=200,
                             text="Create a new site! signup_for=blog signup_user=1")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = RegistrationStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("wp-signup" in f.title for f in findings)
