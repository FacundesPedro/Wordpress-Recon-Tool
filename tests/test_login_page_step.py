"""Tests for LoginPageStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio

LOGIN_FORM = (
    '<html><body><form id="loginform" action="wp-login.php" method="post">'
    '<input type="text" name="log" id="user_login">'
    '<input type="password" name="pwd" id="user_pass">'
    '<input type="submit" name="wp-submit" id="wp-submit" value="Log In">'
    "</form></body></html>"
)

HOMEPAGE = (
    '<html><head><meta name="generator" content="WordPress 7.1"></head>'
    "<body>Welcome to the site</body></html>"
)


class TestLoginPageStep:
    async def test_returns_empty_when_wordlist_none(self, mock_http, mock_target, mock_config):
        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(LoginPageStep, "resolve_wordlist_or_fallback", return_value=None):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_found_login_page(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text=LOGIN_FORM)
        )

        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(
            LoginPageStep, "resolve_wordlist_or_fallback",
            return_value=["/wp-login.php"],
        ):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "WordPress login page detected"
        assert findings[0].module == "discovery"
        assert findings[0].severity == "info"

    async def test_multiple_paths_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text=LOGIN_FORM)
        )

        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(
            LoginPageStep, "resolve_wordlist_or_fallback",
            return_value=["/wp-login.php", "/wp-admin/"],
        ):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert len(findings[0].raw["login_pages"]) == 2

    async def test_homepage_with_wordpress_marker_not_login(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text=HOMEPAGE)
        )

        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(
            LoginPageStep, "resolve_wordlist_or_fallback",
            return_value=["/wp-login.php", "/login/", "/wp-admin/login.php"],
        ):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_no_login_page_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="<html><body>Just a random page</body></html>",
            )
        )

        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(
            LoginPageStep, "resolve_wordlist_or_fallback",
            return_value=["/wp-login.php"],
        ):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 0

    async def test_body_check_case_insensitive(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text='<FORM ID="LOGINFORM" ACTION="wp-login.php"><INPUT NAME="LOG"></FORM>',
            )
        )

        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(
            LoginPageStep, "resolve_wordlist_or_fallback",
            return_value=["/wp-login.php"],
        ):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1

    async def test_status_302_also_accepted(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=302,
                headers={"Location": "https://example.com/wp-admin/"},
                text=LOGIN_FORM,
            )
        )

        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(
            LoginPageStep, "resolve_wordlist_or_fallback",
            return_value=["/wp-admin/"],
        ):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1

    async def test_exception_per_path_does_not_block(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=[
            Exception("timeout"),
            MagicMock(status_code=200, text=LOGIN_FORM),
        ])

        from steps.discovery.login_page_step import LoginPageStep

        with patch.object(
            LoginPageStep, "resolve_wordlist_or_fallback",
            return_value=["/wp-login.php/", "/wp-admin/"],
        ):
            step = LoginPageStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
