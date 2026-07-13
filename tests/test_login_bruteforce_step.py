"""Tests for LoginBruteforceStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


pytestmark = pytest.mark.asyncio


class TestTryLogin:
    """Tests for _try_login method."""

    async def test_redirect_to_wp_admin_is_success(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(**{"status_code": 302, "headers": {"location": "https://example.com/wp-admin/"}})
        mock_http.post = AsyncMock(return_value=mock_resp)

        success, detail = await step._try_login("admin", "password")

        assert success is True
        assert detail == "redirect_to_wp_admin"

    async def test_redirect_to_other_path_is_success(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(**{"status_code": 302, "headers": {"location": "https://custom.com/dashboard"}})
        mock_http.post = AsyncMock(return_value=mock_resp)

        success, detail = await step._try_login("admin", "password")

        assert success is True
        assert "custom.com" in detail

    async def test_200_no_login_error_is_success(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(**{"status_code": 200, "text": "Welcome to WordPress"})
        mock_http.post = AsyncMock(return_value=mock_resp)

        success, detail = await step._try_login("admin", "password")

        assert success is True
        assert detail == "no_error_in_response"

    async def test_200_with_login_error_is_failure(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(**{"status_code": 200, "text": '<div id="login_error">Error</div>'})
        mock_http.post = AsyncMock(return_value=mock_resp)

        success, detail = await step._try_login("admin", "password")

        assert success is False
        assert detail == ""

    async def test_exception_returns_failure(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.post = AsyncMock(side_effect=Exception("Connection error"))

        success, detail = await step._try_login("admin", "password")

        assert success is False
        assert detail == ""


class TestRunWithCredentials:
    """Tests for run method with various credential outcomes."""

    async def test_valid_credentials_found(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "password")]
        )
        step._try_login = AsyncMock(return_value=(True, "redirect_to_wp_admin"))

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "access"
        assert f.step == "login_bruteforce"
        assert f.severity == "high"
        assert "Valid" in f.title
        assert "admin" in f.evidence
        assert "password" in f.evidence
        assert len(f.raw["valid_credentials"]) == 1

    async def test_multiple_valid_credentials(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "password"), ("user", "pass123")]
        )
        step._try_login = AsyncMock(return_value=(True, "redirect_to_wp_admin"))

        findings = await step.run()

        assert len(findings) == 1
        assert len(findings[0].raw["valid_credentials"]) == 2

    async def test_no_valid_credentials(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "password")]
        )
        step._try_login = AsyncMock(return_value=(False, ""))

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "info"
        assert "no valid credentials" in f.title.lower()

    async def test_empty_credentials_list_returns_no_findings(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        step.resolve_credentials_with_fallback = MagicMock(return_value=None)

        findings = await step.run()

        assert findings == []


class TestRunRateLimiting:
    """Tests that SLEEP_BETWEEN_ATTEMPTS introduces delay between attempts."""

    async def test_sleep_called_between_attempts(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("a", "1"), ("b", "2")]
        )
        step._try_login = AsyncMock(return_value=(False, ""))

        with patch("steps.access.login_bruteforce_step.asyncio.sleep", AsyncMock()) as mock_sleep:
            await step.run()

        mock_sleep.assert_called_once_with(1.5)

    async def test_no_sleep_for_single_attempt(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "password")]
        )
        step._try_login = AsyncMock(return_value=(False, ""))

        with patch("steps.access.login_bruteforce_step.asyncio.sleep", AsyncMock()) as mock_sleep:
            await step.run()

        mock_sleep.assert_not_called()


class TestCredentialFallback:
    """Tests for credential fallback resolution."""

    async def test_uses_default_fallback_when_not_configured(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        creds = step.resolve_credentials_with_fallback(config_key="login_wordlist")

        assert creds is not None
        assert len(creds) > 0
        assert all(isinstance(c, tuple) and len(c) == 2 for c in creds)

    async def test_credentials_from_config_wordlist(self, mock_http, mock_target, mock_config):
        from steps.access.login_bruteforce_step import LoginBruteforceStep
        step = LoginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)

        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=[("custom", "creds")]
        )

        creds = step.resolve_credentials_with_fallback(config_key="login_wordlist")
        assert creds == [("custom", "creds")]
