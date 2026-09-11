"""Tests for AuthBypassStep, RateLimitStep, PasswordResetStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.auth_bypass_step import AuthBypassStep
from steps.active.rate_limit_step import RateLimitStep
from steps.active.password_reset_step import PasswordResetStep


class TestAuthBypassStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 60
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return AuthBypassStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_no_protected_paths(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="nope")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_path_bypass_detected(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            path = url.replace("https://example.com", "")
            if path in ("/admin", "/admin.php", "/wp-admin/"):
                return MagicMock(status_code=403, text="denied")
            if path == "/admin/.":
                return MagicMock(status_code=200, text="admin content")
            return MagicMock(status_code=404, text="nope")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("path confusion" in f.title.lower() for f in findings)

    async def test_header_bypass_detected(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if headers.get("X-Forwarded-For") == "127.0.0.1":
                return MagicMock(status_code=200, text="admin content")
            return MagicMock(status_code=403, text="denied")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("X-Forwarded-For" in f.title for f in findings)


class TestRateLimitStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 60
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return RateLimitStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_no_rate_limit_reported(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<form>login</form>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("No rate limiting" in f.title for f in findings)

    async def test_429_stops_probe(self, mock_http, mock_target, mock_config):
        count = {"n": 0}

        async def requestor(method, url, **kwargs):
            if method == "POST":
                count["n"] += 1
                if count["n"] >= 3:
                    return MagicMock(status_code=429, text="too many")
                return MagicMock(status_code=200, text="wrong password")
            return MagicMock(status_code=200, text="<form>login</form>")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert not [f for f in findings if "No rate limiting" in f.title]


class TestPasswordResetStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 60
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return PasswordResetStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_no_limit_reported(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<form>reset</form>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("No rate limiting observed on password reset" in f.title
                   for f in findings)

    async def test_host_reflection_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if headers.get("Host") == "reset-canary-7q4.example" and method == "POST":
                return MagicMock(status_code=200,
                                 text="link: https://reset-canary-7q4.example/reset")
            return MagicMock(status_code=200, text="<form>reset</form>")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Host reflected" in f.title for f in findings)

    async def test_no_reset_endpoints(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="nope")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
