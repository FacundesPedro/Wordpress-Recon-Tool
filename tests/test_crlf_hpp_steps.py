"""Tests for CrlfInjectionStep and HttpParameterPollutionStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.crlf_injection_step import CrlfInjectionStep
from steps.active.http_parameter_pollution_step import HttpParameterPollutionStep


class TestCrlfInjectionStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 50
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return CrlfInjectionStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_header_injection_detected(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "%0d%0a" in url or "%0a" in url:
                return MagicMock(status_code=200,
                                 headers={"X-Canary-Probe": "crlf7q4"},
                                 text="ok")
            return MagicMock(status_code=200, text='<a href="/s?q=1">l</a>')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("CRLF" in f.title for f in findings)

    async def test_no_injection(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, headers={}, text="ok")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []


class TestHttpParameterPollutionStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 50
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return HttpParameterPollutionStep(
            target=mock_target, config=mock_config, http=mock_http
        )

    async def test_status_diff_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "id=1&id=2" in url:
                return MagicMock(status_code=500, text="x" * 100)
            return MagicMock(status_code=200, text='<a href="/s?id=1">l</a>')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Duplicate-parameter" in f.title for f in findings)

    async def test_same_behavior_clean(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text='<a href="/s?id=1">l</a>')
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
