"""Tests for SstiStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.ssti_step import SstiStep


class TestSstiStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 50
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return SstiStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_ssti_detected(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "{{7*7}}" in url:
                return MagicMock(status_code=200, text="result: 49")
            return MagicMock(status_code=200, text='<a href="/s?q=1">l</a>')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("SSTI" in f.title for f in findings)
        assert findings[0].raw["result"] == "49"

    async def test_49_in_baseline_not_flagged(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            return MagicMock(status_code=200, text='<a href="/s?q=1">49 l</a>')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_no_params(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<p>static</p>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
