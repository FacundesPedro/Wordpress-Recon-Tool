"""Tests for WpCronStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestWpCronStep:
    async def test_active_when_200(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=200, text=""))

        from steps.discovery.wp_cron_step import WpCronStep

        step = WpCronStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "wp-cron.php is active"
        assert findings[0].severity == "low"
        assert findings[0].module == "discovery"

    async def test_not_active_when_404(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.discovery.wp_cron_step import WpCronStep

        step = WpCronStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_active_when_403(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=403))

        from steps.discovery.wp_cron_step import WpCronStep

        step = WpCronStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.discovery.wp_cron_step import WpCronStep

        step = WpCronStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_soft404_shell_not_reported(self, mock_http, mock_target, mock_config):
        shell = (
            "<!doctype html><html><head><title>App</title></head>"
            "<body>" + "x" * 500 + "</body></html>"
        )
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=shell)
        )
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text=shell)
        )

        from steps.discovery.wp_cron_step import WpCronStep

        step = WpCronStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []
