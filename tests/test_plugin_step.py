"""Tests for PluginStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestPluginStep:
    async def test_found_plugins(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<script src="/wp-content/plugins/akismet/akismet.js"></script>'
                    '<link href="/wp-content/plugins/contact-form-7/style.css">'
                ),
            )
        )

        from steps.fingerprint.plugin_step import PluginStep

        step = PluginStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "WordPress plugins detected"
        assert "akismet" in findings[0].evidence
        assert "contact-form-7" in findings[0].evidence
        assert findings[0].module == "fingerprint"

    async def test_no_plugins_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="<html><body>No plugins here</body></html>"
            )
        )

        from steps.fingerprint.plugin_step import PluginStep

        step = PluginStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.fingerprint.plugin_step import PluginStep

        step = PluginStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.fingerprint.plugin_step import PluginStep

        step = PluginStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
