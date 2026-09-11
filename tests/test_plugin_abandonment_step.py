"""Tests for PluginAbandonmentStep."""

import json
from unittest.mock import AsyncMock, MagicMock

from steps.vuln.plugin_abandonment_step import (
    PluginAbandonmentStep,
    abandonment_issues,
    parse_last_updated,
)
from datetime import datetime, timezone


class TestParseLastUpdated:
    def test_wporg_format(self):
        result = parse_last_updated("2024-01-15 3:20pm")
        assert result and result.year == 2024

    def test_iso_format(self):
        assert parse_last_updated("2024-01-15T10:00:00")

    def test_garbage(self):
        assert parse_last_updated("nonsense") is None
        assert parse_last_updated("") is None


class TestAbandonmentIssues:
    def test_closed_plugin_high(self):
        issues = abandonment_issues({"slug": "x", "closed": 1}, "plugin")
        assert issues and issues[0]["severity"] == "high"

    def test_old_update_medium(self):
        issues = abandonment_issues({"slug": "x", "last_updated": "2020-01-01"}, "plugin")
        assert issues and issues[0]["severity"] == "medium"
        assert "not updated" in issues[0]["title"]

    def test_recent_update_clean(self):
        recent = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert abandonment_issues({"slug": "x", "last_updated": recent}, "plugin") == []


class TestPluginAbandonmentStep:
    def make_step(self, mock_http, mock_target, mock_config):
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""
        return PluginAbandonmentStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_no_components(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html>plain</html>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_closed_plugin_reported(self, mock_http, mock_target, mock_config):
        html = '<link href="/wp-content/plugins/oldplugin/style.css">'
        api_resp = MagicMock(status_code=200)
        api_resp.json.return_value = {"slug": "oldplugin", "closed": 1,
                                      "close_reason": "security"}
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        mock_http.request = AsyncMock(return_value=api_resp)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("closed" in f.title.lower() for f in findings)
        assert any(f.severity == "high" for f in findings)

    async def test_unknown_plugin_skipped(self, mock_http, mock_target, mock_config):
        html = '<link href="/wp-content/plugins/ghostplugin/style.css">'
        api_resp = MagicMock(status_code=200)
        api_resp.json.return_value = {"error": "not found"}
        mock_http.get = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        mock_http.request = AsyncMock(return_value=api_resp)
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
