"""Tests for WpJsonPluginsStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest


pytestmark = pytest.mark.asyncio


MOCK_PLUGINS = [
    {
        "plugin": "akismet/akismet.php",
        "name": "Akismet Anti-spam",
        "status": "active",
        "version": "4.3.0",
        "description": "Spam protection",
    },
    {
        "plugin": "hello/hello.php",
        "name": "Hello Dolly",
        "status": "inactive",
        "version": "1.7.2",
        "description": "Lyrical experience",
    },
]


class TestRunSkip:
    """Tests that run() returns early when auth is not configured."""

    async def test_returns_empty_when_no_auth(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_returns_empty_when_http_error(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_http.request = AsyncMock(side_effect=Exception("Connection error"))

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "access"
        assert f.severity == "low"
        assert "unavailable" in f.title.lower()


class TestSuccessfulResponse:
    """Tests for 200 response with plugin data."""

    async def test_plugin_inventory_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=MOCK_PLUGINS))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert len(findings) >= 1
        inventory = [f for f in findings if f.severity == "info"][0]
        assert inventory.module == "access"
        assert inventory.severity == "info"
        assert "Plugin Inventory" in inventory.title
        assert inventory.raw["total"] == 2
        assert len(inventory.raw["plugins"]) == 2

    async def test_inactive_plugins_separate_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=MOCK_PLUGINS))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        inactive = [f for f in findings if f.severity == "medium"]
        assert len(inactive) == 1
        assert "Inactive" in inactive[0].title
        assert "Hello Dolly" in inactive[0].evidence

    async def test_empty_plugin_list_returns_no_extra_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=[]))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_non_list_response_no_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value={}))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_parse_error_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(
            status_code=200,
            json=MagicMock(side_effect=ValueError("Invalid JSON")),
        )
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []


class TestStatusCodeHandling:
    """Tests for non-200 status code responses."""

    async def test_401_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=401, json=MagicMock(return_value={}))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_404_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=404)
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []


class TestFormatPluginEvidence:
    """Tests for _format_plugin_evidence helper."""

    async def test_sorts_alphabetically(self, mock_http, mock_target, mock_config):
        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        plugins = [
            {"name": "Zeta", "version": "2.0", "status": "active", "description": ""},
            {"name": "Alpha", "version": "1.0", "status": "inactive", "description": ""},
        ]
        result = step._format_plugin_evidence(plugins)

        lines = result.strip().split("\n")
        assert "Alpha" in lines[0]
        assert "Zeta" in lines[1]

    async def test_status_mark_applied(self, mock_http, mock_target, mock_config):
        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        plugins = [
            {"name": "Test", "version": "1.0", "status": "active", "description": ""},
            {"name": "Inactive", "version": "2.0", "status": "inactive", "description": ""},
        ]
        result = step._format_plugin_evidence(plugins)

        assert "[active]" in result
        assert "[inactive]" in result

    async def test_description_appended_when_present(self, mock_http, mock_target, mock_config):
        from steps.access.plugins_step import WpJsonPluginsStep
        step = WpJsonPluginsStep(target=mock_target, config=mock_config, http=mock_http)

        plugins = [
            {"name": "Test", "version": "1.0", "status": "active", "description": "A test plugin"},
        ]
        result = step._format_plugin_evidence(plugins)

        assert "A test plugin" in result
