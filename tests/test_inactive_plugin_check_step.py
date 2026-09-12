"""Tests for InactivePluginCheckStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest


pytestmark = pytest.mark.asyncio


MOCK_PLUGINS_DATA = [
    {"plugin": "akismet/akismet.php", "status": "active"},
    {"plugin": "hello/hello.php", "status": "inactive"},
    {"plugin": "old-plugin/old.php", "status": "inactive"},
]


class TestRunSkip:
    """Tests that run() returns early when conditions are not met."""

    async def test_returns_empty_when_no_auth(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_returns_empty_when_get_inactive_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)
        step._get_inactive_plugins = AsyncMock(return_value=[])

        findings = await step.run()

        assert findings == []


class TestInactivePluginResults:
    """Tests for run() with various accessibility outcomes."""

    async def test_accessible_plugins_creates_medium_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)
        step._get_inactive_plugins = AsyncMock(return_value=["hello", "old-plugin"])
        step._is_readable = AsyncMock(side_effect=[True, False])

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "medium"
        assert f.module == "access"
        assert "accessible" in f.title.lower()
        assert "hello" in f.evidence
        assert "old-plugin" not in f.evidence
        assert f.raw["accessible"] == ["hello"]
        assert f.raw["protected"] == ["old-plugin"]

    async def test_no_accessible_plugins_creates_info_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)
        step._get_inactive_plugins = AsyncMock(return_value=["hello"])
        step._is_readable = AsyncMock(return_value=False)

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "info"
        assert "not accessible" in f.title.lower()


class TestGetInactivePlugins:
    """Tests for _get_inactive_plugins internal method."""

    async def test_extracts_inactive_slugs_from_response(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=MOCK_PLUGINS_DATA))
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        results = await step._get_inactive_plugins({"Authorization": "Basic test"})

        assert results == ["hello", "old-plugin"]

    async def test_non_200_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=403)
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        results = await step._get_inactive_plugins({"Authorization": "Basic test"})

        assert results == []

    async def test_non_list_response_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value={}))
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        results = await step._get_inactive_plugins({"Authorization": "Basic test"})

        assert results == []

    async def test_exception_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_http.get = AsyncMock(side_effect=Exception("Connection error"))

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        results = await step._get_inactive_plugins({"Authorization": "Basic test"})

        assert results == []

    async def test_active_plugins_excluded(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        data = [
            {"plugin": "active/plugin.php", "status": "active"},
            {"plugin": "other/plugin.php", "status": "active"},
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=data))
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        results = await step._get_inactive_plugins({"Authorization": "Basic test"})

        assert results == []

    async def test_plugin_without_slash_uses_full_slug(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        data = [{"plugin": "simple", "status": "inactive"}]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=data))
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        results = await step._get_inactive_plugins({"Authorization": "Basic test"})

        assert results == ["simple"]


class TestIsReadable:
    """Tests for _is_readable internal method."""

    async def test_200_returns_true(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            text="=== Test Plugin ===\nStable tag: 1.0\n",
        )
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        result = await step._is_readable("test-plugin")

        assert result is True

    async def test_non_200_returns_false(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(status_code=404)
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        result = await step._is_readable("test-plugin")

        assert result is False

    async def test_exception_returns_false(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("Connection error"))

        from steps.access.inactive_plugin_check_step import InactivePluginCheckStep
        step = InactivePluginCheckStep(target=mock_target, config=mock_config, http=mock_http)

        result = await step._is_readable("test-plugin")

        assert result is False
