"""Tests for WpJsonThemesStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest


pytestmark = pytest.mark.asyncio


MOCK_THEMES = [
    {
        "stylesheet": "twentytwentyfour",
        "name": "Twenty Twenty-Four",
        "status": "active",
        "version": "1.1",
        "author": {"name": "WordPress Team"},
    },
    {
        "stylesheet": "twentytwentythree",
        "name": "Twenty Twenty-Three",
        "status": "inactive",
        "version": "1.4",
        "author": {"name": "WordPress Team"},
    },
]


class TestRunSkip:
    """Tests that run() returns early when auth is not configured."""

    async def test_returns_empty_when_no_auth(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_returns_empty_when_http_error(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_http.request = AsyncMock(side_effect=Exception("Connection error"))

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "access"
        assert f.severity == "low"
        assert "unavailable" in f.title.lower()


class TestSuccessfulResponse:
    """Tests for 200 response with theme data."""

    async def test_theme_inventory_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=MOCK_THEMES))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert len(findings) >= 1
        inventory = [f for f in findings if f.severity == "info"][0]
        assert inventory.module == "access"
        assert "Theme Inventory" in inventory.title
        assert inventory.raw["total"] == 2

    async def test_inactive_themes_separate_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=MOCK_THEMES))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        inactive = [f for f in findings if f.severity == "medium"]
        assert len(inactive) == 1
        assert "Inactive" in inactive[0].title
        assert "Twenty Twenty-Three" in inactive[0].evidence

    async def test_empty_theme_list_returns_no_extra_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=[]))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_non_list_response_no_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value={}))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

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

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []


class TestAuthorFieldEdgeCases:
    """Tests for author field being dict, string, or missing."""

    async def test_author_as_dict(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        themes = [
            {
                "stylesheet": "test-theme",
                "name": "Test Theme",
                "status": "active",
                "version": "1.0",
                "author": {"name": "Author Name"},
            },
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=themes))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert len(findings) >= 1
        theme_data = findings[0].raw["themes"][0]
        assert theme_data["author"] == "Author Name"

    async def test_author_as_string(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        themes = [
            {
                "stylesheet": "test-theme",
                "name": "Test Theme",
                "status": "active",
                "version": "1.0",
                "author": "Direct Author String",
            },
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=themes))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        theme_data = findings[0].raw["themes"][0]
        assert theme_data["author"] == "Direct Author String"

    async def test_missing_author_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        themes = [
            {
                "stylesheet": "test-theme",
                "name": "Test Theme",
                "status": "active",
                "version": "1.0",
            },
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=themes))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        theme_data = findings[0].raw["themes"][0]
        assert theme_data["author"] == ""


class TestStatusCodeHandling:
    """Tests for non-200 status code responses."""

    async def test_401_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=401)
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_404_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=404)
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.themes_step import WpJsonThemesStep
        step = WpJsonThemesStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []
