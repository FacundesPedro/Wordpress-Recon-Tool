"""Tests for SiteHealthStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


pytestmark = pytest.mark.asyncio


class TestRunSkipConditions:
    """Tests that run() returns early when conditions are not met."""

    async def test_skips_when_no_wp_user(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = "secret"

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_skips_when_no_application_password(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = ""

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_skips_when_http_client_not_initialized(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_http._client = None

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_skips_when_login_fails(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        raw_client = MagicMock()
        mock_http._client = raw_client

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        with patch("core.auth.AdminSession.login", return_value=False):
            findings = await step.run()

        assert findings == []

    async def test_skips_when_http_error_occurs(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        raw_client = MagicMock()
        mock_http._client = raw_client

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        step._parse_site_health = MagicMock()

        with (
            patch("core.auth.AdminSession.login", return_value=True),
            patch("core.auth.AdminSession.get", side_effect=Exception("HTTP error")),
        ):
            findings = await step.run()

        assert findings == []

    async def test_skips_when_not_200(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        raw_client = MagicMock()
        mock_http._client = raw_client

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(status_code=403)
        step._parse_site_health = MagicMock()

        with (
            patch("core.auth.AdminSession.login", return_value=True),
            patch("core.auth.AdminSession.get", return_value=mock_resp),
        ):
            findings = await step.run()

        assert findings == []

    async def test_skips_when_parse_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        raw_client = MagicMock()
        mock_http._client = raw_client

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(status_code=200, text="<html></html>")
        step._parse_site_health = MagicMock(return_value={})

        with (
            patch("core.auth.AdminSession.login", return_value=True),
            patch("core.auth.AdminSession.get", return_value=mock_resp),
        ):
            findings = await step.run()

        assert findings == []


class TestParseSiteHealth:
    """Tests for _parse_site_health method."""

    async def test_parse_var_site_health_pattern(self, mock_http, mock_target, mock_config):
        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        html = '<script>var siteHealth = {"wp-values": {"version": "6.2"}};</script>'
        result = step._parse_site_health(html)

        assert result == {"wp-values": {"version": "6.2"}}

    async def test_parse_wp_data_dispatch_pattern(self, mock_http, mock_target, mock_config):
        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        html = """<script>wp.data.dispatch('core').setSiteHealthData({"server": {"php_version": "8.0"}});</script>"""
        result = step._parse_site_health(html)

        assert result == {"server": {"php_version": "8.0"}}

    async def test_parse_no_match_returns_empty_dict(self, mock_http, mock_target, mock_config):
        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        html = "<html><body>No health data here</body></html>"
        result = step._parse_site_health(html)

        assert result == {}

    async def test_parse_invalid_json_returns_empty_dict(self, mock_http, mock_target, mock_config):
        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        html = '<script>var siteHealth = {invalid json here};</script>'
        result = step._parse_site_health(html)

        assert result == {}


class TestFormatHealthEvidence:
    """Tests for _format_health_evidence method."""

    async def test_formats_wp_values_section(self, mock_http, mock_target, mock_config):
        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        data = {
            "wp-values": {
                "version": "6.2",
                "siteurl": "https://example.com",
                "home": "https://example.com",
                "active_plugins": ["plugin-a", "plugin-b"],
                "active_theme": "twentytwentythree",
            }
        }
        result = step._format_health_evidence(data)

        assert "6.2" in result
        assert "example.com" in result
        assert "twentytwentythree" in result

    async def test_formats_server_section(self, mock_http, mock_target, mock_config):
        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        data = {
            "server": {
                "name": "Apache",
                "php_version": "8.1",
                "php_extensions": ["curl", "json", "mbstring"],
                "document_root": "/var/www/html",
            }
        }
        result = step._format_health_evidence(data)

        assert "Apache" in result
        assert "8.1" in result
        assert "/var/www/html" in result

    async def test_empty_data_returns_empty_string(self, mock_http, mock_target, mock_config):
        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._format_health_evidence({})

        assert result == ""


class TestRunSuccess:
    """Tests for successful site health run."""

    async def test_successful_run_creates_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        raw_client = MagicMock()
        mock_http._client = raw_client

        from steps.access.site_health_step import SiteHealthStep
        step = SiteHealthStep(target=mock_target, config=mock_config, http=mock_http)

        health_data = {"wp-values": {"version": "6.2"}}
        mock_resp = MagicMock(status_code=200, text="<html>siteHealth data</html>")
        step._parse_site_health = MagicMock(return_value=health_data)
        step._format_health_evidence = MagicMock(return_value="Formatted evidence")

        with (
            patch("core.auth.AdminSession.login", return_value=True),
            patch("core.auth.AdminSession.get", return_value=mock_resp),
        ):
            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "access"
        assert f.step == "site_health"
        assert f.severity == "info"
        assert "Site Health" in f.title
        assert f.raw == health_data
