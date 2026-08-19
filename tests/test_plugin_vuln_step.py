"""Tests for PluginVulnStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.vulndb import CveFinding


pytestmark = pytest.mark.asyncio


class TestDetectPlugins:
    """Tests for _detect_plugins internal method."""

    async def test_auth_detection_returns_plugins_with_versions(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        data = [
            {"plugin": "akismet/akismet.php", "status": "active", "version": "4.3.0"},
            {"plugin": "hello/hello.php", "status": "inactive", "version": "1.7.2"},
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=data))
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.vuln.plugin_vuln_step import PluginVulnStep
        step = PluginVulnStep(target=mock_target, config=mock_config, http=mock_http)

        plugins = await step._detect_plugins()

        assert plugins == [("akismet", "4.3.0"), ("hello", "1.7.2")]

    async def test_passive_detection_fallback(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""
        mock_resp = MagicMock(
            status_code=200,
            text=(
                '<script src="/wp-content/plugins/akismet/akismet.js"></script>'
                '<link href="/wp-content/plugins/contact-form-7/style.css" />'
            ),
        )
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.vuln.plugin_vuln_step import PluginVulnStep
        step = PluginVulnStep(target=mock_target, config=mock_config, http=mock_http)

        plugins = await step._detect_plugins()

        assert ("akismet", None) in plugins
        assert ("contact-form-7", None) in plugins

    async def test_passive_returns_empty_on_http_error(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""
        mock_http.get = AsyncMock(side_effect=Exception("Connection error"))

        from steps.vuln.plugin_vuln_step import PluginVulnStep
        step = PluginVulnStep(target=mock_target, config=mock_config, http=mock_http)

        plugins = await step._detect_plugins()

        assert plugins == []


class TestRunWithVulnDB:
    """Tests for run() with mocked detection and VulnDB."""

    async def test_no_plugins_detected_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.vuln.plugin_vuln_step import PluginVulnStep

        with patch("steps.vuln.plugin_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_plugin_vulns = AsyncMock(return_value=[])
            instance.close = AsyncMock()

            step = PluginVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_plugins = AsyncMock(return_value=[])

            findings = await step.run()

        assert len(findings) == 0

    async def test_plugins_without_vulns_creates_info_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.vuln.plugin_vuln_step import PluginVulnStep

        with patch("steps.vuln.plugin_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_plugin_vulns = AsyncMock(return_value=[])
            instance.close = AsyncMock()

            step = PluginVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_plugins = AsyncMock(return_value=[("akismet", "4.3.0")])

            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "info"
        assert "No plugin CVEs found" in f.title

    async def test_plugins_with_cves_creates_findings(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        mock_vulns = [
            CveFinding(id="CVE-2024-0001", title="XSS vuln", description="XSS in form", cvss_score=7.5, severity="high", fixed_in="4.4.0", source="wpvulndb"),
            CveFinding(id="CVE-2024-0002", title="SQLi vuln", description="SQL injection", cvss_score=9.8, severity="critical", fixed_in="4.4.0", source="wpvulndb"),
        ]

        from steps.vuln.plugin_vuln_step import PluginVulnStep

        with patch("steps.vuln.plugin_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_plugin_vulns = AsyncMock(return_value=mock_vulns)
            instance.close = AsyncMock()

            step = PluginVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_plugins = AsyncMock(return_value=[("akismet", "4.3.0")])

            findings = await step.run()

        assert len(findings) == 2

        high = [f for f in findings if f.severity == "high"]
        critical = [f for f in findings if f.severity == "critical"]
        assert len(high) == 1
        assert len(critical) == 1
        assert "akismet" in high[0].title
        assert "CVE-2024-0001" in high[0].evidence
        assert "CVE-2024-0002" in critical[0].evidence

    async def test_vuln_finding_evidence_format(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        mock_vulns = [
            CveFinding(id="CVE-2024-0001", title="Test vuln", description="Medium vuln", cvss_score=5.5, severity="medium", fixed_in="2.0.0", source="wpscan"),
        ]

        from steps.vuln.plugin_vuln_step import PluginVulnStep

        with patch("steps.vuln.plugin_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_plugin_vulns = AsyncMock(return_value=mock_vulns)
            instance.close = AsyncMock()

            step = PluginVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_plugins = AsyncMock(return_value=[("test-plugin", "1.0.0")])

            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "medium"
        assert f.module == "vuln"
        assert "test-plugin" in f.title
        assert f.raw["plugin"] == "test-plugin"
        assert f.raw["version"] == "1.0.0"
        assert f.raw["cve"]["id"] == "CVE-2024-0001"
