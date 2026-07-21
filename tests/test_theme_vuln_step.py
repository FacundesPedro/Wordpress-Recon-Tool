"""Tests for ThemeVulnStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.vulndb import CveFinding


pytestmark = pytest.mark.asyncio


class TestDetectThemes:
    """Tests for _detect_themes internal method."""

    async def test_auth_detection_returns_themes_with_versions(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        data = [
            {"stylesheet": "twentytwentyfour", "status": "active", "version": "1.1"},
            {"stylesheet": "twentytwentythree", "status": "inactive", "version": "1.4"},
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=data))
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.vuln.theme_vuln_step import ThemeVulnStep
        step = ThemeVulnStep(target=mock_target, config=mock_config, http=mock_http)

        themes = await step._detect_themes()

        assert themes == [("twentytwentyfour", "1.1"), ("twentytwentythree", "1.4")]

    async def test_passive_detection_fallback(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""
        mock_resp = MagicMock(
            status_code=200,
            text=(
                '<link href="/wp-content/themes/twentytwentyfour/style.css" />'
                '<script src="/wp-content/themes/twentytwentythree/script.js"></script>'
            ),
        )
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.vuln.theme_vuln_step import ThemeVulnStep
        step = ThemeVulnStep(target=mock_target, config=mock_config, http=mock_http)

        themes = await step._detect_themes()

        assert ("twentytwentyfour", None) in themes
        assert ("twentytwentythree", None) in themes

    async def test_passive_returns_empty_on_http_error(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""
        mock_http.get = AsyncMock(side_effect=Exception("Connection error"))

        from steps.vuln.theme_vuln_step import ThemeVulnStep
        step = ThemeVulnStep(target=mock_target, config=mock_config, http=mock_http)

        themes = await step._detect_themes()

        assert themes == []


class TestRunWithVulnDB:
    """Tests for run() with mocked detection and VulnDB."""

    async def test_no_themes_detected_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.vuln.theme_vuln_step import ThemeVulnStep

        with patch("steps.vuln.theme_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_theme_vulns = AsyncMock(return_value=[])
            instance.close = AsyncMock()

            step = ThemeVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_themes = AsyncMock(return_value=[])

            findings = await step.run()

        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "0 theme" in findings[0].description

    async def test_themes_without_vulns_creates_info_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.vuln.theme_vuln_step import ThemeVulnStep

        with patch("steps.vuln.theme_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_theme_vulns = AsyncMock(return_value=[])
            instance.close = AsyncMock()

            step = ThemeVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_themes = AsyncMock(return_value=[("twentytwentyfour", "1.1")])

            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "info"
        assert "No theme CVEs found" in f.title

    async def test_themes_with_cves_creates_findings(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        mock_vulns = [
            CveFinding(id="CVE-2024-0010", title="XSS vuln", description="XSS in theme", cvss_score=6.5, severity="medium", fixed_in="2.0.0", source="wpvulndb"),
            CveFinding(id="CVE-2024-0011", title="Auth bypass", description="Auth bypass", cvss_score=8.8, severity="high", fixed_in="2.0.0", source="wpvulndb"),
        ]

        from steps.vuln.theme_vuln_step import ThemeVulnStep

        with patch("steps.vuln.theme_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_theme_vulns = AsyncMock(return_value=mock_vulns)
            instance.close = AsyncMock()

            step = ThemeVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_themes = AsyncMock(return_value=[("test-theme", "1.0.0")])

            findings = await step.run()

        assert len(findings) == 2

        medium = [f for f in findings if f.severity == "medium"]
        high = [f for f in findings if f.severity == "high"]
        assert len(medium) == 1
        assert len(high) == 1
        assert "CVE-2024-0010" in medium[0].evidence
        assert "CVE-2024-0011" in high[0].evidence

    async def test_vuln_finding_evidence_format(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        mock_vulns = [
            CveFinding(id="CVE-2024-0012", title="Test vuln", description="Low vuln", cvss_score=4.0, severity="low", fixed_in="3.0.0", source="wpscan"),
        ]

        from steps.vuln.theme_vuln_step import ThemeVulnStep

        with patch("steps.vuln.theme_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_theme_vulns = AsyncMock(return_value=mock_vulns)
            instance.close = AsyncMock()

            step = ThemeVulnStep(target=mock_target, config=mock_config, http=mock_http)
            step._detect_themes = AsyncMock(return_value=[("my-theme", "1.5.0")])

            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "low"
        assert f.module == "vuln"
        assert "my-theme" in f.title
        assert f.raw["theme"] == "my-theme"
        assert f.raw["version"] == "1.5.0"
        assert f.raw["cve"]["id"] == "CVE-2024-0012"
