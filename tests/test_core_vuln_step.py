"""Tests for CoreVulnStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.vulndb import CveFinding


pytestmark = pytest.mark.asyncio


class TestDetectCoreVersion:
    """Tests for _detect_core_version internal method."""

    async def test_version_from_generator_meta(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            text='<meta name="generator" content="WordPress 6.4.2" />',
        )
        mock_http.get = AsyncMock(return_value=mock_resp)

        from steps.vuln.core_vuln_step import CoreVulnStep
        step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)

        version = await step._detect_core_version()

        assert version == "6.4.2"

    async def test_version_from_readme_html_fallback(self, mock_http, mock_target, mock_config):
        responses = [
            MagicMock(status_code=200, text="<html>No generator meta</html>"),
            MagicMock(status_code=200, text="WordPress 6.3.1"),
        ]
        mock_http.get = AsyncMock(side_effect=responses)

        from steps.vuln.core_vuln_step import CoreVulnStep
        step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)

        version = await step._detect_core_version()

        assert version == "6.3.1"

    async def test_no_version_found_returns_none(self, mock_http, mock_target, mock_config):
        responses = [
            MagicMock(status_code=200, text="<html>No version info</html>"),
            MagicMock(status_code=200, text="<html>Still no version</html>"),
        ]
        mock_http.get = AsyncMock(side_effect=responses)

        from steps.vuln.core_vuln_step import CoreVulnStep
        step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)

        version = await step._detect_core_version()

        assert version is None

    async def test_http_error_returns_none(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("Connection error"))

        from steps.vuln.core_vuln_step import CoreVulnStep
        step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)

        version = await step._detect_core_version()

        assert version is None

    async def test_readme_http_error_returns_none(self, mock_http, mock_target, mock_config):
        responses = [
            MagicMock(status_code=200, text="<html>No version</html>"),
            MagicMock(status_code=404),
        ]
        mock_http.get = AsyncMock(side_effect=responses)

        from steps.vuln.core_vuln_step import CoreVulnStep
        step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)

        version = await step._detect_core_version()

        assert version is None


class TestRunNoVersion:
    """Tests for run() when version is not detected."""

    async def test_returns_empty_when_version_not_detected(self, mock_http, mock_target, mock_config):
        responses = [
            MagicMock(status_code=200, text="<html>No version</html>"),
            MagicMock(status_code=200, text="<html>Still none</html>"),
        ]
        mock_http.get = AsyncMock(side_effect=responses)

        from steps.vuln.core_vuln_step import CoreVulnStep
        step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []


class TestRunWithVulnDB:
    """Tests for run() with mocked VulnDB."""

    async def test_no_vulns_creates_info_finding(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text='<meta name="generator" content="WordPress 6.4.2" />',
            )
        )

        from steps.vuln.core_vuln_step import CoreVulnStep

        with patch("steps.vuln.core_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_core_vulns = AsyncMock(return_value=[])
            instance.close = AsyncMock()

            step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "info"
        assert "No known CVEs" in f.title
        assert f.raw["version"] == "6.4.2"
        assert f.raw["total_cves"] == 0

    async def test_vulns_grouped_by_severity(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text='<meta name="generator" content="WordPress 6.4.2" />',
            )
        )

        mock_vulns = [
            CveFinding(id="CVE-2024-0001", title="Critical vuln", description="Critical RCE", cvss_score=9.8, severity="critical", fixed_in="6.5.0", source="wpvulndb"),
            CveFinding(id="CVE-2024-0002", title="Critical vuln 2", description="Critical SQLi", cvss_score=9.1, severity="critical", fixed_in="6.5.0", source="wpvulndb"),
            CveFinding(id="CVE-2024-0003", title="Medium vuln", description="Medium XSS", cvss_score=5.5, severity="medium", fixed_in="6.4.3", source="wpvulndb"),
        ]

        from steps.vuln.core_vuln_step import CoreVulnStep

        with patch("steps.vuln.core_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_core_vulns = AsyncMock(return_value=mock_vulns)
            instance.close = AsyncMock()

            step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 2

        critical = [f for f in findings if f.severity == "critical"]
        medium = [f for f in findings if f.severity == "medium"]
        assert len(critical) == 1
        assert len(medium) == 1
        assert "2" in critical[0].title
        assert "1" in medium[0].title

    async def test_vuln_finding_structure(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text='<meta name="generator" content="WordPress 6.4.2" />',
            )
        )

        mock_vulns = [
            CveFinding(id="CVE-2024-0001", title="Test vuln", description="Test description", cvss_score=7.5, severity="high", fixed_in="6.5.0", source="wpvulndb"),
        ]

        from steps.vuln.core_vuln_step import CoreVulnStep

        with patch("steps.vuln.core_vuln_step.VulnDB") as mock_vulndb_cls:
            instance = mock_vulndb_cls.return_value
            instance.get_core_vulns = AsyncMock(return_value=mock_vulns)
            instance.close = AsyncMock()

            step = CoreVulnStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "high"
        assert f.module == "vuln"
        assert "6.4.2" in f.title
        assert "CVE-2024-0001" in f.evidence
        assert "CVSS: 7.5" in f.evidence
        assert "6.5.0" in f.evidence
        assert f.raw["version"] == "6.4.2"
        assert len(f.raw["cves"]) == 1
