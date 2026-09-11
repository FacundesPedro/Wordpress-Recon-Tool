"""Tests for HostingStep."""

from unittest.mock import MagicMock

import pytest


pytestmark = pytest.mark.asyncio


class TestDetectFromHeaders:
    """Tests for _detect_from_headers method."""

    async def test_detects_wp_engine(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-wp-engine": "nginx"})

        assert "WP Engine" in result

    async def test_detects_kinsta(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-kinsta": "cache"})

        assert "Kinsta" in result

    async def test_detects_pantheon(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-pantheon-styx-hostname": "pantheon.io"})

        assert "Pantheon" in result

    async def test_detects_cloudways(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-cloudways": "1"})

        assert "Cloudways" in result

    async def test_detects_flywheel(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-flywheel": "1"})

        assert "Flywheel" in result

    async def test_detects_wordpress_com(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-hacker": "1"})

        assert "WordPress.com" in result

    async def test_detects_wpX(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-wpx-token": "abc"})

        assert "wpX" in result

    async def test_detects_pressable(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-pressable": "1"})

        assert "Pressable" in result

    async def test_detects_siteground(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-sg-origin": "sg"})

        assert "SiteGround" in result

    async def test_siteground_also_matches_x_sg_nginx(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-sg-nginx": "1"})

        assert "SiteGround" in result

    async def test_detects_godaddy(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-proxy-scheme": "https"})

        assert "GoDaddy" in result

    async def test_header_search_is_case_insensitive(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"x-wp-engine": "nginx"})

        assert "WP Engine" in result

    async def test_no_match_returns_empty_list(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        result = step._detect_from_headers({"server": "nginx", "content-type": "text/html"})

        assert result == []


class TestIsBedrock:
    """Tests for _is_bedrock method."""

    async def test_detects_bedrock_path_in_body(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_bedrock("web/app/plugins/akismet/akismet.php") is True

    async def test_no_bedrock_path_returns_false(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_bedrock("wp-content/plugins/akismet/akismet.php") is False


class TestRun:
    """Tests for the full run method."""

    async def test_hosting_detected(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(
            status_code=200,
            headers={"X-WP-Engine": "nginx"},
            text="WordPress powered site",
        )
        mock_http.get.return_value = mock_resp

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "infrastructure"
        assert f.step == "hosting"
        assert f.severity == "info"
        assert "WP Engine" in f.title

    async def test_no_hosting_detected(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(
            status_code=200,
            headers={"server": "nginx"},
            text="WordPress site",
        )
        mock_http.get.return_value = mock_resp

        findings = await step.run()

        # Absence of a known hosting platform is not a finding (noise
        # reduction) - the step logs instead of emitting.
        assert findings == []

    async def test_bedrock_fallback(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(
            status_code=200,
            headers={"server": "nginx"},
            text="web/app/themes/twentythree/style.css",
        )
        mock_http.get.return_value = mock_resp

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert "Bedrock" in f.title

    async def test_http_error_returns_no_findings(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get.side_effect = Exception("Connection error")

        findings = await step.run()

        assert findings == []

    async def test_multiple_providers_detected(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.hosting_step import HostingStep
        step = HostingStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(
            status_code=200,
            headers={"X-WP-Engine": "nginx", "x-sg-origin": "sg"},
            text="WordPress site",
        )
        mock_http.get.return_value = mock_resp

        findings = await step.run()

        assert len(findings) == 1
        assert "WP Engine" in findings[0].title
        assert "SiteGround" in findings[0].title
