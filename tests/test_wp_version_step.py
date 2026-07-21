"""Tests for WpVersionStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestWpVersionStep:
    async def test_detects_via_meta_generator(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text='<meta name="generator" content="WordPress 6.4.2" />',
            )
        )

        from steps.fingerprint.wp_version_step import WpVersionStep

        step = WpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "6.4.2" in findings[0].title
        assert findings[0].raw["source"] == "meta generator tag"
        assert findings[0].module == "fingerprint"

    async def test_detects_via_theme_css(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<link href="/wp-content/themes/twentytwentyfour/style.css?ver=6.4.2" '
                    'rel="stylesheet" />'
                ),
            )
        )

        from steps.fingerprint.wp_version_step import WpVersionStep

        step = WpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "6.4.2" in findings[0].title
        assert "theme CSS" in findings[0].raw["source"]

    async def test_detects_via_core_js(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<script src="/wp-includes/js/wp-util.js?ver=6.4.2"></script>'
                ),
            )
        )

        from steps.fingerprint.wp_version_step import WpVersionStep

        step = WpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "6.4.2" in findings[0].title
        assert "core JS" in findings[0].raw["source"]

    async def test_detects_via_meta_generator_different_ordering(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<html><head>'
                    '<meta name="generator" content="WordPress 6.4.2" />'
                    '</head></html>'
                ),
            )
        )

        from steps.fingerprint.wp_version_step import WpVersionStep

        step = WpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "6.4.2" in findings[0].title
        assert "meta generator" in findings[0].raw["source"]

    async def test_first_pattern_wins(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<meta name="generator" content="WordPress 6.4.2" />'
                    '<link href="/wp-content/themes/twentytwentyfour/style.css?ver=6.5.0" />'
                ),
            )
        )

        from steps.fingerprint.wp_version_step import WpVersionStep

        step = WpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "6.4.2" in findings[0].title
        assert "meta generator" in findings[0].raw["source"]

    async def test_no_version_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="<html><body>No version here</body></html>"
            )
        )

        from steps.fingerprint.wp_version_step import WpVersionStep

        step = WpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.fingerprint.wp_version_step import WpVersionStep

        step = WpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
