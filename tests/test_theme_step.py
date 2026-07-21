"""Tests for ThemeStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestThemeStep:
    async def test_found_themes(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<link href="/wp-content/themes/twentytwentyfour/style.css">'
                    '<script src="/wp-content/themes/astra/script.js"></script>'
                ),
            )
        )

        from steps.fingerprint.theme_step import ThemeStep

        step = ThemeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "WordPress themes detected"
        assert "twentytwentyfour" in findings[0].evidence
        assert "astra" in findings[0].evidence
        assert findings[0].module == "fingerprint"

    async def test_no_themes_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="<html><body>No themes here</body></html>"
            )
        )

        from steps.fingerprint.theme_step import ThemeStep

        step = ThemeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.fingerprint.theme_step import ThemeStep

        step = ThemeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.fingerprint.theme_step import ThemeStep

        step = ThemeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
