"""Tests for ThemeBruteforceStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


class TestThemeBruteforceStep:
    async def test_returns_empty_when_wordlist_none(self, mock_target, mock_config):
        mock_http = MagicMock()

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(ThemeBruteforceStep, "resolve_wordlist_or_fallback", return_value=None):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_found_theme_with_version(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe astra/
            MagicMock(status_code=200, text="Theme Name: Astra\nVersion: 4.0.0"),  # style.css
        ])

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["astra"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "Themes discovered via brute-force"
        assert findings[0].module == "discovery"
        assert findings[0].severity == "info"
        assert "astra" in findings[0].evidence
        assert "4.0.0" in findings[0].evidence

    async def test_found_theme_without_version(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe astra/
            MagicMock(status_code=200, text="Theme Name: Astra\nDescription: A fast theme"),  # no version
        ])

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["astra"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "astra" in findings[0].evidence

    async def test_theme_not_found(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["nonexistent"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 0

    async def test_mixed_results(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe astra/
            MagicMock(status_code=200, text="Version: 4.0.0"),  # style.css
            MagicMock(status_code=404),  # probe nonexistent/
        ])

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["astra", "nonexistent"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "astra" in findings[0].evidence

    async def test_style_css_not_found_returns_no_version(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe astra/
            MagicMock(status_code=404),  # style.css not found
        ])

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["astra"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "astra" in findings[0].evidence

    async def test_error_during_probe_skips_slug(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            Exception("connection error"),  # probe astra/ errors
            MagicMock(status_code=200),  # probe kadence/
            MagicMock(status_code=200, text="Version: 1.0.0"),  # style.css
        ])

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["astra", "kadence"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "kadence" in findings[0].evidence
        assert "astra" not in findings[0].evidence
