"""Tests for PluginBruteforceStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


class TestPluginBruteforceStep:
    async def test_returns_empty_when_wordlist_none(self, mock_target, mock_config):
        mock_http = MagicMock()

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(PluginBruteforceStep, "resolve_wordlist_or_fallback", return_value=None):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_found_plugin_with_version(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe akismet/
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),  # readme.txt
        ])

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "Plugins discovered via brute-force"
        assert findings[0].module == "discovery"
        assert findings[0].severity == "info"
        assert "akismet" in findings[0].evidence
        assert "1.0.0" in findings[0].evidence

    async def test_found_plugin_without_version(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe akismet/
            MagicMock(status_code=404),  # readme.txt not found
            MagicMock(status_code=404),  # readme.md not found
        ])

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "akismet" in findings[0].evidence
        assert "unknown" in findings[0].evidence.lower() or "v" not in findings[0].evidence

    async def test_plugin_not_found(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 0

    async def test_mixed_results(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe akismet/
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),  # readme.txt
            MagicMock(status_code=404),  # probe nonexistent/
        ])

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet", "nonexistent"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "akismet" in findings[0].evidence
        assert "nonexistent" not in findings[0].evidence

    async def test_error_during_probe_skips_slug(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            Exception("connection error"),  # probe akismet/ errors
            MagicMock(status_code=200),  # probe contact-form-7/
            MagicMock(status_code=200, text="Version: 2.0.0"),  # readme.txt
        ])

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet", "contact-form-7"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "contact-form-7" in findings[0].evidence
        assert "akismet" not in findings[0].evidence

    async def test_skips_blank_and_comment_lines(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200),  # probe akismet/
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),  # readme.txt
        ])

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["", "akismet", "# comment"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "akismet" in findings[0].evidence

    async def test_403_also_counts_as_found(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=403),  # probe akismet/ - forbidden=exists
            MagicMock(status_code=200, text="Stable tag: 3.0.0"),  # readme.txt
        ])

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "HTTP 403" in findings[0].evidence
