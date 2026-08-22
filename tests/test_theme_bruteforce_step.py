"""Tests for ThemeBruteforceStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


def make_request_side_effect(routes):
    """Return a fake request function keyed by URL suffix.

    Args:
        routes: dict mapping URL suffix -> response-like object.

    Returns:
        Async function that returns the matching response or 404.
    """
    async def fake_request(method, url, **kwargs):
        for suffix, response in routes.items():
            if url.endswith(suffix):
                if isinstance(response, Exception):
                    raise response
                return response
        return MagicMock(status_code=404)
    return fake_request


def make_http(routes):
    """Build a mock HttpClient with path-based responses."""
    http = MagicMock()
    http.unreachable = False
    http.request = AsyncMock(side_effect=make_request_side_effect(routes))
    return http


class TestThemeBruteforceStep:
    async def test_returns_empty_when_wordlist_none(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.unreachable = False

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(ThemeBruteforceStep, "resolve_wordlist_or_fallback", return_value=None):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_found_theme_with_version(self, mock_target, mock_config):
        mock_http = make_http({
            "/wp-content/themes/astra/": MagicMock(status_code=200),
            "/wp-content/themes/astra/style.css": MagicMock(
                status_code=200, text="Theme Name: Astra\nVersion: 4.0.0"
            ),
        })

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
        mock_http = make_http({
            "/wp-content/themes/astra/": MagicMock(status_code=200),
            "/wp-content/themes/astra/style.css": MagicMock(
                status_code=200, text="Theme Name: Astra\nDescription: A fast theme"
            ),
        })

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
        mock_http = make_http({})

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["nonexistent"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 0

    async def test_mixed_results(self, mock_target, mock_config):
        mock_http = make_http({
            "/wp-content/themes/astra/": MagicMock(status_code=200),
            "/wp-content/themes/astra/style.css": MagicMock(
                status_code=200, text="Version: 4.0.0"
            ),
        })

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
        mock_http = make_http({
            "/wp-content/themes/astra/": MagicMock(status_code=200),
        })

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
        mock_http = make_http({
            "/wp-content/themes/astra/": Exception("connection error"),
            "/wp-content/themes/kadence/": MagicMock(status_code=200),
            "/wp-content/themes/kadence/style.css": MagicMock(
                status_code=200, text="Version: 1.0.0"
            ),
        })

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

    async def test_max_probes_cap_limits_requests(self, mock_target, mock_config):
        mock_config.bruteforce_max_probes = 2
        mock_http = make_http({})

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["a", "b", "c"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []
        assert mock_http.request.await_count == 2

    async def test_early_abort_when_target_unreachable(self, mock_target, mock_config):
        mock_http = make_http({})
        mock_http.unreachable = True

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["a", "b", "c"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []
        assert mock_http.request.await_count == 0

    async def test_concurrency_probes_all_slugs(self, mock_target, mock_config):
        slugs = [f"theme-{i}" for i in range(12)]
        routes = {
            f"/wp-content/themes/{slug}/": MagicMock(status_code=200)
            for slug in slugs
        }
        mock_http = make_http(routes)

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=slugs,
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert mock_http.request.await_count >= len(slugs)
        for slug in slugs:
            assert slug in findings[0].evidence

    async def test_progress_logging(self, mock_target, mock_config):
        mock_http = make_http({})

        from steps.discovery.theme_bruteforce_step import ThemeBruteforceStep

        with patch.object(
            ThemeBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["a", "b", "c"],
        ):
            step = ThemeBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            step.logger = MagicMock()
            await step.run()

        progress_messages = [
            call.args[0]
            for call in step.logger.info.call_args_list
            if "Brute-force progress" in call.args[0]
        ]
        assert progress_messages
        assert "3/3" in progress_messages[-1]
