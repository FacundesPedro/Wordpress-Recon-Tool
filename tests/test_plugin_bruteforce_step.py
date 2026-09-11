"""Tests for PluginBruteforceStep."""

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


class TestPluginBruteforceStep:
    async def test_returns_empty_when_wordlist_none(self, mock_target, mock_config):
        mock_http = MagicMock()
        mock_http.unreachable = False

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(PluginBruteforceStep, "resolve_wordlist_or_fallback", return_value=None):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_found_plugin_with_version(self, mock_target, mock_config):
        mock_http = make_http({
            "/wp-content/plugins/akismet/": MagicMock(status_code=200),
            "/wp-content/plugins/akismet/readme.txt": MagicMock(
                status_code=200, text="Stable tag: 1.0.0"
            ),
        })

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
        mock_http = make_http({
            "/wp-content/plugins/akismet/": MagicMock(status_code=200),
        })

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
        mock_http = make_http({})

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 0

    async def test_mixed_results(self, mock_target, mock_config):
        mock_http = make_http({
            "/wp-content/plugins/akismet/": MagicMock(status_code=200),
            "/wp-content/plugins/akismet/readme.txt": MagicMock(
                status_code=200, text="Stable tag: 1.0.0"
            ),
        })

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
        mock_http = make_http({
            "/wp-content/plugins/akismet/": Exception("connection error"),
            "/wp-content/plugins/contact-form-7/": MagicMock(status_code=200),
            "/wp-content/plugins/contact-form-7/readme.txt": MagicMock(
                status_code=200, text="Version: 2.0.0"
            ),
        })

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
        mock_http = make_http({
            "/wp-content/plugins/akismet/": MagicMock(status_code=200),
            "/wp-content/plugins/akismet/readme.txt": MagicMock(
                status_code=200, text="Stable tag: 1.0.0"
            ),
        })

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
        mock_http = make_http({
            "/wp-content/plugins/akismet/": MagicMock(status_code=403),
            "/wp-content/plugins/akismet/readme.txt": MagicMock(
                status_code=200, text="Stable tag: 3.0.0"
            ),
        })

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["akismet"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "HTTP 403" in findings[0].evidence

    async def test_max_probes_cap_limits_requests(self, mock_target, mock_config):
        mock_config.bruteforce_max_probes = 2
        mock_http = make_http({})

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["a", "b", "c"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []
        probe_calls = [
            call for call in mock_http.request.call_args_list
            if "/wp-content/plugins/" in call.args[1]
        ]
        assert len(probe_calls) == 2

    async def test_soft404_shell_not_reported(self, mock_target, mock_config):
        shell = "<html><title>Home</title><body>homepage shell</body></html>"

        async def fake_request(method, url, **kwargs):
            return MagicMock(status_code=200, text=shell)

        mock_http = MagicMock()
        mock_http.unreachable = False
        mock_http.request = AsyncMock(side_effect=fake_request)

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["alpha", "beta", "gamma"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_early_abort_when_target_unreachable(self, mock_target, mock_config):
        mock_http = make_http({})
        mock_http.unreachable = True

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["a", "b", "c"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []
        assert mock_http.request.await_count == 0

    async def test_concurrency_probes_all_slugs(self, mock_target, mock_config):
        slugs = [f"plugin-{i}" for i in range(12)]
        routes = {
            f"/wp-content/plugins/{slug}/": MagicMock(status_code=200)
            for slug in slugs
        }
        mock_http = make_http(routes)

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=slugs,
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert mock_http.request.await_count >= len(slugs)
        for slug in slugs:
            assert slug in findings[0].evidence

    async def test_progress_logging(self, mock_target, mock_config):
        mock_http = make_http({})

        from steps.discovery.plugin_bruteforce_step import PluginBruteforceStep

        with patch.object(
            PluginBruteforceStep, "resolve_wordlist_or_fallback",
            return_value=["a", "b", "c"],
        ):
            step = PluginBruteforceStep(target=mock_target, config=mock_config, http=mock_http)
            step.logger = MagicMock()
            await step.run()

        progress_messages = [
            call.args[0]
            for call in step.logger.info.call_args_list
            if "Brute-force progress" in call.args[0]
        ]
        assert progress_messages
        assert "3/3" in progress_messages[-1]
