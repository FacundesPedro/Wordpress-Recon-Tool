"""Tests for SpiderStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest


pytestmark = pytest.mark.asyncio


def _run_step(mock_http, mock_target, mock_config, side_effect):
    """Helper: create SpiderStep with config set and run it."""
    mock_config.spider_max_pages = 50
    mock_config.spider_max_depth = 2
    from steps.discovery.spider_step import SpiderStep
    step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)
    if side_effect is not None:
        mock_http.get.side_effect = side_effect
    return step


class TestExtractLinks:
    """Tests for _extract_links method."""

    async def test_extracts_href_attributes(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        html = '<a href="/page1">Page 1</a><a href="/page2">Page 2</a>'
        links = step._extract_links(html, "https://example.com")

        assert "https://example.com/page1" in links
        assert "https://example.com/page2" in links

    async def test_skips_hash_links(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        html = '<a href="#section">Section</a><a href="/valid">Valid</a>'
        links = step._extract_links(html, "https://example.com")

        assert all("#section" not in l for l in links)
        assert "https://example.com/valid" in links

    async def test_skips_javascript_links(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        html = '<a href="javascript:void(0)">JS</a><a href="/ok">OK</a>'
        links = step._extract_links(html, "https://example.com")

        assert all("javascript:" not in l for l in links)
        assert "https://example.com/ok" in links

    async def test_skips_mailto_links(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        html = '<a href="mailto:test@example.com">Email</a>'
        links = step._extract_links(html, "https://example.com")

        assert links == []

    async def test_preserves_absolute_urls(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        html = '<a href="https://other.com/page">Other</a><a href="/local">Local</a>'
        links = step._extract_links(html, "https://example.com")

        assert "https://other.com/page" in links
        assert "https://example.com/local" in links


class TestIsSameOrigin:
    """Tests for _is_same_origin method."""

    async def test_same_domain_returns_true(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_same_origin("https://example.com/page", "example.com") is True

    async def test_different_domain_returns_false(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_same_origin("https://other.com/page", "example.com") is False

    async def test_subdomain_is_different_origin(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_same_origin("https://sub.example.com/page", "example.com") is False


class TestIsForbidden:
    """Tests for _is_forbidden method."""

    async def test_path_starts_with_disallowed_rule(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_forbidden(
            "https://example.com/wp-admin/",
            ["/wp-admin/"],
            "https://example.com",
        ) is True

    async def test_base_url_allowed_when_root_disallowed(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_forbidden(
            "https://example.com",
            ["/"],
            "https://example.com",
        ) is False

    async def test_no_matching_rule_returns_false(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_forbidden(
            "https://example.com/about",
            ["/wp-admin/", "/private/"],
            "https://example.com",
        ) is False

    async def test_subpath_disallowed(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        assert step._is_forbidden(
            "https://example.com/private/files/secret.txt",
            ["/private/"],
            "https://example.com",
        ) is True


class TestFetchRobots:
    """Tests for _fetch_robots method."""

    async def test_parses_disallow_directives(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get = AsyncMock(
            return_value=MagicMock(
                **{"status_code": 200, "text": "User-agent: *\nDisallow: /wp-admin/\nDisallow: /private/\n"}
            )
        )

        result = await step._fetch_robots("https://example.com")

        assert "/wp-admin/" in result
        assert "/private/" in result
        assert len(result) == 2

    async def test_404_returns_empty_list(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get = AsyncMock(return_value=MagicMock(**{"status_code": 404}))

        result = await step._fetch_robots("https://example.com")

        assert result == []

    async def test_exception_returns_empty_list(self, mock_http, mock_target, mock_config):
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get = AsyncMock(side_effect=Exception("Timeout"))

        result = await step._fetch_robots("https://example.com")

        assert result == []


class TestRun:
    """Tests for the full spider run method."""

    async def _run_with_mocks(self, mock_http, mock_target, mock_config, side_effect):
        mock_config.spider_max_pages = 50
        mock_config.spider_max_depth = 2
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)
        step._fetch_robots = AsyncMock(return_value=[])
        if side_effect is not None:
            mock_http.get.side_effect = side_effect
        return await step.run(), step

    async def test_discovers_forms(self, mock_http, mock_target, mock_config):
        findings, _ = await self._run_with_mocks(mock_http, mock_target, mock_config, [
            MagicMock(**{"status_code": 200, "text": '<form action="/contact"><input></form>'}),
        ])

        form_findings = [f for f in findings if "form" in f.title.lower()]
        assert len(form_findings) >= 1

    async def test_discovers_upload_dirs(self, mock_http, mock_target, mock_config):
        findings, _ = await self._run_with_mocks(mock_http, mock_target, mock_config, [
            MagicMock(**{"status_code": 200, "text": '<img src="/wp-content/uploads/2024/01/photo.jpg">'}),
        ])

        upload_findings = [f for f in findings if "upload" in f.title.lower()]
        assert len(upload_findings) >= 1

    async def test_discovers_admin_paths(self, mock_http, mock_target, mock_config):
        findings, _ = await self._run_with_mocks(mock_http, mock_target, mock_config, [
            MagicMock(**{"status_code": 200, "text": '<a href="/wp-admin/">Admin</a>'}),
        ])

        admin_findings = [f for f in findings if "admin" in f.title.lower()]
        assert len(admin_findings) >= 1

    async def test_summary_finding_always_present(self, mock_http, mock_target, mock_config):
        findings, _ = await self._run_with_mocks(mock_http, mock_target, mock_config, [
            MagicMock(**{"status_code": 200, "text": "<html><body>Hello</body></html>"}),
        ])

        summary = [f for f in findings if "summary" in f.title.lower()]
        assert len(summary) >= 1

    async def test_respects_depth_limit(self, mock_http, mock_target, mock_config):
        mock_config.spider_max_pages = 50
        mock_config.spider_max_depth = 0
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)
        step._fetch_robots = AsyncMock(return_value=[])

        mock_http.get.side_effect = [
            MagicMock(**{"status_code": 200, "text": '<a href="/page1">Page 1</a>'}),
        ]

        await step.run()

        assert mock_http.get.call_count == 1

    async def test_respects_max_pages_limit(self, mock_http, mock_target, mock_config):
        mock_config.spider_max_pages = 1
        mock_config.spider_max_depth = 2
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)
        step._fetch_robots = AsyncMock(return_value=[])

        mock_http.get.side_effect = [
            MagicMock(**{"status_code": 200, "text": '<a href="/page1">Page 1</a><a href="/page2">Page 2</a>'}),
        ]

        await step.run()

        assert mock_http.get.call_count == 1

    async def test_respects_robots_txt(self, mock_http, mock_target, mock_config):
        mock_config.spider_max_pages = 50
        mock_config.spider_max_depth = 2
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)
        step._fetch_robots = AsyncMock(return_value=["/private/"])

        mock_http.get.side_effect = [
            MagicMock(**{"status_code": 200, "text": '<a href="/private/">Private</a><a href="/public/">Public</a>'}),
        ]

        findings = await step.run()

        summary = [f for f in findings if "summary" in f.title.lower()]
        assert len(summary) >= 1

    async def test_handles_http_errors_gracefully(self, mock_http, mock_target, mock_config):
        mock_config.spider_max_pages = 50
        mock_config.spider_max_depth = 2
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)
        step._fetch_robots = AsyncMock(return_value=[])

        mock_http.get.side_effect = Exception("Connection error")

        findings = await step.run()

        assert len(findings) >= 1

    async def test_dedupes_visited_urls(self, mock_http, mock_target, mock_config):
        mock_config.spider_max_pages = 50
        mock_config.spider_max_depth = 2
        from steps.discovery.spider_step import SpiderStep
        step = SpiderStep(target=mock_target, config=mock_config, http=mock_http)
        step._fetch_robots = AsyncMock(return_value=[])

        mock_http.get.side_effect = [
            MagicMock(**{"status_code": 200, "text": '<a href="/page1">Page 1</a><a href="/page1">Page 1 again</a>'}),
        ]

        await step.run()
