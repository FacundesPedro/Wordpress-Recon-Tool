"""Tests for SitemapStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestSitemapStep:
    async def test_found_with_urls(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<?xml version="1.0"?>'
                    '<urlset><url><loc>https://example.com/page1</loc></url>'
                    '<url><loc>https://example.com/page2</loc></url></urlset>'
                ),
            )
        )

        from steps.discovery.sitemap_step import SitemapStep

        step = SitemapStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "wp-sitemap.xml found"
        assert findings[0].raw["url_count"] == 2
        assert len(findings[0].raw["urls"]) == 2
        assert findings[0].module == "discovery"

    async def test_found_with_no_urls(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text='<?xml version="1.0"?><urlset></urlset>',
            )
        )

        from steps.discovery.sitemap_step import SitemapStep

        step = SitemapStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].raw["url_count"] == 0

    async def test_html_shell_ignored(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="<!doctype html><html><body>homepage</body></html>",
            )
        )

        from steps.discovery.sitemap_step import SitemapStep

        step = SitemapStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_plain_permalink_fallback(self, mock_http, mock_target, mock_config):
        sitemap = (
            '<?xml version="1.0"?>'
            '<urlset><url><loc>https://example.com/page1</loc></url></urlset>'
        )

        async def requestor(url, **kwargs):
            if "sitemap=index" in url:
                return MagicMock(status_code=200, text=sitemap)
            return MagicMock(status_code=200, text="<html>homepage</html>")

        mock_http.get = AsyncMock(side_effect=requestor)

        from steps.discovery.sitemap_step import SitemapStep

        step = SitemapStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "sitemap=index" in findings[0].raw["url"]

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.discovery.sitemap_step import SitemapStep

        step = SitemapStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.discovery.sitemap_step import SitemapStep

        step = SitemapStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
