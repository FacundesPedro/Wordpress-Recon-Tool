"""Tests for ReadmeStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestReadmeStep:
    async def test_found_with_version(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="WordPress is open source software<br/>version 6.4.2",
            )
        )

        from steps.discovery.readme_step import ReadmeStep

        step = ReadmeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "readme.html found"
        assert findings[0].raw["version"] == "6.4.2"
        assert findings[0].module == "discovery"

    async def test_found_without_wordpress_keyword(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="Some random HTML content without the keyword",
            )
        )

        from steps.discovery.readme_step import ReadmeStep

        step = ReadmeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_found_with_wordpress_but_no_version(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="WordPress is open source software",
            )
        )

        from steps.discovery.readme_step import ReadmeStep

        step = ReadmeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].raw["version"] == "Unknown"

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.discovery.readme_step import ReadmeStep

        step = ReadmeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.discovery.readme_step import ReadmeStep

        step = ReadmeStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
