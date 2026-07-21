"""Tests for UploadsListingStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestUploadsListingStep:
    async def test_listing_enabled_with_index_of(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="<html><title>Index of /wp-content/uploads</title></html>",
            )
        )

        from steps.discovery.uploads_listing_step import UploadsListingStep

        step = UploadsListingStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "Uploads directory listing enabled"
        assert findings[0].severity == "low"
        assert findings[0].module == "discovery"

    async def test_listing_enabled_with_title_index(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="<html><title>index</title><body>file1.jpg file2.jpg</body></html>",
            )
        )

        from steps.discovery.uploads_listing_step import UploadsListingStep

        step = UploadsListingStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1

    async def test_listing_disabled(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="<html><body>403 Forbidden</body></html>",
            )
        )

        from steps.discovery.uploads_listing_step import UploadsListingStep

        step = UploadsListingStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.discovery.uploads_listing_step import UploadsListingStep

        step = UploadsListingStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.discovery.uploads_listing_step import UploadsListingStep

        step = UploadsListingStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
