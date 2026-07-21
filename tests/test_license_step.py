"""Tests for LicenseStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestLicenseStep:
    async def test_found_with_version(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="WordPress - Web publishing software\n  version 6.4.2"
            )
        )

        from steps.discovery.license_step import LicenseStep

        step = LicenseStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "license.txt found"
        assert findings[0].raw["version"] == "6.4.2"
        assert findings[0].module == "discovery"

    async def test_found_without_version(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="Some license text without version info"
            )
        )

        from steps.discovery.license_step import LicenseStep

        step = LicenseStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.discovery.license_step import LicenseStep

        step = LicenseStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.discovery.license_step import LicenseStep

        step = LicenseStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
