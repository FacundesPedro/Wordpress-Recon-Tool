"""Tests for VersionedAssetsStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestVersionedAssetsStep:
    async def test_found_versions(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<script src="/script.js?ver=6.4.2"></script>'
                    '<link href="/style.css?ver=1.0.3">'
                ),
            )
        )

        from steps.fingerprint.versioned_assets_step import VersionedAssetsStep

        step = VersionedAssetsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "Version disclosure via assets"
        assert "6.4.2" in findings[0].evidence
        assert "1.0.3" in findings[0].evidence
        assert findings[0].module == "fingerprint"

    async def test_no_versions_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="<html><body>No versions here</body></html>"
            )
        )

        from steps.fingerprint.versioned_assets_step import VersionedAssetsStep

        step = VersionedAssetsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.fingerprint.versioned_assets_step import VersionedAssetsStep

        step = VersionedAssetsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.fingerprint.versioned_assets_step import VersionedAssetsStep

        step = VersionedAssetsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_detects_hex_version(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text='<script src="/script.js?ver=abc123"></script>',
            )
        )

        from steps.fingerprint.versioned_assets_step import VersionedAssetsStep

        step = VersionedAssetsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "abc123" in findings[0].evidence
