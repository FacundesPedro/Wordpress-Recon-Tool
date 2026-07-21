"""Tests for ScriptsStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestScriptsStep:
    async def test_found_scripts(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text=(
                    '<script src="/wp-includes/js/jquery.js"></script>'
                    '<script src="/wp-includes/js/wp-util.js"></script>'
                ),
            )
        )

        from steps.fingerprint.scripts_step import ScriptsStep

        step = ScriptsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "WordPress core scripts detected"
        assert "jquery" in findings[0].evidence
        assert "wp-util" in findings[0].evidence
        assert findings[0].module == "fingerprint"

    async def test_no_scripts_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(
            return_value=MagicMock(
                status_code=200, text="<html><body>No scripts here</body></html>"
            )
        )

        from steps.fingerprint.scripts_step import ScriptsStep

        step = ScriptsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(return_value=MagicMock(status_code=404))

        from steps.fingerprint.scripts_step import ScriptsStep

        step = ScriptsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_handles_exception(self, mock_http, mock_target, mock_config):
        mock_http.get = AsyncMock(side_effect=Exception("connection error"))

        from steps.fingerprint.scripts_step import ScriptsStep

        step = ScriptsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0
