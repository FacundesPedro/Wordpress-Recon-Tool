"""Tests for PathTraversalStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.path_traversal_step import PathTraversalStep


class TestPathTraversalStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 50
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return PathTraversalStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_traversal_detected(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "etc/passwd" in url and "%2e" not in url and "...." not in url:
                return MagicMock(status_code=200,
                                 text="root:x:0:0:root:/root:/bin/bash")
            return MagicMock(status_code=200, text="<html>ok</html>")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("traversal" in f.title.lower() for f in findings)
        assert any(f.raw.get("signature") == "root:x:0:0" for f in findings)

    async def test_no_traversal(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html>ok</html>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_windows_signature(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "win.ini" in url:
                return MagicMock(status_code=200, text="[fonts]\nserif=1")
            return MagicMock(status_code=200, text="<html>ok</html>")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Windows win.ini" in f.title for f in findings)
        assert any(f.raw.get("signature") == "[fonts]" for f in findings)