"""Tests for WebSocketStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.websocket_step import (
    WebSocketStep,
    extract_ws_endpoints,
)


class TestExtractWsEndpoints:
    def test_extracts_wss(self):
        endpoints = extract_ws_endpoints('var s = "wss://example.com/socket"', "example.com")
        assert endpoints == ["wss://example.com/socket"]

    def test_extracts_ws_with_path(self):
        endpoints = extract_ws_endpoints("ws://localhost:9000/rt", "example.com")
        assert endpoints == ["ws://localhost:9000/rt"]

    def test_ignores_http(self):
        endpoints = extract_ws_endpoints("https://example.com/api", "example.com")
        assert endpoints == []

    def test_dedup(self):
        text = "ws://a.com/x ws://a.com/x"
        assert len(extract_ws_endpoints(text, "example.com")) == 1


class TestWebSocketStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.webapp_websocket_probe = enabled
        mock_config.source_scan_max_js = 2
        mock_config.source_scan_max_bytes = 100000
        return WebSocketStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_config(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_no_ws_endpoints(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html>plain</html>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_finds_endpoint_no_crash_on_refused(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="connect ws://example.com/rt")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        # example.com:80 won't complete a websocket handshake in tests; the
        # step should handle connection failure gracefully
        findings = await step.run()
        assert isinstance(findings, list)
