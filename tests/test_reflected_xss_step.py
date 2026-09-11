"""Tests for ReflectedXssStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.reflected_xss_step import (
    MARKER,
    ReflectedXssStep,
    reflection_context,
)


class TestReflectionContext:
    def test_raw_tag(self):
        assert reflection_context(f'value="\x27"><{MARKER}>', MARKER) == "raw-tag"

    def test_encoded(self):
        assert reflection_context(f"&lt;{MARKER}&gt;", MARKER) == "encoded"

    def test_attribute(self):
        assert reflection_context(f"data='{MARKER}'", MARKER) == "attribute"

    def test_none(self):
        assert reflection_context("<p>clean</p>", MARKER) == "none"


class TestReflectedXssStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 50
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        return ReflectedXssStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_raw_reflection_high(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if MARKER in url:
                return MagicMock(status_code=200, text=f'value="\'"><{MARKER}>')
            return MagicMock(status_code=200, text='<a href="/s?q=1">l</a>')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings
        assert findings[0].severity == "high"
        assert findings[0].raw["context"] == "raw-tag"

    async def test_encoded_reflection_ignored(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if MARKER in url:
                return MagicMock(status_code=200, text=f"&lt;{MARKER}&gt;")
            return MagicMock(status_code=200, text='<a href="/s?q=1">l</a>')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
