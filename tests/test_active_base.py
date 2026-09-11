"""Tests for the active module foundation (base_active, gating, caps)."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.base_active import (
    ActiveHttpStep,
    extract_form_fields,
    extract_query_params,
)
from modules.active_module import ActiveModule


class TestExtraction:
    def test_query_params_from_links(self):
        html = '<a href="/page?id=5&x=1">a</a><a href="/other">b</a>'
        pairs = extract_query_params(html)
        assert ("/page", "id") in pairs
        assert ("/page", "x") in pairs

    def test_form_fields(self):
        html = ('<form action="/register"><input name="user">'
                '<input name="pass"></form>')
        pairs = extract_form_fields(html)
        assert ("/register", "user") in pairs
        assert ("/register", "pass") in pairs


class TestActiveModule:
    def test_registered_15_steps(self):
        module = ActiveModule()
        assert len(module) == 15

    def test_names(self):
        module = ActiveModule()
        names = [s.__name__ for s in module.steps]
        assert "SqlInjectionStep" in names
        assert "RequestSmugglingStep" in names
        assert "FileUploadStep" in names


class TestGating:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 10
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10

        class ProbeStep(ActiveHttpStep):
            name = "probe_test"
            description = "test"
            severity = "info"

            async def run(self):
                return self.findings

        return ProbeStep(target=mock_target, config=mock_config, http=mock_http)

    def test_gate_blocks_when_disabled(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert step.gate() is False

    def test_gate_allows_when_enabled(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=True)
        assert step.gate() is True

    async def test_probe_respects_budget(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config)
        mock_http.request = AsyncMock(return_value=MagicMock(status_code=200, text="ok"))
        for _ in range(15):
            await step.probe("/")
        assert step._requests_sent == 10  # hard cap
        assert await step.probe("/") is None

    async def test_probe_handles_errors(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config)
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        assert await step.probe("/") is None
