"""Tests for the active module foundation (base_active, gating, caps)."""

from unittest.mock import AsyncMock, MagicMock

from modules.active_module import ActiveModule
from steps.active.base_active import (
    ActiveHttpStep,
    extract_form_fields,
    extract_query_params,
)


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


def _discovery_step(mock_http, mock_target, mock_config):
    mock_config.active_enabled = True
    mock_config.active_max_requests = 10
    mock_config.active_delay = 0.0
    mock_config.active_max_params = 10

    class DiscoveryStep(ActiveHttpStep):
        name = "discovery_test"
        description = "test"
        severity = "info"

        async def run(self):
            return self.findings

    return DiscoveryStep(target=mock_target, config=mock_config, http=mock_http)


class TestParamDiscovery:
    async def test_homepage_links_and_forms(self, mock_http, mock_target, mock_config):
        html = ('<a href="/p?id=1">x</a>'
                '<form action="/reg"><input name="user"></form>')
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = _discovery_step(mock_http, mock_target, mock_config)
        pairs = await step.discover_params()
        assert ("/p", "id") in pairs
        assert ("/reg", "user") in pairs

    async def test_js_bundle_mining(self, mock_http, mock_target, mock_config):
        html = '<a href="/search?q=1">s</a><script src="/main.js"></script>'
        js = 'fetch("/api/items"); const o={params:{userId:1}};'

        async def handler(method, url, **kwargs):
            if url.endswith("/main.js"):
                return MagicMock(status_code=200, text=js)
            return MagicMock(status_code=200, text=html)

        mock_http.request = AsyncMock(side_effect=handler)
        step = _discovery_step(mock_http, mock_target, mock_config)
        pairs = await step.discover_params()
        assert ("/search", "q") in pairs
        assert any(path == "/api/items" for path, _ in pairs)

    async def test_operator_supplied_params(self, mock_http, mock_target, mock_config):
        mock_config.active_params = "/api/y:q, /api/z:id"
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="")
        )
        step = _discovery_step(mock_http, mock_target, mock_config)
        pairs = await step.discover_params()
        assert ("/api/y", "q") in pairs
        assert ("/api/z", "id") in pairs


class TestEvidencePersistence:
    async def test_run_persists_probe_evidence(self, tmp_path, mock_http, mock_target):
        from config import ScanConfig

        config = ScanConfig(
            output_dir=tmp_path,
            save_raw=True,
            active_enabled=True,
            active_delay=0.0,
            active_max_requests=10,
            active_max_params=10,
        )

        class EStep(ActiveHttpStep):
            name = "evi"
            description = "test"
            severity = "info"

            async def run(self):
                await self.probe("/probe")
                return self.findings

        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="abc", headers={})
        )
        step = EStep(target=mock_target, config=config, http=mock_http)
        await step.run()

        raw = tmp_path / "raw"
        assert (raw / "evi.requests.jsonl").exists()
        assert (raw / "evi.meta.json").exists()
