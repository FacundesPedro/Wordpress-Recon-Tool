# tests/test_runner.py
"""Unit tests for base/runner.py — Runner."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from base.runner import Runner
from core.finding import Finding
from modules.module import Module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_config():
    config = MagicMock()
    config.threads = 5
    config.timeout = 30
    config.insecure = False
    return config


@pytest.fixture
def mock_target():
    target = MagicMock()
    target.url = "https://example.com"
    target.domain = "example.com"
    return target


def make_module(name: str, steps: list | None = None):
    m = Module(name=name, description=f"{name} module")
    for s in (steps or []):
        m.add_step(s)
    return m


# ---------------------------------------------------------------------------
# Runner.__init__
# ---------------------------------------------------------------------------
class TestRunnerInit:
    def test_stores_modules_config_target(self, mock_config, mock_target):
        r = Runner([], mock_config, mock_target)
        assert r.modules == []
        assert r.config is mock_config
        assert r.target is mock_target
        assert r.all_findings == []
        assert r.errors == []
        assert r.modules_run == []
        assert r.started_at is None
        assert r._http is None


# ---------------------------------------------------------------------------
# _get_modules_by_tier
# ---------------------------------------------------------------------------
class TestGetModulesByTier:
    def test_groups_by_tier(self, mock_config, mock_target):
        mod_a = make_module("passive")
        mod_b = make_module("infrastructure")
        r = Runner([mod_a, mod_b], mock_config, mock_target)
        tiers = r._get_modules_by_tier()
        assert mod_a in tiers[1]
        assert mod_b in tiers[2]

    def test_unmatched_module_warns(self, mock_config, mock_target):
        mod = make_module("nonexistent")
        r = Runner([mod], mock_config, mock_target)
        with patch.object(r.logger, "warning") as mock_warn:
            r._get_modules_by_tier()
            mock_warn.assert_called_once()
            assert "does not match any risk tier" in mock_warn.call_args[0][0]

    def test_unknown_module_not_in_any_tier(self, mock_config, mock_target):
        mod = make_module("unknown_mod")
        r = Runner([mod], mock_config, mock_target)
        tiers = r._get_modules_by_tier()
        for t in tiers.values():
            assert mod not in t


# ---------------------------------------------------------------------------
# run_module
# ---------------------------------------------------------------------------
class TestRunModule:
    @pytest.mark.asyncio
    async def test_empty_module_returns_no_findings(self, mock_config, mock_target):
        mod = make_module("passive")
        r = Runner([mod], mock_config, mock_target)
        r._http = MagicMock()
        sem = MagicMock()
        findings = await r.run_module(mod, sem)
        assert findings == []

    @pytest.mark.asyncio
    async def test_runs_steps_and_collects_findings(self, mock_config, mock_target):
        step_cls = MagicMock()
        step_instance = MagicMock()
        step_instance.name = "test_step"
        step_instance.run = AsyncMock(
            return_value=[Finding(
                module="m", step="s", severity="info", title="t",
                description="", evidence="", recommendation="",
            )]
        )
        step_cls.return_value = step_instance
        mod = make_module("passive", [step_cls])
        r = Runner([mod], mock_config, mock_target)
        r._http = MagicMock()
        sem = MagicMock()
        findings = await r.run_module(mod, sem)
        assert len(findings) == 1
        assert findings[0].title == "t"

    @pytest.mark.asyncio
    async     def test_step_error_caught(self, mock_config, mock_target):
        step_cls = MagicMock()
        step_cls.__name__ = "FailingStep"
        step_instance = MagicMock()
        step_instance.name = "failing_step"
        step_instance.run = AsyncMock(side_effect=ValueError("step failed"))
        step_cls.return_value = step_instance
        mod = make_module("passive", [step_cls])
        r = Runner([mod], mock_config, mock_target)
        r._http = MagicMock()
        sem = MagicMock()
        findings = await r.run_module(mod, sem)
        assert len(findings) == 0
        assert len(r.errors) == 1
        assert "step failed" in r.errors[0]

    @pytest.mark.asyncio
    async def test_validate_called_per_module(self, mock_config, mock_target):
        mod = MagicMock(spec=Module)
        mod.name = "passive"
        mod.steps = []
        mod.validate.return_value = ["warning"]
        r = Runner([mod], mock_config, mock_target)
        r._http = MagicMock()
        sem = MagicMock()
        await r.run_module(mod, sem)
        mod.validate.assert_called_once()


# ---------------------------------------------------------------------------
# run_all
# ---------------------------------------------------------------------------
class TestRunAll:
    @pytest.mark.asyncio
    async def test_runs_tiers_sequentially(self, mock_config, mock_target):
        step_cls = MagicMock()
        step_instance = MagicMock()
        step_instance.name = "s"
        step_instance.run = AsyncMock(return_value=[])
        step_cls.return_value = step_instance
        mod = make_module("passive", [step_cls])
        r = Runner([mod], mock_config, mock_target)
        with patch("base.runner.HttpClient") as mock_http_cls:
            mock_http_inst = AsyncMock()
            mock_http_cls.return_value.__aenter__.return_value = mock_http_inst
            report = await r.run_all()
            assert report is not None
            assert r.started_at is not None
            assert len(r.modules_run) == 1

    @pytest.mark.asyncio
    async def test_returns_report_with_metadata(self, mock_config, mock_target):
        r = Runner([], mock_config, mock_target)
        with patch("base.runner.HttpClient") as mock_http_cls:
            mock_http_inst = AsyncMock()
            mock_http_cls.return_value.__aenter__.return_value = mock_http_inst
            report = await r.run_all()
            assert report.target == "https://example.com"
            assert report.domain == "example.com"
            assert report.started_at is not None
            assert report.completed_at is not None


# ---------------------------------------------------------------------------
# get_findings_by_severity
# ---------------------------------------------------------------------------
class TestGetFindingsBySeverity:
    def test_filters_correctly(self, mock_config, mock_target):
        r = Runner([], mock_config, mock_target)
        r.all_findings = [
            Finding(module="m", step="s", severity="high", title="H",
                    description="", evidence="", recommendation=""),
            Finding(module="m", step="s", severity="low", title="L",
                    description="", evidence="", recommendation=""),
            Finding(module="m", step="s", severity="high", title="H2",
                    description="", evidence="", recommendation=""),
        ]
        highs = r.get_findings_by_severity("high")
        assert len(highs) == 2
        lows = r.get_findings_by_severity("low")
        assert len(lows) == 1
        assert r.get_findings_by_severity("critical") == []


# ---------------------------------------------------------------------------
# get_findings_by_module
# ---------------------------------------------------------------------------
class TestGetFindingsByModule:
    def test_filters_by_module_name(self, mock_config, mock_target):
        r = Runner([], mock_config, mock_target)
        r.all_findings = [
            Finding(module="mod_a", step="s", severity="info", title="A",
                    description="", evidence="", recommendation=""),
            Finding(module="mod_b", step="s", severity="low", title="B",
                    description="", evidence="", recommendation=""),
            Finding(module="mod_a", step="s", severity="medium", title="A2",
                    description="", evidence="", recommendation=""),
        ]
        mod_a = r.get_findings_by_module("mod_a")
        assert len(mod_a) == 2
        mod_b = r.get_findings_by_module("mod_b")
        assert len(mod_b) == 1
        assert r.get_findings_by_module("mod_c") == []


# ---------------------------------------------------------------------------
# get_summary
# ---------------------------------------------------------------------------
class TestGetSummary:
    def test_returns_counts_by_severity(self, mock_config, mock_target):
        r = Runner([], mock_config, mock_target)
        r.all_findings = [
            Finding(module="m", step="s", severity="critical", title="C",
                    description="", evidence="", recommendation=""),
            Finding(module="m", step="s", severity="high", title="H",
                    description="", evidence="", recommendation=""),
            Finding(module="m", step="s", severity="medium", title="M",
                    description="", evidence="", recommendation=""),
            Finding(module="m", step="s", severity="low", title="L",
                    description="", evidence="", recommendation=""),
            Finding(module="m", step="s", severity="info", title="I",
                    description="", evidence="", recommendation=""),
        ]
        summary = r.get_summary()
        assert summary["total"] == 5
        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["info"] == 1
