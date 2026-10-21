"""Tests for ffuf timeout auto-sizing, trimming and partial-coverage reporting."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from config import ScanConfig
from core.exceptions import ToolTimeoutError
from steps.tools.ffuf_directory_step import FfufDirectoryStep


def make_step(tmp_path, lines, rate=150, timeout=300, **config_overrides):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text(
        "\n".join(f"path-{i}" for i in range(lines)) + "\n", encoding="utf-8"
    )
    config = ScanConfig(
        output_dir=tmp_path,
        ffuf_rate_limit=rate,
        ffuf_timeout=timeout,
        **config_overrides,
    )
    target = MagicMock()
    target.url = "https://example.com"
    return FfufDirectoryStep(
        target=target, config=config, wordlist=str(wordlist)
    )


class TestSecondsPerProbe:
    def test_uses_rate_limit_when_set(self, tmp_path):
        step = make_step(tmp_path, 10, rate=100)
        assert step._seconds_per_probe() == pytest.approx(0.01)

    def test_falls_back_to_threads_and_http_timeout(self, tmp_path):
        step = make_step(tmp_path, 10, rate=0)
        # threads=40, http_timeout=10 -> 0.25s/probe (pessimistic baseline)
        assert step._seconds_per_probe() == pytest.approx(0.25)


class TestPlanTimeout:
    def test_scales_to_wordlist(self, tmp_path):
        # 29,999 entries at rate 150 with factor 3 -> 600s (the retest case).
        step = make_step(tmp_path, 29_999, rate=150, timeout=300)
        timeout, fits = step._plan_timeout(29_999)
        assert timeout == 600
        assert fits == 29_999  # estimate fits within the cap -> no trimming

    def test_configured_timeout_is_a_floor(self, tmp_path):
        step = make_step(tmp_path, 100, rate=150, timeout=300)
        timeout, fit = step._plan_timeout(100)
        assert timeout == 300
        assert fit == 100

    def test_cap_forces_trimming(self, tmp_path):
        step = make_step(
            tmp_path, 1_000_000, rate=150, timeout=60, ffuf_timeout_max=600
        )
        timeout, fits = step._plan_timeout(1_000_000)
        assert timeout == 600
        assert 0 < fits < 1_000_000

    def test_disabled_keeps_configured(self, tmp_path):
        step = make_step(
            tmp_path, 1_000_000, rate=150, timeout=300, ffuf_auto_timeout=False
        )
        assert step._plan_timeout(1_000_000) == (300, 1_000_000)

    def test_empty_wordlist(self, tmp_path):
        step = make_step(tmp_path, 1, rate=150)
        assert step._plan_timeout(0) == (300, 0)


class TestTrimmedWordlist:
    def test_writes_and_cleans_up(self, tmp_path):
        step = make_step(tmp_path, 50)
        path = step._write_trimmed_wordlist(10)
        assert path is not None
        assert len(Path(path).read_text().splitlines()) == 10
        step._cleanup_temp_wordlist()
        assert not Path(path).exists()


@pytest.mark.asyncio
class TestRunCoverage:
    async def _prepare(self, step):
        step.check_binary = MagicMock(return_value=(True, ""))
        step.check_version_compatibility = MagicMock(return_value=True)
        step._confirm_wordpress = AsyncMock(return_value=True)
        step._persist_raw = MagicMock()
        return step

    async def test_timeout_reports_partial_coverage(self, tmp_path):
        step = await self._prepare(make_step(tmp_path, 1000, rate=10, timeout=60))
        step._async_tool_runner.run = AsyncMock(
            side_effect=ToolTimeoutError("ffuf", 300)
        )
        findings = await step.run()
        timeout = next(f for f in findings if f.title == "FFUF Timeout")
        assert timeout.severity == "info"
        assert timeout.raw["operational"] is True
        assert timeout.raw["wordlist_lines"] == 1000
        assert timeout.raw["estimated_attempted"] > 0
        # The temporary trimmed wordlist is removed and the original restored.
        assert not step._temp_wordlist

    async def test_oversized_wordlist_trims_and_completes(self, tmp_path):
        step = await self._prepare(
            make_step(
                tmp_path, 1000, rate=10, timeout=60, ffuf_timeout_max=60
            )
        )
        from base.tool import ToolResult

        step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout='{"results": []}', stderr="", returncode=0, success=True
            )
        )
        findings = await step.run()
        trimmed = [f for f in findings if "trimmed" in f.title.lower()]
        assert trimmed, "expected an explicit partial-coverage finding"
        assert trimmed[0].raw["wordlist_lines_total"] == 1000
        assert trimmed[0].raw["wordlist_lines_used"] < 1000
        # Wordlist restored after the run.
        assert step.wordlist.endswith("words.txt")
