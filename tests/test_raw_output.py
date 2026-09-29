"""Tests for raw external-tool output persistence."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

from base.tool import ToolResult
from config import ScanConfig
from utils.raw_output import RawArtifactWriter, format_command


def make_writer(tmp_path, **overrides):
    config = ScanConfig(
        output_dir=tmp_path,
        save_raw=True,
        raw_max_bytes=overrides.pop("raw_max_bytes", 5_000_000),
        raw_no_redact=overrides.pop("raw_no_redact", False),
        **overrides,
    )
    return RawArtifactWriter(config=config)


def meta(writer, step):
    path = writer.directory() / f"{step}.meta.json"
    return json.loads(path.read_text())


class TestEnabled:
    def test_disabled_when_flag_not_true(self, tmp_path):
        config = MagicMock()
        assert RawArtifactWriter(config=config).enabled is False

    def test_disabled_when_save_raw_false(self, tmp_path):
        config = ScanConfig(output_dir=tmp_path, save_raw=False)
        assert RawArtifactWriter(config=config).enabled is False

    def test_enabled_with_real_config(self, tmp_path):
        assert make_writer(tmp_path).enabled is True


class TestFormatCommand:
    def test_empty(self):
        assert format_command([]) == ""
        assert format_command(None) == ""

    def test_short_is_single_line(self):
        assert format_command(["nuclei", "-u", "https://example.com"]) == (
            "nuclei -u https://example.com\n"
        )

    def test_wraps_without_overflow(self):
        cmd = ["opendoor"] + [f"--flag{i:02d}" for i in range(20)] + ["target"]
        rendered = format_command(cmd, width=40)
        lines = rendered.splitlines()
        assert len(lines) > 1
        for line in lines[:-1]:
            assert line.endswith("\\")
            assert len(line) <= 41  # content + trailing backslash
        # Last line has no continuation.
        assert not lines[-1].endswith("\\")
        # Rejoining removes continuations and matches shlex.join.
        import shlex

        rejoined = " ".join(
            ln.rstrip("\\").strip() for ln in rendered.splitlines()
        )
        assert rejoined == shlex.join(cmd)

    def test_wrap_keeps_quoting(self):
        rendered = format_command(["tool", "-m", "has space", "x" * 90])
        assert "'has space'" in rendered


class TestPersist:
    def test_writes_all_artifacts(self, tmp_path):
        writer = make_writer(tmp_path)
        result = ToolResult(stdout='{"a":1}\n', stderr="warn", returncode=0, success=True)
        started = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        finished = datetime(2024, 1, 1, 12, 0, 1, tzinfo=timezone.utc)

        base = writer.persist(
            step="nuclei",
            tool="nuclei",
            cmd=["nuclei", "-u", "https://example.com"],
            result=result,
            started_at=started,
            finished_at=finished,
            native_name="nuclei.jsonl",
        )

        assert base is not None
        assert base == tmp_path / "raw"
        assert (base / "nuclei.stdout").read_text() == '{"a":1}\n'
        assert (base / "nuclei.stderr").read_text() == "warn"
        assert (base / "nuclei.cmd").read_text() == "nuclei -u https://example.com\n"
        assert (base / "nuclei.jsonl").read_text() == '{"a":1}\n'
        m = json.loads((base / "nuclei.meta.json").read_text())
        assert m["step"] == "nuclei"
        assert m["tool"] == "nuclei"
        assert m["returncode"] == 0
        assert m["duration_ms"] == 1000.0
        assert m["started_at"].startswith("2024-01-01T12:00:00")

    def test_cmd_is_single_shell_quoted_line(self, tmp_path):
        writer = make_writer(tmp_path)
        result = ToolResult(stdout="", stderr="", returncode=0, success=True)
        base = writer.persist(
            step="tool",
            tool="tool",
            cmd=["tool", "--msg", "hello world", "-p", "a'b"],
            result=result,
        )
        assert base is not None
        # One line, shlex-quoted, ends with a newline.
        content = (base / "tool.cmd").read_text()
        assert content.endswith("\n") and content.count("\n") == 1
        assert content == "tool --msg 'hello world' -p 'a'\"'\"'b'\n"

    def test_redacts_secrets_by_default(self, tmp_path):
        writer = make_writer(tmp_path)
        result = ToolResult(
            stdout="api_key = abc123secretvalue", stderr="", returncode=0, success=True
        )
        writer.persist(
            step="tool", tool="tool", cmd=["tool"], result=result
        )
        content = (writer.directory() / "tool.stdout").read_text()
        assert "abc123secretvalue" not in content
        assert "REDACTED" in content

    def test_raw_no_redact(self, tmp_path):
        writer = make_writer(tmp_path, raw_no_redact=True)
        result = ToolResult(
            stdout="api_key = abc123secretvalue", stderr="", returncode=0, success=True
        )
        writer.persist(step="tool", tool="tool", cmd=["tool"], result=result)
        content = (writer.directory() / "tool.stdout").read_text()
        assert "abc123secretvalue" in content

    def test_size_cap(self, tmp_path):
        writer = make_writer(tmp_path, raw_max_bytes=10)
        result = ToolResult(stdout="x" * 100, stderr="", returncode=0, success=True)
        writer.persist(step="tool", tool="tool", cmd=["tool"], result=result)
        content = (writer.directory() / "tool.stdout").read_text()
        assert "truncated" in content
        assert len(content) < 100

    def test_native_content_override(self, tmp_path):
        writer = make_writer(tmp_path)
        result = ToolResult(stdout="", stderr="", returncode=0, success=True)
        writer.persist(
            step="opendoor",
            tool="opendoor",
            cmd=["opendoor"],
            result=result,
            native_name="opendoor.json",
            native_content='{"items": {}}',
        )
        assert (writer.directory() / "opendoor.json").read_text() == '{"items": {}}'

    def test_custom_raw_dir(self, tmp_path):
        custom = tmp_path / "custom"
        config = ScanConfig(output_dir=tmp_path, save_raw=True, raw_output_dir=str(custom))
        writer = RawArtifactWriter(config=config)
        result = ToolResult(stdout="ok", stderr="", returncode=0, success=True)
        writer.persist(step="t", tool="t", cmd=["t"], result=result)
        assert (custom / "t.stdout").exists()

    def test_unwritable_dir_does_not_raise(self, tmp_path):
        # A file where the raw directory should be makes mkdir fail.
        blocker = tmp_path / "raw"
        blocker.write_text("not a dir")
        writer = make_writer(tmp_path)
        result = ToolResult(stdout="ok", stderr="", returncode=0, success=True)
        assert writer.persist(step="t", tool="t", cmd=["t"], result=result) is None

    def test_disabled_returns_none(self, tmp_path):
        config = ScanConfig(output_dir=tmp_path, save_raw=False)
        writer = RawArtifactWriter(config=config)
        result = ToolResult(stdout="ok", stderr="", returncode=0, success=True)
        assert writer.persist(step="t", tool="t", cmd=["t"], result=result) is None
        assert not (tmp_path / "raw").exists()


class TestStepIntegration:
    def test_nuclei_run_writes_raw_artifacts(self, tmp_path):
        import asyncio

        from steps.tools.nuclei_step import NucleiStep

        async def scenario():
            config = ScanConfig(output_dir=tmp_path, save_raw=True)
            target = MagicMock()
            target.url = "https://example.com"
            step = NucleiStep(target=target, config=config)
            step.check_binary = lambda binary: (True, "")
            step.check_version_compatibility = lambda: True

            async def fake_run(cmd, timeout=None):
                return ToolResult(
                    stdout='{"info": {"name": "x", "severity": "low"}}\n',
                    stderr="",
                    returncode=0,
                    success=True,
                )

            step._async_tool_runner.run = fake_run
            await step.run()
            return step.name

        step_name = asyncio.run(scenario())
        raw = tmp_path / "raw"
        assert (raw / f"{step_name}.stdout").exists()
        assert (raw / "nuclei.jsonl").exists()
        assert (raw / f"{step_name}.meta.json").exists()

