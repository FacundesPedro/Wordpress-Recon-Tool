# tests/test_tool_runner.py
"""Unit tests for base/tool.py — ToolRunner, AsyncToolRunner, sanitization, redaction."""

import asyncio
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from base.tool import (
    SENSITIVE_PATTERN,
    AsyncToolRunner,
    ToolResult,
    ToolRunner,
    _redact_sensitive_from_output,
    _sanitize_arg,
)
from core.exceptions import ToolNotFoundError, ToolTimeoutError


# ---------------------------------------------------------------------------
# _sanitize_arg
# ---------------------------------------------------------------------------
class TestSanitizeArg:
    def test_empty_string(self):
        assert _sanitize_arg("") == ""

    def test_normal_text_unchanged(self):
        assert _sanitize_arg("hello") == "hello"

    def test_semicolon_replaced(self):
        assert _sanitize_arg("a;b") == "a_b"

    def test_ampersand_ampersand_replaced(self):
        assert _sanitize_arg("a&&b") == "a_b"

    def test_pipe_or_replaced(self):
        assert _sanitize_arg("a||b") == "a_b"

    def test_single_pipe_replaced(self):
        assert _sanitize_arg("a|b") == "a_b"

    def test_backtick_replaced(self):
        assert _sanitize_arg("`cmd`") == "_cmd_"

    def test_dollar_paren_replaced(self):
        assert _sanitize_arg("$(cmd)") == "_cmd)"

    def test_newline_replaced(self):
        assert _sanitize_arg("a\nb") == "a_b"

    def test_carriage_return_replaced(self):
        assert _sanitize_arg("a\rb") == "a_b"

    def test_null_replaced(self):
        assert _sanitize_arg("a\0b") == "a_b"

    def test_angle_brackets_replaced(self):
        assert _sanitize_arg("a<b>") == "a_b_"

    def test_braces_replaced(self):
        assert _sanitize_arg("a{b}") == "a_b_"

    def test_tilde_replaced(self):
        assert _sanitize_arg("~user") == "_user"

    def test_multiple_dangerous_chars(self):
        assert _sanitize_arg("a;b|c`d") == "a_b_c_d"

    def test_url_with_colon_not_replaced(self):
        assert _sanitize_arg("https://example.com") == "https://example.com"


# ---------------------------------------------------------------------------
# _redact_sensitive_from_output
# ---------------------------------------------------------------------------
class TestRedactSensitive:
    def test_empty_string(self):
        assert _redact_sensitive_from_output("") == ""

    def test_none_passthrough(self):
        assert _redact_sensitive_from_output(None) is None

    def test_no_match(self):
        text = "No secrets here"
        assert _redact_sensitive_from_output(text) == text

    def test_api_key(self):
        result = _redact_sensitive_from_output("api_key=abc123")
        assert "abc123" not in result
        assert "api_key=[REDACTED]" in result

    def test_token(self):
        result = _redact_sensitive_from_output("token: mysecret")
        assert "mysecret" not in result
        assert "token=[REDACTED]" in result

    def test_password(self):
        result = _redact_sensitive_from_output("password=hunter2")
        assert "hunter2" not in result
        assert "password=[REDACTED]" in result

    def test_secret(self):
        result = _redact_sensitive_from_output('secret="s3cr3t"')
        assert "s3cr3t" not in result
        assert "secret=[REDACTED]" in result

    def test_multiple_matches(self):
        text = "api_key=aaa token=bbb"
        result = _redact_sensitive_from_output(text)
        assert "aaa" not in result
        assert "bbb" not in result
        assert result.count("[REDACTED]") == 2

    def test_credential(self):
        result = _redact_sensitive_from_output("credential=x123")
        assert "x123" not in result
        assert "credential=[REDACTED]" in result


# ---------------------------------------------------------------------------
# SENSITIVE_PATTERN
# ---------------------------------------------------------------------------
class TestSensitivePattern:
    def test_matches_api_key(self):
        assert SENSITIVE_PATTERN.search("api_key=secret123")

    def test_matches_token(self):
        assert SENSITIVE_PATTERN.search("token: mytoken")

    def test_matches_password(self):
        assert SENSITIVE_PATTERN.search("password = pass123")

    def test_no_match_without_value(self):
        assert not SENSITIVE_PATTERN.search("just some text")


# ---------------------------------------------------------------------------
# ToolResult
# ---------------------------------------------------------------------------
class TestToolResult:
    def test_output_prefers_stdout(self):
        r = ToolResult(stdout="hello", stderr="err", returncode=0, success=True)
        assert r.output == "hello"

    def test_output_falls_back_to_stderr(self):
        r = ToolResult(stdout="", stderr="fallback", returncode=1, success=False)
        assert r.output == "fallback"

    def test_output_empty_when_both_empty(self):
        r = ToolResult(stdout="", stderr="", returncode=0, success=True)
        assert r.output == ""

    def test_success_true(self):
        r = ToolResult(stdout="", stderr="", returncode=0, success=True)
        assert r.success is True

    def test_success_false(self):
        r = ToolResult(stdout="", stderr="", returncode=1, success=False)
        assert r.success is False


# ---------------------------------------------------------------------------
# ToolRunner — init and binary checks
# ---------------------------------------------------------------------------
class TestToolRunnerInit:
    def test_binary_path_stored(self):
        r = ToolRunner("mytool")
        assert r._binary_path == "mytool"

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    def test_binary_exists_true(self, mock_which):
        assert ToolRunner("mytool").binary_exists() is True

    @patch("base.tool.shutil.which", return_value=None)
    def test_binary_exists_false(self, mock_which):
        assert ToolRunner("mytool").binary_exists() is False

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    def test_binary_resolve_returns_path(self, mock_which):
        assert ToolRunner("mytool").binary_resolve() == "/usr/bin/mytool"

    @patch("base.tool.shutil.which", return_value=None)
    def test_binary_resolve_returns_none(self, mock_which):
        assert ToolRunner("mytool").binary_resolve() is None


# ---------------------------------------------------------------------------
# ToolRunner._build_cmd
# ---------------------------------------------------------------------------
class TestBuildCmd:
    def test_empty_args_raises(self):
        with pytest.raises(ValueError, match="No command arguments"):
            ToolRunner("mytool")._build_cmd([])

    def test_binary_prepended_when_missing(self):
        cmd = ToolRunner("mytool")._build_cmd(["--flag"])
        assert cmd[0] == "mytool"
        assert cmd[1] == "--flag"

    def test_binary_not_duplicated_when_first(self):
        cmd = ToolRunner("mytool")._build_cmd(["mytool", "--flag"])
        assert cmd == ["mytool", "--flag"]

    def test_arguments_sanitized(self):
        cmd = ToolRunner("mytool")._build_cmd(["mytool", "a;b"])
        assert cmd == ["mytool", "a_b"]


# ---------------------------------------------------------------------------
# ToolRunner.run
# ---------------------------------------------------------------------------
class TestToolRunnerRun:
    @patch("base.tool.shutil.which", return_value=None)
    def test_binary_not_found_raises(self, _):
        with pytest.raises(ToolNotFoundError):
            ToolRunner("missing").run(["missing"])

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.subprocess.run")
    def test_success(self, mock_run, _):
        mock_run.return_value = MagicMock(
            stdout=b"ok", stderr=b"", returncode=0
        )
        result = ToolRunner("mytool").run(["mytool", "--arg"])
        assert result.success is True
        assert result.stdout == "ok"
        assert result.returncode == 0

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.subprocess.run")
    def test_non_zero_return(self, mock_run, _):
        mock_run.return_value = MagicMock(
            stdout=b"", stderr=b"err", returncode=1
        )
        result = ToolRunner("mytool").run(["mytool"])
        assert result.success is False
        assert result.returncode == 1

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.subprocess.run", side_effect=subprocess.TimeoutExpired("mytool", 5))
    def test_timeout_raises(self, mock_run, _):
        with pytest.raises(ToolTimeoutError):
            ToolRunner("mytool").run(["mytool"], timeout=5)

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.subprocess.run", side_effect=OSError("permission denied"))
    def test_os_error_raises_runtime(self, mock_run, _):
        with pytest.raises(RuntimeError, match="Error executing"):
            ToolRunner("mytool").run(["mytool"])

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.subprocess.run")
    def test_output_redacted(self, mock_run, _):
        mock_run.return_value = MagicMock(
            stdout=b"api_key=secret123", stderr=b"", returncode=0
        )
        result = ToolRunner("mytool").run(["mytool"])
        assert "secret123" not in result.stdout
        assert "[REDACTED]" in result.stdout

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.subprocess.run")
    def test_env_filtering_none_values(self, mock_run, _):
        mock_run.return_value = MagicMock(
            stdout=b"ok", stderr=b"", returncode=0
        )
        ToolRunner("mytool").run(["mytool"], env={"A": "1", "B": None})
        _, kwargs = mock_run.call_args
        assert kwargs["env"] == {"A": "1"}

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.subprocess.run")
    def test_env_values_stringified(self, mock_run, _):
        mock_run.return_value = MagicMock(
            stdout=b"ok", stderr=b"", returncode=0
        )
        ToolRunner("mytool").run(["mytool"], env={"A": 123})
        _, kwargs = mock_run.call_args
        assert kwargs["env"] == {"A": "123"}


# ---------------------------------------------------------------------------
# ToolRunner._decode_output
# ---------------------------------------------------------------------------
class TestDecodeOutput:
    def test_empty_bytes(self):
        assert ToolRunner._decode_output(b"") == ""

    def test_none_returns_empty(self):
        assert ToolRunner._decode_output(None) == ""

    def test_utf8(self):
        assert ToolRunner._decode_output("héllo".encode()) == "héllo"

    def test_latin1_fallback(self):
        data = "café".encode("latin-1")
        result = ToolRunner._decode_output(data)
        assert "café" in result

    def test_cp1252_fallback(self):
        data = b"\x93test\x94"
        result = ToolRunner._decode_output(data)
        assert "test" in result

    def test_unrecoverable_uses_replace(self):
        data = b"\xff\xfe"
        result = ToolRunner._decode_output(data)
        assert result  # should not raise, uses replacement chars


# ---------------------------------------------------------------------------
# AsyncToolRunner
# ---------------------------------------------------------------------------
class TestAsyncToolRunner:
    def test_init(self):
        r = AsyncToolRunner("mytool")
        assert r._binary_path == "mytool"

    @patch("base.tool.shutil.which", return_value=None)
    def test_binary_exists_false(self, _):
        assert AsyncToolRunner("missing").binary_exists() is False

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    def test_binary_exists_true(self, _):
        assert AsyncToolRunner("mytool").binary_exists() is True

    def test_build_cmd_empty_raises(self):
        with pytest.raises(ValueError, match="No command arguments"):
            AsyncToolRunner("mytool")._build_cmd([])

    def test_build_cmd_prepends_binary(self):
        cmd = AsyncToolRunner("mytool")._build_cmd(["--flag"])
        assert cmd == ["mytool", "--flag"]

    def test_build_cmd_no_duplicate(self):
        cmd = AsyncToolRunner("mytool")._build_cmd(["mytool", "arg"])
        assert cmd == ["mytool", "arg"]

    @patch("base.tool.shutil.which", return_value=None)
    def test_run_binary_not_found(self, _):
        with pytest.raises(ToolNotFoundError):
            asyncio.get_event_loop().run_until_complete(
                AsyncToolRunner("missing").run(["missing"])
            )

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.asyncio.create_subprocess_exec")
    def test_run_success(self, mock_proc, _):
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"ok", b""))
        proc.returncode = 0
        mock_proc.return_value = proc
        result = asyncio.get_event_loop().run_until_complete(
            AsyncToolRunner("mytool").run(["mytool"])
        )
        assert result.success is True
        assert result.stdout == "ok"

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.asyncio.create_subprocess_exec")
    def test_run_non_zero(self, mock_proc, _):
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"", b"err"))
        proc.returncode = 1
        mock_proc.return_value = proc
        result = asyncio.get_event_loop().run_until_complete(
            AsyncToolRunner("mytool").run(["mytool"])
        )
        assert result.success is False

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.asyncio.create_subprocess_exec", side_effect=OSError("fail"))
    def test_run_os_error(self, mock_proc, _):
        with pytest.raises(RuntimeError, match="Error executing"):
            asyncio.get_event_loop().run_until_complete(
                AsyncToolRunner("mytool").run(["mytool"])
            )

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.asyncio.create_subprocess_exec")
    def test_run_timeout(self, mock_proc, _):
        proc = MagicMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)
        proc.wait = AsyncMock()
        proc.returncode = None
        mock_proc.return_value = proc
        with pytest.raises(ToolTimeoutError):
            asyncio.get_event_loop().run_until_complete(
                AsyncToolRunner("mytool").run(["mytool"], timeout=1)
            )

    @patch("base.tool.shutil.which", return_value="/usr/bin/mytool")
    @patch("base.tool.asyncio.create_subprocess_exec")
    def test_run_none_returncode(self, mock_proc, _):
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"out", b"err"))
        proc.returncode = None
        mock_proc.return_value = proc
        result = asyncio.get_event_loop().run_until_complete(
            AsyncToolRunner("mytool").run(["mytool"])
        )
        assert result.returncode == -1
        assert result.success is False
