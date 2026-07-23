# tests/test_dependencies.py
"""Unit tests for base/dependencies.py — WordlistDependencyMixin, BinaryDependencyMixin."""

from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch

import pytest

from base.dependencies import BinaryDependencyMixin, WordlistDependencyMixin
from base.step import BaseStep, BaseToolStep


# ---------------------------------------------------------------------------
# Concrete test class
# ---------------------------------------------------------------------------
class ConcreteWordlistStep(BaseStep, WordlistDependencyMixin):
    name = "wordlist_step"
    MODULE = "test"

    async def run(self):
        return list(self.findings)


# ---------------------------------------------------------------------------
# WordlistDependencyMixin
# ---------------------------------------------------------------------------
class TestResolveWordlistOrFallback:
    @pytest.fixture
    def step(self):
        return ConcreteWordlistStep()

    def test_custom_path_loads_lines(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("item1\nitem2\nitem3\n")
            tmp_path = f.name
        try:
            result = step.resolve_wordlist_or_fallback(
                config_key="test", custom_path=tmp_path
            )
            assert result == ["item1", "item2", "item3"]
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_custom_path_not_found_falls_through(self, step):
        result = step.resolve_wordlist_or_fallback(
            config_key="test", custom_path="/nonexistent/path.txt"
        )
        assert result is None

    def test_config_key_found_with_file(self, step):
        step.config = MagicMock()
        step.config.keys = {}
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("a\nb\n")
            tmp_path = f.name
        step.config.keys = {"test": tmp_path}
        try:
            result = step.resolve_wordlist_or_fallback(config_key="test")
            assert result == ["a", "b"]
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_config_key_found_but_file_missing_falls_through(self, step):
        step.config = MagicMock()
        step.config.keys = {"test": "/nonexistent/config_path.txt"}
        result = step.resolve_wordlist_or_fallback(
            config_key="test", defaults=["d1", "d2"]
        )
        assert result == ["d1", "d2"]

    def test_wordlist_file_resolved(self, step):
        with patch("base.dependencies.get_wordlist_path") as mock_path:
            with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("x\ny\n")
                tmp_path = f.name
            mock_path.return_value = Path(tmp_path)
            try:
                result = step.resolve_wordlist_or_fallback(
                    config_key="test", wordlist_file="some/path.txt"
                )
                assert result == ["x", "y"]
            finally:
                Path(tmp_path).unlink(missing_ok=True)

    def test_wordlist_file_not_found_falls_to_defaults(self, step):
        with patch("base.dependencies.get_wordlist_path", return_value=None):
            result = step.resolve_wordlist_or_fallback(
                config_key="test", wordlist_file="missing.txt", defaults=["d"]
            )
            assert result == ["d"]

    def test_no_fallbacks_returns_none_with_disabled_finding(self, step):
        result = step.resolve_wordlist_or_fallback(
            config_key="test", name="test wordlist"
        )
        assert result is None
        assert len(step.findings) == 1
        assert step.findings[0].severity == "low"

    def test_with_custom_loader(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("a:1\nb:2\n")
            tmp_path = f.name
        try:
            loader = MagicMock(return_value=[("a", "1"), ("b", "2")])
            result = step.resolve_wordlist_or_fallback(
                config_key="test",
                custom_path=tmp_path,
                loader=loader,
            )
            assert result == [("a", "1"), ("b", "2")]
            loader.assert_called_once()
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_loader_raises_logs_warning(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("data\n")
            tmp_path = f.name
        try:
            loader = MagicMock(side_effect=ValueError("bad loader"))
            with patch.object(step.logger, "warning") as mock_warn:
                result = step.resolve_wordlist_or_fallback(
                    config_key="test",
                    custom_path=tmp_path,
                    defaults=["fallback"],
                    loader=loader,
                )
                assert result == ["fallback"]
                assert mock_warn.call_count >= 1
                assert any("bad loader" in c[0][0] for c in mock_warn.call_args_list)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_config_has_no_keys_attribute(self, step):
        step.config = MagicMock(spec=[])  # no keys attribute
        result = step.resolve_wordlist_or_fallback(
            config_key="test", defaults=["d"]
        )
        assert result == ["d"]


class TestLoadCredentialsFromWordlist:
    @pytest.fixture
    def step(self):
        return ConcreteWordlistStep()

    def test_parses_valid_format(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("admin:password\nuser:pass123\n")
            tmp_path = f.name
        try:
            creds = step.load_credentials_from_wordlist(Path(tmp_path))
            assert creds == [("admin", "password"), ("user", "pass123")]
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_skips_comments(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("#comment\nadmin:pass\n")
            tmp_path = f.name
        try:
            creds = step.load_credentials_from_wordlist(Path(tmp_path))
            assert creds == [("admin", "pass")]
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_skips_lines_without_colon(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("justtext\nadmin:pass\n")
            tmp_path = f.name
        try:
            creds = step.load_credentials_from_wordlist(Path(tmp_path))
            assert creds == [("admin", "pass")]
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_skips_empty_parts(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(":pass\nadmin:\n:\n")
            tmp_path = f.name
        try:
            creds = step.load_credentials_from_wordlist(Path(tmp_path))
            assert len(creds) == 0
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_handles_file_not_found(self, step):
        creds = step.load_credentials_from_wordlist(Path("/nonexistent/file.txt"))
        assert creds == []

    def test_strips_whitespace(self, step):
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("  admin  :  password  \n")
            tmp_path = f.name
        try:
            creds = step.load_credentials_from_wordlist(Path(tmp_path))
            assert creds == [("admin", "password")]
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_handles_os_error(self, step):
        path = MagicMock(spec=Path)
        path.__enter__ = MagicMock(side_effect=OSError("permission denied"))
        path.__exit__ = MagicMock()
        with patch("builtins.open", side_effect=OSError("denied")), \
             patch.object(step.logger, "error") as mock_err:
            creds = step.load_credentials_from_wordlist(Path("/denied.txt"))
            assert creds == []
            mock_err.assert_called_once()


class TestResolveCredentialsWithFallback:
    def test_delegates_to_resolve_wordlist_or_fallback(self):
        step = ConcreteWordlistStep()
        step.resolve_wordlist_or_fallback = MagicMock(return_value=[("u", "p")])
        result = step.resolve_credentials_with_fallback(config_key="creds")
        assert result == [("u", "p")]
        step.resolve_wordlist_or_fallback.assert_called_once()
        _, kwargs = step.resolve_wordlist_or_fallback.call_args
        assert kwargs["config_key"] == "creds"
        assert kwargs["name"] == "credential wordlist"
        assert kwargs["wordlist_file"] == "credentials/common_wp.txt"


# ---------------------------------------------------------------------------
# BinaryDependencyMixin
# ---------------------------------------------------------------------------
class ConcreteBinaryStep(BaseToolStep, BinaryDependencyMixin):
    _tool_binary = "testbin"
    name = "binary_step"
    MODULE = "test"

    def __init__(self):
        BaseToolStep.__init__(self)
        BinaryDependencyMixin.__init__(self)

    def build_command(self):
        return ["testbin"]

    def parse_output(self, result):
        return []


class TestBinaryDependencyMixin:
    def test_init_sets_default_install_hint(self):
        step = ConcreteBinaryStep()
        assert step._binary_tool_name == "testbin"
        assert "install" in step._binary_install_hint

    def test_init_uses_custom_install_hint(self):
        class CustomStep(BaseToolStep, BinaryDependencyMixin):
            _tool_binary = "custom_bin"
            name = "custom"
            MODULE = "test"

            def __init__(self):
                BaseToolStep.__init__(self)
                BinaryDependencyMixin.__init__(self)

            def build_command(self):
                return ["custom_bin"]

            def parse_output(self, result):
                return []

        step = CustomStep()
        assert step._binary_tool_name == "custom_bin"

    @pytest.mark.asyncio
    async def test_check_binary_with_warning_exists(self):
        step = ConcreteBinaryStep()
        with patch.object(step, "check_binary", return_value=(True, "")):
            result = await step.check_binary_with_warning()
            assert result is True

    @pytest.mark.asyncio
    async def test_check_binary_with_warning_not_found(self):
        step = ConcreteBinaryStep()
        with patch.object(step, "check_binary", return_value=(False, "not found")), \
             patch.object(step.logger, "warning") as mock_warn:
            result = await step.check_binary_with_warning()
            assert result is False
            mock_warn.assert_called_once()
            assert len(step.findings) == 1
            assert "skipped" in step.findings[0].title

    @pytest.mark.asyncio
    async def test_check_binary_with_warning_custom_args(self):
        step = ConcreteBinaryStep()
        with patch.object(step, "check_binary", return_value=(False, "not found")):
            result = await step.check_binary_with_warning(
                binary="otherbin",
                install_hint="pip install otherbin",
                finding_title="Other tool not available",
            )
            assert result is False
            assert "Other tool" in step.findings[0].title

    def test_get_default_install_hint_known(self):
        step = ConcreteBinaryStep()
        hint = step._get_default_install_hint("nmap")
        assert "nmap" in hint
        assert "apt install" in hint

    def test_get_default_install_hint_unknown(self):
        step = ConcreteBinaryStep()
        hint = step._get_default_install_hint("rare_tool")
        assert "rare_tool" in hint
        assert "package manager" in hint

    def test_get_default_install_hint_whois(self):
        step = ConcreteBinaryStep()
        hint = step._get_default_install_hint("whois")
        assert "brew install" in hint
