# tests/test_main_cli.py
"""Unit tests for main.py — CLI helpers and Typer commands."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from main import _save_report, build_modules, get_module_names, resolve_domain


# ---------------------------------------------------------------------------
# resolve_domain
# ---------------------------------------------------------------------------
class TestResolveDomain:
    def test_extracts_domain(self):
        assert resolve_domain("https://example.com") == "example.com"

    def test_with_www(self):
        assert resolve_domain("https://www.example.com/path") == "www.example.com"

    def test_with_port(self):
        assert resolve_domain("http://example.com:8080") == "example.com:8080"

    def test_no_scheme_returns_raw(self):
        assert resolve_domain("example.com") == "example.com"

    def test_empty_string(self):
        assert resolve_domain("") == ""


# ---------------------------------------------------------------------------
# get_module_names
# ---------------------------------------------------------------------------
class TestGetModuleNames:
    def test_uses_modules_arg_when_provided(self):
        result = get_module_names("light", modules_arg="passive,fingerprint")
        assert result == ["passive", "fingerprint"]

    def test_falls_back_to_profile(self):
        result = get_module_names("passive")
        assert result == ["passive"]

    def test_unknown_profile_returns_empty(self):
        result = get_module_names("nonexistent")
        assert result == []

    def test_strips_whitespace(self):
        result = get_module_names("light", modules_arg=" passive , fingerprint ")
        assert result == ["passive", "fingerprint"]


# ---------------------------------------------------------------------------
# build_modules
# ---------------------------------------------------------------------------
class TestBuildModules:
    def test_returns_instances(self):
        modules = build_modules(["passive"])
        assert len(modules) == 1
        assert modules[0].name == "passive"

    def test_skips_unknown_modules(self):
        modules = build_modules(["passive", "nonexistent"])
        assert len(modules) == 1
        assert modules[0].name == "passive"

    def test_skips_tools_when_no_tools_enabled(self):
        modules = build_modules(["tools"])
        assert modules == []

    def test_includes_tools_when_enabled(self):
        modules = build_modules(
            ["tools"],
            enable_wpscan=True,
        )
        assert len(modules) == 1
        assert modules[0].name == "tools"

    def test_returns_multiple_modules(self):
        modules = build_modules(["passive", "infrastructure"])
        assert len(modules) == 2

    def test_empty_list_returns_empty(self):
        modules = build_modules([])
        assert modules == []


# ---------------------------------------------------------------------------
# _save_report
# ---------------------------------------------------------------------------
class TestSaveReport:
    @pytest.fixture
    def report(self):
        from datetime import datetime

        from utils.report import Report

        return Report(
            target="https://example.com",
            domain="example.com",
            started_at=datetime(2024, 1, 1, 12, 0, 0),
            completed_at=datetime(2024, 1, 1, 12, 1, 0),
            findings=[],
            modules_run=[],
            errors=[],
        )

    @pytest.fixture
    def config(self, tmp_path):
        config = MagicMock()
        config.output_dir = tmp_path
        config.output_format = "json"
        return config

    def test_saves_json(self, report, config, tmp_path):
        with patch("main.JsonFormatter.save") as mock_save:
            _save_report(report, config, None, tmp_path)
            mock_save.assert_called_once()

    def test_saves_markdown(self, report, config, tmp_path):
        config.output_format = "markdown"
        with patch("main.MarkdownFormatter.save") as mock_save:
            _save_report(report, config, None, tmp_path)
            mock_save.assert_called_once()

    def test_saves_sarif(self, report, config, tmp_path):
        config.output_format = "sarif"
        with patch("main.SarifFormatter.save") as mock_save:
            _save_report(report, config, None, tmp_path)
            mock_save.assert_called_once()

    def test_saves_html(self, report, config, tmp_path):
        config.output_format = "html"
        with patch("main.HtmlFormatter.save") as mock_save:
            _save_report(report, config, None, tmp_path)
            mock_save.assert_called_once()

    def test_saves_pdf(self, report, config, tmp_path):
        config.output_format = "pdf"
        with patch("main.PdfFormatter.save") as mock_save:
            _save_report(report, config, None, tmp_path)
            mock_save.assert_called_once()

    def test_pdf_import_error_does_not_crash(self, report, config, tmp_path):
        config.output_format = "pdf"
        with patch("main.PdfFormatter.save", side_effect=ImportError("No module named weasyprint")):
            _save_report(report, config, None, tmp_path)

    def test_pdf_generic_error_does_not_crash(self, report, config, tmp_path):
        config.output_format = "pdf"
        with patch("main.PdfFormatter.save", side_effect=RuntimeError("boom")):
            _save_report(report, config, None, tmp_path)

    def test_json_error_does_not_crash(self, report, config, tmp_path):
        config.output_format = "json"
        with patch("main.JsonFormatter.save", side_effect=RuntimeError("boom")):
            _save_report(report, config, None, tmp_path)

    def test_saves_all_formats(self, report, config, tmp_path):
        config.output_format = "all"
        with patch("main.JsonFormatter.save") as json_save, \
             patch("main.MarkdownFormatter.save") as md_save, \
             patch("main.SarifFormatter.save") as sarif_save, \
             patch("main.HtmlFormatter.save") as html_save, \
             patch("main.PdfFormatter.save") as pdf_save:
            _save_report(report, config, None, tmp_path)
            json_save.assert_called_once()
            md_save.assert_called_once()
            sarif_save.assert_called_once()
            html_save.assert_called_once()
            pdf_save.assert_called_once()


# ---------------------------------------------------------------------------
# Reachability pre-flight abort
# ---------------------------------------------------------------------------
class TestReachabilityAbort:
    def test_unreachable_target_exits_with_error(self, tmp_path):
        from typer.testing import CliRunner

        from core.reachability import ReachabilityResult
        from main import app

        runner = CliRunner()
        with patch(
            "core.reachability.check_reachability",
            new=AsyncMock(
                return_value=ReachabilityResult(
                    reachable=False,
                    domain="example.com",
                    error="DNS resolution failed — domain may not exist",
                    error_category="dns",
                )
            ),
        ):
            result = runner.invoke(
                app, ["main", "--target", "https://example.com", "-o", str(tmp_path)]
            )
        assert result.exit_code == 1

    def test_skip_reachability_check_does_not_probe(self, tmp_path):
        from typer.testing import CliRunner

        from main import app

        runner = CliRunner()
        with patch("core.reachability.check_reachability") as mock_probe, \
             patch("main.build_modules", return_value=[]):
            result = runner.invoke(
                app,
                [
                    "main",
                    "--target",
                    "https://example.com",
                    "-o",
                    str(tmp_path),
                    "--skip-reachability-check",
                ],
            )
        mock_probe.assert_not_called()
        assert result.exit_code == 1  # no modules selected → exit 1
