"""Tests for Report dataclass, JsonFormatter, MarkdownFormatter, and PdfFormatter."""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.finding import Finding
from utils.report import (
    JsonFormatter,
    MarkdownFormatter,
    PdfFormatter,
    Report,
    generate_report_filename,
)


@pytest.fixture
def mock_weasyprint():
    mock_mod = MagicMock()
    with patch.dict("sys.modules", {"weasyprint": mock_mod}):
        yield mock_mod


def make_sample_finding(severity: str = "info", **overrides: object) -> Finding:
    kwargs: dict[str, object] = dict(
        module="test",
        step="check",
        severity=severity,
        title="Test finding",
        description="A description",
        evidence="evidence text",
        recommendation="fix it",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)  # type: ignore[arg-type]


def make_report(findings=None, errors=None, modules=None):
    report = Report(
        target="https://example.com",
        domain="example.com",
        started_at=datetime(2024, 1, 1, 12, 0, 0),
        completed_at=datetime(2024, 1, 1, 12, 1, 30),
    )
    report.findings = findings or []
    report.errors = errors or []
    report.modules_run = modules or []
    return report


class TestReport:
    def test_get_summary_empty(self):
        report = make_report()
        summary = report.get_summary()
        assert summary["total"] == 0
        assert summary["critical"] == 0
        assert summary["high"] == 0
        assert summary["medium"] == 0
        assert summary["low"] == 0
        assert summary["info"] == 0

    def test_get_summary_with_findings(self):
        findings = [
            make_sample_finding("critical"),
            make_sample_finding("high"),
            make_sample_finding("high"),
            make_sample_finding("info"),
        ]
        report = make_report(findings=findings)
        summary = report.get_summary()
        assert summary["total"] == 4
        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["info"] == 1

    def test_get_findings_by_severity(self):
        findings = [
            make_sample_finding("critical", title="Crit 1"),
            make_sample_finding("high", title="High 1"),
            make_sample_finding("critical", title="Crit 2"),
        ]
        report = make_report(findings=findings)
        crits = report.get_findings_by_severity("critical")
        assert len(crits) == 2
        highs = report.get_findings_by_severity("high")
        assert len(highs) == 1

    def test_to_dict_structure(self):
        findings = [make_sample_finding("high")]
        report = make_report(findings=findings, errors=["err1"], modules=["fingerprint"])
        d = report.to_dict()
        assert d["target"] == "https://example.com"
        assert d["domain"] == "example.com"
        assert "started_at" in d
        assert "completed_at" in d
        assert d["duration_seconds"] == 90.0
        assert d["summary"]["total"] == 1
        assert d["modules_run"] == ["fingerprint"]
        assert d["errors"] == ["err1"]
        assert len(d["findings"]) == 1
        assert d["findings"][0]["title"] == "Test finding"


class TestJsonFormatter:
    def test_format(self):
        report = make_report(findings=[make_sample_finding("low")])
        output = JsonFormatter.format(report)
        assert '"target": "https://example.com"' in output
        assert '"domain": "example.com"' in output
        assert '"severity": "low"' in output

    def test_format_with_indent(self):
        report = make_report()
        output = JsonFormatter.format(report, indent=4)
        assert "    " in output

    def test_save(self, tmp_path):
        report = make_report(findings=[make_sample_finding("medium")])
        path = tmp_path / "report.json"
        JsonFormatter.save(report, path)
        assert path.exists()
        content = path.read_text()
        assert '"severity": "medium"' in content
        assert '"target": "https://example.com"' in content


class TestMarkdownFormatter:
    def test_format_full(self):
        findings = [
            make_sample_finding("critical", title="Crit Issue", evidence="found it"),
            make_sample_finding("high", title="High Issue"),
            make_sample_finding("medium", title="Med Issue"),
            make_sample_finding("info", title="Info Issue"),
        ]
        report = make_report(
            findings=findings,
            errors=["error 1"],
            modules=["fingerprint", "access"],
        )
        output = MarkdownFormatter.format(report)
        assert "# Reconnaissance Report: example.com" in output
        assert "**Target:** https://example.com" in output
        assert "**Duration:** 90.0s" in output
        assert "Critical" in output
        assert "High" in output
        assert "Medium" in output
        assert "Informational" in output
        assert "Crit Issue" in output
        assert "High Issue" in output
        assert "Med Issue" in output
        assert "Info Issue" in output
        assert "fingerprint" in output
        assert "access" in output
        assert "error 1" in output

    def test_format_no_findings(self):
        report = make_report()
        output = MarkdownFormatter.format(report)
        assert "Summary" in output
        assert "Total Findings:** 0" in output
        assert "Critical & High" not in output
        assert "Medium & Low" not in output
        assert "Informational" not in output

    def test_format_finding(self):
        finding = make_sample_finding("high", title="XSS", recommendation="sanitize")
        output = MarkdownFormatter._format_finding(finding)
        assert "### XSS" in output
        assert "test" in output
        assert "sanitize" in output

    def test_save(self, tmp_path):
        report = make_report(findings=[make_sample_finding("low")])
        path = tmp_path / "report.md"
        MarkdownFormatter.save(report, path)
        assert path.exists()
        content = path.read_text()
        assert "Reconnaissance Report" in content


class TestPdfFormatter:
    def test_format_raises_import_error_without_weasyprint(self):
        report = make_report()
        with pytest.raises(ImportError, match="WeasyPrint"):
            PdfFormatter.format(report)

    def test_save_raises_import_error_without_weasyprint(self, tmp_path):
        report = make_report()
        out_path = tmp_path / "report.pdf"
        with pytest.raises(ImportError, match="WeasyPrint"):
            PdfFormatter.save(report, out_path)

    def test_format_with_mocked_weasyprint(self, mock_weasyprint):
        mock_html = MagicMock()
        mock_html_instance = MagicMock()
        mock_html.return_value = mock_html_instance
        mock_html_instance.write_pdf.return_value = b"%PDF-1.4 mock"
        mock_weasyprint.HTML = mock_html

        report = make_report(findings=[make_sample_finding("info")])
        result = PdfFormatter.format(report)

        assert result == b"%PDF-1.4 mock"
        mock_html.assert_called_once()
        mock_html_instance.write_pdf.assert_called_once()

    def test_save_with_mocked_weasyprint(self, mock_weasyprint, tmp_path):
        mock_html = MagicMock()
        mock_html_instance = MagicMock()
        mock_html.return_value = mock_html_instance
        mock_html_instance.write_pdf.return_value = b"%PDF-1.4 mock"
        mock_weasyprint.HTML = mock_html

        report = make_report()
        out_path = tmp_path / "report.pdf"
        PdfFormatter.save(report, out_path)

        assert out_path.exists()
        assert out_path.read_bytes() == b"%PDF-1.4 mock"


class TestGenerateReportFilename:
    def test_generates_filename(self):
        ts = datetime(2024, 6, 15, 10, 30, 0)
        name = generate_report_filename("example.com", ts)
        assert name == "recon_example_com_20240615_103000"

    def test_replaces_dots_and_colons(self):
        ts = datetime(2024, 1, 1, 0, 0, 0)
        name = generate_report_filename("my.site.com:8080", ts)
        assert "." not in name
        assert ":" not in name
        assert name.startswith("recon_my_site_com_8080_")
