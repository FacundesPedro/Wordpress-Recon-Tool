"""Tests for PdfFormatter."""
from pathlib import Path

import pytest

from core.finding import Finding
from utils.report import PdfFormatter, Report


def make_report():
    report = Report(target="https://example.com", domain="example.com")
    report.findings.append(
        Finding(
            module="test",
            step="check",
            severity="high",
            title="Test finding",
            description="A test finding",
            evidence="evidence text",
            recommendation="fix it",
        )
    )
    return report


class TestPdfFormatWithoutWeasyPrint:
    """Tests when WeasyPrint is not installed."""

    def test_format_raises_import_error_without_weasyprint(self):
        report = make_report()
        with pytest.raises(ImportError, match="WeasyPrint"):
            PdfFormatter.format(report)

    def test_save_raises_import_error_without_weasyprint(self, tmp_path):
        report = make_report()
        out_path = tmp_path / "report.pdf"
        with pytest.raises(ImportError, match="WeasyPrint"):
            PdfFormatter.save(report, out_path)
