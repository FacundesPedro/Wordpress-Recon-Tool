"""Tests for PdfFormatter (xhtml2pdf backend)."""
import types
from unittest.mock import MagicMock, patch

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


def fake_pisa(write=b"%PDF-1.4 mock", err=0):
    """Build a fake ``xhtml2pdf.pisa`` module object."""
    fake = MagicMock()

    def _create(src=None, dest=None, encoding=None):
        if dest is not None and err == 0:
            dest.write(write)
        result = MagicMock()
        result.err = err
        return result

    fake.CreatePDF.side_effect = _create
    return fake


def fake_xhtml2pdf(pisa_module):
    module = types.ModuleType("xhtml2pdf")
    module.__dict__["pisa"] = pisa_module
    return module


class TestPdfFormatWithoutXhtml2pdf:
    """Tests when xhtml2pdf is not installed."""

    def test_format_raises_import_error_without_xhtml2pdf(self):
        report = make_report()
        with patch.dict("sys.modules", {"xhtml2pdf": None}), pytest.raises(
            ImportError, match="xhtml2pdf"
        ):
            PdfFormatter.format(report)

    def test_save_raises_import_error_without_xhtml2pdf(self, tmp_path):
        report = make_report()
        out_path = tmp_path / "report.pdf"
        with patch.dict("sys.modules", {"xhtml2pdf": None}), pytest.raises(
            ImportError, match="xhtml2pdf"
        ):
            PdfFormatter.save(report, out_path)


class TestPdfFormatWithXhtml2pdf:
    """Tests with a mocked xhtml2pdf backend."""

    def test_format_returns_pdf_bytes(self):
        report = make_report()
        module = fake_xhtml2pdf(fake_pisa())
        with patch.dict("sys.modules", {"xhtml2pdf": module}):
            assert PdfFormatter.format(report) == b"%PDF-1.4 mock"

    def test_format_passes_utf8_encoding(self):
        report = make_report()
        pisa = fake_pisa()
        module = fake_xhtml2pdf(pisa)
        with patch.dict("sys.modules", {"xhtml2pdf": module}):
            PdfFormatter.format(report)
        assert pisa.CreatePDF.call_args.kwargs["encoding"] == "utf-8"

    def test_format_raises_on_render_error(self):
        report = make_report()
        module = fake_xhtml2pdf(fake_pisa(err=1))
        with patch.dict("sys.modules", {"xhtml2pdf": module}), pytest.raises(
            RuntimeError, match="xhtml2pdf"
        ):
            PdfFormatter.format(report)

    def test_save_writes_file(self, tmp_path):
        report = make_report()
        out_path = tmp_path / "report.pdf"
        module = fake_xhtml2pdf(fake_pisa())
        with patch.dict("sys.modules", {"xhtml2pdf": module}):
            PdfFormatter.save(report, out_path)
        assert out_path.read_bytes() == b"%PDF-1.4 mock"
