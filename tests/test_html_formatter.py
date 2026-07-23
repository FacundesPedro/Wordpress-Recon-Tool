"""Tests for HtmlFormatter report output."""
from pathlib import Path

from core.finding import Finding
from utils.report import HtmlFormatter, Report


def make_report(findings=None, modules=None, errors=None):
    report = Report(target="https://example.com", domain="example.com")
    if findings:
        report.findings = findings
    if modules:
        report.modules_run = modules
    if errors:
        report.errors = errors
    return report


def make_finding(severity: str, module="test", step="check", **kwargs):
    defaults = dict(
        module=module,
        step=step,
        severity=severity,
        title=f"Test {severity} finding",
        description=f"A {severity} severity test finding",
        evidence="evidence text",
        recommendation="fix it",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestHtmlDocumentStructure:
    """Tests for top-level HTML document structure."""

    def test_contains_doctype(self):
        html = HtmlFormatter.format(make_report())
        assert html.startswith("<!DOCTYPE html>")

    def test_contains_html_tag(self):
        html = HtmlFormatter.format(make_report())
        assert "<html" in html

    def test_contains_title_with_domain(self):
        html = HtmlFormatter.format(make_report())
        assert "example.com" in html

    def test_contains_stylesheet(self):
        html = HtmlFormatter.format(make_report())
        assert "<style>" in html

    def test_contains_container_div(self):
        html = HtmlFormatter.format(make_report())
        assert 'class="container"' in html


class TestHtmlSummary:
    """Tests for dashboard and severity distribution."""

    def test_severity_distribution_section_present(self):
        html = HtmlFormatter.format(make_report())
        assert "Severity Distribution" in html

    def test_shows_severity_counts_in_cards(self):
        findings = [
            make_finding("critical"),
            make_finding("high"),
            make_finding("medium"),
            make_finding("low"),
            make_finding("info"),
        ]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "CRITICAL" in html
        assert "HIGH" in html
        assert "MEDIUM" in html
        assert "LOW" in html
        assert "INFO" in html

    def test_total_count_in_donut_or_overview(self):
        findings = [make_finding("high"), make_finding("medium")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "2" in html
        assert "Total Findings" in html


class TestHtmlModulesRun:
    """Tests for modules run section."""

    def test_modules_section_present_when_modules_exist(self):
        html = HtmlFormatter.format(make_report(modules=["access", "discovery"]))
        assert "Modules Run" in html
        assert "access" in html
        assert "discovery" in html

    def test_modules_section_absent_when_no_modules(self):
        html = HtmlFormatter.format(make_report())
        assert "Modules Run" not in html


class TestHtmlFindings:
    """Tests for findings rendering."""

    def test_critical_and_high_findings_section(self):
        findings = [make_finding("critical"), make_finding("high")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Critical &amp; High Findings" in html

    def test_medium_and_low_findings_section(self):
        findings = [make_finding("medium"), make_finding("low")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Medium &amp; Low Findings" in html

    def test_info_findings_section(self):
        findings = [make_finding("info")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Informational" in html

    def test_finding_shows_severity_badge(self):
        findings = [make_finding("high")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "HIGH" in html

    def test_finding_shows_title(self):
        findings = [make_finding("medium")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Test medium finding" in html

    def test_finding_shows_module_step(self):
        findings = [make_finding("low", module="test_module", step="test_step")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "test_module / test_step" in html

    def test_finding_shows_description(self):
        findings = [make_finding("info")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "A info severity test finding" in html

    def test_finding_shows_evidence_in_evidence_block(self):
        f = make_finding("high", evidence="important evidence content")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "important evidence content" in html

    def test_finding_shows_recommendation(self):
        f = make_finding("high", recommendation="recommended action")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "recommended action" in html
        assert "Recommendation" in html

    def test_finding_no_evidence_omits_evidence_block(self):
        f = make_finding("high", evidence="")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert 'class="fc-evidence"' not in html

    def test_finding_no_recommendation_omits_rec(self):
        f = make_finding("high", recommendation="")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "Recommendation" not in html

    def test_multiple_findings_all_rendered(self):
        findings = [make_finding("high"), make_finding("high")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Critical &amp; High Findings" in html
        assert html.count("Test high finding") == 2


class TestHtmlNoFindings:
    """Tests for empty reports."""

    def test_empty_report_no_findings_sections(self):
        html = HtmlFormatter.format(make_report())
        assert "Critical" not in html
        assert "Medium" not in html
        assert "Informational" not in html


class TestHtmlErrors:
    """Tests for errors section."""

    def test_errors_section_present(self):
        html = HtmlFormatter.format(make_report(errors=["error 1"]))
        assert "Errors" in html
        assert "error 1" in html

    def test_errors_section_absent_when_no_errors(self):
        html = HtmlFormatter.format(make_report())
        assert 'class="errors-section"' not in html


class TestHtmlEscape:
    """Tests for HTML entity escaping."""

    def test_escapes_html_in_finding_title(self):
        f = make_finding("high", title="Title with <script>alert('xss')</script>")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_escapes_html_in_evidence(self):
        f = make_finding("high", evidence="Text with <tag>")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "<tag>" not in html
        assert "&lt;tag&gt;" in html

    def test_escapes_html_in_description(self):
        f = make_finding("high", description='Description with "quotes"')
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "&quot;" in html


class TestHtmlSave:
    """Tests for save method."""

    def test_save_writes_file(self, tmp_path):
        report = make_report(findings=[make_finding("info")])
        out_path = tmp_path / "report.html"
        HtmlFormatter.save(report, out_path)
        assert out_path.exists()
        content = out_path.read_text()
        assert "<!DOCTYPE html>" in content
        assert "INFO" in content
