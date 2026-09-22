"""Tests for HtmlFormatter report output."""
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
        assert 'class="wrap"' in html


class TestHtmlSummary:
    """Tests for the severity ledger and distribution."""

    def test_severity_ledger_section_present(self):
        html = HtmlFormatter.format(make_report())
        assert "Severity Ledger" in html

    def test_shows_severity_labels_in_legend(self):
        findings = [
            make_finding("critical"),
            make_finding("high"),
            make_finding("medium"),
            make_finding("low"),
            make_finding("info"),
        ]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Critical" in html
        assert "High" in html
        assert "Medium" in html
        assert "Low" in html
        assert "Info" in html

    def test_total_count_in_ledger(self):
        findings = [make_finding("high"), make_finding("medium")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "2 total" in html
        assert "Severity Ledger" in html


class TestHtmlModulesRun:
    """Tests for the scope/modules section."""

    def test_modules_section_present_when_modules_exist(self):
        html = HtmlFormatter.format(make_report(modules=["access", "discovery"]))
        assert "Modules run" in html
        assert "access" in html
        assert "discovery" in html

    def test_modules_section_shows_none_when_empty(self):
        html = HtmlFormatter.format(make_report())
        assert "Modules run" in html
        assert '<span class="module-tag">none</span>' in html


class TestHtmlFindings:
    """Tests for findings rendering."""

    def test_critical_and_high_findings_section(self):
        findings = [make_finding("critical"), make_finding("high")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Critical &amp; High" in html

    def test_medium_and_low_findings_section(self):
        findings = [make_finding("medium"), make_finding("low")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Medium &amp; Low" in html

    def test_info_findings_section(self):
        findings = [make_finding("info")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Informational" in html

    def test_finding_shows_severity_badge(self):
        findings = [make_finding("high")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert 'class="sev-tag sev-high"' in html
        assert ">High<" in html

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
        assert 'class="evidence"' in html

    def test_finding_shows_recommendation(self):
        f = make_finding("high", recommendation="recommended action")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "recommended action" in html
        assert "Recommendation" in html

    def test_finding_no_evidence_omits_evidence_block(self):
        f = make_finding("high", evidence="")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert 'class="evidence"' not in html

    def test_finding_no_recommendation_omits_rec(self):
        f = make_finding("high", recommendation="")
        html = HtmlFormatter.format(make_report(findings=[f]))
        assert "Recommendation" not in html

    def test_multiple_findings_all_rendered(self):
        findings = [make_finding("high"), make_finding("high")]
        html = HtmlFormatter.format(make_report(findings=findings))
        assert "Critical &amp; High" in html
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
        assert 'class="errors"' not in html


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
        assert "Info" in content
