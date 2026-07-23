"""Tests for SARIF report formatter."""
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.finding import Finding
from utils.report import Report, SarifFormatter, generate_report_filename


def make_finding(severity: str, module: str = "test", step: str = "check", **kwargs) -> Finding:
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


class TestSarifDocumentStructure:
    """Tests for top-level SARIF document structure."""

    def test_document_has_required_keys(self):
        report = Report(target="https://example.com", domain="example.com")
        doc = SarifFormatter._build_document(report)

        assert "$schema" in doc
        assert doc["$schema"] == SarifFormatter.SCHEMA
        assert "version" in doc
        assert doc["version"] == "2.1.0"
        assert "runs" in doc
        assert isinstance(doc["runs"], list)

    def test_run_has_required_sections(self):
        report = Report(target="https://example.com", domain="example.com")
        doc = SarifFormatter._build_document(report)
        run = doc["runs"][0]

        assert "tool" in run
        assert "results" in run
        assert "invocations" in run
        assert "properties" in run

    def test_tool_driver_structure(self):
        report = Report(target="https://example.com", domain="example.com")
        doc = SarifFormatter._build_document(report)
        driver = doc["runs"][0]["tool"]["driver"]

        assert driver["name"] == "wp-recon-tool"
        assert driver["version"] == "1.0.0"
        assert "rules" in driver


class TestSarifRules:
    """Tests for SARIF rules array."""

    def test_rule_has_required_fields(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("medium"))
        doc = SarifFormatter._build_document(report)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        assert len(rules) == 1
        rule = rules[0]
        assert "id" in rule
        assert "shortDescription" in rule
        assert "fullDescription" in rule
        assert "defaultConfiguration" in rule
        assert "properties" in rule

    def test_duplicate_rules_collapsed(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("medium", module="test", step="check"))
        report.findings.append(make_finding("high", module="test", step="check"))
        doc = SarifFormatter._build_document(report)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        assert len(rules) == 1


class TestSarifResults:
    """Tests for SARIF results array."""

    def test_result_has_required_fields(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("high"))
        doc = SarifFormatter._build_document(report)
        results = doc["runs"][0]["results"]

        assert len(results) == 1
        result = results[0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result
        assert "properties" in result

    def test_severity_mapping_critical_to_error(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("critical"))
        doc = SarifFormatter._build_document(report)
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_severity_mapping_high_to_error(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("high"))
        doc = SarifFormatter._build_document(report)
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_severity_mapping_medium_to_warning(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("medium"))
        doc = SarifFormatter._build_document(report)
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_severity_mapping_low_to_note(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("low"))
        doc = SarifFormatter._build_document(report)
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_severity_mapping_info_to_none(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("info"))
        doc = SarifFormatter._build_document(report)
        assert doc["runs"][0]["results"][0]["level"] == "none"

    def test_finding_properties_in_result(self):
        report = Report(target="https://example.com", domain="example.com")
        f = make_finding("medium", raw={"extra": "data"})
        report.findings.append(f)
        doc = SarifFormatter._build_document(report)
        props = doc["runs"][0]["results"][0]["properties"]

        assert props["severity"] == "medium"
        assert props["module"] == "test"
        assert props["step"] == "check"
        assert props["raw"] == {"extra": "data"}


class TestSarifInvocations:
    """Tests for SARIF invocations array."""

    def test_invocation_has_timing_fields(self):
        report = Report(target="https://example.com", domain="example.com")
        doc = SarifFormatter._build_document(report)
        inv = doc["runs"][0]["invocations"][0]

        assert "startTimeUtc" in inv
        assert "endTimeUtc" in inv
        assert "executionSuccessful" in inv

    def test_execution_successful_without_errors(self):
        report = Report(target="https://example.com", domain="example.com")
        doc = SarifFormatter._build_document(report)
        assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True

    def test_execution_not_successful_with_errors(self):
        report = Report(target="https://example.com", domain="example.com", errors=["error 1"])
        doc = SarifFormatter._build_document(report)
        assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is False


class TestSarifEmptyFindings:
    """Tests for SARIF output with no findings."""

    def test_empty_findings_no_rules(self):
        report = Report(target="https://example.com", domain="example.com")
        doc = SarifFormatter._build_document(report)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]

        assert rules == []

    def test_empty_findings_no_results(self):
        report = Report(target="https://example.com", domain="example.com")
        doc = SarifFormatter._build_document(report)
        results = doc["runs"][0]["results"]

        assert results == []


class TestSarifFormatAndSave:
    """Tests for format() and save() methods."""

    def test_format_returns_valid_json(self):
        report = Report(target="https://example.com", domain="example.com")
        report.findings.append(make_finding("low"))

        result = SarifFormatter.format(report)

        parsed = json.loads(result)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 1

    def test_save_writes_file(self, tmp_path):
        report = Report(target="https://example.com", domain="example.com")
        out_path = tmp_path / "report.sarif"

        SarifFormatter.save(report, out_path)

        assert out_path.exists()
        content = out_path.read_text()
        assert '"version": "2.1.0"' in content


class TestGenerateReportFilename:
    """Tests for generate_report_filename helper."""

    def test_generates_filename_with_domain_and_timestamp(self):
        dt = datetime(2024, 3, 15, 10, 30, 0)
        name = generate_report_filename("example.com", dt)

        assert "example" in name
        assert "com" in name
        assert "20240315" in name
        assert "103000" in name

    def test_replaces_dots_and_colons(self):
        dt = datetime(2024, 1, 1, 0, 0, 0)
        name = generate_report_filename("my.site.com:8080", dt)

        assert "my_site_com_8080" in name
