"""Tests for finding evidence sanitization and the evidence bundle."""

from pathlib import Path

from core.finding import Finding
from utils.evidence_bundle import (
    attach_commands,
    render_evidence_markdown,
    write_evidence_bundle,
)


def make_finding(**overrides):
    defaults = dict(
        module="tools",
        step="wpscan",
        severity="high",
        title="Plugin Vulnerable",
        description="desc",
        evidence="evidence",
        recommendation="update",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestFindingSanitization:
    def test_strips_ansi_and_box_from_evidence(self):
        finding = make_finding(
            evidence="\x1b[96m╔══════╗\x1b[0m\n║ error: boom ║\n╚══════╝"
        )
        assert "\x1b" not in finding.evidence
        assert "╔" not in finding.evidence
        assert "error: boom" in finding.evidence

    def test_strips_ansi_from_description(self):
        finding = make_finding(description="\x1b[91mred text\x1b[0m")
        assert finding.description == "red text"

    def test_with_command_is_immutable(self):
        finding = make_finding()
        updated = finding.with_command("nuclei -u https://x")
        assert finding.command == ""
        assert updated.command == "nuclei -u https://x"
        assert updated.title == finding.title

    def test_command_serialized(self):
        finding = make_finding().with_command("ffuf -u https://x/FUZZ")
        assert finding.to_dict()["command"] == "ffuf -u https://x/FUZZ"


class TestAttachCommands:
    def test_reads_step_cmd(self, tmp_path):
        raw = tmp_path / "raw"
        raw.mkdir()
        (raw / "wpscan.cmd").write_text(
            "wpscan --url https://x --api-token <REDACTED>\n"
        )
        config = type("C", (), {"output_dir": tmp_path, "raw_output_dir": ""})()
        findings = attach_commands([make_finding()], config)
        assert "wpscan --url" in findings[0].command
        assert "REDACTED" in findings[0].command

    def test_missing_cmd_leaves_empty(self, tmp_path):
        config = type("C", (), {"output_dir": tmp_path, "raw_output_dir": ""})()
        findings = attach_commands([make_finding()], config)
        assert findings[0].command == ""

    def test_custom_raw_dir(self, tmp_path):
        raw = tmp_path / "custom"
        raw.mkdir()
        (raw / "wpscan.cmd").write_text("wpscan --url https://x\n")
        config = type(
            "C", (), {"output_dir": tmp_path, "raw_output_dir": str(raw)}
        )()
        assert "wpscan" in attach_commands([make_finding()], config)[0].command


class TestRenderBundle:
    def test_includes_command_artifact_and_excerpt(self, tmp_path):
        raw = tmp_path / "raw"
        raw.mkdir()
        (raw / "wpscan.cmd").write_text("wpscan --url https://x\n")
        (raw / "wpscan.output").write_text(
            "# step: wpscan\n########## stdout ##########\n"
            "Plugin: cf7 | Version: 6.1.7\n"
        )
        config = type(
            "C", (), {"output_dir": tmp_path, "raw_output_dir": "", "save_raw": True}
        )()
        finding = make_finding(evidence="Plugin: cf7 | Version: 6.1.7")
        markdown = render_evidence_markdown([finding], config, target="https://x")
        assert "# Evidências por achado" in markdown
        assert "wpscan --url https://x" in markdown
        assert "wpscan.output" in markdown
        assert "Plugin: cf7" in markdown

    def test_no_findings(self, tmp_path):
        config = type("C", (), {"output_dir": tmp_path, "raw_output_dir": ""})()
        assert "Nenhum achado" in render_evidence_markdown([], config)

    def test_write_bundle(self, tmp_path):
        config = type("C", (), {"output_dir": tmp_path, "raw_output_dir": ""})()
        path = write_evidence_bundle(
            [make_finding()], config, tmp_path / "EVIDENCIAS.md"
        )
        assert path is not None and path.exists()
        assert "Evidências" in path.read_text(encoding="utf-8")


class TestReportEvidenceIndex:
    def _report(self):
        from utils.report import Report

        finding = make_finding().with_command("wpscan --url https://x")
        return Report(
            target="https://x", domain="x", findings=[finding]
        )

    def test_markdown_report_index(self):
        from utils.report import MarkdownFormatter

        markdown = MarkdownFormatter.format(self._report())
        assert "Evidence Index" in markdown
        assert "wpscan --url https://x" in markdown
        assert "raw/wpscan.output" in markdown

    def test_html_report_index(self):
        from utils.report import HtmlFormatter

        html = HtmlFormatter.format(self._report())
        assert "Evidence Index" in html
        assert "wpscan --url https://x" in html

    def test_no_index_without_commands(self):
        from utils.report import MarkdownFormatter, Report

        report = Report(
            target="https://x", domain="x", findings=[make_finding()]
        )
        assert "Evidence Index" not in MarkdownFormatter.format(report)
