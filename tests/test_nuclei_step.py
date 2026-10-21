"""Tests for NucleiStep."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.target import Target
from steps.tools.nuclei_step import NucleiStep


@pytest.fixture
def mock_config():
    return MagicMock(spec=ScanConfig)


@pytest.fixture
def mock_target():
    return Target(url="https://example.com", domain="example.com")


@pytest.fixture
def nuclei_step(mock_target, mock_config):
    return NucleiStep(target=mock_target, config=mock_config)


@pytest.fixture
def nuclei_step_custom(mock_target, mock_config):
    return NucleiStep(
        target=mock_target,
        config=mock_config,
        severity="high,critical",
        threads=50,
        timeout=120,
    )


class TestInit:
    def test_defaults(self, nuclei_step):
        assert nuclei_step.name == "nuclei"
        assert nuclei_step._tool_binary == "nuclei"
        assert nuclei_step.severity_filter == "medium,high,critical"
        assert nuclei_step.threads == 25
        assert nuclei_step.rate_limit == 150
        assert nuclei_step.timeout == 300

    def test_custom_params(self, nuclei_step_custom):
        assert nuclei_step_custom.severity_filter == "high,critical"
        assert nuclei_step_custom.threads == 50
        assert nuclei_step_custom.timeout == 120


class TestBuildCommand:
    def test_default_command(self, nuclei_step):
        cmd = nuclei_step.build_command()
        assert cmd[0] == "nuclei"
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-severity" in cmd
        assert "medium,high,critical" in cmd
        assert "-jsonl" in cmd
        assert "-concurrency" in cmd
        assert "25" in cmd
        assert "-rl" in cmd
        assert "150" in cmd
        assert "-silent" in cmd
        assert "-quiet" not in cmd

    def test_quiet_flag(self, mock_target, mock_config):
        mock_config.quiet = True
        step = NucleiStep(target=mock_target, config=mock_config)
        cmd = step.build_command()
        assert "-quiet" in cmd

    def test_custom_severity(self, nuclei_step_custom):
        cmd = nuclei_step_custom.build_command()
        assert "-severity" in cmd
        assert "high,critical" in cmd
        assert "-concurrency" in cmd
        assert "50" in cmd

    def test_pinned_target_passes_sni_and_host(self, mock_config):
        target = Target(
            url="https://example.com",
            domain="example.com",
            connect_ip="10.0.0.1",
        )
        step = NucleiStep(target=target, config=mock_config)
        cmd = step.build_command()
        assert "-sni" in cmd
        assert cmd[cmd.index("-sni") + 1] == "example.com"
        assert "-H" in cmd
        assert "Host: example.com" in cmd

    def test_stats_flags_with_real_config(self, mock_target, tmp_path):
        config = ScanConfig(output_dir=tmp_path)
        step = NucleiStep(target=mock_target, config=config)
        cmd = step.build_command()
        assert "-stats" in cmd
        assert "-si" in cmd

    def test_stats_can_be_disabled(self, mock_target, tmp_path):
        config = ScanConfig(output_dir=tmp_path, nuclei_stats=False)
        step = NucleiStep(target=mock_target, config=config)
        assert "-stats" not in step.build_command()


class TestParseNucleiStats:
    def test_json_stats_block(self):
        from steps.tools.nuclei_step import parse_nuclei_stats

        stderr = (
            "[INF] started\n"
            '{"templates": 120, "requests": 350, "matched": 0, "errors": 1}\n'
            '{"templates": 120, "requests": 400, "matched": 2, "errors": 1}\n'
        )
        stats = parse_nuclei_stats(stderr)
        assert stats["requests"] == 400
        assert stats["templates"] == 120
        assert stats["matched"] == 2

    def test_no_stats(self):
        from steps.tools.nuclei_step import parse_nuclei_stats

        assert parse_nuclei_stats("") == {}
        assert parse_nuclei_stats("[INF] no json here") == {}

    @pytest.mark.asyncio
    @patch("steps.tools.nuclei_step.NucleiStep.check_binary")
    async def test_zero_result_summary_records_coverage(self, mock_check, nuclei_step):
        mock_check.return_value = (True, "")
        nuclei_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout="",
                stderr='{"templates": 90, "requests": 210, "matched": 0}',
                returncode=0,
                success=True,
            )
        )
        findings = await nuclei_step.run()
        completed = next(f for f in findings if f.title == "Nuclei Completed")
        assert completed.raw["coverage_verified"] is True
        assert completed.raw["stats"]["templates"] == 90
        assert "templates=90" in completed.description


SAMPLE_NUCLEI_FINDING = {
    "template-id": "wordpress-xss",
    "info": {
        "name": "WordPress XSS Detected",
        "severity": "high",
        "description": "Cross-site scripting in WordPress",
        "remediation": "Update WordPress to latest version",
        "tags": ["wordpress", "xss"],
        "template-id": "wordpress-xss",
        "matched-at": "https://example.com/wp-admin",
    },
    "matched-at": "https://example.com/wp-admin",
}


class TestParseNucleiFinding:
    def test_high_severity(self, nuclei_step):
        finding = nuclei_step._parse_nuclei_finding(SAMPLE_NUCLEI_FINDING)
        assert finding is not None
        assert "Nuclei: WordPress XSS Detected" in finding.title
        assert finding.severity == "high"
        assert "Cross-site scripting" in finding.description
        assert "Update WordPress" in finding.recommendation
        assert "wordpress-xss" in finding.raw["template_id"]

    def test_info_severity(self, nuclei_step):
        data = dict(SAMPLE_NUCLEI_FINDING)
        data["info"] = {"name": "Info finding", "severity": "info"}
        finding = nuclei_step._parse_nuclei_finding(data)
        assert finding.severity == "info"

    def test_unknown_severity_defaults_to_low(self, nuclei_step):
        data = dict(SAMPLE_NUCLEI_FINDING)
        data["info"] = {"name": "Unknown", "severity": "unknown"}
        finding = nuclei_step._parse_nuclei_finding(data)
        assert finding.severity == "low"
        assert finding.raw["severity_unknown"] is True

    def test_missing_severity_defaults_to_low(self, nuclei_step):
        data = dict(SAMPLE_NUCLEI_FINDING)
        data["info"] = {"name": "No severity"}
        finding = nuclei_step._parse_nuclei_finding(data)
        assert finding.severity == "low"
        assert finding.raw["severity_unknown"] is True


class TestParseOutput:
    def test_empty_stdout(self, nuclei_step):
        result = ToolResult(stdout="", stderr="", returncode=0, success=True)
        findings = nuclei_step.parse_output(result)
        assert len(findings) == 0

    def test_stdout_with_stderr_no_templates(self, nuclei_step):
        result = ToolResult(
            stdout="", stderr="no templates found", returncode=0, success=True
        )
        findings = nuclei_step.parse_output(result)
        assert len(findings) == 0

    def test_single_finding(self, nuclei_step):
        result = ToolResult(
            stdout=json.dumps(SAMPLE_NUCLEI_FINDING),
            stderr="",
            returncode=0,
            success=True,
        )
        findings = nuclei_step.parse_output(result)
        assert len(findings) == 1
        assert "Nuclei: WordPress XSS Detected" in findings[0].title

    def test_multiple_findings(self, nuclei_step):
        data = [SAMPLE_NUCLEI_FINDING, SAMPLE_NUCLEI_FINDING]
        output = "\n".join(json.dumps(f) for f in data)
        result = ToolResult(stdout=output, stderr="", returncode=0, success=True)
        findings = nuclei_step.parse_output(result)
        assert len(findings) == 2

    def test_skips_invalid_lines(self, nuclei_step):
        output = "not json\n" + json.dumps(SAMPLE_NUCLEI_FINDING)
        result = ToolResult(stdout=output, stderr="", returncode=0, success=True)
        findings = nuclei_step.parse_output(result)
        assert len(findings) == 1

    def test_no_findings_fallback(self, nuclei_step):
        result = ToolResult(
            stdout="[Nuclei] Scan completed with no findings",
            stderr="",
            returncode=0,
            success=True,
        )
        findings = nuclei_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "Nuclei Completed"
        assert findings[0].severity == "info"

    def test_unparseable_output_emits_finding(self, nuclei_step):
        result = ToolResult(
            stdout="{not valid json",
            stderr="",
            returncode=0,
            success=True,
        )
        findings = nuclei_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "Nuclei Output Unparseable"
        assert findings[0].severity == "medium"
        assert findings[0].raw["operational"] is True


class TestDetectNucleiError:
    def test_no_templates_error(self, nuclei_step):
        stderr = "no templates found"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, "")
        assert detected
        assert "Templates Missing" in finding.title

    def test_connection_refused(self, nuclei_step):
        stderr = "connection refused"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, "")
        assert detected
        assert "Network Error" in finding.title

    def test_timeout(self, nuclei_step):
        # A network error only short-circuits the scan when nothing was produced.
        stderr = "timeout"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, "")
        assert detected
        assert "Network Error" in finding.title

    def test_timeout_with_results_is_not_a_network_error(self, nuclei_step):
        stderr = "timeout"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, '{"info": {}}')
        assert not detected
        assert finding is None

    def test_unknown_flag(self, nuclei_step):
        stderr = "unknown flag: -xyz"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, "")
        assert detected
        assert "Flag Error" in finding.title

    def test_permission_denied(self, nuclei_step):
        stderr = "permission denied"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, "")
        assert detected
        assert "Permission Error" in finding.title

    def test_eacces(self, nuclei_step):
        stderr = "eacces"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, "")
        assert detected
        assert "Permission Error" in finding.title

    def test_no_error(self, nuclei_step):
        stderr = ""
        stdout = '{"matched-at": "https://example.com"}'
        detected, finding = nuclei_step._detect_nuclei_error(stderr, stdout)
        assert not detected
        assert finding is None


class TestRun:
    @patch("steps.tools.nuclei_step.NucleiStep.check_binary")
    async def test_binary_not_found(self, mock_check, nuclei_step):
        mock_check.return_value = (False, "nuclei not found")
        findings = await nuclei_step.run()
        assert len(findings) == 1
        assert "Nuclei Not Available" in findings[0].title

    @patch("steps.tools.nuclei_step.NucleiStep.check_binary")
    async def test_timeout(self, mock_check, nuclei_step):
        mock_check.return_value = (True, "")
        nuclei_step._async_tool_runner.run = AsyncMock(
            side_effect=ToolTimeoutError("nuclei", 300)
        )
        findings = await nuclei_step.run()
        assert len(findings) == 1
        assert "Nuclei Timeout" in findings[0].title

    @patch("steps.tools.nuclei_step.NucleiStep.check_binary")
    async def test_unexpected_exception(self, mock_check, nuclei_step):
        mock_check.return_value = (True, "")
        nuclei_step._async_tool_runner.run = AsyncMock(
            side_effect=RuntimeError("boom")
        )
        findings = await nuclei_step.run()
        assert len(findings) == 1
        assert "Nuclei Error" in findings[0].title

    @patch("steps.tools.nuclei_step.NucleiStep.check_binary")
    async def test_successful_run(self, mock_check, nuclei_step):
        mock_check.return_value = (True, "")
        nuclei_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout=json.dumps(SAMPLE_NUCLEI_FINDING),
                stderr="",
                returncode=0,
                success=True,
            )
        )
        findings = await nuclei_step.run()
        assert len(findings) == 1
        assert "Nuclei: WordPress XSS Detected" in findings[0].title

    @patch("steps.tools.nuclei_step.NucleiStep.check_binary")
    async def test_detected_error_in_run(self, mock_check, nuclei_step):
        mock_check.return_value = (True, "")
        nuclei_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout="",
                stderr="no templates found",
                returncode=1,
                success=False,
            )
        )
        findings = await nuclei_step.run()
        assert len(findings) == 1
        assert "Templates Missing" in findings[0].title

    @patch("steps.tools.nuclei_step.NucleiStep.check_binary")
    async def test_run_with_errors(self, mock_check, nuclei_step):
        mock_check.return_value = (True, "")
        nuclei_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout="", stderr="error occurred", returncode=1, success=False
            )
        )
        findings = await nuclei_step.run()
        assert len(findings) == 1
        assert "Nuclei Execution Failed" in findings[0].title
