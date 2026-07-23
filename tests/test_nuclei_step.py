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
        assert nuclei_step.threads == 100
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
        assert "100" in cmd
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

    def test_unknown_severity_defaults_to_info(self, nuclei_step):
        data = dict(SAMPLE_NUCLEI_FINDING)
        data["info"] = {"name": "Unknown", "severity": "unknown"}
        finding = nuclei_step._parse_nuclei_finding(data)
        assert finding.severity == "info"


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
        stderr = "timeout"
        detected, finding = nuclei_step._detect_nuclei_error(stderr, "timeout")
        assert detected
        assert "Network Error" in finding.title

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
