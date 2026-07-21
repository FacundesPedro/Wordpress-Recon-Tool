"""Tests for WhoisStep."""

from unittest.mock import MagicMock, patch

import pytest

from base.tool import ToolResult

pytestmark = pytest.mark.asyncio


class TestSkipConditions:
    """Tests for early return conditions."""

    async def test_returns_skip_finding_when_whois_not_found(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.whois_step import WhoisStep

        step = WhoisStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()

        with patch.object(WhoisStep, "check_binary", return_value=(False, "not found")):
            findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "WHOIS check skipped"
        assert findings[0].module == "passive"
        assert findings[0].severity == "low"

    async def test_returns_empty_when_no_domain(self):
        mock_target = MagicMock()
        mock_target.domain = None
        mock_config = MagicMock()

        from steps.passive.whois_step import WhoisStep

        step = WhoisStep(target=mock_target, config=mock_config)
        findings = await step.run()

        assert findings == []


class TestSuccessfulRun:
    """Tests for successful WHOIS queries."""

    async def test_parsed_data_creates_finding(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.whois_step import WhoisStep

        step = WhoisStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()
        step._tool_runner.run.return_value = ToolResult(
            stdout="Registrar: Example Registrar Inc.\nCreation Date: 2020-01-01\n",
            stderr="",
            returncode=0,
            success=True,
        )

        with patch.object(WhoisStep, "check_binary", return_value=(True, "")):
            findings = await step.run()

        whois = [f for f in findings if f.title == "WHOIS Information Retrieved"]
        assert len(whois) == 1
        assert whois[0].module == "passive"
        assert whois[0].severity == "info"

    async def test_empty_output_no_finding(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.whois_step import WhoisStep

        step = WhoisStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()
        step._tool_runner.run.return_value = ToolResult(
            stdout="No match for example.com\n",
            stderr="",
            returncode=0,
            success=True,
        )

        with patch.object(WhoisStep, "check_binary", return_value=(True, "")):
            findings = await step.run()

        whois = [f for f in findings if f.title == "WHOIS Information Retrieved"]
        assert len(whois) == 0

    async def test_failed_result_skips_parse(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.whois_step import WhoisStep

        step = WhoisStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()
        step._tool_runner.run.return_value = ToolResult(
            stdout="",
            stderr="error",
            returncode=1,
            success=False,
        )

        with patch.object(WhoisStep, "check_binary", return_value=(True, "")):
            findings = await step.run()

        whois = [f for f in findings if f.title == "WHOIS Information Retrieved"]
        assert len(whois) == 0


class TestParseOutput:
    """Tests for parse_output method."""

    async def test_null_result_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.whois_step import WhoisStep

        step = WhoisStep(target=mock_target, config=mock_config)
        findings = step.parse_output(None)
        assert findings == []

    async def test_empty_stdout_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.whois_step import WhoisStep

        step = WhoisStep(target=mock_target, config=mock_config)
        result = ToolResult(stdout="", stderr="", returncode=0, success=True)
        findings = step.parse_output(result)
        assert findings == []
