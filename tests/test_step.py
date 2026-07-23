# tests/test_step.py
"""Unit tests for base/step.py — BaseStep, BaseToolStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from base.step import BaseStep, BaseToolStep
from base.tool import ToolNotFoundError, ToolResult
from core.exceptions import ToolTimeoutError
from core.finding import Finding


# ---------------------------------------------------------------------------
# Concrete subclasses for testing
# ---------------------------------------------------------------------------
class ConcreteStep(BaseStep):
    name = "concrete"
    description = "A concrete step for testing"

    async def run(self) -> list[Finding]:
        return list(self.findings)


class ConcreteToolStep(BaseToolStep):
    _tool_binary = "testtool"
    name = "concrete_tool"
    description = "A concrete tool step"
    MODULE = "tools"

    def build_command(self) -> list[str]:
        return ["testtool", "--flag"]

    def parse_output(self, result: ToolResult) -> list[Finding]:
        return [
            Finding(
                module="tools",
                step=self.name,
                severity="info",
                title="Parsed",
                description="A parsed finding",
                evidence=result.stdout,
                recommendation="",
            )
        ]


# ---------------------------------------------------------------------------
# BaseStep
# ---------------------------------------------------------------------------
class TestBaseStep:
    def test_init_defaults(self):
        step = ConcreteStep()
        assert step.name == "ConcreteStep"
        assert step.description == "A concrete step for testing"
        assert step.target is None
        assert step.config is not None
        assert step.http is None
        assert step.findings == []

    def test_init_with_overrides(self):
        target = MagicMock()
        config = MagicMock()
        step = ConcreteStep(
            target=target,
            config=config,
            name="custom_name",
            description="custom desc",
        )
        assert step.name == "custom_name"
        assert step.description == "custom desc"
        assert step.target is target
        assert step.config is config

    def test_init_name_falls_back_to_class(self):
        step = ConcreteStep(name=None)
        assert step.name == "ConcreteStep"

    def test_init_description_falls_back_to_class(self):
        step = ConcreteStep(description=None)
        assert step.description == "A concrete step for testing"

    def test_init_config_default_when_none(self):
        step = ConcreteStep(config=None)
        assert step.config is not None

    def test_add_finding(self):
        step = ConcreteStep()
        step._add_finding(
            module="test_mod",
            severity="high",
            title="Test title",
            description="Test desc",
            evidence="evidence text",
            recommendation="fix it",
            raw={"key": "val"},
        )
        assert len(step.findings) == 1
        f = step.findings[0]
        assert f.module == "test_mod"
        assert f.severity == "high"
        assert f.title == "Test title"
        assert f.description == "Test desc"
        assert f.evidence == "evidence text"
        assert f.recommendation == "fix it"
        assert f.raw == {"key": "val"}
        assert f.step == "ConcreteStep"

    def test_add_finding_defaults(self):
        step = ConcreteStep()
        step._add_finding(module="mod", severity="low", title="T")
        f = step.findings[0]
        assert f.description == ""
        assert f.evidence == ""
        assert f.recommendation == ""
        assert f.raw == {}

    def test_add_finding_appends_multiple(self):
        step = ConcreteStep()
        step._add_finding(module="a", severity="info", title="A")
        step._add_finding(module="b", severity="medium", title="B")
        assert len(step.findings) == 2

    def test_clear_findings(self):
        step = ConcreteStep()
        step._add_finding(module="m", severity="info", title="T")
        step.clear_findings()
        assert len(step.findings) == 0

    @pytest.mark.asyncio
    async def test_run_returns_findings(self):
        step = ConcreteStep()
        step._add_finding(module="m", severity="info", title="T")
        results = await step.run()
        assert len(results) == 1


# ---------------------------------------------------------------------------
# BaseToolStep
# ---------------------------------------------------------------------------
class TestBaseToolStepInit:
    def test_init_creates_runners(self):
        step = ConcreteToolStep()
        assert step._async_tool_runner is not None
        assert step._tool_runner is not None
        assert step._version_checker is not None
        assert step._async_tool_runner._binary_path == "testtool"
        assert step._tool_runner._binary_path == "testtool"


class TestGetVersionRequirement:
    def test_no_requirements_returns_none(self):
        step = ConcreteToolStep()
        assert step.get_version_requirement() is None

    def test_required_version(self):
        step = ConcreteToolStep()
        step.required_version = "1.0.0"
        req = step.get_version_requirement()
        assert req is not None
        assert req.tool == "testtool"
        assert req.required_version == "1.0.0"

    def test_min_version(self):
        step = ConcreteToolStep()
        step.min_version = "2.0.0"
        req = step.get_version_requirement()
        assert req is not None
        assert req.min_version == "2.0.0"

    def test_max_version(self):
        step = ConcreteToolStep()
        step.max_version = "3.0.0"
        req = step.get_version_requirement()
        assert req is not None
        assert req.max_version == "3.0.0"

    def test_supported_versions(self):
        step = ConcreteToolStep()
        step.supported_versions = ["1.0", "2.0"]
        req = step.get_version_requirement()
        assert req is not None
        assert req.supported_versions == ["1.0", "2.0"]


class TestCheckVersionCompatibility:
    def test_no_requirement_returns_true(self):
        step = ConcreteToolStep()
        assert step.check_version_compatibility() is True

    def test_skip_version_check_returns_true(self):
        step = ConcreteToolStep()
        step.required_version = "1.0.0"
        step.config.skip_version_check = True
        assert step.check_version_compatibility() is True

    def test_compatible_version_returns_true(self):
        step = ConcreteToolStep()
        step.required_version = "1.0.0"
        mock_result = MagicMock()
        mock_result.is_compatible = True
        step._version_checker = MagicMock()
        step._version_checker.validate.return_value = mock_result
        assert step.check_version_compatibility() is True

    def test_incompatible_version_returns_false_and_adds_finding(self):
        step = ConcreteToolStep()
        step.required_version = "1.0.0"
        mock_result = MagicMock()
        mock_result.is_compatible = False
        mock_result.installed = "2.0.0"
        mock_result.message = "Version mismatch"
        mock_result.requirements = "== 1.0.0"
        step._version_checker = MagicMock()
        step._version_checker.validate.return_value = mock_result
        result = step.check_version_compatibility()
        assert result is False
        assert len(step.findings) == 1
        assert "Incompatible" in step.findings[0].title

    def test_verbose_version_check_logs(self):
        step = ConcreteToolStep()
        step.required_version = "1.0.0"
        step.config.verbose_version_check = True
        mock_result = MagicMock()
        mock_result.is_compatible = True
        mock_result.installed = "1.0.0"
        mock_result.requirements = "== 1.0.0"
        step._version_checker = MagicMock()
        step._version_checker.validate.return_value = mock_result
        with patch.object(step.logger, "info") as mock_info:
            assert step.check_version_compatibility() is True
            mock_info.assert_called_once()

    def test_version_mismatch_error_returns_false(self):
        from utils.tool_version_checker import VersionMismatchError

        step = ConcreteToolStep()
        step.required_version = "1.0.0"
        step._version_checker = MagicMock()
        step._version_checker.validate.side_effect = VersionMismatchError(
            tool="testtool", installed="1.0.0", required="2.0.0"
        )
        assert step.check_version_compatibility() is False


class TestCheckBinary:
    def test_binary_exists(self):
        with patch("base.tool.shutil.which", return_value="/usr/bin/testtool"):
            exists, err = ConcreteToolStep.check_binary("testtool")
            assert exists is True
            assert err == ""

    def test_binary_resolved(self):
        with patch("base.tool.shutil.which", side_effect=[None, "/usr/bin/testtool"]):
            exists, err = ConcreteToolStep.check_binary("testtool")
            assert exists is True
            assert err == ""

    def test_binary_not_found(self):
        with patch("base.tool.shutil.which", return_value=None):
            exists, err = ConcreteToolStep.check_binary("missing")
            assert exists is False
            assert "not found" in err


class TestVerifyBinary:
    def test_returns_true_when_exists(self):
        step = ConcreteToolStep()
        with patch.object(step, "check_binary", return_value=(True, "")):
            assert step.verify_binary() is True

    def test_raises_when_not_found(self):
        step = ConcreteToolStep()
        with patch.object(step, "check_binary", return_value=(False, "not found")), \
             pytest.raises(ToolNotFoundError):
            step.verify_binary()


class TestBaseToolStepRun:
    @pytest.mark.asyncio
    async def test_binary_not_found_returns_findings(self):
        step = ConcreteToolStep()
        with patch.object(step, "check_binary", return_value=(False, "not found")):
            findings = await step.run()
            assert len(findings) == 1
            assert "Not Available" in findings[0].title

    @pytest.mark.asyncio
    async def test_version_incompatible_returns_early(self):
        step = ConcreteToolStep()
        with patch.object(step, "check_binary", return_value=(True, "")), \
             patch.object(step, "check_version_compatibility", return_value=False):
            findings = await step.run()
            assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_success_calls_parse_output(self):
        step = ConcreteToolStep()
        result = ToolResult(stdout="ok", stderr="", returncode=0, success=True)
        step._async_tool_runner = MagicMock()
        step._async_tool_runner.run = AsyncMock(return_value=result)
        with patch.object(step, "check_binary", return_value=(True, "")), \
             patch.object(step, "check_version_compatibility", return_value=True):
            findings = await step.run()
            assert len(findings) == 1
            assert findings[0].title == "Parsed"

    @pytest.mark.asyncio
    async def test_tool_failed_adds_finding(self):
        step = ConcreteToolStep()
        result = ToolResult(stdout="", stderr="error msg", returncode=1, success=False)
        step._async_tool_runner = MagicMock()
        step._async_tool_runner.run = AsyncMock(return_value=result)
        with patch.object(step, "check_binary", return_value=(True, "")), \
             patch.object(step, "check_version_compatibility", return_value=True):
            findings = await step.run()
            assert len(findings) == 1
            assert "Failed" in findings[0].title
            assert "error msg" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_timeout_adds_finding(self):
        step = ConcreteToolStep()
        step._async_tool_runner = MagicMock()
        step._async_tool_runner.run = AsyncMock(side_effect=ToolTimeoutError("testtool", 10))
        with patch.object(step, "check_binary", return_value=(True, "")), \
             patch.object(step, "check_version_compatibility", return_value=True):
            findings = await step.run()
            assert len(findings) == 1
            assert "Timeout" in findings[0].title

    @pytest.mark.asyncio
    async def test_unexpected_exception_adds_finding(self):
        step = ConcreteToolStep()
        step._async_tool_runner = MagicMock()
        step._async_tool_runner.run = AsyncMock(side_effect=RuntimeError("boom"))
        with patch.object(step, "check_binary", return_value=(True, "")), \
             patch.object(step, "check_version_compatibility", return_value=True):
            findings = await step.run()
            assert len(findings) == 1
            assert "Error" in findings[0].title
