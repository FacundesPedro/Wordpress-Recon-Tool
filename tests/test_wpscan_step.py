"""Tests for WpscanStep."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.target import Target
from steps.tools.wpscan_step import WpscanStep


@pytest.fixture
def mock_config():
    return MagicMock(spec=ScanConfig)


@pytest.fixture
def mock_target():
    return Target(url="https://example.com", domain="example.com")


@pytest.fixture
def wpscan_step(mock_target, mock_config):
    return WpscanStep(target=mock_target, config=mock_config)


@pytest.fixture
def wpscan_step_with_token(mock_target, mock_config):
    return WpscanStep(
        target=mock_target,
        config=mock_config,
        api_token="test-token-123",
        enumerate="vp,vt",
        timeout=120,
    )


class TestInit:
    def test_defaults(self, wpscan_step):
        assert wpscan_step.name == "wpscan"
        assert wpscan_step._tool_binary == "wpscan"
        assert wpscan_step.enumerate == "vp,vt,tt,cb,u"
        assert wpscan_step.timeout == 600

    def test_custom_params(self, wpscan_step_with_token):
        assert wpscan_step_with_token.api_token == "test-token-123"
        assert wpscan_step_with_token.enumerate == "vp,vt"
        assert wpscan_step_with_token.timeout == 120


class TestBuildCommand:
    def test_with_token(self, wpscan_step_with_token):
        cmd = wpscan_step_with_token.build_command()
        assert cmd[0] == "wpscan"
        assert "--url" in cmd
        assert "https://example.com" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert "--api-token" in cmd
        assert "test-token-123" in cmd
        assert "--enumerate" in cmd
        assert "vp,vt" in cmd
        assert "--random-user-agent" in cmd

    def test_without_token(self, wpscan_step):
        cmd = wpscan_step.build_command()
        assert "--api-token" not in cmd

    def test_insecure_flag(self, mock_target, mock_config):
        mock_config.insecure = True
        step = WpscanStep(target=mock_target, config=mock_config, api_token="tok")
        cmd = step.build_command()
        assert "--disable-tls-checks" in cmd

    def test_quiet_flag(self, mock_target, mock_config):
        mock_config.quiet = True
        step = WpscanStep(target=mock_target, config=mock_config, api_token="tok")
        cmd = step.build_command()
        assert "--quiet" in cmd


SAMPLE_VERSION = {"number": "6.4.2", "vulnerabilities": []}
SAMPLE_VERSION_VULN = {
    "number": "5.8.0",
    "vulnerabilities": [
        {"title": "XSS vulnerability", "type": "XSS"}
    ],
}
SAMPLE_PLUGIN = {
    "akismet": {
        "version": "5.3",
        "vulnerabilities": [],
        "location": "wp-content/plugins/akismet",
        "confidence": "100",
    }
}
SAMPLE_PLUGIN_VULN = {
    "contact-form-7": {
        "version": "5.0",
        "vulnerabilities": [
            {"title": "SQL Injection", "type": "SQLi"}
        ],
        "location": "wp-content/plugins/contact-form-7",
        "confidence": "100",
    }
}
SAMPLE_THEME = {
    "twentytwentyfour": {
        "version": "1.0",
        "vulnerabilities": [],
        "location": "wp-content/themes/twentytwentyfour",
    }
}
SAMPLE_THEME_VULN = {
    "astra": {
        "version": "3.0",
        "vulnerabilities": [
            {"title": "Stored XSS", "type": "XSS"}
        ],
        "location": "wp-content/themes/astra",
    }
}
SAMPLE_USERS = {
    "1": {"username": "admin", "id": 1, "roles": ["administrator"]},
    "2": {"username": "editor", "id": 2, "roles": ["editor"]},
}
SAMPLE_ENTRIES = [
    "wp-config.bak",
    "some-other-file.txt",
]
SAMPLE_TIMTHUMBS = ["wp-content/plugins/timthumb/timthumb.php"]


class TestParseVersion:
    def test_no_version(self, wpscan_step):
        findings = wpscan_step._parse_version({})
        assert len(findings) == 0

    def test_version_found(self, wpscan_step):
        findings = wpscan_step._parse_version({"version": SAMPLE_VERSION})
        assert len(findings) == 1
        assert findings[0].title == "WordPress Version Detected: 6.4.2"
        assert findings[0].severity == "info"

    def test_version_with_vulns(self, wpscan_step):
        findings = wpscan_step._parse_version({"version": SAMPLE_VERSION_VULN})
        assert len(findings) == 1
        assert "Vulnerable" in findings[0].title
        assert findings[0].severity == "high"


class TestParsePlugins:
    def test_no_plugins(self, wpscan_step):
        findings = wpscan_step._parse_plugins({})
        assert len(findings) == 0

    def test_plugin_found(self, wpscan_step):
        findings = wpscan_step._parse_plugins({"plugins": SAMPLE_PLUGIN})
        assert len(findings) == 1
        assert findings[0].title == "Plugin Detected: akismet"
        assert findings[0].severity == "info"

    def test_plugin_vulnerable(self, wpscan_step):
        findings = wpscan_step._parse_plugins({"plugins": SAMPLE_PLUGIN_VULN})
        assert len(findings) == 1
        assert "Plugin Vulnerable: contact-form-7" in findings[0].title
        assert findings[0].severity == "critical"


class TestParseThemes:
    def test_no_themes(self, wpscan_step):
        findings = wpscan_step._parse_themes({})
        assert len(findings) == 0

    def test_theme_found(self, wpscan_step):
        findings = wpscan_step._parse_themes({"themes": SAMPLE_THEME})
        assert len(findings) == 1
        assert findings[0].title == "Theme Detected: twentytwentyfour"
        assert findings[0].severity == "info"

    def test_theme_vulnerable(self, wpscan_step):
        findings = wpscan_step._parse_themes({"themes": SAMPLE_THEME_VULN})
        assert len(findings) == 1
        assert "Theme Vulnerable: astra" in findings[0].title
        assert findings[0].severity == "high"


class TestParseUsers:
    def test_no_users(self, wpscan_step):
        findings = wpscan_step._parse_users({})
        assert len(findings) == 0

    def test_users_found(self, wpscan_step):
        findings = wpscan_step._parse_users({"users": SAMPLE_USERS})
        assert len(findings) == 2
        assert findings[0].title == "User Found: admin"
        assert findings[1].title == "User Found: editor"

    def test_user_with_roles(self, wpscan_step):
        findings = wpscan_step._parse_users({"users": SAMPLE_USERS})
        assert "administrator" in findings[0].evidence


class TestParseConfigBackups:
    def test_no_entries(self, wpscan_step):
        findings = wpscan_step._parse_config_backups({})
        assert len(findings) == 0

    def test_config_entry_detected(self, wpscan_step):
        data = {"interesting_entries": SAMPLE_ENTRIES}
        findings = wpscan_step._parse_config_backups(data)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "wp-config.bak" in findings[0].evidence

    def test_non_config_entry_skipped(self, wpscan_step):
        data = {"interesting_entries": ["readme.html"]}
        findings = wpscan_step._parse_config_backups(data)
        assert len(findings) == 0


class TestParseTimthumbs:
    def test_no_timthumbs(self, wpscan_step):
        findings = wpscan_step._parse_timthumbs({})
        assert len(findings) == 0

    def test_timthumb_detected(self, wpscan_step):
        data = {"timthumbs": SAMPLE_TIMTHUMBS}
        findings = wpscan_step._parse_timthumbs(data)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "Timthumb" in findings[0].title


class TestParseOutput:
    def test_empty_stdout(self, wpscan_step):
        result = ToolResult(stdout="", stderr="", returncode=0, success=True)
        findings = wpscan_step.parse_output(result)
        assert len(findings) == 0

    def test_invalid_json(self, wpscan_step):
        result = ToolResult(stdout="not json", stderr="", returncode=0, success=True)
        findings = wpscan_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "WPScan Output Parse Error"

    def test_full_output(self, wpscan_step):
        data = {
            "version": SAMPLE_VERSION,
            "plugins": SAMPLE_PLUGIN,
            "themes": SAMPLE_THEME,
            "users": SAMPLE_USERS,
        }
        result = ToolResult(
            stdout=json.dumps(data), stderr="", returncode=0, success=True
        )
        findings = wpscan_step.parse_output(result)
        assert len(findings) == 5

    def test_no_findings_fallback(self, wpscan_step):
        result = ToolResult(
            stdout=json.dumps({}), stderr="", returncode=0, success=True
        )
        findings = wpscan_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "WPScan Completed"


class TestDetectWpscanError:
    def test_readline_error(self, wpscan_step):
        stderr = "cannot load such file -- readline"
        detected, finding = wpscan_step._detect_wpscan_error(stderr, "")
        assert detected
        assert finding is not None
        assert "Ruby Readline" in finding.title

    def test_binary_not_found(self, wpscan_step):
        stderr = "No such file or directory - wpscan"
        detected, finding = wpscan_step._detect_wpscan_error(stderr, "")
        assert detected
        assert "Binary Not Found" in finding.title

    def test_permission_denied(self, wpscan_step):
        stderr = "permission denied"
        detected, finding = wpscan_step._detect_wpscan_error(stderr, "")
        assert detected
        assert "Permission Denied" in finding.title

    def test_no_error(self, wpscan_step):
        stderr = ""
        stdout = '{"version": {"number": "6.4.2"}}'
        detected, finding = wpscan_step._detect_wpscan_error(stderr, stdout)
        assert not detected
        assert finding is None


class TestRun:
    @patch("steps.tools.wpscan_step.WpscanStep.check_binary")
    async def test_binary_not_found(self, mock_check, wpscan_step):
        mock_check.return_value = (False, "wpscan not found")
        findings = await wpscan_step.run()
        assert len(findings) == 1
        assert "WPScan Not Available" in findings[0].title

    @patch("steps.tools.wpscan_step.WpscanStep.check_binary")
    async def test_timeout(self, mock_check, wpscan_step):
        mock_check.return_value = (True, "")
        wpscan_step._async_tool_runner.run = AsyncMock(
            side_effect=ToolTimeoutError("wpscan", 600)
        )
        findings = await wpscan_step.run()
        assert len(findings) == 1
        assert "WPScan Timeout" in findings[0].title

    @patch("steps.tools.wpscan_step.WpscanStep.check_binary")
    async def test_unexpected_exception(self, mock_check, wpscan_step):
        mock_check.return_value = (True, "")
        wpscan_step._async_tool_runner.run = AsyncMock(
            side_effect=RuntimeError("boom")
        )
        findings = await wpscan_step.run()
        assert len(findings) == 1
        assert "WPScan Error" in findings[0].title

    @patch("steps.tools.wpscan_step.WpscanStep.check_binary")
    async def test_successful_run(self, mock_check, wpscan_step):
        mock_check.return_value = (True, "")
        data = {"version": SAMPLE_VERSION}
        wpscan_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout=json.dumps(data), stderr="", returncode=0, success=True
            )
        )
        findings = await wpscan_step.run()
        assert len(findings) == 1
        assert "Version Detected" in findings[0].title

    @patch("steps.tools.wpscan_step.WpscanStep.check_binary")
    async def test_detected_error_in_run(self, mock_check, wpscan_step):
        mock_check.return_value = (True, "")
        wpscan_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout="",
                stderr="cannot load such file -- readline",
                returncode=1,
                success=False,
            )
        )
        findings = await wpscan_step.run()
        assert len(findings) == 1
        assert "Ruby Readline Error" in findings[0].title

    @patch("steps.tools.wpscan_step.WpscanStep.check_binary")
    async def test_run_with_errors(self, mock_check, wpscan_step):
        mock_check.return_value = (True, "")
        wpscan_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout="", stderr="error occurred", returncode=1, success=False
            )
        )
        findings = await wpscan_step.run()
        assert len(findings) == 1
        assert "WPScan Execution Failed" in findings[0].title
