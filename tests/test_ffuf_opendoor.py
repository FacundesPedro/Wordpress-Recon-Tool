"""Tests for FFUF and OpenDoor steps."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from base.tool import ToolResult
from config import ScanConfig
from core.target import Target
from steps.tools.ffuf_directory_step import FfufDirectoryStep
from steps.tools.ffuf_files_step import FfufFilesStep
from steps.tools.ffuf_wp_step import FfufWpStep
from steps.tools.opendoor_step import OpenDoorStep


@pytest.fixture
def mock_config():
    return MagicMock(spec=ScanConfig)


@pytest.fixture
def mock_target():
    return Target(url="https://example.com", domain="example.com")


@pytest.fixture
def ffuf_directory_step(mock_target, mock_config):
    return FfufDirectoryStep(
        target=mock_target,
        config=mock_config,
    )


@pytest.fixture
def ffuf_files_step(mock_target, mock_config):
    return FfufFilesStep(
        target=mock_target,
        config=mock_config,
    )


@pytest.fixture
def ffuf_wp_step(mock_target, mock_config):
    return FfufWpStep(
        target=mock_target,
        config=mock_config,
    )


@pytest.fixture
def opendoor_step(mock_target, mock_config):
    return OpenDoorStep(
        target=mock_target,
        config=mock_config,
    )


class TestFfufDirectoryStep:
    def test_init_defaults(self, ffuf_directory_step):
        """Test FFUF directory step initialization."""
        assert ffuf_directory_step.name == "ffuf_directory"
        assert ffuf_directory_step._tool_binary == "ffuf"
        assert ffuf_directory_step.timeout == 300
        assert ffuf_directory_step.rate_limit == 0
        assert ffuf_directory_step.filter_status == "404"

    def test_init_config_overrides(self, mock_target):
        """Test FFUF config/env overrides."""
        config = MagicMock(spec=ScanConfig)
        config.ffuf_wordlist = "/custom/words.txt"
        config.ffuf_timeout = 111
        config.ffuf_rate_limit = 7
        step = FfufDirectoryStep(target=mock_target, config=config)
        assert step.wordlist == "/custom/words.txt"
        assert step.timeout == 111
        assert step.rate_limit == 7

    def test_build_command(self, ffuf_directory_step):
        """Test command building."""
        ffuf_directory_step.config = MagicMock(quiet=False, insecure=False)
        cmd = ffuf_directory_step.build_command()
        assert "ffuf" in cmd
        assert "https://example.com/FUZZ/" in cmd
        assert "-json" in cmd

    def test_parse_output(self, ffuf_directory_step):
        """Test output parsing."""
        mock_output = json.dumps({
            "url": "https://example.com/admin",
            "status": 200,
            "length": 1234,
            "word": "admin"
        })
        result = ToolResult(stdout=mock_output, stderr="", returncode=0, success=True)
        findings = ffuf_directory_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "Directory Found: admin"


class TestFfufFilesStep:
    def test_init_defaults(self, ffuf_files_step):
        """Test FFUF files step initialization."""
        assert ffuf_files_step.name == "ffuf_files"
        assert ffuf_files_step._tool_binary == "ffuf"

    def test_build_command(self, ffuf_files_step):
        """Test command building."""
        ffuf_files_step.config = MagicMock(quiet=False, insecure=False)
        cmd = ffuf_files_step.build_command()
        assert "ffuf" in cmd
        assert "https://example.com/FUZZ" in cmd

    def test_parse_output(self, ffuf_files_step):
        """Test output parsing."""
        mock_output = json.dumps({
            "url": "https://example.com/wp-config.php",
            "status": 200,
            "length": 500,
            "word": "wp-config.php"
        })
        result = ToolResult(stdout=mock_output, stderr="", returncode=0, success=True)
        findings = ffuf_files_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "File Found: wp-config.php"


class TestFfufWpStep:
    def test_init_defaults(self, ffuf_wp_step):
        """Test FFUF WordPress step initialization."""
        assert ffuf_wp_step.name == "ffuf_wp"
        assert ffuf_wp_step._tool_binary == "ffuf"

    def test_build_command(self, ffuf_wp_step):
        """Test command building."""
        ffuf_wp_step.config = MagicMock(quiet=False, insecure=False)
        cmd = ffuf_wp_step.build_command()
        assert "ffuf" in cmd
        assert "https://example.com/FUZZ" in cmd

    def test_parse_output(self, ffuf_wp_step):
        """Test output parsing."""
        mock_output = json.dumps({
            "url": "https://example.com/wp-admin",
            "status": 200,
            "length": 1000,
            "word": "wp-admin"
        })
        result = ToolResult(stdout=mock_output, stderr="", returncode=0, success=True)
        findings = ffuf_wp_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "WordPress Path Found: wp-admin"


class TestOpenDoorStep:
    def test_init_defaults(self, opendoor_step):
        """Test OpenDoor step initialization."""
        assert opendoor_step.name == "opendoor"
        assert opendoor_step._tool_binary == "opendoor"
        assert opendoor_step.mode == "wp_paths"
        assert opendoor_step.wordlist.endswith("wp_paths.txt")
        assert opendoor_step.timeout == 300
        assert opendoor_step.threads == 20
        assert opendoor_step.delay == 0.5

    def test_init_config_overrides(self, mock_target):
        """Test OpenDoor config/env overrides."""
        config = MagicMock(spec=ScanConfig)
        config.opendoor_mode = "backup"
        config.opendoor_wordlist = "/custom/backups.txt"
        config.opendoor_timeout = 120
        config.opendoor_rate_limit = 8
        config.opendoor_delay = 0.2
        step = OpenDoorStep(target=mock_target, config=config)
        assert step.mode == "backup"
        assert step.wordlist == "/custom/backups.txt"
        assert step.timeout == 120
        assert step.threads == 8
        assert step.delay == 0.2

    def test_init_unknown_mode_falls_back(self, mock_target):
        """Unknown OpenDoor mode falls back to wp_paths wordlist."""
        config = MagicMock(spec=ScanConfig)
        config.opendoor_mode = "does_not_exist"
        step = OpenDoorStep(target=mock_target, config=config)
        assert step.mode == "wp_paths"
        assert step.wordlist.endswith("wp_paths.txt")

    def test_build_command(self, opendoor_step):
        """Test command building uses the modern OpenDoor CLI."""
        opendoor_step.config = MagicMock(quiet=False, insecure=False)
        opendoor_step._reports_dir = "/tmp/opendoor-reports"
        cmd = opendoor_step.build_command()
        assert "opendoor" in cmd
        assert "--host" in cmd
        assert "https://example.com" in cmd
        assert "--scan" in cmd
        assert "directories" in cmd
        assert "--wordlist" in cmd
        assert "--reports" in cmd
        assert "json" in cmd
        assert "/tmp/opendoor-reports" in cmd
        assert "--port" not in cmd

    def test_build_command_splits_explicit_port(self):
        """OpenDoor rejects host:port, so explicit ports use --port."""
        target = Target(url="http://127.0.0.1:8123", domain="127.0.0.1")
        step = OpenDoorStep(target=target, config=MagicMock(spec=ScanConfig))
        step._reports_dir = "/tmp/opendoor-reports"
        cmd = step.build_command()
        assert "http://127.0.0.1" in cmd
        assert "127.0.0.1:8123" not in cmd
        assert "--port" in cmd
        assert cmd[cmd.index("--port") + 1] == "8123"

    def test_parse_output_report_items(self, opendoor_step):
        """Test parsing of the modern report_items JSON schema."""
        report = {
            "items": {"success": ["https://example.com/wp-content"]},
            "report_items": {
                "success": [
                    {"url": "https://example.com/wp-content", "code": 200, "size": 2000}
                ],
                "indexof": [
                    {"url": "https://example.com/uploads/", "code": 200, "size": 300}
                ],
                "failed": [
                    {"url": "https://example.com/nope", "code": 404, "size": 0}
                ],
            },
            "total": {"success": 1, "indexof": 1, "failed": 1},
        }
        result = ToolResult(
            stdout=json.dumps(report), stderr="", returncode=0, success=True
        )
        findings = opendoor_step.parse_output(result)
        titles = {f.title for f in findings}
        assert len(findings) == 2
        assert "OpenDoor Path Found: wp-content" in titles
        assert "OpenDoor Directory Listing: uploads" in titles

    def test_parse_output_legacy_items(self, opendoor_step):
        """Test parsing of the legacy items-only JSON schema."""
        report = {"items": {"success": ["https://example.com/wp-admin"]}}
        result = ToolResult(
            stdout=json.dumps(report), stderr="", returncode=0, success=True
        )
        findings = opendoor_step.parse_output(result)
        assert len(findings) == 1
        assert findings[0].title == "OpenDoor Path Found: wp-admin"

    def test_parse_output_invalid_json(self, opendoor_step):
        result = ToolResult(stdout="not json", stderr="", returncode=0, success=True)
        assert opendoor_step.parse_output(result) == []

    async def test_run_reads_json_report(self, opendoor_step):
        """run() should locate and parse the emitted JSON report file."""
        report = {
            "items": {"success": ["https://example.com/wp-content"]},
            "report_items": {
                "success": [
                    {"url": "https://example.com/wp-content", "code": 200, "size": 2000}
                ]
            },
            "total": {"success": 1},
        }

        async def fake_run(cmd, timeout=None):
            reports_dir = cmd[cmd.index("--reports-dir") + 1]
            target_dir = Path(reports_dir) / "example.com"
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "example.com.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            return ToolResult(stdout="", stderr="", returncode=0, success=True)

        opendoor_step.check_binary = lambda binary: (True, "")
        opendoor_step._async_tool_runner.run = fake_run

        findings = await opendoor_step.run()
        assert len(findings) == 1
        assert findings[0].title == "OpenDoor Path Found: wp-content"


class TestAllSteps:
    def test_ffuf_directory_check_binary(self, ffuf_directory_step):
        """Test binary check."""
        exists, error = ffuf_directory_step.check_binary("ffuf")
        assert isinstance(exists, bool)

    def test_ffuf_files_check_binary(self, ffuf_files_step):
        """Test binary check."""
        exists, error = ffuf_files_step.check_binary("ffuf")
        assert isinstance(exists, bool)

    def test_ffuf_wp_check_binary(self, ffuf_wp_step):
        """Test binary check."""
        exists, error = ffuf_wp_step.check_binary("ffuf")
        assert isinstance(exists, bool)

    def test_opendoor_check_binary(self, opendoor_step):
        """Test binary check."""
        exists, error = opendoor_step.check_binary("opendoor")
        assert isinstance(exists, bool)
