"""Tests for FFUF and OpenDoor steps."""

import json
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

    def test_build_command(self, opendoor_step):
        """Test command building."""
        opendoor_step.config = MagicMock(quiet=False, insecure=False)
        cmd = opendoor_step.build_command()
        assert "opendoor" in cmd
        assert "https://example.com" in cmd
        assert "-mode" in cmd
        assert "wp_paths" in cmd

    def test_parse_output(self, opendoor_step):
        """Test output parsing."""
        mock_output = json.dumps({
            "url": "https://example.com/wp-content",
            "status": 200,
            "length": 2000,
            "word": "wp-content"
        })
        result = ToolResult(stdout=mock_output, stderr="", returncode=0, success=True)
        findings = opendoor_step.parse_output(result)
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
