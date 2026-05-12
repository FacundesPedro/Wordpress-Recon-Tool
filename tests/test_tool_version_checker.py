"""Tests for tool version checker."""

import pytest

from utils.tool_version_checker import (
    VersionChecker,
    VersionMismatchError,
    VersionRequirement,
)


class TestVersionRequirement:
    """Test version requirement compatibility checks."""

    def test_required_version_compatible(self):
        """Test exact version requirement - compatible."""
        req = VersionRequirement(
            tool="test",
            required_version="1.0.0",
        )
        assert req.is_compatible("1.0.0") is True

    def test_required_version_incompatible(self):
        """Test exact version requirement - incompatible."""
        req = VersionRequirement(
            tool="test",
            required_version="1.0.0",
        )
        assert req.is_compatible("1.0.1") is False
        assert req.is_compatible("0.9.9") is False

    def test_min_version_compatible(self):
        """Test minimum version requirement - compatible."""
        req = VersionRequirement(
            tool="test",
            min_version="1.0.0",
        )
        assert req.is_compatible("1.0.0") is True
        assert req.is_compatible("1.0.1") is True
        assert req.is_compatible("2.0.0") is True

    def test_min_version_incompatible(self):
        """Test minimum version requirement - incompatible."""
        req = VersionRequirement(
            tool="test",
            min_version="1.0.0",
        )
        assert req.is_compatible("0.9.9") is False
        assert req.is_compatible("1.0.0-beta") is False

    def test_version_range_compatible(self):
        """Test version range - compatible."""
        req = VersionRequirement(
            tool="test",
            min_version="1.0.0",
            max_version="2.0.0",
        )
        assert req.is_compatible("1.0.0") is True
        assert req.is_compatible("1.5.0") is True
        assert req.is_compatible("2.0.0") is True

    def test_version_range_incompatible(self):
        """Test version range - incompatible."""
        req = VersionRequirement(
            tool="test",
            min_version="1.0.0",
            max_version="2.0.0",
        )
        assert req.is_compatible("0.9.9") is False
        assert req.is_compatible("2.0.1") is False

    def test_supported_versions_compatible(self):
        """Test supported versions list - compatible."""
        req = VersionRequirement(
            tool="test",
            supported_versions=["1.0.0", "1.0.1", "1.1.0"],
        )
        assert req.is_compatible("1.0.0") is True
        assert req.is_compatible("1.0.1") is True

    def test_supported_versions_incompatible(self):
        """Test supported versions list - incompatible."""
        req = VersionRequirement(
            tool="test",
            supported_versions=["1.0.0", "1.0.1", "1.1.0"],
        )
        assert req.is_compatible("1.0.2") is False
        assert req.is_compatible("2.0.0") is False

    def test_no_requirements_always_compatible(self):
        """Test that no requirements means always compatible."""
        req = VersionRequirement(tool="test")
        assert req.is_compatible("1.0.0") is True
        assert req.is_compatible("99.99.99") is True


class TestVersionChecker:
    """Test version checker functionality."""

    @pytest.fixture
    def checker(self):
        return VersionChecker()

    def test_format_required_version(self, checker):
        """Test formatting required version."""
        req = VersionRequirement(
            tool="test",
            required_version="1.0.0",
        )
        assert checker._format_requirements(req) == "== 1.0.0"

    def test_format_min_version(self, checker):
        """Test formatting minimum version."""
        req = VersionRequirement(
            tool="test",
            min_version="1.0.0",
        )
        assert checker._format_requirements(req) == ">= 1.0.0"

    def test_format_version_range(self, checker):
        """Test formatting version range."""
        req = VersionRequirement(
            tool="test",
            min_version="1.0.0",
            max_version="2.0.0",
        )
        assert checker._format_requirements(req) == ">= 1.0.0, <= 2.0.0"

    def test_format_supported_versions(self, checker):
        """Test formatting supported versions."""
        req = VersionRequirement(
            tool="test",
            supported_versions=["1.0.0", "1.0.1"],
        )
        assert checker._format_requirements(req) == "in ['1.0.0', '1.0.1']"

    def test_format_no_requirements(self, checker):
        """Test formatting no requirements."""
        req = VersionRequirement(tool="test")
        assert checker._format_requirements(req) == "any"

    def test_parse_version_wpscan(self, checker):
        """Test parsing WPScan version from output."""
        output = "WPScan 3.8.23 [Release date: 2023-01-01]\n"
        assert checker._parse_version(output, "wpscan") == "3.8.23"

    def test_parse_version_nuclei(self, checker):
        """Test parsing Nuclei version from output."""
        output = "nuclei version 3.1.0\n"
        assert checker._parse_version(output, "nuclei") == "3.1.0"

    def test_parse_version_ffuf(self, checker):
        """Test parsing FFUF version from output."""
        output = "FFUF: 2.0.0-dev\n"
        assert checker._parse_version(output, "ffuf") == "2.0.0"

    def test_parse_version_unknown(self, checker):
        """Test parsing version with unknown tool."""
        output = "Some tool version 1.2.3\n"
        assert checker._parse_version(output, "unknown") == "1.2.3"

    def test_generate_compatible_message(self, checker):
        """Test generating compatible message."""
        req = VersionRequirement(tool="test", required_version="1.0.0")
        message = checker._generate_message("1.0.0", req, True)
        assert "compatible" in message.lower()

    def test_generate_incompatible_message_required(self, checker):
        """Test generating incompatible message for required version."""
        req = VersionRequirement(tool="test", required_version="1.0.0")
        message = checker._generate_message("1.0.1", req, False)
        assert "Required 1.0.0" in message

    def test_validate_compatible(self, checker):
        """Test validation with compatible version."""
        req = VersionRequirement(
            tool="test",
            required_version="1.0.0",
        )
        result = checker.check_compatibility("test", req)
        assert result.tool == "test"
        assert result.requirements == "== 1.0.0"

    def test_validate_strict_incompatible_raises_error(self, checker):
        """Test strict validation raises error on incompatibility."""
        req = VersionRequirement(
            tool="test",
            required_version="99.99.99",
        )
        with pytest.raises(VersionMismatchError):
            checker.validate("test", req, strict=True)


class TestVersionMismatchError:
    """Test version mismatch error handling."""

    def test_error_message(self):
        """Test error message contains required information."""
        error = VersionMismatchError(
            tool="wpscan",
            installed="1.0.0",
            required="2.0.0",
        )
        assert "wpscan" in str(error)
        assert "1.0.0" in str(error)
        assert "2.0.0" in str(error)

    def test_error_attributes(self):
        """Test error attributes are accessible."""
        error = VersionMismatchError(
            tool="wpscan",
            installed="1.0.0",
            required="2.0.0",
        )
        assert error.tool == "wpscan"
        assert error.installed == "1.0.0"
        assert error.required == "2.0.0"
