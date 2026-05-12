# tests/test_ssrf_protection.py
"""Tests for SSRF protection module."""

import pytest

from core.ssrf_protection import (
    _normalize_ip,
    is_cloud_metadata,
    is_localhost,
    is_private_ip,
    is_safe_target,
    is_safe_url,
    sanitize_target_for_logging,
    validate_safe_url,
)


class TestPrivateIPDetection:
    """Tests for private IP detection."""

    def test_rfc1918_10_network(self):
        """Test 10.x.x.x range is detected as private."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True
        assert is_private_ip("10.1.2.3") is True

    def test_rfc1918_172_network(self):
        """Test 172.16.x.x range is detected as private."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True
        assert is_private_ip("172.20.1.1") is True

    def test_rfc1918_192_network(self):
        """Test 192.168.x.x range is detected as private."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True
        assert is_private_ip("192.168.1.100") is True

    def test_loopback_addresses(self):
        """Test loopback addresses are detected as private."""
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.255.255.255") is True
        assert is_private_ip("127.0.0.0") is True

    def test_link_local_addresses(self):
        """Test link-local addresses are detected as private."""
        assert is_private_ip("169.254.0.1") is True
        assert is_private_ip("169.254.255.255") is True

    def test_ipv6_loopback(self):
        """Test IPv6 loopback is detected as private."""
        assert is_private_ip("::1") is True

    def test_ipv6_private_ranges(self):
        """Test IPv6 private ranges are detected."""
        assert is_private_ip("fc00::1") is True
        assert is_private_ip("fd00::1") is True
        assert is_private_ip("fe80::1") is True

    def test_public_ips_not_blocked(self):
        """Test public IPs are not blocked."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("9.9.9.9") is False
        assert is_private_ip("208.67.222.222") is False

    def test_invalid_ip_handled(self):
        """Test invalid IPs are handled gracefully."""
        assert is_private_ip("invalid") is False
        assert is_private_ip("") is False
        assert is_private_ip("999.999.999.999") is False


class TestLocalhostDetection:
    """Tests for localhost detection."""

    def test_localhost_names(self):
        """Test localhost name variations."""
        assert is_localhost("localhost") is True
        assert is_localhost("localhost.localdomain") is True
        assert is_localhost("ip6-localhost") is True
        assert is_localhost("ip6-loopback") is True

    def test_localhost_ips(self):
        """Test localhost IP addresses."""
        assert is_localhost("localhost", "127.0.0.1") is True
        assert is_localhost("localhost", "::1") is True
        assert is_localhost("test", "127.0.0.1") is True

    def test_non_localhost(self):
        """Test non-localhost hosts."""
        assert is_localhost("example.com") is False
        assert is_localhost("google.com") is False
        assert is_localhost("test", "8.8.8.8") is False

    def test_ipv6_loopback(self):
        """Test IPv6 loopback."""
        assert is_localhost("test", "::1") is True


class TestCloudMetadataDetection:
    """Tests for cloud metadata endpoint detection."""

    def test_cloud_metadata_ips(self):
        """Test cloud metadata IP detection."""
        assert is_cloud_metadata("test", "169.254.169.254") is True
        assert is_cloud_metadata("test", "169.254.170.2") is True
        assert is_cloud_metadata("test", "100.100.100.200") is True

    def test_cloud_metadata_hostnames(self):
        """Test cloud metadata hostname detection."""
        assert is_cloud_metadata("metadata.google.internal") is True
        assert is_cloud_metadata("metadata") is True
        assert is_cloud_metadata("instance-data") is True

    def test_non_metadata(self):
        """Test non-metadata hosts."""
        assert is_cloud_metadata("example.com") is False
        assert is_cloud_metadata("google.com", "8.8.8.8") is False
        assert is_cloud_metadata("test", "1.1.1.1") is False


class TestSafeTargetCheck:
    """Tests for safe target determination."""

    def test_private_targets_blocked(self):
        """Test private IP targets are blocked."""
        assert is_safe_target("192.168.1.1") is True
        assert is_safe_target("10.0.0.1") is True
        assert is_safe_target("172.16.0.1") is True

    def test_localhost_targets_blocked(self):
        """Test localhost targets are blocked."""
        assert is_safe_target("127.0.0.1") is True
        assert is_safe_target("localhost") is True
        assert is_safe_target("::1") is True

    def test_cloud_metadata_blocked(self):
        """Test cloud metadata targets are blocked."""
        assert is_safe_target("169.254.169.254") is True

    def test_public_targets_allowed(self):
        """Test public IP targets are allowed."""
        assert is_safe_target("8.8.8.8") is False
        assert is_safe_target("1.1.1.1") is False
        assert is_safe_target("example.com") is False


class TestURLValidation:
    """Tests for URL validation."""

    def test_valid_urls_pass(self, safe_urls):
        """Test valid URLs pass validation."""
        for url in safe_urls:
            result = validate_safe_url(url)
            assert result == url

    def test_localhost_urls_rejected(self):
        """Test localhost URLs are rejected."""
        with pytest.raises(ValueError, match="localhost"):
            validate_safe_url("http://127.0.0.1:8080")
        with pytest.raises(ValueError, match="localhost"):
            validate_safe_url("http://localhost/admin")

    def test_cloud_metadata_urls_rejected(self):
        """Test cloud metadata URLs are rejected."""
        with pytest.raises(ValueError, match="metadata"):
            validate_safe_url("http://169.254.169.254/latest/")
        with pytest.raises(ValueError, match="metadata"):
            validate_safe_url("http://metadata.google.internal/")

    def test_invalid_scheme_rejected(self):
        """Test non-HTTP schemes are rejected."""
        with pytest.raises(ValueError, match="HTTP/HTTPS"):
            validate_safe_url("ftp://example.com")
        with pytest.raises(ValueError, match="HTTP/HTTPS"):
            validate_safe_url("file:///etc/passwd")

    def test_is_safe_url_returns_bool(self, safe_urls, unsafe_urls):
        """Test is_safe_url returns boolean."""
        for url in safe_urls:
            assert is_safe_url(url) is True
        for url in unsafe_urls:
            assert is_safe_url(url) is False

    def test_allow_private_option(self):
        """Test allow_private option."""
        url = "http://192.168.1.1:8080"
        with pytest.raises(ValueError):
            validate_safe_url(url, allow_private=False)
        result = validate_safe_url(url, allow_private=True)
        assert result == url


class TestIPNormalization:
    """Tests for IP normalization."""

    def test_ipv4_normalization(self):
        """Test IPv4 addresses are normalized."""
        assert _normalize_ip("8.8.8.8") == "8.8.8.8"
        assert _normalize_ip("1.1.1.1") == "1.1.1.1"

    def test_ipv6_normalization(self):
        """Test IPv6 addresses are normalized."""
        assert _normalize_ip("::1") == "::1"
        assert _normalize_ip("fe80::1") == "fe80::1"

    def test_invalid_ip_returns_original(self):
        """Test invalid IPs return original string."""
        assert _normalize_ip("invalid") == "invalid"
        assert _normalize_ip("") == ""


class TestLogSanitization:
    """Tests for target sanitization in logs."""

    def test_ip_redaction(self):
        """Test IP addresses are redacted."""
        result = sanitize_target_for_logging("Connecting to 192.168.1.1:8080")
        assert "192.168.1.1" not in result
        assert "[REDACTED_IP]" in result

    def test_port_redaction(self):
        """Test ports are redacted."""
        result = sanitize_target_for_logging("http://example.com:8080/path")
        assert ":8080" not in result
        assert ":[PORT]" in result

    def test_sensitive_data_redaction(self):
        """Test sensitive data is redacted."""
        result = sanitize_target_for_logging('api_key="secret123"')
        assert "secret123" not in result
        assert "[API_KEY]" in result

        result = sanitize_target_for_logging("password=supersecret")
        assert "supersecret" not in result
        assert "[PASSWORD]" in result

    def test_empty_target(self):
        """Test empty target returns placeholder."""
        assert sanitize_target_for_logging("") == "[empty]"
        assert sanitize_target_for_logging(None) == "[empty]"
