"""Tests for split-horizon target helpers (utils/target_net.py)."""

from unittest.mock import MagicMock

from core.target import Target
from utils.target_net import (
    host_header,
    pinned_ip,
    pinned_url,
    restore_public_host,
    scan_host,
    sni_hostname,
)


class TestPinnedTarget:
    def test_pinned_target_helpers(self):
        target = Target(
            url="https://app.example.com:8443/base",
            domain="app.example.com",
            connect_ip="10.0.0.5",
        )
        assert pinned_ip(target) == "10.0.0.5"
        assert scan_host(target) == "10.0.0.5"
        assert host_header(target) == "app.example.com:8443"
        assert pinned_url(target) == "https://10.0.0.5:8443"

    def test_unpinned_target_helpers(self):
        target = Target(url="https://app.example.com", domain="app.example.com")
        assert pinned_ip(target) is None
        assert scan_host(target) == "app.example.com"
        assert host_header(target) is None
        assert pinned_url(target) == "https://app.example.com"

    def test_default_port_omitted_from_host_header(self):
        target = Target(
            url="https://app.example.com/x",
            domain="app.example.com",
            connect_ip="10.0.0.5",
        )
        assert host_header(target) == "app.example.com"

    def test_mock_target_is_not_pinned(self):
        # Guards against MagicMock targets in tests being treated as pinned.
        target = MagicMock()
        assert pinned_ip(target) is None
        assert host_header(target) is None

    def test_scan_host_falls_back_to_url(self):
        target = MagicMock(spec=["url", "domain", "connect_ip"])
        target.connect_ip = ""
        target.domain = ""
        target.url = "https://fallback.example"
        assert scan_host(target) == "https://fallback.example"


class TestSniHostname:
    def test_pinned_returns_domain(self):
        target = Target(
            url="https://app.example.com:8443/x",
            domain="app.example.com",
            connect_ip="10.0.0.5",
        )
        assert sni_hostname(target) == "app.example.com"

    def test_unpinned_is_none(self):
        target = Target(url="https://app.example.com", domain="app.example.com")
        assert sni_hostname(target) is None


class TestRestorePublicHost:
    def test_rewrites_pinned_ip(self):
        target = Target(
            url="https://app.example.com:8443/base",
            domain="app.example.com",
            connect_ip="10.0.0.5",
        )
        assert (
            restore_public_host("https://10.0.0.5:8443/wp-cron.php?x=1", target)
            == "https://app.example.com:8443/wp-cron.php?x=1"
        )

    def test_keeps_public_url(self):
        target = Target(
            url="https://app.example.com",
            domain="app.example.com",
            connect_ip="10.0.0.5",
        )
        assert (
            restore_public_host("https://app.example.com/x", target)
            == "https://app.example.com/x"
        )

    def test_unpinned_unchanged(self):
        target = Target(url="https://app.example.com", domain="app.example.com")
        assert (
            restore_public_host("https://10.0.0.5/x", target)
            == "https://10.0.0.5/x"
        )
