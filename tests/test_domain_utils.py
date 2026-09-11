"""Tests for domain scope helpers (non-public domain detection)."""

from utils.domain_utils import (
    extract_hostname,
    is_ip_literal,
    is_non_public_domain,
)


class TestExtractHostname:
    def test_with_port(self):
        assert extract_hostname("http://localhost:3000") == "localhost"

    def test_full_url(self):
        assert extract_hostname("https://example.com/path") == "example.com"


class TestIsIpLiteral:
    def test_ipv4(self):
        assert is_ip_literal("192.168.1.1")
        assert is_ip_literal("127.0.0.1")

    def test_ipv6(self):
        assert is_ip_literal("::1")

    def test_not_ip(self):
        assert not is_ip_literal("example.com")
        assert not is_ip_literal("")


class TestIsNonPublicDomain:
    def test_localhost(self):
        assert is_non_public_domain("localhost")

    def test_reserved_suffixes(self):
        assert is_non_public_domain("app.localhost")
        assert is_non_public_domain("mysite.local")
        assert is_non_public_domain("svc.internal")
        assert is_non_public_domain("demo.test")

    def test_ip_literals(self):
        assert is_non_public_domain("127.0.0.1")
        assert is_non_public_domain("10.0.0.5")

    def test_single_label(self):
        assert is_non_public_domain("mypc")

    def test_public_domains_not_flagged(self):
        assert not is_non_public_domain("example.com")
        assert not is_non_public_domain("client-site.co.uk")
        assert not is_non_public_domain("sub.example.com")

    def test_empty(self):
        assert is_non_public_domain("")
        assert is_non_public_domain(None)
