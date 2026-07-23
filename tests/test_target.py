# tests/test_target.py
"""Tests for Target class — URL validation, normalization, domain extraction."""

import pytest

from core.exceptions import ValidationError
from core.target import Target


class TestTargetValidation:
    """Tests for URL normalization and scheme handling."""

    def test_https_url_kept_as_is(self):
        t = Target("https://example.com")
        assert t.url == "https://example.com"

    def test_http_url_kept_as_is(self):
        t = Target("http://example.com")
        assert t.url == "http://example.com"

    def test_bare_domain_gets_https(self):
        t = Target("example.com")
        assert t.url == "https://example.com"

    def test_bare_domain_with_path(self):
        t = Target("example.com/wp-admin")
        assert t.url == "https://example.com"

    def test_leading_whitespace_stripped(self):
        t = Target("  https://example.com")
        assert t.url == "https://example.com"

    def test_trailing_whitespace_stripped(self):
        t = Target("https://example.com  ")
        assert t.url == "https://example.com"

    def test_subdomain_preserved(self):
        t = Target("https://www.example.com")
        assert t.url == "https://www.example.com"
        assert t.domain == "www.example.com"

    def test_deep_subdomain_preserved(self):
        t = Target("https://a.b.c.example.com")
        assert t.url == "https://a.b.c.example.com"
        assert t.domain == "a.b.c.example.com"

    def test_trailing_slash_stripped_from_url(self):
        t = Target("https://example.com/")
        assert t.url == "https://example.com"

    def test_path_after_domain_stripped(self):
        t = Target("https://example.com/some/path?q=1")
        assert t.url == "https://example.com"


class TestTargetIPv4:
    """Tests for IPv4 target handling."""

    def test_ipv4_bare_address(self):
        t = Target("8.8.8.8")
        assert t.url == "https://8.8.8.8"
        assert t.domain == "8.8.8.8"

    def test_ipv4_with_scheme(self):
        t = Target("http://192.168.1.1")
        assert t.url == "http://192.168.1.1"
        assert t.domain == "192.168.1.1"

    def test_ipv4_with_port(self):
        t = Target("https://10.0.0.1:8080")
        assert t.url == "https://10.0.0.1:8080"
        assert t.domain == "10.0.0.1"

    def test_ipv4_with_path(self):
        t = Target("http://127.0.0.1/wp-admin")
        assert t.url == "http://127.0.0.1"
        assert t.domain == "127.0.0.1"


class TestTargetIPv6:
    """Tests for IPv6 target handling."""

    def test_ipv6_full_address(self):
        t = Target("http://[2001:db8::1]")
        assert t.url == "http://[2001:db8::1]"
        assert t.domain == "2001:db8::1"

    def test_ipv6_loopback(self):
        t = Target("http://[::1]")
        assert t.url == "http://[::1]"
        assert t.domain == "::1"

    def test_ipv6_with_port(self):
        t = Target("http://[::1]:8080")
        assert t.url == "http://[::1]:8080"
        assert t.domain == "::1"


class TestTargetPort:
    """Tests for port handling."""

    def test_port_preserved(self):
        t = Target("https://example.com:443")
        assert t.url == "https://example.com:443"

    def test_non_numeric_port_makes_url_invalid(self):
        with pytest.raises(ValidationError):
            Target("https://example.com:notaport")

    def test_ipv4_port(self):
        t = Target("https://1.2.3.4:9090")
        assert t.url == "https://1.2.3.4:9090"


class TestTargetInvalid:
    """Tests for invalid URL handling."""

    def test_empty_url_does_not_raise(self):
        t = Target("")
        assert t.url == ""
        assert t.domain == ""

    def test_validate_and_normalize_empty_string(self):
        t = Target("https://example.com")
        result = t._validate_and_normalize("")
        assert result == {}

    def test_invalid_hostname_raises(self):
        with pytest.raises(ValidationError):
            Target("https://-invalid-.com")

    def test_garbage_text_raises(self):
        with pytest.raises(ValidationError):
            Target("not a url at all")


class TestTargetDomain:
    """Tests for domain extraction."""

    def test_simple_domain(self):
        t = Target("https://example.com")
        assert t.domain == "example.com"

    def test_subdomain_domain(self):
        t = Target("https://blog.example.com")
        assert t.domain == "blog.example.com"

    def test_ipv4_domain(self):
        t = Target("https://1.2.3.4")
        assert t.domain == "1.2.3.4"

    def test_domain_not_in_url_with_port(self):
        t = Target("https://example.com:8080")
        assert t.domain == "example.com"
        assert ":8080" not in t.domain


class TestTargetScope:
    """Tests for scope handling."""

    def test_default_scope_is_domain(self):
        t = Target("https://example.com")
        assert t.scope == ["example.com"]

    def test_custom_scope_preserved(self):
        t = Target("https://example.com", scope=["other.com"])
        assert t.scope == ["other.com"]

    def test_empty_scope_gets_domain(self):
        t = Target("https://example.com", scope=[])
        assert t.scope == ["example.com"]

    def test_scope_with_multiple_domains(self):
        t = Target("https://example.com", scope=["a.com", "b.com"])
        assert t.scope == ["a.com", "b.com"]


class TestTargetStrRepr:
    """Tests for __str__ and __repr__."""

    def test_str_returns_url(self):
        t = Target("https://example.com")
        assert str(t) == "https://example.com"

    def test_repr_contains_url_and_domain(self):
        t = Target("https://example.com")
        r = repr(t)
        assert "example.com" in r
        assert "url=" in r
        assert "domain=" in r


class TestSplitHostPort:
    """Tests for _split_host_port static method."""

    def test_host_only(self):
        host, port = Target._split_host_port("example.com")
        assert host == "example.com"
        assert port is None

    def test_host_with_port(self):
        host, port = Target._split_host_port("example.com:443")
        assert host == "example.com"
        assert port == 443

    def test_ipv4_with_port(self):
        host, port = Target._split_host_port("1.2.3.4:8080")
        assert host == "1.2.3.4"
        assert port == 8080

    def test_ipv4_no_port(self):
        host, port = Target._split_host_port("1.2.3.4")
        assert host == "1.2.3.4"
        assert port is None

    def test_ipv6_with_port(self):
        host, port = Target._split_host_port("[::1]:8080")
        assert host == "[::1]"
        assert port == 8080

    def test_ipv6_no_port(self):
        host, port = Target._split_host_port("[::1]")
        assert host == "[::1]"
        assert port is None

    def test_ipv6_unclosed_bracket(self):
        host, port = Target._split_host_port("[::1")
        assert host == "[::1"
        assert port is None

    def test_non_numeric_after_colon(self):
        host, port = Target._split_host_port("example.com:notaport")
        assert host == "example.com:notaport"
        assert port is None
