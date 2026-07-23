# tests/test_whois_parser.py
"""Unit tests for utils/whois_parser.py — WhoisParser."""

from unittest.mock import patch

from utils.whois_parser import HARDCODED_PATTERNS, WhoisParser


class TestHardcodedPatterns:
    def test_patterns_loaded(self):
        assert len(HARDCODED_PATTERNS) > 0

    def test_common_fields_present(self):
        names = [p.name for p in HARDCODED_PATTERNS]
        assert "registrar" in names
        assert "created" in names
        assert "expires" in names
        assert "name_server" in names
        assert "status" in names


class TestWhoisParserInit:
    def test_loads_hardcoded_patterns(self):
        parser = WhoisParser()
        assert len(parser.patterns) > 0
        assert not parser.using_wordlist
        assert parser.loaded_tld is None

    def test_uses_hardcoded_patterns_by_default(self):
        parser = WhoisParser()
        names = [p.name for p in parser.patterns]
        assert "registrar" in names


class TestDetectTld:
    def test_com_tld(self):
        parser = WhoisParser()
        assert parser._detect_tld("example.com") == "com"

    def test_org_tld(self):
        parser = WhoisParser()
        assert parser._detect_tld("example.org") == "org"

    def test_br_tld(self):
        parser = WhoisParser()
        assert parser._detect_tld("example.com.br") == "br"

    def test_co_uk_tld(self):
        parser = WhoisParser()
        assert parser._detect_tld("example.co.uk") == "uk"

    def test_empty_returns_generic(self):
        parser = WhoisParser()
        assert parser._detect_tld("") == "generic"

    def test_no_dot_returns_generic(self):
        parser = WhoisParser()
        assert parser._detect_tld("localhost") == "generic"


class TestParse:
    def test_empty_output_returns_empty_dict(self):
        parser = WhoisParser()
        assert parser.parse("") == {}

    def test_parses_registrar(self):
        parser = WhoisParser()
        output = "Registrar: GoDaddy"
        result = parser.parse(output)
        assert result.get("registrar") == ["GoDaddy"]

    def test_parses_name_servers(self):
        parser = WhoisParser()
        output = "Name Server: ns1.example.com\nName Server: ns2.example.com"
        result = parser.parse(output)
        assert len(result.get("name_server", [])) == 2

    def test_parses_creation_date(self):
        parser = WhoisParser()
        output = "Creation Date: 2020-01-15"
        result = parser.parse(output)
        assert "2020-01-15" in result.get("created", [])

    def test_parses_multiple_formats(self):
        parser = WhoisParser()
        output = "Created: 2020-01-15\nCreation Date: 2020-02-01"
        result = parser.parse(output)
        assert len(result.get("created", [])) == 2

    def test_cleans_percent_comments(self):
        parser = WhoisParser()
        output = "% This is a comment\nRegistrar: GoDaddy"
        result = parser.parse(output)
        assert result.get("registrar") == ["GoDaddy"]

    def test_domain_triggers_tld_loading(self):
        parser = WhoisParser()
        with patch.object(parser, "load_tld_patterns", return_value=False) as mock:
            parser.parse("Registrar: GoDaddy", domain="example.com")
            mock.assert_called_once_with("com")

    def test_reuses_loaded_tld(self):
        parser = WhoisParser()
        parser.loaded_tld = "com"
        with patch.object(parser, "load_tld_patterns") as mock:
            parser.parse("Registrar: GoDaddy", domain="example.com")
            mock.assert_not_called()

    def test_ignores_bad_patterns(self):
        parser = WhoisParser()
        parser.patterns = []
        result = parser.parse("Some random text")
        assert result == {}

    def test_dnssec_parsed(self):
        parser = WhoisParser()
        output = "DNSSEC: signedDelegation"
        result = parser.parse(output)
        assert result.get("dnssec") == ["signedDelegation"]


class TestToFindingDict:
    def test_converts_parsed_data(self):
        parser = WhoisParser()
        parsed = {
            "registrar": ["GoDaddy"],
            "created": ["2020-01-15"],
            "name_server": ["ns1.example.com"],
        }
        result = parser.to_finding_dict(parsed)
        assert result["registrar"] == "GoDaddy"
        assert result["creation_date"] == "2020-01-15"
        assert result["nameservers"] == ["ns1.example.com"]

    def test_falls_back_to_alternate_fields(self):
        parser = WhoisParser()
        parsed = {"whois": ["GoDaddy"], "creation_date": ["2020-01-15"]}
        result = parser.to_finding_dict(parsed)
        assert result["registrar"] == "GoDaddy"

    def test_empty_parsed_returns_none_values(self):
        parser = WhoisParser()
        result = parser.to_finding_dict({})
        assert result["registrar"] is None
        assert result["nameservers"] == []

    def test_combines_name_server_fields(self):
        parser = WhoisParser()
        parsed = {"name_server": ["ns1.com"], "nserver": ["ns2.com"]}
        result = parser.to_finding_dict(parsed)
        assert len(result["nameservers"]) == 2

    def test_combines_status_fields(self):
        parser = WhoisParser()
        parsed = {"status": ["clientHold"], "domain_status": ["serverHold"]}
        result = parser.to_finding_dict(parsed)
        assert len(result["status"]) == 2


class TestGetStatusMessage:
    def test_default_message(self):
        parser = WhoisParser()
        msg = parser.get_status_message()
        assert "fallback" in msg

    def test_wordlist_message(self):
        parser = WhoisParser()
        parser.using_wordlist = True
        parser.loaded_tld = "com"
        msg = parser.get_status_message()
        assert "wordlist" in msg
        assert "com" in msg

    def test_message_contains_dir_hint(self):
        parser = WhoisParser()
        msg = parser.get_status_message()
        assert "whois" in msg.lower()
