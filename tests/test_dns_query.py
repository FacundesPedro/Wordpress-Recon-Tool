"""Tests for utils/dns_query.py (dig parsing + domain helpers)."""

from utils.dns_query import (
    build_dig_command,
    organizational_domain,
    parse_dig_output,
)

FULL_TXT = """\
; <<>> DiG 9.18 <<>> example.com TXT +noall +answer +comments
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; QUESTION SECTION:
;example.com.			IN	TXT
example.com.		300	IN	TXT	"v=spf1 include:_spf.google.com -all"
"""

NO_ANSWERS = """\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0
"""

SERVFAIL = """\
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 2
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
"""

NXDOMAIN = """\
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 3
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0
"""


class TestBuildCommand:
    def test_basic(self):
        cmd = build_dig_command("example.com", "TXT")
        assert cmd[0] == "dig"
        assert "example.com" in cmd
        assert "TXT" in cmd
        assert "+short" not in cmd
        assert "+noall" in cmd

    def test_nameserver(self):
        cmd = build_dig_command("_dmarc.example.com", "TXT", nameserver="ns1.example.com")
        assert "@ns1.example.com" in cmd


class TestParseDigOutput:
    def test_full_answer(self):
        res = parse_dig_output(FULL_TXT)
        assert res.status == "NOERROR"
        assert res.answer_count == 1
        assert res.records == ["v=spf1 include:_spf.google.com -all"]
        assert res.no_error
        assert not res.indeterminate
        assert not res.no_record

    def test_no_answers_is_proven_absence(self):
        res = parse_dig_output(NO_ANSWERS)
        assert res.status == "NOERROR"
        assert res.answer_count == 0
        assert res.no_record
        assert not res.indeterminate

    def test_servfail_is_indeterminate(self):
        res = parse_dig_output(SERVFAIL)
        assert res.indeterminate
        assert not res.no_record

    def test_nxdomain_is_absence(self):
        res = parse_dig_output(NXDOMAIN)
        assert res.no_record
        assert not res.indeterminate

    def test_garbage_is_error(self):
        res = parse_dig_output("")
        assert res.error
        assert res.indeterminate


class TestOrganizationalDomain:
    def test_simple(self):
        assert organizational_domain("app.example.com") == "example.com"

    def test_already_registrable(self):
        assert organizational_domain("example.com") == "example.com"

    def test_multi_label_suffix(self):
        assert organizational_domain("portal.example.com.br") == "example.com.br"
        assert organizational_domain("a.b.example.co.uk") == "example.co.uk"

    def test_single_label(self):
        assert organizational_domain("localhost") == "localhost"
