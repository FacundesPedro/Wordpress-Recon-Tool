"""Tests for EmailSecurityStep."""

from unittest.mock import MagicMock

from steps.passive.email_security_step import (
    EmailSecurityStep,
    analyze_dmarc,
    analyze_spf,
)


class TestAnalyzeSpf:
    def test_no_spf(self):
        issue = analyze_spf(["v=DMARC1; p=none"])
        assert issue and "No SPF" in issue["title"]

    def test_plus_all_high(self):
        issue = analyze_spf(["v=spf1 ip4:1.2.3.4 +all"])
        assert issue and issue["severity"] == "high"

    def test_soft_fail_low(self):
        issue = analyze_spf(["v=spf1 include:_spf.google.com ~all"])
        assert issue and issue["severity"] == "low"

    def test_hard_fail_clean(self):
        assert analyze_spf(["v=spf1 include:_spf.google.com -all"]) is None


class TestAnalyzeDmarc:
    def test_no_dmarc(self):
        issue = analyze_dmarc(["v=spf1 -all"])
        assert issue and "No DMARC" in issue["title"]

    def test_p_none_medium(self):
        issue = analyze_dmarc(["v=DMARC1; p=none"])
        assert issue and issue["severity"] == "medium"

    def test_p_reject_clean(self):
        assert analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:x@y.com"]) is None

    def test_p_quarantine_clean(self):
        assert analyze_dmarc(["v=DMARC1; p=quarantine"]) is None


class TestEmailSecurityStep:
    def make_step(self, mock_target, mock_config):
        return EmailSecurityStep(target=mock_target, config=mock_config)

    def test_dig_missing_skips(self, mock_target, mock_config):
        step = self.make_step(mock_target, mock_config)
        step.check_binary = MagicMock(return_value=(False, "missing"))
        import asyncio
        findings = asyncio.run(step.run())
        assert findings == []

    def test_no_domain_skips(self, mock_config):
        target = MagicMock()
        target.domain = None
        step = self.make_step(target, mock_config)
        import asyncio
        findings = asyncio.run(step.run())
        assert findings == []

    def test_weak_spf_and_dmarc_reported(self, mock_target, mock_config):
        mock_target.domain = "example.com"
        step = self.make_step(mock_target, mock_config)
        step.check_binary = MagicMock(return_value=(True, ""))
        step._query_txt = MagicMock(
            side_effect=lambda q, rt="TXT": (
                ["v=spf1 +all"]
                if q == "example.com"
                else (["v=DMARC1; p=none"] if "_dmarc" in q else [])
            )
        )
        import asyncio
        findings = asyncio.run(step.run())
        titles = [f.title for f in findings]
        assert any("+all" in t for t in titles)
        assert any("p=none" in t for t in titles)
