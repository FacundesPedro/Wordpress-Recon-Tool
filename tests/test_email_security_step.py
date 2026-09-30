"""Tests for EmailSecurityStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.passive.email_security_step import (
    EmailSecurityStep,
    analyze_dmarc,
    analyze_spf,
)


class TestAnalyzeSpf:
    def test_no_spf(self):
        issue = analyze_spf(["v=DMARC1; p=none"])
        assert issue and "No SPF" in issue["title"]

    def test_plus_all_medium(self):
        issue = analyze_spf(["v=spf1 ip4:1.2.3.4 +all"])
        assert issue and issue["severity"] == "medium"

    def test_tilde_all_not_treated_as_plus_all(self):
        issue = analyze_spf(["v=spf1 ip4:1.2.3.4 ~all"])
        assert issue and "soft fail" in issue["title"].lower()

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
        from utils.dns_query import DigResult

        mock_target.domain = "example.com"
        step = self.make_step(mock_target, mock_config)
        step.check_binary = MagicMock(return_value=(True, ""))
        step._check_dkim = AsyncMock()

        async def fake_query(name, record_type="TXT"):
            if name == "example.com" and record_type == "TXT":
                return DigResult(
                    status="NOERROR", answer_count=1, records=["v=spf1 +all"]
                )
            if name == "_dmarc.example.com":
                return DigResult(
                    status="NOERROR", answer_count=1, records=["v=DMARC1; p=none"]
                )
            return DigResult(status="NOERROR", answer_count=0)

        step._query_with_fallback = AsyncMock(side_effect=fake_query)
        import asyncio
        findings = asyncio.run(step.run())
        titles = [f.title for f in findings]
        assert any("+all" in t for t in titles)
        assert any("p=none" in t for t in titles)

    def test_lookup_failure_not_reported_as_no_record(self, mock_target, mock_config):
        """SERVFAIL must not be reported as 'No SPF record found'."""
        from utils.dns_query import DigResult

        mock_target.domain = "example.com"
        step = self.make_step(mock_target, mock_config)
        step.check_binary = MagicMock(return_value=(True, ""))
        step._check_dkim = AsyncMock()
        step._query_with_fallback = AsyncMock(
            side_effect=lambda name, record_type="TXT": DigResult(
                status="SERVFAIL", error=True
            )
        )
        import asyncio
        findings = asyncio.run(step.run())
        titles = [f.title for f in findings]
        assert not any("No SPF" in t for t in titles)
        assert not any("No DMARC" in t for t in titles)
        assert any(f.raw.get("operational") for f in findings)

    def test_dmarc_inherited_from_org_domain(self, mock_target, mock_config):
        from utils.dns_query import DigResult

        mock_target.domain = "sub.example.com"
        step = self.make_step(mock_target, mock_config)
        step.check_binary = MagicMock(return_value=(True, ""))
        step._check_dkim = AsyncMock()

        async def fake_query(name, record_type="TXT"):
            if name == "_dmarc.sub.example.com":
                return DigResult(status="NOERROR", answer_count=0)  # no record
            if name == "_dmarc.example.com":
                return DigResult(
                    status="NOERROR",
                    answer_count=1,
                    records=["v=DMARC1; p=reject; sp=none"],
                )
            return DigResult(status="NOERROR", answer_count=0)

        step._query_with_fallback = AsyncMock(side_effect=fake_query)
        import asyncio
        findings = asyncio.run(step.run())
        dmarc = [f for f in findings if "DMARC" in f.title]
        assert dmarc
        # sp=none applies to the subdomain -> weak policy reported.
        assert dmarc[0].severity == "medium"
        assert dmarc[0].raw.get("scope") == "sp"
        assert "inherited" in dmarc[0].evidence.lower()
