"""Tests for DnsStep."""

from unittest.mock import MagicMock, patch

import pytest

from base.tool import ToolResult

pytestmark = pytest.mark.asyncio


class TestSkipConditions:
    """Tests for early return conditions."""

    async def test_returns_empty_when_dig_not_found(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()

        with patch.object(DnsStep, "check_binary", return_value=(False, "not found")):
            findings = await step.run()

        assert findings == []

    async def test_returns_empty_when_no_domain(self):
        mock_target = MagicMock()
        mock_target.domain = None
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        findings = await step.run()

        assert findings == []


class TestRecordQuery:
    """Tests for DNS record querying and findings."""

    async def test_a_record_found(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()
        step._tool_runner.run.return_value = ToolResult(
            stdout="93.184.216.34\n", stderr="", returncode=0, success=True
        )

        with patch.object(DnsStep, "check_binary", return_value=(True, "")):
            findings = await step.run()

        record_findings = [f for f in findings if "Records Found" in f.title]
        assert len(record_findings) >= 1
        a_finding = next(f for f in record_findings if "A " in f.title)
        assert a_finding.module == "passive"
        assert a_finding.severity == "info"
        assert "93.184.216.34" in a_finding.evidence
        assert a_finding.raw["count"] == 1

    async def test_multiple_record_types_returned(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()
        step._tool_runner.run.return_value = ToolResult(
            stdout="93.184.216.34\n", stderr="", returncode=0, success=True
        )

        with patch.object(DnsStep, "check_binary", return_value=(True, "")):
            findings = await step.run()

        record_findings = [f for f in findings if "Records Found" in f.title]
        assert len(record_findings) == 6

    async def test_no_records_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._tool_runner = MagicMock()
        step._tool_runner.run.return_value = ToolResult(
            stdout="", stderr="", returncode=0, success=True
        )

        with patch.object(DnsStep, "check_binary", return_value=(True, "")):
            findings = await step.run()

        no_dns = [f for f in findings if f.title == "No DNS records found"]
        assert len(no_dns) == 0


class TestParseOutput:
    """Tests for parse_output method."""

    async def test_null_result_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        findings = step.parse_output(None, "A")
        assert findings == []

    async def test_failed_result_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        result = ToolResult(stdout="", stderr="error", returncode=1, success=False)
        findings = step.parse_output(result, "A")
        assert findings == []

    async def test_empty_output_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        result = ToolResult(stdout="   \n\n  ", stderr="", returncode=0, success=True)
        findings = step.parse_output(result, "A")
        assert findings == []

    async def test_valid_results_create_finding(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        result = ToolResult(
            stdout="93.184.216.34\n2606:2800:220:1:248:1893:25c8:1946\n",
            stderr="",
            returncode=0,
            success=True,
        )
        findings = step.parse_output(result, "AAAA")
        assert len(findings) == 1
        assert "AAAA" in findings[0].title
        assert findings[0].raw["count"] == 2


class TestIsValidResult:
    """Tests for _is_valid_result filter."""

    async def test_accepts_valid_ip(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        assert step._is_valid_result("93.184.216.34")

    async def test_rejects_timeout(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        assert not step._is_valid_result("connection timed out; no servers could be reached")

    async def test_rejects_servfail(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        assert not step._is_valid_result("SERVFAIL")

    async def test_rejects_nxdomain(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        assert not step._is_valid_result("NXDOMAIN")

    async def test_rejects_dig_header(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        assert not step._is_valid_result("; <<>> DiG 9.10.6 <<>>")


class TestSpfAnalysis:
    """Tests for SPF record analysis."""

    async def test_no_spf_record_found(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["TXT"] = ["google-site-verification=abc"]

        with patch.object(DnsStep, "check_binary", return_value=(True, "")):
            step._analyze_spf("example.com")

        spf_finding = [f for f in step.findings if f.title == "No SPF Record Found"]
        assert len(spf_finding) == 1
        assert spf_finding[0].severity == "medium"

    async def test_spf_with_hard_fail_is_info(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["TXT"] = ["v=spf1 include:_spf.google.com -all"]

        step._analyze_spf("example.com")

        spf_finding = [f for f in step.findings if f.title == "SPF Configuration Detected"]
        assert len(spf_finding) == 1
        assert spf_finding[0].severity == "info"
        assert "Hard fail" in spf_finding[0].description

    async def test_spf_with_soft_fail_is_low(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["TXT"] = ["v=spf1 include:_spf.google.com ~all"]

        step._analyze_spf("example.com")

        spf_finding = [f for f in step.findings if f.title == "SPF Configuration Detected"]
        assert len(spf_finding) == 1
        assert spf_finding[0].severity == "low"
        assert "Softfail" in spf_finding[0].description

    async def test_spf_with_no_fail_mechanism_is_medium(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["TXT"] = ["v=spf1 include:_spf.google.com include:_spf.yahoo.com include:_spf.zoho.com include:spf.mailgun.org include:mail.zendesk.com include:spf.mandrillapp.com"]

        step._analyze_spf("example.com")

        spf_finding = [f for f in step.findings if f.title == "SPF Configuration Detected"]
        assert spf_finding[0].severity == "medium"


class TestIntelAnalysis:
    """Tests for DNS intelligence analysis."""

    async def test_google_verification_detected(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["TXT"] = [
            '"google-site-verification=ABC123_TOKEN_DEF456"',
        ]

        step._analyze_google_verification("example.com")

        gv = [f for f in step.findings if f.title == "Google Site Verification Detected"]
        assert len(gv) == 1
        assert gv[0].severity == "info"
        assert "ABC123_TOKEN_DEF456" in gv[0].evidence

    async def test_hosting_provider_detected(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["A"] = ["1.2.3.4"]
        step._dns_records["NS"] = ["ns1.cloudflare.com", "ns2.cloudflare.com"]

        step._analyze_hosting_provider("example.com")

        hp = [f for f in step.findings if f.title == "Hosting Provider Detected"]
        assert len(hp) == 1
        assert hp[0].severity == "info"
        assert "Cloudflare" in hp[0].description

    async def test_email_provider_detected(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["MX"] = ["10 mail.google.com."]

        step._analyze_email_provider("example.com")

        ep = [f for f in step.findings if f.title == "Email Provider Detected"]
        assert len(ep) == 1
        assert ep[0].severity == "info"
        assert "Google" in ep[0].description

    async def test_no_email_provider_when_no_mx(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.dns_step import DnsStep

        step = DnsStep(target=mock_target, config=mock_config)
        step._dns_records["MX"] = []

        step._analyze_email_provider("example.com")

        ep = [f for f in step.findings if f.title == "Email Provider Detected"]
        assert len(ep) == 0
