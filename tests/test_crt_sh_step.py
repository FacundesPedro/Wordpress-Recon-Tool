"""Tests for CrtShStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


MOCK_CERT_JSON = """[
    {
        "name_value": "sub.example.com\\nwww.example.com",
        "common_name": "example.com",
        "alternate_names": "mail.example.com\\napi.example.com"
    },
    {
        "name_value": "blog.example.com",
        "common_name": "*.example.com",
        "alternate_names": "dev.example.com"
    }
]"""


class TestSkipConditions:
    """Tests for early return conditions."""

    async def test_returns_empty_when_no_domain(self, mock_http):
        mock_target = MagicMock()
        mock_target.domain = None

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=mock_http)
        findings = await step.run()
        assert findings == []

    async def test_returns_skip_finding_when_no_http(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=None)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].title == "Certificate Transparency skipped"
        assert findings[0].module == "passive"
        assert findings[0].severity == "low"


class TestQueryPatterns:
    """Tests for _build_query_patterns."""

    async def test_builds_three_patterns(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        patterns = step._build_query_patterns("example.com")
        assert len(patterns) == 3
        assert "example.com" in patterns[0]


class TestQueryAndParse:
    """Tests for query and parse logic."""

    async def test_200_with_valid_json_finds_subdomains(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = MOCK_CERT_JSON
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=mock_http)

        findings = await step.run()

        domains_finding = [f for f in findings if "Subdomains Discovered" in f.title]
        assert len(domains_finding) == 1
        assert domains_finding[0].module == "passive"
        assert domains_finding[0].severity == "info"
        assert domains_finding[0].raw["valid_count"] >= 5

    async def test_200_with_empty_json_returns_no_certificates(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = "[]"
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=mock_http)

        findings = await step.run()

        no_cert = [f for f in findings if f.title == "No certificates found"]
        assert len(no_cert) == 1
        assert no_cert[0].severity == "info"

    async def test_html_fallback_parse(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = (
            '<html><body><table><tr><td class="outer">sub.example.com</td></tr>'
            '<tr><td class="outer">www.example.com</td></tr></table></body></html>'
        )
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=mock_http)

        findings = await step.run()

        domains_finding = [f for f in findings if "Subdomains Discovered" in f.title]
        assert len(domains_finding) == 1
        assert domains_finding[0].raw["valid_count"] >= 2

    async def test_429_retry_then_succeeds(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        rate_limit_resp = MagicMock(status_code=429)
        success_resp = MagicMock(status_code=200)
        success_resp.text = MOCK_CERT_JSON
        mock_http.request = AsyncMock(
            side_effect=[rate_limit_resp, success_resp]
        )

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=mock_http)

        findings = await step.run()

        domains_finding = [f for f in findings if "Subdomains Discovered" in f.title]
        assert len(domains_finding) == 1

    async def test_429_all_attempts_fail_records_errors(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        rate_limit_resp = MagicMock(status_code=429)
        mock_http.request = AsyncMock(return_value=rate_limit_resp)

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=mock_http)

        findings = await step.run()

        assert len(findings) == 0

    async def test_timeout_all_attempts_records_errors(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=TimeoutError("timed out"))

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=mock_http)

        findings = await step.run()

        assert len(findings) == 0


class TestCreateFindings:
    """Tests for _create_findings output."""

    async def test_wildcard_count_over_10_escalates_severity(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        step._domains = {f"*.sub{i}.example.com" for i in range(12)}
        step._domains.add("www.example.com")

        step._create_findings("example.com")

        domains_finding = [f for f in step.findings if "Subdomains Discovered" in f.title]
        assert len(domains_finding) == 1
        assert domains_finding[0].severity == "low"

    async def test_wildcard_over_5_triggers_separate_finding(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        step._domains = {f"*.sub{i}.example.com" for i in range(7)}
        step._domains.add("www.example.com")

        step._create_findings("example.com")

        wildcard = [f for f in step.findings if f.title == "High Wildcard Certificate Usage"]
        assert len(wildcard) == 1
        assert wildcard[0].severity == "info"

    async def test_no_domains_does_nothing(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        step._domains = set()

        step._create_findings("example.com")
        assert len(step.findings) == 0


class TestExtractDomainsFromCert:
    """Tests for _extract_domains_from_cert."""

    async def test_extracts_all_fields(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        cert = {
            "name_value": "sub.example.com\nwww.example.com",
            "common_name": "example.com",
            "alternate_names": "mail.example.com",
        }
        step._extract_domains_from_cert(cert)
        assert "sub.example.com" in step._domains
        assert "www.example.com" in step._domains
        assert "example.com" in step._domains
        assert "mail.example.com" in step._domains

    async def test_handles_empty_fields(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        cert = {"name_value": "", "common_name": "", "alternate_names": ""}
        step._extract_domains_from_cert(cert)
        assert len(step._domains) == 0


class TestIsValidSubdomain:
    """Tests for _is_valid_subdomain."""

    async def test_accepts_wildcard(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        assert step._is_valid_subdomain("*.example.com", "example.com")

    async def test_accepts_subdomain(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        assert step._is_valid_subdomain("sub.example.com", "example.com")

    async def test_accepts_exact_domain(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        assert step._is_valid_subdomain("example.com", "example.com")

    async def test_rejects_too_short(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        assert not step._is_valid_subdomain("ab", "example.com")

    async def test_rejects_unrelated_domain(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        assert not step._is_valid_subdomain("evil.com", "example.com")


class TestParseHtml:
    """Tests for HTML fallback parsing."""

    async def test_parse_html_extracts_domains(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.crt_sh_step import CrtShStep

        step = CrtShStep(target=mock_target, http=MagicMock())
        html = (
            '<table><tr><td class="outer">sub.example.com</td></tr>'
            '<tr><td class="outer">www.example.com</td></tr></table>'
        )
        step._parse_html(html)
        assert "sub.example.com" in step._domains
        assert "www.example.com" in step._domains
        assert len(step._domains) == 2
