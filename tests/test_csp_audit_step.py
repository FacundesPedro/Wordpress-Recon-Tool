"""Tests for CspAuditStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.csp_audit_step import CspAuditStep, audit_csp, parse_csp


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)

    def items(self):
        return self._data.items()


def response(status, headers: dict, text=""):
    return MagicMock(status_code=status, headers=HeaderDict(headers), text=text)


def make_step(mock_http, mock_target, mock_config):
    return CspAuditStep(target=mock_target, config=mock_config, http=mock_http)


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp
        return response(404, {})

    return _respond


class TestParseCsp:
    def test_basic_directives(self):
        d = parse_csp(
            "default-src 'self'; script-src 'self' https://cdn.example.com; "
            "object-src 'none'"
        )
        assert d["default-src"] == ["'self'"]
        assert d["script-src"] == ["'self'", "https://cdn.example.com"]
        assert d["object-src"] == ["'none'"]

    def test_empty(self):
        assert parse_csp("") == {}


class TestAuditCsp:
    def test_strong_policy_no_issues(self):
        d = parse_csp(
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; report-to csp-endpoint; "
            "upgrade-insecure-requests"
        )
        assert audit_csp(d) == []

    def test_unsafe_inline_flagged(self):
        issues = audit_csp(parse_csp("script-src 'self' 'unsafe-inline'"))
        assert any("unsafe-inline" in i["title"] for i in issues)

    def test_unsafe_eval_flagged(self):
        issues = audit_csp(parse_csp("script-src 'self' 'unsafe-eval'"))
        assert any("unsafe-eval" in i["title"] for i in issues)

    def test_missing_object_src(self):
        issues = audit_csp(parse_csp("script-src 'self'"))
        assert any("object-src" in i["title"] for i in issues)

    def test_object_src_not_none(self):
        issues = audit_csp(parse_csp("object-src *"))
        assert any("not 'none'" in i["title"] for i in issues)

    def test_missing_base_uri_form_action(self):
        issues = audit_csp(parse_csp("default-src 'self'; object-src 'none'"))
        titles = {i["title"] for i in issues}
        assert any("base-uri" in t for t in titles)
        assert any("form-action" in t for t in titles)

    def test_no_script_directive(self):
        issues = audit_csp(
            parse_csp("object-src 'none'; base-uri 'self'; form-action 'self'")
        )
        assert any("no script restrictions" in i["title"] for i in issues)

    def test_script_falls_back_to_default(self):
        issues = audit_csp(
            parse_csp(
                "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
            )
        )
        assert any("falls back to default-src" in i["title"] for i in issues)

    def test_missing_reporting(self):
        issues = audit_csp(
            parse_csp(
                "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
            )
        )
        assert any("violation reporting" in i["title"] for i in issues)


class TestCspAuditStep:
    async def test_no_csp_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=responder({"/": response(200, {})}))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_weak_csp_findings(self, mock_http, mock_target, mock_config):
        # unsafe-inline only counts for scripts when it appears in script-src
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"
        mock_http.request = AsyncMock(
            side_effect=responder({"/": response(200, {"content-security-policy": csp})})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = {f.title for f in findings}
        assert "CSP allows inline scripts (unsafe-inline)" in titles
        assert "CSP allows eval (unsafe-eval)" in titles
        assert all(f.severity in ("medium", "low", "info") for f in findings)

    async def test_strong_csp_no_findings(self, mock_http, mock_target, mock_config):
        csp = (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; report-to ep; "
            "upgrade-insecure-requests"
        )
        mock_http.request = AsyncMock(
            side_effect=responder({"/": response(200, {"content-security-policy": csp})})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_evidence_truncated(self, mock_http, mock_target, mock_config):
        csp = "default-src 'self' " + ("; report-uri https://r.example" * 30)
        mock_http.request = AsyncMock(
            side_effect=responder({"/": response(200, {"content-security-policy": csp})})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings
        assert all(len(f.evidence) <= 300 for f in findings)

    async def test_homepage_failure(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
