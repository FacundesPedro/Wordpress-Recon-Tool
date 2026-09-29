"""Tests for JwtAuditStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.jwt_audit_step import (
    JwtAuditStep,
    decode_jwt,
    jwt_issues,
    weak_hmac_secret,
)
import base64
import hashlib
import hmac
import json
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, secret: str = None) -> str:
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    if secret:
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
    else:
        sig = ""
    return f"{h}.{p}.{sig}"


class TestDecodeJwt:
    def test_decodes_valid_token(self):
        token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
        decoded = decode_jwt(token)
        assert decoded is not None
        header, payload = decoded
        assert header["alg"] == "HS256"
        assert payload["sub"] == "1"

    def test_rejects_malformed(self):
        assert decode_jwt("not-a-jwt") is None
        assert decode_jwt("a.b") is None


class TestJwtIssues:
    def test_alg_none_high(self):
        issues = jwt_issues({"alg": "none"}, {"sub": "1"}, "h.p.")
        assert any(i["severity"] == "high" for i in issues)
        assert not any(i["severity"] == "critical" for i in issues)

    def test_empty_signature_high(self):
        issues = jwt_issues({"alg": "HS256"}, {"sub": "1"}, "h.p.")
        assert any("empty signature" in i["title"].lower() for i in issues)

    def test_weak_email_claim_is_low(self):
        issues = jwt_issues({"alg": "HS256"}, {"email": "a@b.c"}, "h.p.sig")
        claim = [i for i in issues if "sensitive" in i["title"].lower()][0]
        assert claim["severity"] == "low"

    def test_strong_password_claim_is_medium(self):
        issues = jwt_issues({"alg": "HS256"}, {"password": "x"}, "h.p.sig")
        claim = [i for i in issues if "sensitive" in i["title"].lower()][0]
        assert claim["severity"] == "medium"

    def test_missing_exp(self):
        issues = jwt_issues({"alg": "HS256"}, {"sub": "1"}, "h.p.sig")
        assert any("no expiry" in i["title"] for i in issues)

    def test_long_lived_token(self):
        future = time.time() + 400 * 86400
        issues = jwt_issues({"alg": "HS256"}, {"exp": future}, "h.p.sig")
        assert any("long-lived" in i["title"].lower() for i in issues)

    def test_sensitive_claims_flagged(self):
        issues = jwt_issues({"alg": "HS256"}, {"email": "a@b.c"}, "h.p.sig")
        assert any("sensitive" in i["title"].lower() for i in issues)

    def test_kid_header_flagged(self):
        issues = jwt_issues({"alg": "HS256", "kid": "k1"}, {"exp": 1}, "h.p.sig")
        assert any("kid" in i["title"] for i in issues)


class TestWeakHmac:
    def test_detects_weak_secret(self):
        token = make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="secret")
        assert weak_hmac_secret(token, ["secret", "other"]) == "secret"

    def test_rejects_strong_secret(self):
        token = make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="unrelated-long-secret")
        assert weak_hmac_secret(token, ["secret"]) is None


class TestJwtAuditStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True):
        mock_config.webapp_jwt_audit = enabled
        mock_config.source_scan_max_js = 5
        mock_config.source_scan_max_bytes = 100000
        return JwtAuditStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_config(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        findings = await step.run()
        assert findings == []

    async def test_no_tokens_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, headers=MagicMock(
                get=lambda k, d=None: None), text="<html>no tokens</html>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_alg_none_token_reported(self, mock_http, mock_target, mock_config):
        token = make_jwt({"alg": "none"}, {"sub": "1"})
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, headers=MagicMock(
                get=lambda k, d=None: None), text=f"token: {token}")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("alg:none" in f.title for f in findings)

    async def test_weak_secret_reported(self, mock_http, mock_target, mock_config):
        token = make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="secret")
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, headers=MagicMock(
                get=lambda k, d=None: None), text=f"token: {token}")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("weak" in f.title.lower() for f in findings)
