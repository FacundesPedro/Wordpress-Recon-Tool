# recon_wp/steps/webapp/jwt_audit_step.py
"""
JWT audit - extracts JSON Web Tokens and audits them offline (no verification
requests against auth endpoints).

Covers WSTG 4.6.10 (Testing JSON Web Tokens): decodes header/payload segments
and reports structural weaknesses:
- alg:none or empty signature
- missing/expired/long-lived exp
- sensitive claims in the payload
- kid/jku/jwk header parameters (key-injection surface)
- weak HS256 secrets (offline dictionary check with stdlib hmac)
"""

# WHAT: Audits JWTs found in cookies, HTML, and JS for structural weaknesses
# HOW: Extracts JWT-shaped strings, base64url-decodes header/payload, checks
#      alg/exp/claims and verifies weak HMAC secrets offline
# WHY: JWT flaws (alg confusion, missing expiry, sensitive claims) are common
#      and detectable without active probing

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Optional

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.source_discovery import extract_asset_urls, fetch_assets

JWT_RE = re.compile(
    r"\b([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]*)"
)

SENSITIVE_CLAIMS = (
    "email", "phone", "ssn", "password", "secret", "api_key", "apikey",
    "token", "private_key", "credit_card", "card_number", "address",
)

WEAK_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "your-256-bit-secret",
    "key", "changeme", "supersecret", "shhhhh", "keyboard cat", "s3cr3t",
    "test", "dev", "mysecret", "tokensecret",
]

MAX_TOKENS = 10
LONG_LIVED_DAYS = 30


def b64url_decode(segment: str) -> Optional[bytes]:
    """Decode a base64url segment with padding fix; None on failure."""
    try:
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + padding)
    except Exception:
        return None


def decode_jwt(token: str) -> Optional[tuple[dict, dict]]:
    """Decode a JWT into (header, payload) dicts; None if not parseable."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    if header_raw is None or payload_raw is None:
        return None
    try:
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def jwt_issues(header: dict, payload: dict, token: str) -> list[dict]:
    """Evaluate a decoded JWT; return issue dicts (severity/title/...)."""
    issues: list[dict] = []
    alg = str(header.get("alg", "")).lower()

    if alg in ("none", ""):
        issues.append({
            "severity": "critical",
            "title": "JWT uses alg:none",
            "description": (
                "The token declares alg:none or omits the algorithm, meaning "
                "no signature verification is expected for this token."
            ),
            "recommendation": "Reject alg:none server-side and pin allowed algorithms",
        })

    if not token.split(".")[2]:
        issues.append({
            "severity": "critical",
            "title": "JWT has an empty signature",
            "description": "The signature segment is empty; the token is unsigned.",
            "recommendation": "Enforce signature verification for all tokens",
        })

    if "kid" in header or "jku" in header or "jwk" in header:
        keys = [k for k in ("kid", "jku", "jwk") if k in header]
        issues.append({
            "severity": "low",
            "title": f"JWT header carries key-selection parameter(s): {', '.join(keys)}",
            "description": (
                "kid/jku/jwk parameters can enable key-injection or key-confusion "
                "attacks if the server resolves keys from untrusted input."
            ),
            "recommendation": "Resolve keys server-side only; validate kid against an allowlist",
        })

    exp = payload.get("exp")
    now = time.time()
    if exp is None:
        issues.append({
            "severity": "medium",
            "title": "JWT has no expiry (exp)",
            "description": "The token never expires; a leaked token is valid forever.",
            "recommendation": "Set short-lived exp claims and rotate refresh tokens",
        })
    elif isinstance(exp, (int, float)):
        if exp < now:
            issues.append({
                "severity": "info",
                "title": "JWT is expired (observed token already past exp)",
                "description": "The observed token's exp is in the past (informational).",
                "recommendation": "No action if this was a historical sample",
            })
        elif exp - now > LONG_LIVED_DAYS * 86400:
            issues.append({
                "severity": "medium",
                "title": "JWT is long-lived (>30 days)",
                "description": (
                    f"The token expires in {(exp - now) / 86400:.0f} days, "
                    f"extending the window for stolen-token replay."
                ),
                "recommendation": "Use short-lived access tokens with refresh rotation",
            })

    sensitive = [k for k in payload if str(k).lower() in SENSITIVE_CLAIMS]
    if sensitive:
        issues.append({
            "severity": "medium",
            "title": f"JWT payload carries sensitive claim(s): {', '.join(sensitive)}",
            "description": (
                "JWT payloads are base64-encoded, not encrypted. Sensitive "
                "data in claims is readable by anyone who obtains the token."
            ),
            "recommendation": "Keep only identifiers in JWT claims; store sensitive data server-side",
        })

    return issues


def weak_hmac_secret(token: str, secrets_list: list[str]) -> Optional[str]:
    """Return the matching weak secret if the HMAC signature verifies offline."""
    signing_input = token.rsplit(".", 1)[0].encode()
    signature = token.rsplit(".", 1)[1]
    for candidate in secrets_list:
        expected = hmac.new(
            candidate.encode(), signing_input, hashlib.sha256
        ).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
        if hmac.compare_digest(expected_b64, signature):
            return candidate
    return None


class JwtAuditStep(BaseHttpStep):
    """Audit JWTs found in cookies/HTML/JS for structural weaknesses."""

    name = "jwt_audit"
    description = "Audit JWTs for alg:none, expiry, sensitive claims, weak HMAC secrets"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        if not getattr(self.config, "webapp_jwt_audit", True):
            self.logger.debug("JWT audit disabled by config")
            return self.findings

        self.logger.info("Auditing JWTs (offline decode, no auth probes)...")

        tokens: list[str] = []

        # 1. Homepage body + cookies
        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings
        tokens.extend(JWT_RE.findall(response.text or ""))
        for cookie_header in response.headers.get_list("set-cookie") \
                if hasattr(response.headers, "get_list") else \
                [response.headers.get("set-cookie") or ""]:
            tokens.extend(JWT_RE.findall(cookie_header))

        # 2. JS assets (bounded)
        try:
            asset_urls = extract_asset_urls(response.text or "", self.target.url)
            assets = await fetch_assets(
                self.http, self.target.url, asset_urls,
                max_files=int(getattr(self.config, "source_scan_max_js", 20)),
                max_bytes=int(getattr(self.config, "source_scan_max_bytes", 1000000)),
            )
            for _url, content in assets:
                tokens.extend(JWT_RE.findall(content))
        except Exception as e:
            self.logger.debug(f"JS asset fetch failed: {e}")

        # dedupe, keep unique tokens by payload signature
        unique: list[str] = []
        seen: set[str] = set()
        for match in tokens:
            token = ".".join(match) if isinstance(match, tuple) else match
            if token in seen:
                continue
            seen.add(token)
            unique.append(token)
            if len(unique) >= MAX_TOKENS:
                break

        if not unique:
            self.logger.info("JWT audit: no JWT-shaped tokens found")
            return self.findings

        weak_secrets = WEAK_SECRETS
        for token in unique:
            decoded = decode_jwt(token)
            if decoded is None:
                continue
            header, payload = decoded
            issues = jwt_issues(header, payload, token)

            if str(header.get("alg", "")).lower().startswith("hs"):
                weak = weak_hmac_secret(token, weak_secrets)
                if weak:
                    issues.append({
                        "severity": "critical",
                        "title": "JWT signed with a weak/guessable HMAC secret",
                        "description": (
                            f"The HS256 signature verifies offline against a "
                            f"common secret (matched a known weak-secret "
                            f"dictionary entry). Tokens can be forged."
                        ),
                        "recommendation": (
                            "Use a high-entropy server-side signing key and "
                            "rotate it"
                        ),
                    })

            if not issues:
                continue
            # mask token in evidence: show header only
            evidence = token.split(".")[0] + ".<payload>.<signature>"
            for issue in issues:
                self._add_finding(
                    module=self.MODULE,
                    severity=issue["severity"],
                    title=issue["title"],
                    description=issue["description"],
                    evidence=f"JWT header (b64): {evidence}",
                    recommendation=issue["recommendation"],
                    raw={"header": header,
                         "claims": sorted(payload.keys()),
                         "alg": header.get("alg")},
                )

        self.logger.info(
            f"JWT audit: {len(self.findings)} finding(s) across "
            f"{len(unique)} token(s)"
        )
        return self.findings
