# recon_wp/steps/webapp/host_header_step.py
"""
Host header probe - checks for virtual hosts and Host/X-Forwarded-Host reflection.

Covers WSTG 4.7.17 (Testing for Host Header Injection): sends canary Host and
X-Forwarded-Host headers and checks for an unknown virtual host responding or
the canary being reflected in the response.
"""

# WHAT: Detects vhost takeover surface and Host/X-Forwarded-Host reflection
# HOW: Baseline GET /, then GET / with canary Host and X-Forwarded-Host
#      headers (no redirect following), compares responses
# WHY: Reflected host headers enable cache poisoning, cookie injection,
#      password-reset poisoning, and SSRF phishing; unknown vhosts are a
#      takeover surface when their CNAME is left dangling

import re
import secrets

from base.http_step import BaseHttpStep
from core.finding import Finding

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def build_canary() -> str:
    """Build a random canary host that cannot collide with real sites."""
    return f"canary-host-{secrets.token_hex(4)}.example"


def _headers_text(headers) -> str:
    """Flatten a headers-like object into one searchable string."""
    try:
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    except Exception:
        return ""


def extract_title(text: str) -> str:
    """Extract a cleaned <title> from HTML, or "" if absent."""
    match = _TITLE_RE.search(text or "")
    if not match:
        return ""
    return " ".join(match.group(1).split())[:80]


class HostHeaderStep(BaseHttpStep):
    """Probe Host/X-Forwarded-Host handling for vhosts and reflection."""

    name = "host_header"
    description = "Probe Host/X-Forwarded-Host handling (vhosts, reflection)"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        if not getattr(self.config, "webapp_host_probe", True):
            self.logger.debug("Host header probe disabled by config")
            return self.findings

        self.logger.info("Probing Host header handling...")

        canary = build_canary()

        try:
            baseline = await self.fetch("/", "GET", follow_redirects=False)
        except Exception as e:
            self.logger.debug(f"Baseline request failed: {e}")
            return self.findings

        baseline_status = baseline.status_code
        baseline_text = getattr(baseline, "text", "") or ""

        host_resp = await self._request_with(headers={"Host": canary})
        if host_resp is not None:
            self._check_host_reflection(host_resp, canary, baseline_status, baseline_text)

        xfh_resp = await self._request_with(headers={"X-Forwarded-Host": canary})
        if xfh_resp is not None:
            self._check_xfh_reflection(xfh_resp, canary)

        return self.findings

    async def _request_with(self, headers: dict):
        try:
            return await self.fetch("/", "GET", headers=headers, follow_redirects=False)
        except Exception as e:
            self.logger.debug(f"Header probe failed: {e}")
            return None

    def _check_host_reflection(
        self, response, canary: str, baseline_status: int, baseline_text: str
    ) -> None:
        status = response.status_code
        text = getattr(response, "text", "") or ""
        headers_dump = _headers_text(response.headers)

        if canary in text or canary in headers_dump:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Host header reflected in response",
                description=(
                    f"The server reflected the custom Host header ({canary}) in "
                    "the response body or headers, which can be abused for "
                    "password-reset poisoning and SSRF phishing."
                ),
                evidence=f"Host: {canary} -> HTTP {status} (reflected)",
                recommendation=(
                    "Derive absolute URLs from a configured domain instead of "
                    "the raw Host header"
                ),
                raw={"status": status, "canary": canary},
            )
            return

        if status == 200 and baseline_status == 404:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Unknown Host header gets a valid virtual host",
                description=(
                    f"An unknown Host header ({canary}) returned HTTP 200 while "
                    "the default returned HTTP 404 — the server answers for "
                    "arbitrary vhosts, a subdomain-takeover surface."
                ),
                evidence=f"Host: {canary} -> HTTP 200 (baseline {baseline_status})",
                recommendation=(
                    "Reject unknown Host headers with 404/421, or verify the "
                    "vhost's DNS record is not a dangling CNAME"
                ),
                raw={"status": status, "baseline_status": baseline_status, "canary": canary},
            )
        elif status == 200 and baseline_status == 200 and text and text != baseline_text:
            title = extract_title(text)
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Different virtual host responds for unknown Host header",
                description=(
                    f"An unknown Host header ({canary}) returned different "
                    "content from the default vhost"
                    + (f" (title: {title})" if title else "")
                    + " — a separate virtual host is answering."
                ),
                evidence=f"Host: {canary} -> HTTP 200, content differs from baseline",
                recommendation=(
                    "Confirm the vhost is intended; unknown vhosts should be "
                    "rejected to prevent takeover"
                ),
                raw={"status": status, "title": title, "canary": canary},
            )

    def _check_xfh_reflection(self, response, canary: str) -> None:
        status = response.status_code
        text = getattr(response, "text", "") or ""
        headers_dump = _headers_text(response.headers)

        if canary in text or canary in headers_dump:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="X-Forwarded-Host reflected in response",
                description=(
                    f"The server reflected the X-Forwarded-Host header "
                    f"({canary}) in the response body or headers. Behind a "
                    "cache this enables cache poisoning and cookie/session "
                    "injection."
                ),
                evidence=f"X-Forwarded-Host: {canary} -> HTTP {status} (reflected)",
                recommendation=(
                    "Do not trust X-Forwarded-Host from untrusted clients; "
                    "strip it or validate against the expected domain"
                ),
                raw={"status": status, "canary": canary},
            )
