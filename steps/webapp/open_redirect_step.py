# recon_wp/steps/webapp/open_redirect_step.py
"""
Open redirect check - probes redirect parameters with a canary URL.

Covers WSTG 4.11.4 (Testing for Client-side URL Redirect): appends common
redirect parameter names carrying an untrusted canary URL to key paths and
reports when the server issues a redirect (3xx) to the canary.
"""

# WHAT: Detects open redirects via canary-URL parameter probes
# HOW: GETs key paths with ?param=<canary> (no redirect following); a 3xx
#      Location pointing at the canary means the parameter is unvalidated
# WHY: Open redirects enable phishing and break OAuth redirect validation

import secrets
from urllib.parse import quote, unquote

from base.http_step import BaseHttpStep
from core.finding import Finding

DEFAULT_REDIRECT_PATHS = [
    "/",
    "/login",
    "/logout",
    "/signin",
    "/signout",
    "/sign-in",
    "/sign-out",
    "/redirect",
    "/go",
    "/url",
    "/next",
    "/return",
    "/home",
    "/account",
    "/index",
    "/session",
]

# Paths where an open redirect is most dangerous (phishing/auth flows)
AUTH_PATHS = {
    "/login",
    "/logout",
    "/signin",
    "/signout",
    "/sign-in",
    "/sign-out",
    "/authenticate",
    "/auth",
    "/account",
    "/session",
}

REDIRECT_PARAMS = [
    "url",
    "redirect",
    "redirect_uri",
    "next",
    "return",
    "returnTo",
    "rurl",
    "redir",
    "continue",
    "dest",
    "destUrl",
    "forward",
    "to",
    "target",
    "out",
]

_REDIRECT_STATUS = (301, 302, 303, 307, 308)
MAX_FINDINGS = 10


def build_canary() -> str:
    """Build a random canary redirect target that cannot collide with real sites."""
    return f"https://redirect-canary-{secrets.token_hex(4)}.example"


def canary_in_location(location: str, canary: str) -> bool:
    """True if a Location header redirects to (or through) the canary host."""
    if not location:
        return False
    host = canary.split("//", 1)[1].split("/", 1)[0]
    candidates = [location, unquote(location)]
    return any(host in candidate for candidate in candidates)


class OpenRedirectStep(BaseHttpStep):
    """Detect open redirects by probing redirect parameters with a canary."""

    name = "open_redirect"
    description = "Detect open redirects via canary-URL parameter probes"
    severity = "high"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        if not getattr(self.config, "webapp_open_redirect", True):
            self.logger.debug("Open redirect check disabled by config")
            return self.findings

        self.logger.info("Probing for open redirects...")

        canary = build_canary()
        max_requests = getattr(self.config, "webapp_redirect_max_requests", 60)

        probed = 0
        for path in DEFAULT_REDIRECT_PATHS:
            for param in REDIRECT_PARAMS:
                if probed >= max_requests or len(self.findings) >= MAX_FINDINGS:
                    break
                probed += 1
                query = f"{param}={quote(canary, safe='')}"
                full_path = f"{path}?{query}" if not path.endswith("/") else f"{path}{query}"
                try:
                    response = await self.fetch(full_path, "GET", follow_redirects=False)
                except Exception as e:
                    self.logger.debug(f"Redirect probe {path}?{param} failed: {e}")
                    continue

                if response.status_code not in _REDIRECT_STATUS:
                    continue
                location = response.headers.get("location") or ""
                if not canary_in_location(location, canary):
                    continue

                if path in AUTH_PATHS:
                    severity = "high"
                    note = "on an authentication-related path"
                else:
                    severity = "medium"
                    note = "on a non-authentication path"

                self._add_finding(
                    module=self.MODULE,
                    severity=severity,
                    title=f"Open redirect via {param} parameter at {path}",
                    description=(
                        f"The parameter '{param}' at {path} redirects to an "
                        f"untrusted URL {note} (HTTP {response.status_code})."
                    ),
                    evidence=(
                        f"GET {self.target.url}{full_path} -> "
                        f"{response.status_code} Location: {location[:200]}"
                    ),
                    recommendation=(
                        "Validate redirect targets against an allowlist of "
                        "same-origin paths; reject absolute URLs or external hosts"
                    ),
                    raw={
                        "path": path,
                        "param": param,
                        "status": response.status_code,
                        "location": location,
                        "canary": canary,
                    },
                )
                self.logger.info(f"Open redirect: {path}?{param}")

        if len(self.findings) >= MAX_FINDINGS:
            self.logger.info(
                f"Open redirect: {len(self.findings)} hit(s) (reporting capped)"
            )
        elif not self.findings:
            self.logger.info(f"Open redirect: no hits after {probed} probes")
        return self.findings
