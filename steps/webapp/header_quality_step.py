# recon_wp/steps/webapp/header_quality_step.py
"""
Security header quality check - validates present-but-weak security headers.

Complements the infrastructure HeadersStep (which reports *missing* headers)
by checking the *quality* of headers that are present: HSTS parameters,
X-Frame-Options value, and CSP frame-ancestors.
"""

# WHAT: Checks quality of present security headers (HSTS, XFO, CSP)
# HOW: Fetches homepage, parses header values for weak parameters
# WHY: A present-but-weak header provides less protection than intended

from base.http_step import BaseHttpStep
from core.finding import Finding

MIN_HSTS_MAX_AGE = 31536000  # 1 year


def parse_hsts(value: str) -> dict:
    """Parse a Strict-Transport-Security header value."""
    parts = [p.strip() for p in value.split(";")]
    max_age = 0
    include_subdomains = False
    preload = False
    for part in parts:
        lower = part.lower()
        if lower.startswith("max-age="):
            try:
                max_age = int(lower.split("=", 1)[1])
            except (ValueError, IndexError):
                max_age = 0
        elif lower == "includesubdomains":
            include_subdomains = True
        elif lower == "preload":
            preload = True
    return {"max_age": max_age, "include_subdomains": include_subdomains, "preload": preload}


class HeaderQualityStep(BaseHttpStep):
    """Check quality of present security headers."""

    name = "header_quality"
    description = "Check quality of security headers (HSTS, X-Frame-Options, CSP)"
    severity = "low"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking security header quality...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Failed to fetch homepage: {e}")
            return self.findings

        headers = {k.lower(): v for k, v in response.headers.items()}

        hsts = headers.get("strict-transport-security")
        if hsts:
            parsed = parse_hsts(hsts)
            if parsed["max_age"] < MIN_HSTS_MAX_AGE:
                self._add_finding(
                    module=self.MODULE,
                    severity="low",
                    title="Weak HSTS max-age",
                    description=(
                        f"Strict-Transport-Security max-age is {parsed['max_age']}s "
                        f"(below the recommended {MIN_HSTS_MAX_AGE}s / 1 year)."
                    ),
                    evidence=hsts,
                    recommendation="Increase HSTS max-age to at least 31536000 (1 year)",
                    raw={"hsts": hsts, **parsed},
                )
            if not parsed["include_subdomains"]:
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title="HSTS without includeSubDomains",
                    description=(
                        "Strict-Transport-Security is set without the "
                        "includeSubDomains directive; subdomains are not forced to HTTPS."
                    ),
                    evidence=hsts,
                    recommendation="Add includeSubDomains to the HSTS header",
                    raw={"hsts": hsts, **parsed},
                )

        xfo = (headers.get("x-frame-options") or "").strip()
        if xfo:
            if xfo.lower() == "none":
                self._add_finding(
                    module=self.MODULE,
                    severity="medium",
                    title="X-Frame-Options set to NONE",
                    description=(
                        "X-Frame-Options: NONE explicitly allows the site to be "
                        "framed, enabling clickjacking."
                    ),
                    evidence=xfo,
                    recommendation=(
                        "Use X-Frame-Options DENY (or SAMEORIGIN) and/or CSP "
                        "frame-ancestors"
                    ),
                    raw={"x-frame-options": xfo},
                )
            elif xfo.lower().startswith("allow-from"):
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title="Deprecated X-Frame-Options Allow-From",
                    description=(
                        "X-Frame-Options Allow-From is only supported by older "
                        "Firefox and is otherwise ignored."
                    ),
                    evidence=xfo,
                    recommendation="Use CSP frame-ancestors for origin-restricted framing",
                    raw={"x-frame-options": xfo},
                )

        csp = headers.get("content-security-policy")
        if csp and "frame-ancestors" not in csp.lower():
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="CSP without frame-ancestors",
                description=(
                    "A Content-Security-Policy is present but lacks the "
                    "frame-ancestors directive, so clickjacking protection relies "
                    "solely on X-Frame-Options."
                ),
                evidence=csp[:300],
                recommendation="Add frame-ancestors 'self' (or an explicit allowlist) to the CSP",
                raw={"csp": csp},
            )

        return self.findings
