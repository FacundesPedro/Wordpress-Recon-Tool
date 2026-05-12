# recon_wp/steps/infrastructure/headers_step.py
"""
HTTP Security Headers enumeration.

Checks for presence/absence of security-related HTTP headers.
"""

# WHAT: Checks HTTP response headers for security headers
# HOW: Fetches homepage, compares against list (X-Frame-Options, CSP, HSTS, etc.)
# WHY: Missing headers indicate security misconfigurations

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class HeadersStep(BaseHttpStep, WordlistDependencyMixin):
    """Check for security-related HTTP headers."""

    name = "headers"
    description = "Check HTTP security headers"
    severity = "info"
    MODULE = "infrastructure"

    DEFAULT_SECURITY_HEADERS = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Checking HTTP security headers...")

        security_headers = self.resolve_wordlist_or_fallback(
            config_key="security_headers",
            defaults=self.DEFAULT_SECURITY_HEADERS,
            name="security headers wordlist",
        )
        if not security_headers:
            return self.findings

        try:
            response = await self.http.get(self.target.url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            missing_headers = []
            present_headers = {}

            for header in security_headers:
                header_lower = header.lower()
                if header_lower in headers:
                    present_headers[header] = headers[header_lower]
                else:
                    missing_headers.append(header)

            if missing_headers:
                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="Missing security headers",
                    description=f"Found {len(missing_headers)} missing security header(s)",
                    evidence=", ".join(missing_headers),
                    recommendation="Consider adding missing security headers",
                    raw={"missing": missing_headers, "present": present_headers},
                )
                self.logger.info(f"Missing headers: {', '.join(missing_headers)}")

            if present_headers:
                self.logger.debug(f"Present headers: {present_headers}")

        except Exception as e:
            self.logger.error(f"Error checking headers: {e}")

        return self.findings
