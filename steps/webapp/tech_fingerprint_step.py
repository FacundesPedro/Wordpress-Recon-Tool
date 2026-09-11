# recon_wp/steps/webapp/tech_fingerprint_step.py
"""
Technology fingerprinting - framework/CMS/server identification.

Covers WSTG 4.1.8 (Fingerprint Web Application Framework) and 4.1.9
(Fingerprint Web Application): identifies frameworks, CMSs, and server
technologies from response headers, cookies, and HTML patterns. Informational
output that contextualizes other findings.
"""

# WHAT: Fingerprints frameworks/CMS/servers from headers, cookies, and HTML
# HOW: Signature matching over homepage headers + body
# WHY: Knowing the stack contextualizes every other finding

import re

from base.http_step import BaseHttpStep
from core.finding import Finding

# (label, kind, header, regex)
HEADER_SIGNATURES = [
    ("Next.js", "framework", "x-powered-by", r"Next\.js"),
    ("Nuxt", "framework", "x-powered-by", r"Nuxt"),
    ("Express", "framework", "x-powered-by", r"Express"),
    ("PHP", "language", "x-powered-by", r"PHP[/ ]([\d.]+)?"),
    ("ASP.NET", "framework", "x-powered-by", r"ASP\.NET"),
    ("ASP.NET", "framework", "x-aspnet-version", r"(.+)"),
    ("Django", "framework", "server", r"django"),
    ("Webpack", "bundler", "x-webpack", r".+"),
]

BODY_SIGNATURES = [
    ("Next.js", "framework", r"__NEXT_DATA__"),
    ("Nuxt", "framework", r"__NUXT__"),
    ("SvelteKit", "framework", r"__sveltekit"),
    ("Astro", "framework", r"astro-island|data-astro-cid"),
    ("React", "library", r"data-reactroot|__reactContainer"),
    ("Vue", "library", r"data-v-app|data-v-[0-9a-f]{8}"),
    ("Angular", "library", r"ng-version="),
    ("Django", "framework", r"csrfmiddlewaretoken"),
    ("Ruby on Rails", "framework", r"csrf-token|authenticity_token"),
    ("Laravel", "framework", r"laravel_session|XSRF-TOKEN"),
    ("ASP.NET", "framework", r"__VIEWSTATE|__VIEWSTATEGENERATOR"),
    ("Spring Boot", "framework", r"JSESSIONID"),
    ("WordPress", "cms", r"wp-content|wp-includes"),
    ("Drupal", "cms", r"drupal-settings-json|Drupal\.settings"),
    ("Joomla", "cms", r"/media/jui/|Joomla!"),
    ("Shopify", "cms", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Wix", "cms", r"static\.wixstatic\.com|wix-code"),
    ("Squarespace", "cms", r"static1\.squarespace\.com"),
    ("Cloudflare", "cdn", r"cdn-cgi/"),
]

COOKIE_SIGNATURES = [
    ("PHP", "language", r"PHPSESSID"),
    ("Laravel", "framework", r"laravel_session|XSRF-TOKEN"),
    ("Ruby on Rails", "framework", r"_session_id"),
    ("ASP.NET", "framework", r"ASP\.NET_SessionId|\.ASPXAUTH"),
    ("Express", "framework", r"connect\.sid"),
    ("Django", "framework", r"sessionid|csrftoken"),
    ("Spring Boot", "framework", r"JSESSIONID"),
]

MAX_FINDINGS = 12


class TechFingerprintStep(BaseHttpStep):
    """Fingerprint frameworks/CMS/servers from headers, cookies, and HTML."""

    name = "tech_fingerprint"
    description = "Fingerprint web frameworks/CMS/servers (informational)"
    severity = "info"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Fingerprinting web technologies...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        detected: list[tuple[str, str, str]] = []  # (label, kind, evidence)
        seen: set[str] = set()

        html = response.text or ""
        headers = response.headers
        cookies = headers.get("set-cookie") or ""

        for label, kind, header, pattern in HEADER_SIGNATURES:
            value = headers.get(header)
            if not value:
                continue
            match = re.search(pattern, value, re.I)
            if match and label not in seen:
                seen.add(label)
                evidence = f"{header}: {match.group(0)[:60]}"
                detected.append((label, kind, evidence))

        for label, kind, pattern in BODY_SIGNATURES:
            if label in seen:
                continue
            match = re.search(pattern, html, re.I)
            if match:
                seen.add(label)
                detected.append((label, kind, f"body pattern: {match.group(0)[:40]}"))

        for label, kind, pattern in COOKIE_SIGNATURES:
            if label in seen:
                continue
            if re.search(pattern, cookies, re.I):
                seen.add(label)
                detected.append((label, kind, "Set-Cookie signature"))

        for label, kind, evidence in detected[:MAX_FINDINGS]:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title=f"Technology detected: {label} ({kind})",
                description=(
                    f"The application appears to use {label} "
                    f"(identified via {evidence})."
                ),
                evidence=evidence,
                recommendation="No action - informational fingerprint for "
                               "contextualizing other findings",
                raw={"technology": label, "kind": kind, "evidence": evidence},
            )

        self.logger.info(
            f"Tech fingerprint: {len(detected)} technology(ies) detected"
        )
        return self.findings
