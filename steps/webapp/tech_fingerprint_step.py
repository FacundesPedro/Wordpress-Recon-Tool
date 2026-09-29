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
    # Infrastructure / server banners (version captured where advertised).
    ("nginx", "server", "server", r"nginx(?:/([\d.]+))?"),
    ("Apache httpd", "server", "server", r"Apache(?:/([\d.]+))?"),
    ("Microsoft IIS", "server", "server", r"Microsoft-IIS(?:/([\d.]+))?"),
    ("Caddy", "server", "server", r"Caddy"),
    ("LiteSpeed", "server", "server", r"LiteSpeed"),
    ("Tomcat", "server", "server", r"Apache-Coyote|Tomcat(?:/([\d.]+))?"),
    ("Gunicorn", "server", "server", r"gunicorn(?:/([\d.]+))?"),
    ("Werkzeug", "server", "server", r"Werkzeug(?:/([\d.]+))?"),
]

BODY_SIGNATURES = [
    ("Next.js", "framework", r"__NEXT_DATA__"),
    ("Nuxt", "framework", r"__NUXT__"),
    ("SvelteKit", "framework", r"__sveltekit"),
    ("Astro", "framework", r"astro-island|data-astro-cid"),
    ("React", "library", r"data-reactroot|__reactContainer|react-dom"),
    ("Vue", "library", r"data-v-app|data-v-[0-9a-f]{8}"),
    (
        "Angular",
        "framework",
        r"ng-version=|data-beasties-container|main\.[0-9a-f]{6,}\.js"
        r"|chunk-[A-Z0-9]{6,}\.js",
    ),
    ("Tailwind CSS", "css", r"@layer theme,base,components,utilities|--tw-[a-z-]+:"),
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
    (
        "Keycloak",
        "idp",
        r"keycloak(?:\.v2)?|Keycloak Administration Console"
        r"|/auth/realms/[^/\"'\s]+|/realms/[^/\"'\s]+/protocol/openid-connect",
    ),
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

    KEYCLOAK_REALMS = ("auth/realms/master", "realms/master")

    async def _probe_keycloak(self, detected, seen) -> None:
        """Detect a Keycloak IdP by probing its realm discovery endpoint."""
        if "Keycloak" in seen:
            return
        for path in self.KEYCLOAK_REALMS:
            try:
                response = await self.ctx.web.get(path)
            except Exception as e:
                self.logger.debug(f"Keycloak probe {path} failed: {e}")
                continue
            if getattr(response, "status_code", None) != 200:
                continue
            try:
                data = response.json()
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            if "public_key" in data or (
                "realm" in data and "token-service" in str(data).lower()
            ):
                seen.add("Keycloak")
                detected.append(
                    ("Keycloak", "idp", f"realm discovery at /{path}")
                )
                return

    async def run(self) -> list[Finding]:
        self.logger.info("Fingerprinting web technologies...")

        try:
            response = await self.ctx.web.homepage()
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

        # Keycloak commonly sits under /auth and is not linked from the SPA
        # shell, so probe the well-known realm endpoint explicitly.
        await self._probe_keycloak(detected, seen)

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

        # Machine-readable inventory so the recon table is populated from the
        # report JSON rather than assembled by hand.
        if detected:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title=f"Technology fingerprint: {len(detected)} component(s)",
                description="Detected components: "
                + ", ".join(f"{label} ({kind})" for label, kind, _ in detected),
                evidence="\n".join(
                    f"{label} [{kind}] - {evidence}"
                    for label, kind, evidence in detected
                ),
                recommendation="No action - informational inventory",
                raw={
                    "technologies": [
                        {"name": label, "kind": kind, "evidence": evidence}
                        for label, kind, evidence in detected
                    ]
                },
            )

        self.logger.info(
            f"Tech fingerprint: {len(detected)} technology(ies) detected"
        )
        return self.findings
