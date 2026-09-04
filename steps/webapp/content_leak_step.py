# recon_wp/steps/webapp/content_leak_step.py
"""
Content information leak check - reviews HTML pages for leaked information.

Covers WSTG 4.1.5 (Review Web Page Content for Information Leakage):
emails, internal IPs/hostnames, framework generator meta, and config-like
HTML comments.
"""

# WHAT: Scans rendered HTML pages for information leakage
# HOW: Fetches homepage + discovered internal links, applies content rules
# WHY: Page content often leaks infrastructure details useful for attacks

import re

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.source_discovery import extract_link_urls

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_EMAIL_SKIP_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "woff",
    "woff2", "ttf", "eot", "mp4", "webm", "json", "html", "xml", "txt", "map",
}
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b"
)
_INTERNAL_HOST_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)?(?:internal|intranet|internal|staging|dev|test|qa)"
    r"\.(?:corp|local|lan|internal|example)[:,/:\s]",
    re.IGNORECASE,
)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_COMMENT_CONFIG_RE = re.compile(
    r"<!--(?P<body>[^>]*?\b(?:admin|password|passwd|internal|deprecated|temporary"
    r"|\bTODO\b|\bFIXME\b|config|secret)[^>]*?)-->",
    re.IGNORECASE,
)


class ContentLeakStep(BaseHttpStep):
    """Scan homepage and discovered pages for information leakage."""

    name = "content_leak"
    description = "Review web page content for information leakage"
    severity = "info"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Reviewing page content for information leakage...")

        base_url = self.target.url
        pages: list[tuple[str, str]] = []

        try:
            response = await self.fetch("/")
            pages.append(("/", getattr(response, "text", "") or ""))
        except Exception as e:
            self.logger.debug(f"Failed to fetch homepage: {e}")
            return self.findings

        max_pages = getattr(self.config, "webapp_max_pages", 10)
        links = extract_link_urls(pages[0][1], base_url)
        for link in links:
            if len(pages) >= max_pages:
                break
            try:
                response = await self.fetch(link[len(base_url):] or "/")
            except Exception:
                continue
            pages.append((link, getattr(response, "text", "") or ""))

        self.logger.debug(f"Analyzing {len(pages)} page(s)")

        emails: set[str] = set()
        internal_ips: set[str] = set()
        internal_hosts: set[str] = set()
        generators: set[str] = set()
        config_comments: list[str] = []

        for page_name, text in pages:
            if not text:
                continue
            for email in _EMAIL_RE.findall(text):
                tld = email.rsplit(".", 1)[-1].lower()
                if tld not in _EMAIL_SKIP_TLDS:
                    emails.add(email)
            internal_ips.update(_INTERNAL_IP_RE.findall(text))
            internal_hosts.update(h.strip(" ,:/") for h in _INTERNAL_HOST_RE.findall(text))
            generators.update(g.strip() for g in _GENERATOR_RE.findall(text))
            for comment in _COMMENT_CONFIG_RE.findall(text):
                snippet = " ".join(comment.split())[:160]
                if snippet and f"{page_name}: {snippet}" not in config_comments:
                    config_comments.append(f"{page_name}: {snippet}")

        if internal_ips:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Internal IP addresses in page content",
                description=(
                    "Page content references internal IP address(es): "
                    + ", ".join(sorted(internal_ips))
                ),
                evidence=", ".join(sorted(internal_ips)),
                recommendation="Remove internal IP addresses from public page content",
                raw={"ips": sorted(internal_ips)},
            )

        if internal_hosts:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Internal hostnames in page content",
                description=(
                    "Page content references internal hostname(s): "
                    + ", ".join(sorted(internal_hosts))
                ),
                evidence=", ".join(sorted(internal_hosts)),
                recommendation="Remove internal hostnames from public page content",
                raw={"hosts": sorted(internal_hosts)},
            )

        if emails:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Email addresses in page content",
                description=(
                    f"Found {len(emails)} unique email address(es) in page content"
                ),
                evidence=", ".join(sorted(emails)[:20]),
                recommendation=(
                    "Review whether staff/developer email addresses should be public"
                ),
                raw={"emails": sorted(emails)},
            )

        if generators:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Framework/version disclosed via meta generator",
                description=(
                    "The meta generator tag discloses the framework or CMS "
                    "in use: " + ", ".join(sorted(generators))
                ),
                evidence=", ".join(sorted(generators)),
                recommendation=(
                    "Remove or genericize the meta generator tag to reduce "
                    "fingerprinting"
                ),
                raw={"generators": sorted(generators)},
            )

        if config_comments:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Configuration-like HTML comments in page source",
                description=(
                    f"HTML comments containing configuration keywords "
                    f"(admin, password, internal, TODO...) found in {len(config_comments)} "
                    "location(s)."
                ),
                evidence=" | ".join(config_comments[:10]),
                recommendation=(
                    "Remove development/internal comments before production release"
                ),
                raw={"comments": config_comments},
            )

        return self.findings
