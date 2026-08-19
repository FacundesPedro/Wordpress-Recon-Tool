"""
Correlate installed theme versions against CVEs from vulnerability databases.
"""

# WHAT: Matches detected theme slugs against VulnDB to find known vulnerabilities
# HOW: Detects themes via REST API (auth) or passive HTML scraping, queries VulnDB
# WHY: Outdated themes can expose XSS, SQLi, and other high-severity vulnerabilities

import re
from typing import Optional

from base.http_step import BaseHttpStep
from core.auth import get_wp_auth_header
from core.finding import Finding
from core.vulndb import VulnDB, to_finding_severity


class ThemeVulnStep(BaseHttpStep):
    """Query vulnerability databases for CVEs affecting installed themes."""
    name = "theme_vuln"
    description = "Correlate installed theme versions against known CVEs"
    severity = "info"
    MODULE = "vuln"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking themes for known CVEs...")

        cache_ttl = getattr(self.config, "vulndb_cache_ttl", 300)
        wpscan_token = getattr(self.config, "wpscan_api_token", "")
        db = VulnDB(cache_ttl=cache_ttl, wpscan_token=wpscan_token)

        themes = await self._detect_themes()

        if not themes:
            self.logger.debug("No themes detected — skipping CVE check")
            return self.findings

        all_vulns = []
        try:
            for slug, ver in themes:
                vulns = await db.get_theme_vulns(slug)
                if vulns:
                    all_vulns.append({
                        "slug": slug,
                        "version": ver or "unknown",
                        "cves": [
                            {
                                "id": v.id,
                                "cvss_score": v.cvss_score,
                                "severity": v.severity,
                                "fixed_in": v.fixed_in,
                                "source": v.source,
                            }
                            for v in vulns
                        ],
                    })
        finally:
            await db.close()

        if not all_vulns:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="No theme CVEs found",
                description=f"Checked {len(themes)} theme(s) — no known CVEs detected",
                evidence=f"Themes checked: {', '.join(s for s, _ in themes)}",
                recommendation="Keep all themes updated to their latest versions",
                raw={"themes_checked": len(themes), "vulnerable": 0},
            )
            return self.findings

        for entry in all_vulns:
            for cve in entry["cves"]:
                sev = to_finding_severity(cve["severity"])
                self._add_finding(
                    module=self.MODULE,
                    severity=sev,
                    title=f"{entry['slug']} {entry['version']} — {cve['id']}",
                    description=(
                        f"Theme {entry['slug']} version {entry['version']} "
                        f"has {cve['id']} (CVSS: {cve['cvss_score']})"
                    ),
                    evidence=(
                        f"Theme: {entry['slug']}\n"
                        f"Version: {entry['version']}\n"
                        f"CVE: {cve['id']}\n"
                        f"CVSS: {cve['cvss_score']}\n"
                        f"Fixed in: {cve['fixed_in'] or 'N/A'}\n"
                        f"Source: {cve['source']}"
                    ),
                    recommendation=(
                        f"Update {entry['slug']} to version {cve['fixed_in']} "
                        f"or later to patch this vulnerability"
                    ),
                    raw={"theme": entry["slug"], "version": entry["version"], "cve": cve},
                )

        return self.findings

    async def _detect_themes(self) -> list[tuple[str, Optional[str]]]:
        auth = get_wp_auth_header(
            self.config.wp_user, self.config.wp_application_password
        )
        if auth:
            return await self._detect_themes_auth(auth)
        return await self._detect_themes_passive()

    async def _detect_themes_auth(self, auth: dict) -> list[tuple[str, Optional[str]]]:
        try:
            resp = await self.http.get(
                self.urljoin("wp-json/wp/v2/themes"), headers=auth
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        results = []
        for t in data:
            slug = t.get("stylesheet", "") or t.get("textdomain", "")
            version = t.get("version", "") or None
            if slug:
                results.append((slug, version))
        return results

    async def _detect_themes_passive(self) -> list[tuple[str, Optional[str]]]:
        if not self.target:
            return []
        try:
            resp = await self.http.get(self.target.url)
            if resp.status_code != 200:
                return []
            slugs = set(re.findall(r"/wp-content/themes/([^/]+)/", resp.text))
            return [(s, None) for s in slugs]
        except Exception:
            return []
