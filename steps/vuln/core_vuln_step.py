"""
Correlate WordPress core version against CVEs from vulnerability databases.
"""

# WHAT: Queries vulnerability databases for CVEs affecting the detected WP core version
# HOW: Detects core version from generator tag or readme.html, then queries VulnDB
# WHY: Running outdated WordPress core is the single highest-risk configuration

import re
from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding
from core.vulndb import VulnDB, to_finding_severity


class CoreVulnStep(BaseHttpStep):
    """Query vulnerability databases for CVEs affecting the WordPress core version."""
    name = "core_vuln"
    description = "Correlate WordPress core version against known CVEs"
    severity = "info"
    MODULE = "vuln"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking WordPress core version for known CVEs...")

        version = await self._detect_core_version()
        if not version:
            self.logger.info("Could not detect WordPress core version")
            return self.findings

        cache_ttl = getattr(self.config, "vulndb_cache_ttl", 300)
        wpscan_token = getattr(self.config, "wpscan_api_token", "")
        db = VulnDB(cache_ttl=cache_ttl, wpscan_token=wpscan_token)
        try:
            vulns = await db.get_core_vulns(version)
        finally:
            await db.close()

        if not vulns:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="No known CVEs for WordPress core",
                description=(
                    f"WordPress {version} has no known vulnerabilities "
                    "in the vulnerability database"
                ),
                evidence=f"Version: {version}",
                recommendation="Keep WordPress updated to the latest version",
                raw={"version": version, "total_cves": 0},
            )
            return self.findings

        by_severity: dict[str, list[dict]] = {}
        for v in vulns:
            sev = to_finding_severity(v.severity)
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append({
                "id": v.id,
                "title": v.title,
                "cvss_score": v.cvss_score,
                "fixed_in": v.fixed_in,
                "source": v.source,
            })

        for raw_sev, items in sorted(by_severity.items()):
            self._add_finding(
                module=self.MODULE,
                severity=raw_sev,  # type: ignore[arg-type]
                title=f"WordPress {version} — {len(items)} {raw_sev.upper()} severity CVE(s)",
                description=(
                    f"WordPress core version {version} has {len(items)} "
                    f"known {raw_sev} severity vulnerabilities"
                ),
                evidence="\n".join(
                    f"  {i['id']} (CVSS: {i['cvss_score']}, fixed in: {i['fixed_in'] or 'N/A'})"
                    for i in items
                ),
                recommendation="Update WordPress to a patched version. Latest: https://wordpress.org/download/",
                raw={"version": version, "severity": raw_sev, "cves": items},
            )

        return self.findings

    async def _detect_core_version(self) -> Optional[str]:
        if not self.target:
            return None
        try:
            resp = await self.http.get(self.target.url)
            if resp.status_code == 200:
                m = re.search(
                    (
                        r'<meta name="generator"[^>]+'
                        r'content="WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"'
                    ),
                    resp.text,
                    re.IGNORECASE,
                )
                if m:
                    return m.group(1)
        except Exception:
            pass

        try:
            resp = await self.http.get(self.urljoin("readme.html"))
            if resp.status_code == 200:
                m = re.search(r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", resp.text)
                if m:
                    return m.group(1)
        except Exception:
            pass

        return None
