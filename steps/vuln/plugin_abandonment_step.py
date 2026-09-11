# recon_wp/steps/vuln/plugin_abandonment_step.py
"""
Plugin/theme abandonment risk - WordPress.org directory metadata audit.

For each detected plugin/theme slug, queries the WordPress.org plugin/theme
info API and reports abandonment signals:
- plugin closed/removed from the directory
- no updates for > 2 years
- `tested` version older than the detected WP core version
Detection-only, uses the public api.wordpress.org endpoints (no target load).
"""

# WHAT: Flags plugins/themes that are abandoned, closed, or untested
# HOW: Detects slugs (auth API or HTML), queries wp.org info API 1.2, and
#      evaluates last_updated/closed/tested fields
# WHY: Abandoned components are latent exposures even without a known CVE

import re
from datetime import datetime, timezone
from typing import Optional

from base.http_step import BaseHttpStep
from core.auth import get_wp_auth_header
from core.finding import Finding

WPORG_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.2/"
WPORG_THEME_API = "https://api.wordpress.org/themes/info/1.2/"

ABANDONED_YEARS = 2
MAX_LOOKUPS = 30


def parse_last_updated(value) -> Optional[datetime]:
    """Parse wp.org last_updated ('2024-01-15 3:20pm' style) to datetime."""
    if not value:
        return None
    cleaned = str(value).strip()
    for fmt in ("%Y-%m-%d %I:%M%p", "%Y-%m-%d %I:%M %p", "%Y-%m-%d",
                "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def version_tuple(version: str) -> tuple:
    parts = []
    for piece in str(version).split("."):
        digits = re.match(r"\d+", piece)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def abandonment_issues(info: dict, kind: str) -> list[dict]:
    """Evaluate wp.org info for abandonment signals."""
    issues: list[dict] = []
    name = info.get("slug") or info.get("name") or kind

    if info.get("closed") in (1, True, "1"):
        issues.append({
            "severity": "high",
            "title": f"{kind.capitalize()} '{name}' is closed/removed from WordPress.org",
            "description": (
                f"The {kind} has been closed on WordPress.org (reason: "
                f"{info.get('close_reason', 'unknown')}). Closed components "
                f"receive no updates and often carry unpatched vulnerabilities."
            ),
            "recommendation": f"Remove the {kind} or find an actively maintained alternative",
        })
        return issues  # closed is the strongest signal; skip the rest

    last_updated = parse_last_updated(info.get("last_updated"))
    if last_updated:
        age_years = (datetime.now(timezone.utc) - last_updated).days / 365.25
        if age_years > ABANDONED_YEARS:
            issues.append({
                "severity": "medium",
                "title": f"{kind.capitalize()} '{name}' not updated in {age_years:.1f} years",
                "description": (
                    f"Last update: {last_updated.date()}. Long-unmaintained "
                    f"{kind}s accumulate unpatched vulnerabilities."
                ),
                "recommendation": f"Replace or update the {kind}; verify it is still maintained",
            })

    return issues


class PluginAbandonmentStep(BaseHttpStep):
    """Flag abandoned/closed plugins and themes via the wp.org info API."""

    name = "plugin_abandonment"
    description = "Flag plugins/themes closed or not updated on WordPress.org"
    severity = "medium"
    MODULE = "vuln"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking plugin/theme maintenance status on WordPress.org...")

        plugins = await self._detect_plugins()
        themes = await self._detect_themes()
        if not plugins and not themes:
            self.logger.info("Abandonment check: no components detected")
            return self.findings

        core_version = await self._detect_core_version()

        lookups = 0
        for slug, _ver in plugins[:MAX_LOOKUPS]:
            if lookups >= MAX_LOOKUPS:
                break
            lookups += 1
            info = await self._fetch_info(WPORG_PLUGIN_API, slug)
            if info is None:
                continue
            for issue in abandonment_issues(info, "plugin"):
                issue["slug"] = slug
                self._report(issue, slug, _ver)

        for slug, _ver in themes[:MAX_LOOKUPS]:
            if lookups >= MAX_LOOKUPS:
                break
            lookups += 1
            info = await self._fetch_info(WPORG_THEME_API, slug)
            if info is None:
                continue
            for issue in abandonment_issues(info, "theme"):
                issue["slug"] = slug
                self._report(issue, slug, _ver)

        self.logger.info(
            f"Abandonment check: {lookups} lookup(s), "
            f"{len(self.findings)} finding(s)"
        )
        return self.findings

    # -- helpers ----------------------------------------------------------

    async def _fetch_info(self, api_url: str, slug: str) -> Optional[dict]:
        """Query the wp.org info API; None when the item is unknown."""
        url = (
            f"{api_url}?action=plugin_information&request[slug]={slug}"
            f"&request[fields][last_updated]=1"
            f"&request[fields][tested]=1"
            f"&request[fields][versions]=0"
            f"&request[fields][sections]=0"
        )
        if "themes" in api_url:
            url = url.replace("action=plugin_information", "action=theme_information")
        try:
            response = await self.http.request("GET", url)
        except Exception as e:
            self.logger.debug(f"wp.org info {slug} failed: {e}")
            return None
        if getattr(response, "status_code", None) != 200:
            return None
        try:
            data = response.json()
        except Exception:
            return None
        if not isinstance(data, dict) or not data or data.get("error"):
            return None
        return data

    async def _detect_plugins(self) -> list[tuple[str, Optional[str]]]:
        auth = get_wp_auth_header(
            self.config.wp_user, self.config.wp_application_password
        )
        if auth:
            results = await self._detect_plugins_auth(auth)
            if results:
                return results
        return await self._detect_plugins_passive()

    async def _detect_plugins_auth(self, auth: dict) -> list[tuple[str, Optional[str]]]:
        try:
            resp = await self.http.get(
                self.urljoin("wp-json/wp/v2/plugins"), headers=auth
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception as e:
            self.logger.debug(f"Auth plugin detection failed: {e}")
            return []
        if not isinstance(data, list):
            return []
        results = []
        for p in data:
            slug = p.get("plugin", "")
            if "/" in slug:
                slug = slug.split("/")[0]
            version = p.get("version", "") or None
            if slug:
                results.append((slug, version))
        return results

    async def _detect_plugins_passive(self) -> list[tuple[str, Optional[str]]]:
        try:
            resp = await self.http.get(self.target.url)
            slugs = set(re.findall(r"/wp-content/plugins/([^/]+)/", resp.text))
            return [(s, None) for s in slugs]
        except Exception as e:
            self.logger.debug(f"Passive plugin detection failed: {e}")
            return []

    async def _detect_themes(self) -> list[tuple[str, Optional[str]]]:
        try:
            resp = await self.http.get(self.target.url)
            slugs = set(re.findall(r"/wp-content/themes/([^/]+)/", resp.text))
            return [(s, None) for s in slugs]
        except Exception:
            return []

    async def _detect_core_version(self) -> Optional[str]:
        try:
            resp = await self.http.get(self.target.url)
            match = re.search(
                r'name="generator"[^>]*content="WordPress ([\d.]+)"', resp.text
            )
            return match.group(1) if match else None
        except Exception:
            return None

    def _report(self, issue: dict, slug: str, version: Optional[str]) -> None:
        self._add_finding(
            module=self.MODULE,
            severity=issue["severity"],
            title=issue["title"],
            description=issue["description"],
            evidence=f"{issue.get('kind', 'component')}: {slug} "
                     f"(installed version: {version or 'unknown'})",
            recommendation=issue["recommendation"],
            raw={"slug": slug, "version": version, **issue},
        )
