# WHAT: Brute-force plugin path discovery via response-code oracle
# HOW: HTTP GET to known plugin paths — 200/301/403 confirms existence
# WHY: Finds installed plugins without requiring authenticated access

import re
from typing import Optional

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class PluginBruteforceStep(BaseHttpStep, WordlistDependencyMixin):
    name = "plugin_bruteforce"
    description = "Brute-force plugin discovery via response-code oracle"
    severity = "info"
    MODULE = "discovery"

    async def run(self) -> list[Finding]:
        self.logger.info("Brute-forcing WordPress plugins...")

        slugs = self.resolve_wordlist_or_fallback(
            config_key="",
            defaults=self._default_plugin_slugs(),
            name="plugin wordlist",
            wordlist_file="plugins/plugin_fallback.txt",
        )
        if not slugs:
            return self.findings

        if len(slugs) <= 30:
            self.logger.warning(
                "Using small fallback plugin list (30 entries). "
                "For better coverage, download SecLists wordpress-plugins.fuzz.txt "
                "(~20k entries) and configure via WP_PLUGIN_WORDLIST or place it in "
                "~/.config/recon-wp/wordlists/plugins/plugin_fallback.txt"
            )

        found = []
        for slug in slugs:
            slug = slug.strip()
            if not slug or slug.startswith("#"):
                continue
            exists, version, status = await self._probe_plugin(slug)
            if exists:
                found.append({"slug": slug, "version": version, "status": status})
                self.logger.debug(f"Found plugin: {slug} (v{version or 'unknown'})")

        if not found:
            self.logger.info("No additional plugins found via brute-force")
            return self.findings

        evidence_lines = []
        for p in sorted(found, key=lambda x: x["slug"]):
            v = f" v{p['version']}" if p["version"] else ""
            evidence_lines.append(f"  {p['slug']}{v} [{p['status']}]")

        self._add_finding(
            module=self.MODULE,
            severity=self.severity,
            title="Plugins discovered via brute-force",
            description=f"Found {len(found)} plugin(s) via response-code oracle",
            evidence="\n".join(evidence_lines),
            recommendation=(
                "Review all discovered plugins for known vulnerabilities. "
                "Remove unused plugins entirely."
            ),
            raw={"plugins": found, "total": len(found)},
        )

        return self.findings

    async def _probe_plugin(self, slug: str) -> tuple[bool, Optional[str], str]:
        path = f"wp-content/plugins/{slug}/"
        try:
            response = await self.get(path)
            status = response.status_code
        except Exception:
            return False, None, "error"

        if status in (200, 301, 302, 403):
            version = await self._try_extract_version(slug)
            return True, version, f"HTTP {status}"
        return False, None, f"HTTP {status}"

    async def _try_extract_version(self, slug: str) -> Optional[str]:
        for readme in ("readme.txt", "readme.md"):
            path = f"wp-content/plugins/{slug}/{readme}"
            try:
                resp = await self.get(path)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            version = self._parse_version(resp.text)
            if version:
                return version
        return None

    def _parse_version(self, text: str) -> Optional[str]:
        m = re.search(
            r"(?:Stable tag|Version):\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            text,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)
        return None

    def _default_plugin_slugs(self) -> list[str]:
        return [
            "akismet", "contact-form-7", "elementor", "jetpack",
            "woocommerce", "wordfence", "wordpress-seo", "wpforms-lite",
            "w3-total-cache", "updraftplus", "all-in-one-wp-migration",
            "revslider", "gravityforms", "better-wp-security",
            "litespeed-cache", "really-simple-ssl", "redirection",
            "tablepress", "duplicator", "backupbuddy",
            "nextgen-gallery", "maintenance", "smart-slider-3",
            "seo-by-rank-math", "essential-addons-for-elementor-lite",
            "wp-fastest-cache", "all-in-one-seo-pack", "yoast-seo",
            "wpmu-dev-seo", "sitepress-multilingual-cms",
        ]
