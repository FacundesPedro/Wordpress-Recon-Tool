# WHAT: Brute-force plugin path discovery via response-code oracle
# HOW: HTTP GET to known plugin paths — 200/301/403 confirms existence
# WHY: Finds installed plugins without requiring authenticated access

import asyncio
import re
import time
from typing import Optional

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import Soft404Detector


class PluginBruteforceStep(BaseHttpStep, WordlistDependencyMixin):
    name = "plugin_bruteforce"
    description = "Brute-force plugin discovery via response-code oracle"
    severity = "info"
    MODULE = "discovery"

    CONCURRENCY_DEFAULT = 4
    PROGRESS_EVERY = 500

    def _config_int(self, key: str, default: int) -> int:
        """Read an integer config value, falling back to default on missing/invalid."""
        if self.config is None:
            return default
        value = getattr(self.config, key, None)
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping plugin brute-force"
            )
            return self.findings

        self.logger.info("Brute-forcing WordPress plugins...")

        slugs = self.resolve_wordlist_or_fallback(
            config_key="",
            defaults=self._default_plugin_slugs(),
            name="plugin wordlist",
            wordlist_file="plugins/plugin_fallback.txt",
        )
        if not slugs:
            return self.findings

        if self.http.unreachable:
            self.logger.warning("Target unreachable — aborting plugin brute-force")
            return self.findings

        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        concurrency = self._config_int(
            "bruteforce_concurrency", self.CONCURRENCY_DEFAULT
        )
        max_probes = self._config_int("bruteforce_max_probes", 0)
        if max_probes > 0:
            slugs = slugs[:max_probes]

        slugs = [
            s.strip()
            for s in slugs
            if s and s.strip() and not s.startswith("#")
        ]

        if len(slugs) <= 30:
            self.logger.warning(
                "Using small fallback plugin list (30 entries). "
                "For better coverage, download SecLists wordpress-plugins.fuzz.txt "
                "(~20k entries) and configure via WP_PLUGIN_WORDLIST or place it in "
                "~/.config/recon-wp/wordlists/plugins/plugin_fallback.txt"
            )

        self.logger.info(
            f"Brute-forcing {len(slugs)} plugin(s) with concurrency {concurrency}..."
        )

        semaphore = asyncio.Semaphore(concurrency)

        async def probe(slug: str):
            async with semaphore:
                return await self._probe_plugin(slug, detector)

        found = []
        total = len(slugs)
        processed = 0
        start = time.monotonic()
        batch_size = concurrency * 10

        for offset in range(0, total, batch_size):
            if self.http.unreachable:
                self.logger.warning(
                    "Target unreachable — aborting plugin brute-force"
                )
                break
            batch = slugs[offset : offset + batch_size]
            results = await asyncio.gather(*(probe(s) for s in batch))
            for slug, (exists, version, status) in zip(batch, results):
                processed += 1
                if exists:
                    found.append(
                        {"slug": slug, "version": version, "status": status}
                    )
                    self.logger.debug(
                        f"Found plugin: {slug} (v{version or 'unknown'})"
                    )
            if processed % self.PROGRESS_EVERY == 0 or processed >= total:
                elapsed = time.monotonic() - start
                self.logger.info(
                    f"Brute-force progress: {processed}/{total} plugin(s) "
                    f"probed, {len(found)} found ({elapsed:.1f}s)"
                )

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

    async def _probe_plugin(
        self, slug: str, detector: Soft404Detector
    ) -> tuple[bool, Optional[str], str]:
        path = f"wp-content/plugins/{slug}/"
        try:
            response = await self.get(path)
            status = response.status_code
        except Exception:
            return False, None, "error"

        if status in (200, 301, 302, 403):
            if detector.is_soft404(response):
                self.logger.debug(
                    f"Plugin probe {slug}: catch-all/soft-404 shell - skipped"
                )
                return False, None, f"HTTP {status}"
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
