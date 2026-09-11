# WHAT: Brute-force theme path discovery via response-code oracle
# HOW: HTTP GET to known theme paths — 200/301/403 confirms existence
# WHY: Identifies active and deactivated themes for vulnerability matching

import asyncio
import re
import time
from typing import Optional

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class ThemeBruteforceStep(BaseHttpStep, WordlistDependencyMixin):
    name = "theme_bruteforce"
    description = "Brute-force theme discovery via response-code oracle"
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
                "Target does not appear to be WordPress - skipping theme brute-force"
            )
            return self.findings

        self.logger.info("Brute-forcing WordPress themes...")

        slugs = self.resolve_wordlist_or_fallback(
            config_key="",
            defaults=self._default_theme_slugs(),
            name="theme wordlist",
            wordlist_file="plugins/theme_fallback.txt",
        )
        if not slugs:
            return self.findings

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

        if len(slugs) <= 15:
            self.logger.warning(
                "Using small fallback theme list (15 entries). "
                "For better coverage, provide a comprehensive theme wordlist via "
                "~/.config/recon-wp/wordlists/plugins/theme_fallback.txt"
            )

        self.logger.info(
            f"Brute-forcing {len(slugs)} theme(s) with concurrency {concurrency}..."
        )

        semaphore = asyncio.Semaphore(concurrency)

        async def probe(slug: str):
            async with semaphore:
                return await self._probe_theme(slug)

        found = []
        total = len(slugs)
        processed = 0
        start = time.monotonic()
        batch_size = concurrency * 10

        for offset in range(0, total, batch_size):
            if self.http.unreachable:
                self.logger.warning(
                    "Target unreachable — aborting theme brute-force"
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
                        f"Found theme: {slug} (v{version or 'unknown'})"
                    )
            if processed % self.PROGRESS_EVERY == 0 or processed >= total:
                elapsed = time.monotonic() - start
                self.logger.info(
                    f"Brute-force progress: {processed}/{total} theme(s) "
                    f"probed, {len(found)} found ({elapsed:.1f}s)"
                )

        if not found:
            self.logger.info("No additional themes found via brute-force")
            return self.findings

        evidence_lines = []
        for t in sorted(found, key=lambda x: x["slug"]):
            v = f" v{t['version']}" if t["version"] else ""
            evidence_lines.append(f"  {t['slug']}{v} [{t['status']}]")

        self._add_finding(
            module=self.MODULE,
            severity=self.severity,
            title="Themes discovered via brute-force",
            description=f"Found {len(found)} theme(s) via response-code oracle",
            evidence="\n".join(evidence_lines),
            recommendation=(
                "Review all discovered themes for known vulnerabilities. "
                "Remove unused themes to reduce attack surface."
            ),
            raw={"themes": found, "total": len(found)},
        )

        return self.findings

    async def _probe_theme(self, slug: str) -> tuple[bool, Optional[str], str]:
        path = f"wp-content/themes/{slug}/"
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
        path = f"wp-content/themes/{slug}/style.css"
        try:
            resp = await self.get(path)
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        m = re.search(r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", resp.text)
        if m:
            return m.group(1)
        return None

    def _default_theme_slugs(self) -> list[str]:
        return [
            "astra", "avada", "divi", "enfold", "generatepress",
            "hello-elementor", "jupiter", "kadence", "oceanwp",
            "porto", "salient", "the7", "twenty-twenty-four",
            "ui-element", "heateor-woo-floating-cart",
        ]
