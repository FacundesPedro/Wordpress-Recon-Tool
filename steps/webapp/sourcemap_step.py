# recon_wp/steps/webapp/sourcemap_step.py
"""
Sourcemap discovery - detects exposed JavaScript sourcemap files.

Sourcemaps (e.g. app.js.map) contain the original unminified source and are
a frequent source of leaked secrets and internal structure.
"""

# WHAT: Detects exposed .js.map sourcemap files
# HOW: Extracts JS asset URLs from homepage, probes <file>.map variants
# WHY: Exposed sourcemaps leak original source code, comments, and configs

from urllib.parse import urlsplit

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.source_discovery import extract_asset_urls, strip_query


class SourcemapStep(BaseHttpStep):
    """Detect exposed JavaScript sourcemap files."""

    name = "sourcemap"
    description = "Detect exposed JavaScript sourcemap files"
    severity = "low"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        if not getattr(self.config, "source_scan_sourcemaps", True):
            self.logger.debug("Sourcemap check disabled by config")
            return self.findings

        self.logger.info("Checking for exposed JavaScript sourcemaps...")

        base_url = self.target.url
        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Failed to fetch homepage: {e}")
            return self.findings

        html = getattr(response, "text", "") or ""
        assets = extract_asset_urls(html, base_url)
        js_urls = [u for u in assets if strip_query(u).endswith(".js")]

        max_js = getattr(self.config, "source_scan_max_js", 20)
        found_maps: list[tuple[str, int]] = []

        for js_url in js_urls[:max_js]:
            map_url = strip_query(js_url) + ".map"
            try:
                response = await self.http.request("GET", map_url)
            except Exception:
                continue
            if getattr(response, "status_code", None) == 200:
                text = getattr(response, "text", "") or ""
                found_maps.append((map_url, len(text.splitlines())))
                self.logger.info(f"Exposed sourcemap: {map_url}")

        for map_url, line_count in found_maps:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Exposed JavaScript sourcemap",
                description=(
                    f"Sourcemap {urlsplit(map_url).path} is publicly accessible "
                    f"({line_count} lines of original source recovered)."
                ),
                evidence=map_url,
                recommendation=(
                    "Disable sourcemap generation in production builds "
                    "(or serve them only with authentication)"
                ),
                raw={"map_url": map_url, "source_lines": line_count},
            )

        if found_maps:
            self.logger.info(f"Found {len(found_maps)} exposed sourcemap(s)")
        else:
            self.logger.info("No exposed sourcemaps found")

        return self.findings
