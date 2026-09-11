# recon_wp/steps/webapp/sourcemap_step.py
"""
Sourcemap discovery - detects exposed JavaScript sourcemap files.

Sourcemaps (e.g. app.js.map) contain the original unminified source and are
a frequent source of leaked secrets and internal structure.
"""

# WHAT: Detects exposed .js.map sourcemap files
# HOW: Fetches JS assets, parses sourceMappingURL= comments, probes the
#      referenced maps (falling back to the <file>.map suffix convention)
# WHY: Exposed sourcemaps leak original source code, comments, and configs

import json
import re
from urllib.parse import urljoin, urlsplit

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.source_discovery import (
    extract_asset_urls,
    fetch_assets,
    normalize_url,
    strip_query,
)
from utils.soft404 import is_html_body

_SOURCE_MAPPING_URL_RE = re.compile(
    r"^\s*//#\s*sourceMappingURL=(\S+)\s*$", re.MULTILINE
)


def is_sourcemap_content(content: str) -> bool:
    """True when the body is a Source Map v3 JSON document, not a shell.

    SPA catch-alls answer 200 with the app shell for every .map path;
    a real sourcemap is a JSON object with "version" plus "mappings"
    (v3) and/or "sources". HTML and arbitrary JSON never match.
    """
    if not content:
        return False
    if is_html_body(content):
        return False
    if not content.lstrip().startswith("{"):
        return False
    try:
        data = json.loads(content)
    except (TypeError, ValueError):
        return False
    if not isinstance(data, dict) or "version" not in data:
        return False
    return "mappings" in data or "sources" in data


def extract_sourcemap_urls(js_content: str) -> list[str]:
    """Extract sourceMappingURL comment targets from JS content."""
    if not js_content or not isinstance(js_content, str):
        return []
    return [m.strip() for m in _SOURCE_MAPPING_URL_RE.findall(js_content)]


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
        js_assets = await fetch_assets(self.http, base_url, js_urls, max_files=max_js)
        fetched_urls = {url for url, _text in js_assets}

        map_candidates: list[tuple[str, str]] = []
        seen: set[str] = set()
        for js_url, js_text in js_assets:
            referenced = extract_sourcemap_urls(js_text)
            if referenced:
                for raw in referenced:
                    if raw.startswith("data:"):
                        continue
                    # sourceMappingURL is relative to the JS file, not the page
                    candidate = urljoin(js_url, raw)
                    map_url = normalize_url(candidate, base_url)
                    if map_url and map_url not in seen:
                        seen.add(map_url)
                        map_candidates.append((map_url, "source_mapping_url"))
            else:
                fallback = strip_query(js_url) + ".map"
                if fallback not in seen:
                    seen.add(fallback)
                    map_candidates.append((fallback, "map_suffix"))

        # JS that could not be fetched: fall back to the .map suffix probe
        for js_url in js_urls[:max_js]:
            if js_url in fetched_urls:
                continue
            fallback = strip_query(js_url) + ".map"
            if fallback not in seen:
                seen.add(fallback)
                map_candidates.append((fallback, "map_suffix"))

        found_maps: list[tuple[str, int, str]] = []
        for map_url, origin in map_candidates:
            try:
                response = await self.http.request("GET", map_url)
            except Exception:
                continue
            if getattr(response, "status_code", None) == 200:
                text = getattr(response, "text", "") or ""
                if not is_sourcemap_content(text):
                    self.logger.debug(
                        f"Sourcemap probe {map_url}: response is not a sourcemap "
                        f"(likely an SPA/soft-404 shell) - skipped"
                    )
                    continue
                found_maps.append((map_url, len(text.splitlines()), origin))
                self.logger.info(f"Exposed sourcemap: {map_url}")

        for map_url, line_count, origin in found_maps:
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
                raw={
                    "map_url": map_url,
                    "source_lines": line_count,
                    "discovery": origin,
                },
            )

        if found_maps:
            self.logger.info(f"Found {len(found_maps)} exposed sourcemap(s)")
        else:
            self.logger.info("No exposed sourcemaps found")

        return self.findings
