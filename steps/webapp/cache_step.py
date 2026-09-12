# recon_wp/steps/webapp/cache_step.py
"""
Cache analysis - cache-layer detection and web cache deception canary.

Covers WSTG 4.2.x/4.7.x cache behavior: detects caching layers from response
headers (Age, X-Cache, CF-Cache-Status, X-Varnish), audits Cache-Control on
the homepage, and performs a capped path-suffix web-cache-deception canary:
appends a static-looking suffix to a dynamic path and checks whether the
response is cacheable and reflected. Findings require corroborating cache
headers to limit false positives.
"""

# WHAT: Detects cache layers and potential web cache deception surface
# HOW: Header analysis + capped path-suffix canary probes corroborated by
#      cache-status headers
# WHY: Cache deception stores authenticated responses under public URLs

from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import Soft404Detector

CACHE_INDICATOR_HEADERS = [
    "age", "x-cache", "cf-cache-status", "x-varnish", "x-served-by",
    "x-drupal-cache", "x-proxy-cache", "x-fastly-request-id",
    "x-vercel-cache", "x-cache-hits",
]

SUFFIXES = [".css", ".js", ".html"]
MAX_CANARY_PATHS = 3
MAX_FINDINGS = 5


def cache_layer(headers) -> Optional[str]:
    """Return the name of the first detected caching layer, if any."""
    for header in CACHE_INDICATOR_HEADERS:
        value = headers.get(header)
        if value:
            return header
    return None


def cacheable(headers) -> bool:
    """True when Cache-Control allows shared caching.

    max-age=0 / s-maxage=0 require revalidation on every use and do not
    meaningfully cache content, so they are treated as not cacheable.
    """
    cc = (headers.get("cache-control") or "").lower()
    if "no-store" in cc or "private" in cc:
        return False
    if "max-age=0" in cc or "s-maxage=0" in cc:
        return False
    return "public" in cc or "max-age" in cc or "s-maxage" in cc


class CacheAnalysisStep(BaseHttpStep):
    """Detect cache layers and potential cache deception surface."""

    name = "cache_analysis"
    description = "Detect caching layers and web cache deception surface"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Analyzing cache behavior...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        layer = cache_layer(response.headers)
        if layer:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title=f"Caching layer detected ({layer})",
                description=(
                    f"The response carries cache headers ({layer}: "
                    f"{response.headers.get(layer, '')[:80]}). Cache rules "
                    f"apply to this site - review what is cacheable."
                ),
                evidence=f"{layer}: {response.headers.get(layer, '')[:100]}",
                recommendation="Ensure dynamic/authenticated responses are "
                               "marked Cache-Control: private, no-store",
                raw={"layer": layer},
            )

        if cacheable(response.headers):
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Homepage is publicly cacheable",
                description=(
                    "Cache-Control allows shared caching of the homepage. "
                    "Verify no personalized content is embedded."
                ),
                evidence=f"Cache-Control: {response.headers.get('cache-control', '')[:120]}",
                recommendation="Keep personalized/dynamic pages private, no-store",
                raw={},
            )

        # Path-suffix canary (cache deception surface)
        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        canary_paths = ["/account", "/profile", "/api/user", "/dashboard", "/me"]
        for path in canary_paths[:MAX_CANARY_PATHS]:
            if len(self.findings) >= MAX_FINDINGS:
                break
            await self._probe_deception(path, detector)

        self.logger.info(f"Cache analysis: {len(self.findings)} finding(s)")
        return self.findings

    async def _probe_deception(self, path: str, detector: Soft404Detector) -> None:
        """Probe a dynamic-looking path with static suffixes."""
        for suffix in SUFFIXES:
            probe_path = f"{path}/canary7q4{suffix}"
            probe_url = self.urljoin(probe_path)
            try:
                response = await self.fetch(probe_path, follow_redirects=False)
            except Exception as e:
                self.logger.debug(f"Cache canary {probe_path} failed: {e}")
                continue
            status = getattr(response, "status_code", None)
            if status is None or status >= 400:
                continue
            if detector.is_soft404(response):
                self.logger.debug(
                    f"Cache canary {probe_path}: catch-all shell - skipped"
                )
                continue
            # dynamic path tolerated the suffix -> origin ignores it
            layer_seen = cache_layer(response.headers) is not None
            cacheable_response = cacheable(response.headers)
            if cacheable_response and layer_seen:
                self._add_finding(
                    module=self.MODULE,
                    severity="medium",
                    title=f"Possible cache deception surface at {path}",
                    description=(
                        f"Appending '{suffix}' to {path} returns HTTP {status} "
                        f"with cacheable headers. If this path serves "
                        f"authenticated content, a cache deception attack may "
                        f"store it under a public URL. Manual verification "
                        f"with an authenticated session is required."
                    ),
                    evidence=f"GET {probe_url} -> {status}, "
                             f"Cache-Control: "
                             f"{response.headers.get('cache-control', '')[:80]}",
                    recommendation="Mark dynamic responses private, no-store; "
                                   "align cache rules with response types",
                    raw={"path": path, "url": probe_url,
                         "status": status},
                )
                return
