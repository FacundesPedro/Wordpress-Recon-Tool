# recon_wp/steps/passive/core_currency_step.py
"""
WordPress core currency check against the official wordpress.org API.

``core_vuln`` depends on WPVulnerability (often unreachable from restricted
networks) and ``wpscan`` requires an API token. This step closes the patch-gap
blind spot without either: it asks
``https://api.wordpress.org/core/version-check/1.7/?version=<installed>`` and
reports when WordPress itself says an upgrade is available.
"""

# WHAT: Compare the installed WordPress core version with the latest release
# HOW: version-check API (no token) + ?ver= detection when the generator is gone
# WHY: An outdated core is the highest-impact patch gap on many installs

from __future__ import annotations

import time

import httpx

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.core_version import detect_core_version

API_URL = "https://api.wordpress.org/core/version-check/1.7/"
CACHE_TTL = 3600
_TIMEOUT = 10.0

# version -> (checked_at monotonic, parsed offer). One API call per version per
# hour is plenty; it also keeps repeated multi-target runs polite.
_CACHE: dict[str, tuple[float, dict]] = {}


def clear_cache() -> None:
    """Drop the version-check cache (used by tests)."""
    _CACHE.clear()


def parse_version_check(data: dict, installed: str) -> dict | None:
    """Return the relevant offer, or None when the payload is unusable.

    The API returns ``offers[0].response`` in {``upgrade``, ``autoupdate``,
    ``latest``, ``development``}; ``current`` is the latest stable release.
    """
    offers = data.get("offers") if isinstance(data, dict) else None
    if not isinstance(offers, list) or not offers:
        return None
    offer = next((o for o in offers if isinstance(o, dict)), None)
    if offer is None:
        return None
    current = str(offer.get("current") or offer.get("version") or "").strip()
    if not current:
        return None
    return {
        "installed": installed,
        "current": current,
        "response": str(offer.get("response") or "").lower(),
        "php_version": offer.get("php_version"),
        "download": offer.get("download"),
    }


class CoreCurrencyStep(BaseHttpStep):
    """Detect the core version and warn when wordpress.org offers an upgrade."""

    name = "core_currency"
    description = "Compare WordPress core against the latest official release"
    severity = "medium"
    MODULE = "passive"
    requires = ("wordpress",)

    async def run(self) -> list[Finding]:
        self.logger.info("Checking WordPress core currency...")

        try:
            is_wp = await self.ctx.web.wordpress()
        except Exception:
            is_wp = False
        if not is_wp:
            self.logger.debug("Target is not WordPress - core currency skipped")
            return self.findings

        try:
            homepage = await self.ctx.web.homepage()
        except Exception as e:
            self.logger.debug(f"Homepage unavailable: {e}")
            return self.findings
        if getattr(homepage, "status_code", 0) != 200:
            return self.findings

        installed, source = detect_core_version(homepage.text)
        if not installed:
            self.logger.info(
                "Core version not detected (generator removed and no core "
                "?ver= asset found)"
            )
            return self.findings

        offer = await self._version_check(installed)
        if offer is None:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="WordPress core currency check failed",
                description=(
                    "The wordpress.org version-check API could not be "
                    "queried, so the installed core may be outdated but this "
                    "was not verified. This is an execution note."
                ),
                evidence=f"Installed: {installed} (detected from {source})",
                recommendation=(
                    "Check https://wordpress.org/download/releases/ manually "
                    "or re-run when api.wordpress.org is reachable"
                ),
                raw={
                    "operational": True,
                    "installed": installed,
                    "source": source,
                    "api": API_URL,
                },
            )
            return self.findings

        current = offer["current"]
        if offer["response"] == "upgrade" and current != installed:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title=f"WordPress core is outdated: {installed} (latest {current})",
                description=(
                    f"wordpress.org reports an available upgrade from "
                    f"{installed} to {current}. Outdated core releases carry "
                    "publicly known vulnerabilities."
                ),
                evidence=(
                    f"Installed: {installed} (detected from {source})\n"
                    f"Latest: {current}\n"
                    f"API response: {offer['response']}"
                ),
                recommendation=(
                    f"Update WordPress core to {current} (or the latest "
                    "security release on the current branch)"
                ),
                raw={
                    "installed": installed,
                    "latest": current,
                    "response": offer["response"],
                    "source": source,
                    "php_version": offer.get("php_version"),
                    "download": offer.get("download"),
                    "api": API_URL,
                },
            )
            self.logger.info(
                f"Core outdated: installed {installed}, latest {current}"
            )
        else:
            self.logger.info(
                f"Core currency OK: {installed} (API response "
                f"{offer['response'] or 'unknown'})"
            )

        return self.findings

    async def _version_check(self, installed: str) -> dict | None:
        """Query the API (cached for ``CACHE_TTL``) and parse the offer."""
        cached = _CACHE.get(installed)
        now = time.monotonic()
        if cached is not None and now - cached[0] < CACHE_TTL:
            return cached[1]
        data = await self._fetch_api(installed)
        if data is None:
            return None
        offer = parse_version_check(data, installed)
        if offer is not None:
            _CACHE[installed] = (now, offer)
        return offer

    async def _fetch_api(self, installed: str) -> dict | None:
        params = {"version": installed, "locale": "en_US"}
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": "wp-recon-tool core-currency"},
            ) as client:
                response = await client.get(API_URL, params=params)
            if response.status_code != 200:
                self.logger.debug(
                    f"version-check API returned {response.status_code}"
                )
                return None
            return response.json()
        except Exception as e:
            self.logger.debug(f"version-check API request failed: {e}")
            return None
