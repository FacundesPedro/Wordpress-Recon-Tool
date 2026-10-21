# recon_wp/steps/fingerprint/plugin_version_step.py
"""
Plugin version detection - extracts version info for detected plugins.

Attempts to fetch version information from readme.txt, readme.md, or
the plugin's main PHP file header.
"""

# WHAT: Extract version information for detected WordPress plugins
# HOW: Fetch readme.txt, readme.md, or main PHP file for version strings
# WHY: Plugin versions enable targeted vulnerability research

import re
from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.plugin_fingerprint import PluginFingerprinter, assets_from_html
from utils.slugs import detect_plugins_from_html


class PluginVersionStep(BaseHttpStep):
    """
    Detect WordPress plugin versions by fetching version files.

    Attempts multiple sources in order of preference:
    1. readme.txt - Standard WordPress plugin readme format
    2. readme.md  - Markdown-formatted readme
    3. {plugin}.php - Main plugin file header
    """

    name = "plugin_version"
    description = "Detect WordPress plugin versions"
    severity = "info"
    MODULE = "fingerprint"

    VERSION_PATTERNS = [
        (r"stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "stable_tag"),
        (r"\*\*stable tag:\*\*\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "stable_tag_md"),
        (r"version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "version_header"),
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Detecting plugin versions...")

        self._homepage_html = ""
        plugin_names = await self._detect_plugins()
        if not plugin_names:
            self.logger.warning("No plugins detected - cannot enumerate versions")
            return self.findings

        self.logger.info(f"Found {len(plugin_names)} plugin(s), fetching versions...")

        plugin_versions = {}
        for plugin in plugin_names:
            version_info = await self._get_plugin_version(plugin)
            if version_info["version"] == "unknown":
                fingerprint = await self._fingerprint_plugin(plugin)
                if fingerprint:
                    version_info.update(fingerprint)
            plugin_versions[plugin] = version_info

        known_versions = {
            name: info
            for name, info in plugin_versions.items()
            if info["version"] != "unknown"
        }
        unknown_versions = {
            name: info
            for name, info in plugin_versions.items()
            if info["version"] == "unknown"
        }

        evidence_parts = []
        for name, info in sorted(plugin_versions.items()):
            if info["version"] != "unknown":
                evidence_parts.append(f"{name}: {info['version']}")
            else:
                evidence_parts.append(f"{name}: unknown")

        if evidence_parts:
            evidence = ", ".join(evidence_parts)
        else:
            evidence = "No version information found"

        description_parts = []
        if known_versions:
            description_parts.append(f"{len(known_versions)} with known version(s)")
        if unknown_versions:
            description_parts.append(f"{len(unknown_versions)} with unknown version")

        self._add_finding(
            module=self.MODULE,
            severity=self.severity,
            title="WordPress plugin versions detected",
            description=f"Version information retrieved - {'; '.join(description_parts)}",
            evidence=evidence,
            recommendation="Ensure all plugins are updated to latest versions",
            raw={
                "plugins": plugin_versions,
                "summary": {
                    "total": len(plugin_versions),
                    "known": len(known_versions),
                    "unknown": len(unknown_versions),
                },
            },
        )

        self.logger.info(
            f"Plugin versions: {len(known_versions)} known, {len(unknown_versions)} unknown"
        )

        return self.findings

    async def _detect_plugins(self) -> list[str]:
        """Detect plugin names from homepage HTML."""
        try:
            response = await self.ctx.web.homepage()
            if response.status_code != 200:
                return []

            content = response.text
            self._homepage_html = content
            return detect_plugins_from_html(content)

        except Exception as e:
            self.logger.error(f"Error detecting plugins: {e}")
            return []

    def _fingerprint_enabled(self) -> bool:
        # Strict identity: MagicMock test configs must not trigger network I/O.
        return getattr(self.config, "plugin_fingerprint_enabled", True) is True

    async def _fingerprint_plugin(self, plugin: str) -> Optional[dict]:
        """Resolve a blocked readme via asset hashes against upstream tags."""
        if not self._fingerprint_enabled():
            return None
        assets = assets_from_html(self._homepage_html, plugin)
        timeout = getattr(self.config, "plugin_fingerprint_timeout", 10)
        max_tags = getattr(self.config, "plugin_fingerprint_max_tags", 30)
        try:
            async with PluginFingerprinter(
                target_url=self.public_url(fallback=str(self.target.url)),
                timeout=float(timeout or 10),
                max_tags=int(max_tags or 30),
            ) as fingerprinter:
                result = await fingerprinter.fingerprint(
                    plugin,
                    asset_paths=assets or None,
                    fetch_target=lambda asset: self._fetch_asset(plugin, asset),
                )
        except Exception as e:  # never fail version enumeration
            self.logger.debug(f"Fingerprint failed for {plugin}: {e}")
            return None
        if not result.found:
            self.logger.debug(
                f"No asset-hash match for {plugin}: {result.error or 'no candidates'}"
            )
            return None
        self.logger.info(
            f"Fingerprinted {plugin} -> {result.version} ({result.confidence})"
        )
        return {
            "version": result.version or "unknown",
            "source": "asset-hash",
            "confidence": result.confidence,
            "method": result.method,
            "candidates": result.candidates[:10],
        }

    async def _fetch_asset(self, plugin: str, asset: str) -> Optional[bytes]:
        try:
            response = await self.ctx.web.get(
                f"wp-content/plugins/{plugin}/{asset}"
            )
            if response.status_code != 200:
                return None
            return response.content
        except Exception:
            return None

    async def _get_plugin_version(self, plugin: str) -> dict:
        """Attempt to get version from multiple sources."""
        version_info = {"version": "unknown", "source": None}

        sources = [
            f"wp-content/plugins/{plugin}/readme.txt",
            f"wp-content/plugins/{plugin}/readme.md",
            f"wp-content/plugins/{plugin}/{plugin}.php",
        ]

        for source_path in sources:
            version = await self._fetch_version(source_path)
            if version:
                version_info["version"] = version
                version_info["source"] = source_path.split("/")[-1]
                break

        return version_info

    async def _fetch_version(self, path: str) -> Optional[str]:
        """Fetch a file and extract version from it."""
        try:
            response = await self.ctx.web.get(path)

            if response.status_code != 200:
                return None

            content = response.text.lower()

            for pattern, pattern_type in self.VERSION_PATTERNS:
                match = re.search(pattern, content)
                if match:
                    return match.group(1)

            return None

        except Exception as e:
            self.logger.debug(f"Error fetching {path}: {e}")
            return None
