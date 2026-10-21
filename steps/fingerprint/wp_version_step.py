# recon_wp/steps/fingerprint/wp_version_step.py
"""
WordPress version detection from various sources.

Extracts WordPress version from generator meta tag, CSS, and JS.
"""

# WHAT: Detects WordPress version from homepage HTML
# HOW: Regex search for generator meta, style.css?ver=, wp-util.js?ver=
# WHY: Version is critical for vulnerability research

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.core_version import detect_core_version


class WpVersionStep(BaseHttpStep):
    """Detect WordPress version from meta tags, CSS/JS files, or readme."""

    name = "wp_version"
    description = "Detect WordPress version"
    severity = "info"
    MODULE = "fingerprint"

    async def run(self) -> list[Finding]:
        self.logger.info("Detecting WordPress version...")

        version = None
        source = None

        try:
            response = await self.ctx.web.homepage()
            if response.status_code == 200:
                version, source = detect_core_version(response.text)

        except Exception as e:
            self.logger.error(f"Error detecting WordPress version: {e}")

        if version:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title=f"WordPress version {version}",
                description=f"WordPress version {version} detected from {source}",
                evidence=f"Version: {version} from {source}",
                recommendation="Update WordPress to latest version",
                raw={"version": version, "source": source},
            )
            self.logger.info(f"Detected WordPress version {version} from {source}")
        else:
            self.logger.info("Could not detect WordPress version")

        return self.findings
