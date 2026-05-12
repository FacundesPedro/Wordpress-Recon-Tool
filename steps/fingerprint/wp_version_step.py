# recon_wp/steps/fingerprint/wp_version_step.py
"""
WordPress version detection from various sources.

Extracts WordPress version from generator meta tag, CSS, and JS.
"""

# WHAT: Detects WordPress version from homepage HTML
# HOW: Regex search for generator meta, style.css?ver=, wp-util.js?ver=
# WHY: Version is critical for vulnerability research

import re

from base.http_step import BaseHttpStep
from core.finding import Finding


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
            response = await self.http.get(self.target.url)
            if response.status_code == 200:
                content = response.text.lower()

                meta_match = re.search(
                    r'<meta\s+name="generator"\s+content="wordpress\s+([0-9.]+)"',
                    content,
                    re.IGNORECASE,
                )
                if meta_match:
                    version = meta_match.group(1)
                    source = "meta generator tag"

                if not version:
                    css_match = re.search(
                        r"/wp-content/themes/[^/]+/style\.css\?ver=([0-9.]+)", content
                    )
                    if css_match:
                        version = css_match.group(1)
                        source = "theme CSS version"

                if not version:
                    js_match = re.search(
                        r"/wp-includes/js/wp-util\.js\?ver=([0-9.]+)", content
                    )
                    if js_match:
                        version = js_match.group(1)
                        source = "core JS version"

                if not version:
                    generator_match = re.search(
                        r'content="WordPress\s+([0-9.]+)"', content
                    )
                    if generator_match:
                        version = generator_match.group(1)
                        source = "generator meta"

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
