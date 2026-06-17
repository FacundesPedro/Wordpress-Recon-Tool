# recon_wp/steps/fingerprint/plugin_step.py
"""
Plugin enumeration - discovers installed plugins.

Detects plugins linked in HTML source.
"""

# WHAT: Detects installed plugins from homepage HTML
# HOW: Regex for /wp-content/plugins/[name]/ patterns
# WHY: Plugin vulnerabilities are common attack vectors

import re

from base.http_step import BaseHttpStep
from core.finding import Finding


class PluginStep(BaseHttpStep):
    """
    Detect installed WordPress plugins by parsing HTML for wp-content/plugins/ links.

    Note: This step only detects plugins explicitly linked in the HTML.
    For comprehensive enumeration, use wordlist-based brute force (see docs/missing_wordlists.md).
    """

    name = "plugin"
    description = "Detect installed WordPress plugins"
    severity = "info"
    MODULE = "fingerprint"

    async def run(self) -> list[Finding]:
        self.logger.info("Detecting WordPress plugins...")

        plugins = set()

        try:
            response = await self.http.get(self.target.url)
            if response.status_code == 200:
                content = response.text

                plugin_matches = re.findall(r"/wp-content/plugins/([^/]+)/", content)
                plugins.update(plugin_matches)

                if plugins:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="WordPress plugins detected",
                        description=f"Found {len(plugins)} plugin(s) in page source",
                        evidence=", ".join(sorted(plugins)),
                        recommendation="Ensure plugins are updated to latest versions",
                        raw={"plugins": list(plugins)},
                    )
                    self.logger.info(f"Detected plugins: {', '.join(plugins)}")
                else:
                    self.logger.debug("No plugins detected in page source")

        except Exception as e:
            self.logger.error(f"Error detecting plugins: {e}")

        return self.findings
