# recon_wp/steps/fingerprint/theme_step.py
"""
Theme enumeration - discovers installed themes.

Detects themes linked in HTML source.
"""

# WHAT: Detects active WordPress theme from homepage HTML
# HOW: Regex for /wp-content/themes/[name]/ patterns
# WHY: Theme vulnerabilities can be exploited

import re

from base.http_step import BaseHttpStep
from core.finding import Finding


class ThemeStep(BaseHttpStep):
    """
    Detect installed WordPress themes by parsing HTML for wp-content/themes/ links.

    Note: For comprehensive enumeration, use wordlist-based brute force.
    This step only detects themes explicitly linked in the HTML.
    """

    name = "theme"
    description = "Detect installed WordPress themes"
    severity = "info"
    MODULE = "fingerprint"

    async def run(self) -> list[Finding]:
        self.logger.info("Detecting WordPress themes...")

        themes = set()

        try:
            response = await self.http.get(self.target.url)
            if response.status_code == 200:
                content = response.text

                theme_matches = re.findall(r"/wp-content/themes/([^/]+)/", content)
                themes.update(theme_matches)

                if themes:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="WordPress themes detected",
                        description=f"Found {len(themes)} theme(s) in page source",
                        evidence=", ".join(sorted(themes)),
                        recommendation="Ensure themes are updated to latest versions",
                        raw={"themes": list(themes)},
                    )
                    self.logger.info(f"Detected themes: {', '.join(themes)}")
                else:
                    self.logger.debug("No themes detected in page source")

        except Exception as e:
            self.logger.error(f"Error detecting themes: {e}")

        return self.findings
