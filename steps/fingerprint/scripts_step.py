# recon_wp/steps/fingerprint/scripts_step.py
"""
Scripts enumeration - discovers WordPress core scripts.

Detects core scripts loaded by WordPress.
"""

# WHAT: Lists WordPress core scripts from homepage HTML
# HOW: Regex for /wp-includes/js/[name].js patterns
# WHY: Identifies loaded JavaScript for further analysis

import re

from base.http_step import BaseHttpStep
from core.finding import Finding


class ScriptsStep(BaseHttpStep):
    """
    Detect WordPress core scripts by parsing HTML for wp-includes/js/ links.

    Note: For comprehensive enumeration, use wordlist-based brute force (see docs/missing_wordlists.md).
    """

    name = "scripts"
    description = "Detect WordPress core scripts"
    severity = "info"
    MODULE = "fingerprint"

    async def run(self) -> list[Finding]:
        self.logger.info("Detecting WordPress core scripts...")

        scripts = set()

        try:
            response = await self.http.get(self.target.url)
            if response.status_code == 200:
                content = response.text

                script_matches = re.findall(r"/wp-includes/js/([^/]+)\.js", content)
                scripts.update(script_matches)

                if scripts:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="WordPress core scripts detected",
                        description=f"Found {len(scripts)} core script(s) in page source",
                        evidence=", ".join(sorted(scripts)),
                        recommendation="Ensure WordPress core is updated",
                        raw={"scripts": list(scripts)},
                    )
                    self.logger.info(f"Detected scripts: {', '.join(scripts)}")
                else:
                    self.logger.debug("No scripts detected in page source")

        except Exception as e:
            self.logger.error(f"Error detecting scripts: {e}")

        return self.findings
