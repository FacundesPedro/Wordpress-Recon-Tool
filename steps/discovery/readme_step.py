# recon_wp/steps/discovery/readme_step.py
"""
Readme enumeration - checks for WordPress readme.html.

Checks if readme.html is exposed and extracts WordPress version.
"""

# WHAT: Fetches readme.html and extracts WordPress version if present
# HOW: HTTP GET to readme.html, regex for "version X.X.X"
# WHY: Version disclosure aids targeted vulnerability research

import re

from base.http_step import BaseHttpStep
from core.finding import Finding


class ReadmeStep(BaseHttpStep):
    """Check for readme.html which may expose WordPress version."""

    name = "readme"
    description = "Check for readme.html file"
    severity = "info"
    MODULE = "discovery"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for readme.html...")
        url = self.urljoin("readme.html")

        try:
            response = await self.http.get(url)
            if response.status_code == 200:
                content = response.text.lower()

                if "wordpress" in content:
                    version_match = re.search(
                        r"version\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", content
                    )
                    version = version_match.group(1) if version_match else "Unknown"

                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="readme.html found",
                        description=f"WordPress readme.html found. Potential version: {version}",
                        evidence=url,
                        recommendation="Remove readme.html from production servers",
                        raw={"url": url, "version": version},
                    )
                    self.logger.info(f"Found readme.html with version {version}")
                else:
                    self.logger.debug("readme.html found but no WordPress signature")
            else:
                self.logger.debug(
                    f"readme.html not found (status: {response.status_code})"
                )
        except Exception as e:
            self.logger.error(f"Error checking readme.html: {e}")

        return self.findings
