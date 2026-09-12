# recon_wp/steps/discovery/license_step.py
"""
License enumeration - checks for WordPress license.txt.

Checks if license.txt exposes WordPress version.
"""

# WHAT: Fetches license.txt and extracts WordPress version
# HOW: HTTP GET to license.txt, regex for "version X.X.X"
# WHY: Version disclosure aids targeted vulnerability research

import re

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.http_validation import is_wp_license


class LicenseStep(BaseHttpStep):
    """Check for license.txt which exposes WordPress version."""

    name = "license"
    description = "Check for license.txt file"
    severity = "info"
    MODULE = "discovery"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for license.txt...")
        url = self.urljoin("license.txt")

        try:
            response = await self.http.get(url)
            if response.status_code == 200:
                content = getattr(response, "text", "") or ""

                if is_wp_license(response):
                    version_match = re.search(
                        r"version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", content
                    )
                    version = version_match.group(1) if version_match else "Unknown"
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="license.txt found",
                        description=(
                            "WordPress license.txt found"
                            + (
                                f" exposing version {version}"
                                if version != "Unknown"
                                else ""
                            )
                        ),
                        evidence=url,
                        recommendation="Remove license.txt from production servers",
                        raw={
                            "url": url,
                            "final_url": str(getattr(response, "url", None) or url),
                            "version": version,
                        },
                    )
                    self.logger.info(f"Found license.txt with version {version}")
                else:
                    self.logger.debug("license.txt found but no WordPress signature")
            else:
                self.logger.debug(
                    f"license.txt not found (status: {response.status_code})"
                )
        except Exception as e:
            self.logger.error(f"Error checking license.txt: {e}")

        return self.findings
