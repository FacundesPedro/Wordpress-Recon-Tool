# recon_wp/steps/fingerprint/versioned_assets_step.py
"""
Versioned assets enumeration - finds version disclosure in assets.

Scans for version strings in CSS/JS asset URLs.
"""

# WHAT: Finds version parameters (?ver=) in asset URLs
# HOW: Regex for ?ver= patterns in HTML content
# WHY: Version strings can reveal WordPress/core/component versions

import re

from base.http_step import BaseHttpStep
from core.finding import Finding


class VersionedAssetsStep(BaseHttpStep):
    """
    Find version disclosure via ?ver= parameters in CSS/JS assets.
    """

    name = "versioned_assets"
    description = "Find version disclosure via asset URLs"
    severity = "info"
    MODULE = "fingerprint"

    async def run(self) -> list[Finding]:
        self.logger.info("Scanning for versioned assets...")

        versions = set()

        try:
            response = await self.http.get(self.target.url)
            if response.status_code == 200:
                content = response.text

                ver_matches = re.findall(r"\?ver=([0-9a-f]{5,32}|[0-9.]+)", content)
                versions.update(ver_matches)

                if versions:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="Version disclosure via assets",
                        description=f"Found {len(versions)} unique version(s) in asset URLs",
                        evidence=", ".join(sorted(versions)[:10]),
                        recommendation="Consider removing version parameters from static assets",
                        raw={"versions": list(versions)},
                    )
                    self.logger.info(f"Found versions: {', '.join(list(versions)[:5])}")
                else:
                    self.logger.debug("No versioned assets found")

        except Exception as e:
            self.logger.error(f"Error scanning versioned assets: {e}")

        return self.findings
