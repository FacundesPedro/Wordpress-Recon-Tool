# recon_wp/steps/discovery/uploads_listing_step.py
"""
Uploads listing - checks if wp-content/uploads has directory listing enabled.

Detects if uploaded files are publicly browsable.
"""

# WHAT: Checks if wp-content/uploads/ has directory listing enabled
# HOW: HTTP GET to wp-content/uploads/, looks for "Index of" in response
# WHY: Exposes all uploaded files to visitors

from base.http_step import BaseHttpStep
from core.finding import Finding


class UploadsListingStep(BaseHttpStep):
    """Check if wp-content/uploads has directory listing enabled."""

    name = "uploads_listing"
    description = "Check for directory listing in wp-content/uploads"
    severity = "low"
    MODULE = "discovery"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for uploads directory listing...")
        url = self.urljoin("wp-content/uploads/")

        try:
            response = await self.http.get(url)
            if response.status_code == 200:
                content = response.text.lower()
                if "index of" in content or "<title>index" in content:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="Uploads directory listing enabled",
                        description="wp-content/uploads/ has directory listing enabled, exposing uploaded files",
                        evidence=url,
                        recommendation="Disable directory listing in web server config",
                        raw={"url": url},
                    )
                    self.logger.info("Uploads directory listing is enabled")
                else:
                    self.logger.debug("Uploads directory found but no listing")
            else:
                self.logger.debug(
                    f"Uploads directory not found or not accessible (status: {response.status_code})"
                )
        except Exception as e:
            self.logger.error(f"Error checking uploads directory: {e}")

        return self.findings
