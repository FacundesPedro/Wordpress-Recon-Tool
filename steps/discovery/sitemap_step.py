# recon_wp/steps/discovery/sitemap_step.py
"""
Sitemap enumeration - checks for wp-sitemap.xml (WP 5.5+).

Discovers public URLs listed in WordPress sitemap.
"""

# WHAT: Fetches wp-sitemap.xml and lists discovered URLs
# HOW: HTTP GET to wp-sitemap.xml, parses <loc> tags
# WHY: Reveals site structure and potentially sensitive public content

import re

from base.http_step import BaseHttpStep
from core.finding import Finding


class SitemapStep(BaseHttpStep):
    """Check for wp-sitemap.xml which lists public posts/pages."""

    name = "sitemap"
    description = "Check for WordPress sitemap"
    severity = "info"
    MODULE = "discovery"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for wp-sitemap.xml...")
        url = self.urljoin("wp-sitemap.xml")

        try:
            response = await self.http.get(url)
            if response.status_code == 200:
                content = response.text

                url_pattern = re.compile(r"<loc>([^<]+)</loc>")
                urls = url_pattern.findall(content)
                url_count = len(urls)

                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="wp-sitemap.xml found",
                    description=f"WordPress sitemap found exposing {url_count} URLs",
                    evidence=f"First 5 URLs: {', '.join(urls[:5])}" if urls else url,
                    recommendation="Ensure only public content is included in sitemap",
                    raw={"url": url, "url_count": url_count, "urls": urls[:20]},
                )
                self.logger.info(f"Found wp-sitemap.xml with {url_count} URLs")
            else:
                self.logger.debug(
                    f"wp-sitemap.xml not found (status: {response.status_code})"
                )
        except Exception as e:
            self.logger.error(f"Error checking wp-sitemap.xml: {e}")

        return self.findings
