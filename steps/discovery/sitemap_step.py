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
from utils.http_validation import is_xml_body


class SitemapStep(BaseHttpStep):
    """Check for wp-sitemap.xml which lists public posts/pages."""

    name = "sitemap"
    description = "Check for WordPress sitemap"
    severity = "info"
    MODULE = "discovery"

    SITEMAP_PATHS = [
        "wp-sitemap.xml",
        "?sitemap=index",
    ]

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping wp-sitemap check"
            )
            return self.findings

        self.logger.info("Checking for wp-sitemap.xml...")

        for path in self.SITEMAP_PATHS:
            url = self.urljoin(path)
            try:
                response = await self.http.get(url)
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")
                continue

            if response.status_code != 200:
                self.logger.debug(
                    f"{path} not found (status: {response.status_code})"
                )
                continue
            if not is_xml_body(response):
                self.logger.debug(
                    f"{path} is not an XML sitemap (catch-all/soft-404) - skipped"
                )
                continue

            url_pattern = re.compile(r"<loc>([^<]+)</loc>")
            urls = url_pattern.findall(response.text or "")
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
            break
        else:
            self.logger.info("No WordPress sitemap found")

        return self.findings
