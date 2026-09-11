# recon_wp/steps/ssrf/oembed_proxy_step.py
"""
oEmbed proxy SSRF - tests /wp-json/oembed/1.0/proxy for SSRF.

Tests if the oEmbed proxy endpoint allows requests to arbitrary URLs.
"""

# WHAT: Tests oEmbed proxy endpoint for SSRF vulnerability
# HOW: Sends request to /wp-json/oembed/1.0/proxy with arbitrary URL
# WHY: SSRF can be used to access internal services or cloud metadata

from base.http_step import BaseHttpStep
from core.finding import Finding


class OembedProxyStep(BaseHttpStep):
    """
    Check if the oEmbed proxy endpoint is vulnerable to SSRF.
    The endpoint /wp-json/oembed/1.0/proxy can be abused to make requests to arbitrary URLs.
    """

    name = "oembed_proxy"
    description = "Check oEmbed proxy for SSRF"
    severity = "medium"
    MODULE = "ssrf"

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping oEmbed proxy check"
            )
            return self.findings

        self.logger.info("Checking oEmbed proxy for SSRF...")

        url = self.urljoin("wp-json/oembed/1.0/proxy")

        ssrf_url = f"{url}?url=http://127.0.0.1"

        try:
            response = await self.http.get(ssrf_url)

            if response.status_code == 200:
                content = response.text.lower()

                if "wordpress" in content or "html" in content:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="oEmbed proxy potentially vulnerable to SSRF",
                        description="The /wp-json/oembed/1.0/proxy endpoint may allow SSRF attacks",
                        evidence=ssrf_url,
                        recommendation="Restrict access to oEmbed proxy or validate URLs properly",
                        raw={"url": ssrf_url},
                    )
                    self.logger.info("oEmbed proxy may be vulnerable to SSRF")
                else:
                    self.logger.debug("oEmbed proxy responded but content unclear")
            else:
                self.logger.debug(
                    f"oEmbed proxy returned status {response.status_code}"
                )

        except Exception as e:
            self.logger.error(f"Error checking oEmbed proxy: {e}")

        return self.findings
