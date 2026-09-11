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
from utils.http_validation import json_body, rest_route_fallbacks


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

        for path in rest_route_fallbacks("wp-json/oembed/1.0/proxy"):
            separator = "&" if "?" in path else "?"
            ssrf_url = self.urljoin(path) + separator + "url=http://127.0.0.1"

            try:
                response = await self.http.get(ssrf_url)
            except Exception as e:
                self.logger.error(f"Error checking oEmbed proxy: {e}")
                continue

            status = getattr(response, "status_code", None)

            if status in (401, 403):
                self.logger.debug(
                    "oEmbed proxy requires authentication - not vulnerable"
                )
                return self.findings

            if status == 200:
                data = json_body(response)
                if isinstance(data, dict) and not data.get("code") and (
                    "html" in data
                    or "provider_name" in data
                    or data.get("type")
                ):
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
                    return self.findings
            else:
                self.logger.debug(
                    f"oEmbed proxy returned status {status} for {path}"
                )

        return self.findings
