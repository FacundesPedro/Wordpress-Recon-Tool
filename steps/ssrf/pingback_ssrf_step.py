# recon_wp/steps/ssrf/pingback_ssrf_step.py
"""
Pingback SSRF - tests for pingback.ping SSRF via XML-RPC.

Tests if pingback.ping can be used to make arbitrary HTTP requests.
"""

# WHAT: Tests pingback.ping for SSRF via XML-RPC
# HOW: Sends pingback.ping request with arbitrary target URL
# WHY: pingback.ping can be abused for SSRF and DDoS attacks

from base.http_step import BaseHttpStep
from core.finding import Finding


class PingbackSsrfStep(BaseHttpStep):
    """
    Check if pingback.ping method is available for SSRF attacks.
    Note: This is already covered by XmlrpcSsrfStep, but kept as separate step for clarity.
    """

    name = "pingback_ssrf"
    description = "Check for pingback.ping SSRF"
    severity = "medium"
    MODULE = "ssrf"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for pingback.ping SSRF...")

        url = self.urljoin("xmlrpc.php")

        pingback_request = f"""<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://{self.target.domain}/</string></value></param>
<param><value><string>{self.target.url}</string></value></param>
</params>
</methodCall>"""

        try:
            response = await self.http.post(
                url, content=pingback_request, headers={"Content-Type": "text/xml"}
            )

            content = response.text

            if (
                "pingback.ping" in content.lower()
                or "<faultCode>0</faultCode>" in content
            ):
                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="pingback.ping is available",
                    description="The pingback.ping method is available and could be abused for SSRF/DDoS",
                    evidence=url,
                    recommendation="Disable pingback.ping if not needed",
                    raw={"url": url},
                )
                self.logger.info("pingback.ping is available for SSRF")

        except Exception as e:
            self.logger.error(f"Error checking pingback.ping: {e}")

        return self.findings
