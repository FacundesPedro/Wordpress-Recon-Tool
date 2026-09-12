# recon_wp/steps/xmlrpc/xmlrpc_ssrf_step.py
"""
XML-RPC SSRF - tests for pingback.ping SSRF vulnerability.

Tests if pingback.ping accepts arbitrary target URLs.
"""

# WHAT: Tests pingback.ping for SSRF vulnerability
# HOW: Sends pingback.ping with arbitrary target, checks response
# WHY: pingback.ping can be used to port scan internal network
# SECURITY: Skips private IPs (SSRF protection)

from base.http_step import BaseHttpStep
from core.finding import Finding
from core.ssrf_protection import is_blocked_target
from utils.xml_parser import extract_fault_code, is_xmlrpc_success


class XmlrpcSsrfStep(BaseHttpStep):
    """Check if pingback.ping method is available for SSRF attacks.

    SECURITY:
    - Uses safe XML parsing
    - Validates pingback responses properly
    """

    name = "xmlrpc_ssrf"
    description = "Check for XML-RPC pingback SSRF"
    severity = "medium"
    MODULE = "xmlrpc"

    PINGBACK_REQUEST = """<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://{target}/</string></value></param>
<param><value><string>{target_url}</string></value></param>
</params>
</methodCall>"""

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for XML-RPC pingback.ping SSRF...")

        url = self.urljoin("xmlrpc.php")

        if is_blocked_target(self.target.domain):
            self.logger.debug(
                f"Skipping pingback SSRF check for {self.target.domain} - in SSRF blocklist"
            )
            return self.findings

        pingback_request = self.PINGBACK_REQUEST.format(
            target=self.target.domain, target_url=self.target.url
        )

        try:
            response = await self.http.post(
                url, content=pingback_request, headers={"Content-Type": "text/xml"}
            )

            content = response.text

            fault_code = extract_fault_code(content)
            is_success = is_xmlrpc_success(content)
            lower_content = content.lower()
            mentions_pingback = "pingback.ping" in lower_content
            clean_method_response = (
                "<methodresponse" in lower_content
                and "<fault" not in lower_content
            )

            if fault_code > 0 or (
                response.status_code == 200
                and clean_method_response
                and (mentions_pingback or is_success)
            ):
                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="XML-RPC pingback.ping is available",
                    description="The pingback.ping method is available and could be abused for SSRF/DDoS attacks",
                    evidence=url,
                    recommendation="Disable pingback.ping if not needed",
                    raw={
                        "url": url,
                        "fault_code": fault_code,
                        "status_code": response.status_code,
                    },
                )
                self.logger.info("pingback.ping is available")

        except Exception as e:
            self.logger.error(f"Error checking pingback.ping: {e}")

        return self.findings
