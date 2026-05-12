# recon_wp/steps/xmlrpc/xmlrpc_detect_step.py
"""
XML-RPC detection - checks if xmlrpc.php is enabled.

Sends system.listMethods to detect if XML-RPC is responding.
"""

# WHAT: Detects if XML-RPC interface is enabled
# HOW: POST system.listMethods to xmlrpc.php
# WHY: XML-RPC is a common attack vector (brute force, SSRF, DDoS)

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.xml_parser import check_xmlrpc_available, parse_xmlrpc_response


class XmlrpcDetectStep(BaseHttpStep):
    """Check if XML-RPC is enabled by sending a system.listMethods request.

    SECURITY:
    - Uses safe XML parsing
    - Validates response properly
    """

    name = "xmlrpc_detect"
    description = "Detect if XML-RPC is enabled"
    severity = "info"
    MODULE = "xmlrpc"

    XMLRPC_REQUEST = """<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>"""

    async def run(self) -> list[Finding]:
        self.logger.info("Checking if XML-RPC is enabled...")

        url = self.urljoin("xmlrpc.php")

        try:
            response = await self.http.post(
                url, content=self.XMLRPC_REQUEST, headers={"Content-Type": "text/xml"}
            )

            if response.status_code == 200:
                content = response.text

                if check_xmlrpc_available(content):
                    rpc_response = parse_xmlrpc_response(content)

                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="XML-RPC is enabled",
                        description="XML-RPC interface is available and responding",
                        evidence=url,
                        recommendation="Disable XML-RPC if not needed to reduce attack surface",
                        raw={"url": url, "has_array": rpc_response.has_array},
                    )
                    self.logger.info("XML-RPC is enabled")
                else:
                    self.logger.debug("XML-RPC responded but with unexpected content")
            else:
                self.logger.debug(f"XML-RPC returned status {response.status_code}")

        except Exception as e:
            self.logger.error(f"Error checking XML-RPC: {e}")

        return self.findings
