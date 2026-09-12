# recon_wp/steps/xmlrpc/xmlrpc_methods_step.py
"""
XML-RPC methods enumeration - lists available XML-RPC methods.

Retrieves all available XML-RPC methods.
"""

# WHAT: Lists all available XML-RPC methods
# HOW: POST system.listMethods, parses method names
# WHY: Identifies dangerous methods (wp.getUsersBlogs, pingback.ping, multicall)

import re

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class XmlrpcMethodsStep(BaseHttpStep, WordlistDependencyMixin):
    """Enumerate available XML-RPC methods via system.listMethods."""

    name = "xmlrpc_listMethods"
    description = "Enumerate XML-RPC methods"
    severity = "info"
    MODULE = "xmlrpc"

    XMLRPC_REQUEST = """<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>"""

    DEFAULT_DANGEROUS_METHODS = [
        "wp.getUsersBlogs",
        "wp.getCategories",
        "metaWeblog.getUsersBlogs",
        "pingback.ping",
        "system.multicall",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Enumerating XML-RPC methods...")

        dangerous_methods = self.resolve_wordlist_or_fallback(
            config_key="xmlrpc_dangerous_methods",
            defaults=self.DEFAULT_DANGEROUS_METHODS,
            name="XML-RPC dangerous methods wordlist",
            wordlist_file="xmlrpc/dangerous_methods.txt",
        )
        if not dangerous_methods:
            return self.findings

        url = self.urljoin("xmlrpc.php")

        try:
            response = await self.http.post(
                url, content=self.XMLRPC_REQUEST, headers={"Content-Type": "text/xml"}
            )

            if response.status_code == 200 and "<array>" in response.text:
                methods = re.findall(r"<string>([^<]+)</string>", response.text)

                found_dangerous = [m for m in methods if m in dangerous_methods]

                if methods:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="XML-RPC methods enumerated",
                        description=f"Found {len(methods)} XML-RPC method(s), {len(found_dangerous)} potentially dangerous",
                        evidence=f"{url}: Methods: {', '.join(methods[:10])}{'...' if len(methods) > 10 else ''}",
                        recommendation="Disable dangerous XML-RPC methods if not needed",
                        raw={"url": url, "methods": methods,
                             "dangerous_methods": found_dangerous},
                    )
                    self.logger.info(
                        f"Found {len(methods)} methods, {len(found_dangerous)} dangerous"
                    )

        except Exception as e:
            self.logger.error(f"Error enumerating XML-RPC methods: {e}")

        return self.findings
