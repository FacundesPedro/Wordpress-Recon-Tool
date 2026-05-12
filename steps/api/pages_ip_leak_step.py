# recon_wp/steps/api/pages_ip_leak_step.py
"""
Pages IP leak detection - checks if REST API exposes internal IP addresses.

WordPress can leak the internal server IP address through the REST API
pages endpoint when a page has been modified by a user whose IP is stored
in the revision metadata.
"""

# WHAT: Detects IP address leakage via REST API pages endpoint
# HOW: Fetches /wp-json/wp/v2/pages and inspects response for IP patterns
# WHY: Internal IP addresses aid attackers in network mapping

import json
import re

from base.http_step import BaseHttpStep
from core.finding import Finding


class PagesIpLeakStep(BaseHttpStep):
    """Detect internal IP address leakage via REST API pages endpoint."""

    name = "pages_ip_leak"
    description = "Detect IP address leakage via REST API"
    severity = "medium"
    MODULE = "api"

    # Regex pattern to match IPv4 addresses
    IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    # Private IP ranges to check against
    PRIVATE_RANGES = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
    ]

    @staticmethod
    def _ip_to_int(ip: str) -> int:
        """Convert dotted quad IP to integer for range comparison."""
        parts = [int(p) for p in ip.split(".")]
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address falls within private ranges."""
        try:
            ip_int = self._ip_to_int(ip)
            for start, end in self.PRIVATE_RANGES:
                start_int = self._ip_to_int(start)
                end_int = self._ip_to_int(end)
                if start_int <= ip_int <= end_int:
                    return True
            # Also check localhost
            if ip.startswith("127."):
                return True
            return False
        except (ValueError, IndexError):
            return False

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for IP address leakage via REST API...")

        url = self.urljoin("wp-json/wp/v2/pages")

        try:
            response = await self.http.get(url)

            if response.status_code != 200:
                self.logger.debug(
                    f"REST API pages endpoint not accessible (status: {response.status_code})"
                )
                return self.findings

            try:
                data = response.json()
            except json.JSONDecodeError:
                self.logger.debug("Failed to parse REST API response")
                return self.findings

            # Convert response to string for IP pattern matching
            response_str = json.dumps(data)

            # Find all IP addresses in the response
            ip_matches = self.IP_PATTERN.findall(response_str)
            private_ips = []

            for ip in ip_matches:
                if self._is_private_ip(ip):
                    # Validate it's not a false positive like a version number
                    parts = ip.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        private_ips.append(ip)

            # Deduplicate
            private_ips = list(set(private_ips))

            if private_ips:
                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="Internal IP addresses leaked via REST API",
                    description=(
                        f"Found {len(private_ips)} internal IP address(es) in the "
                        "REST API pages response. This may reveal server network "
                        "architecture."
                    ),
                    evidence=", ".join(private_ips),
                    recommendation=(
                        "Consider restricting REST API access or filtering sensitive "
                        "fields from API responses. Review page revision metadata."
                    ),
                    raw={
                        "ips_found": private_ips,
                        "url": url,
                        "endpoint": "wp-json/wp/v2/pages",
                    },
                )
                self.logger.warning(
                    f"Found {len(private_ips)} private IP(s) leaked via REST API"
                )
            else:
                self.logger.debug("No IP addresses detected in REST API response")

        except Exception as e:
            self.logger.error(f"Error checking REST API IP leakage: {e}")

        return self.findings
