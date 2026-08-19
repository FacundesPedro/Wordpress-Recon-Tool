# recon_wp/steps/passive/shodan_step.py
"""
Shodan intelligence gathering.

Queries Shodan REST API for host information, open ports, and
technology fingerprints related to the target domain.
"""

import asyncio
import json
import socket
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from config import Config
    from core.http_client import HttpClient
    from core.target import Target

from base.step import BaseStep
from core.finding import Finding


class ShodanStep(BaseStep):
    """Gather intelligence from Shodan.

    Queries the Shodan REST API for open ports, service banners,
    technology fingerprints, and host information associated with
    the target domain.
    """

    name = "shodan"
    description = "Shodan intelligence gathering"
    severity = "info"
    MODULE = "passive"

    SHODAN_API_BASE = "https://api.shodan.io"
    REQUEST_TIMEOUT = 30

    def __init__(
        self,
        target: Optional["Target"] = None,
        config: Optional["Config"] = None,
        http: Optional["HttpClient"] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self.http = http
        self._api_key: str = ""
        self._errors: list[str] = []

    async def run(self) -> list[Finding]:
        self.logger.debug("Starting Shodan intelligence gathering...")

        if not self.target or not self.target.domain:
            self.logger.warning("No target domain provided")
            return self.findings

        if not self.http:
            self.logger.warning("HTTP client not available, skipping Shodan lookup")
            return self.findings

        self._api_key = self._get_api_key()
        if not self._api_key:
            self.logger.warning("Shodan API key not configured — skipping")
            return self.findings

        domain = self.target.domain
        ip_address = self._resolve_ip(domain)
        if not ip_address:
            return self.findings

        host_data = await self._query_host_info(ip_address)
        if host_data:
            self._emit_host_findings(domain, ip_address, host_data)

        search_results = await self._query_search(domain)
        if search_results:
            self._emit_search_findings(domain, search_results)

        if not self.findings and not self._errors:
            self.logger.debug(f"No Shodan data found for {domain}")

        return self.findings

    def _get_api_key(self) -> str:
        """Get Shodan API key from config."""
        if self.config and hasattr(self.config, "shodan_api_key"):
            return self.config.shodan_api_key
        return ""

    def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            ip = socket.gethostbyname(domain)
            self.logger.debug(f"Resolved {domain} -> {ip}")
            return ip
        except socket.gaierror as e:
            self.logger.warning(f"Could not resolve domain {domain}: {e}")
            return None

    async def _query_host_info(self, ip: str) -> Optional[dict]:
        """Query Shodan for host information on a specific IP."""
        url = f"{self.SHODAN_API_BASE}/shodan/host/{ip}?key={self._api_key}"
        self.logger.debug(f"Querying Shodan host info for {ip}")
        try:
            response = await self.http.request(
                "GET", url, timeout=self.REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                self.logger.warning("Invalid Shodan API key")
                self._errors.append("Invalid API key")
            elif response.status_code == 404:
                self.logger.debug(f"IP {ip} not found on Shodan")
            else:
                self.logger.debug(f"Shodan host query returned {response.status_code}")
                self._errors.append(f"HTTP {response.status_code}")
        except asyncio.TimeoutError:
            self.logger.debug("Shodan host query timed out")
            self._errors.append("Timeout")
        except Exception as e:
            self.logger.debug(f"Shodan host query error: {e}")
            self._errors.append(str(e))
        return None

    async def _query_search(self, domain: str) -> Optional[list[dict]]:
        """Search Shodan for hostname matches."""
        url = (
            f"{self.SHODAN_API_BASE}/shodan/host/search"
            f"?query=hostname%3A{domain}&key={self._api_key}"
        )
        self.logger.debug(f"Querying Shodan search for hostname:{domain}")
        try:
            response = await self.http.request(
                "GET", url, timeout=self.REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("matches", [])
            else:
                self.logger.debug(f"Shodan search returned {response.status_code}")
        except asyncio.TimeoutError:
            self.logger.debug("Shodan search query timed out")
        except Exception as e:
            self.logger.debug(f"Shodan search error: {e}")
        return None

    def _emit_host_findings(self, domain: str, ip: str, data: dict) -> None:
        """Create findings from Shodan host data."""
        ports = data.get("ports", [])
        if ports:
            sorted_ports = sorted(ports)
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Shodan Open Ports Discovered",
                description=(
                    f"Discovered {len(sorted_ports)} open port(s) on "
                    f"{domain} ({ip}) via Shodan"
                ),
                evidence="\n".join(f"  - Port {p}" for p in sorted_ports),
                recommendation=(
                    "Review open ports and ensure only necessary services "
                    "are exposed to the internet"
                ),
                raw={
                    "domain": domain,
                    "ip": ip,
                    "ports": sorted_ports,
                    "total_ports": len(sorted_ports),
                },
            )

        host_info = {
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("asn", ""),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
        }
        if any(host_info.values()):
            info_lines = [
                f"  ISP: {host_info['isp']}",
                f"  Organization: {host_info['org']}",
                f"  ASN: {host_info['asn']}",
                f"  Location: {host_info['city']}, {host_info['country']}",
            ]
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Shodan Host Information",
                description=(
                    f"Network and location information for {domain} ({ip})"
                ),
                evidence="\n".join(info_lines),
                recommendation="This information helps identify hosting provider and infrastructure",
                raw={"domain": domain, "ip": ip, **host_info},
            )

        ssl_data = data.get("ssl", {})
        if ssl_data:
            cert = ssl_data.get("cert", {})
            cn = cert.get("subject", {}).get("CN", "Unknown")
            issuer = cert.get("issuer", {}).get("O", "Unknown")
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Shodan SSL/TLS Certificate Information",
                description=f"SSL/TLS certificate details for {domain} ({ip})",
                evidence=f"  Common Name: {cn}\n  Issuer: {issuer}",
                recommendation="Verify the SSL certificate is valid and properly configured",
                raw={"domain": domain, "ip": ip, "ssl": ssl_data},
            )

    def _emit_search_findings(self, domain: str, matches: list[dict]) -> None:
        """Create findings from Shodan search results."""
        if not matches:
            return

        services = []
        for match in matches[:20]:
            port = match.get("port", "?")
            transport = match.get("transport", "")
            product = match.get("product", "")
            version = match.get("version", "")
            service = f"{port}/{transport}"
            if product:
                service += f" - {product}"
                if version:
                    service += f" {version}"
            services.append(service)

        wordpress_matches = [
            m for m in matches if "wordpress" in json.dumps(m).lower()
        ]

        if wordpress_matches:
            wp_ports = sorted({p for m in wordpress_matches if (p := m.get("port")) is not None})
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Shodan WordPress Installation Detected",
                description=(
                    f"Shodan found {len(wordpress_matches)} service(s) "
                    f"with WordPress fingerprints for {domain}"
                ),
                evidence=f"  WordPress detected on ports: {', '.join(str(p) for p in wp_ports)}",
                recommendation="Ensure WordPress is up to date and properly secured",
                raw={
                    "domain": domain,
                    "wordpress_matches": len(wordpress_matches),
                    "ports": wp_ports,
                },
            )

        self._add_finding(
            module=self.MODULE,
            severity="info",
            title="Shodan Service Fingerprints",
            description=f"Discovered {len(matches)} service fingerprint(s) for {domain}",
            evidence=(
                "Services (top 20):\n" + "\n".join(f"  - {s}" for s in services)
            ),
            recommendation="Review exposed services and ensure they are properly hardened",
            raw={
                "domain": domain,
                "total_services": len(matches),
                "services": [
                    {
                        "port": m.get("port"),
                        "transport": m.get("transport"),
                        "product": m.get("product"),
                        "version": m.get("version"),
                    }
                    for m in matches
                ],
            },
        )
