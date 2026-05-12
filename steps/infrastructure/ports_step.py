# recon_wp/steps/infrastructure/ports_step.py
"""
Port scanning via pingback.ping - uses WordPress as a proxy.

WARNING: Uses the target WordPress site to scan ports. SSRF protection is applied.
"""

# WHAT: Scans internal ports via XML-RPC pingback.ping SSRF technique
# HOW: Sends pingback.ping with port targets, checks response for open ports
# WHY: Reveals internal services accessible from the WordPress server
# SECURITY: Blocks private IPs, loopback, cloud metadata (169.254.x.x)

import asyncio
from pathlib import Path

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from core.ssrf_protection import is_safe_target


class PortsStep(BaseHttpStep, WordlistDependencyMixin):
    """Scan internal ports via XML-RPC pingback.ping SSRF.

    SECURITY: This step includes SSRF protection to prevent scanning
    private/internal networks. Only targets not in the blocklist are scanned.
    """

    name = "ports"
    description = "Scan internal ports via pingback"
    severity = "info"
    MODULE = "infrastructure"

    DEFAULT_COMMON_PORTS = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1723,
        3306,
        3389,
        5900,
        8080,
        8443,
    ]

    REQUEST_DELAY = 0.2

    @staticmethod
    def load_ports_from_file(path: Path) -> list[int]:
        """Load ports from a wordlist file."""
        ports = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            port = int(line)
                            if 1 <= port <= 65535:
                                ports.append(port)
                        except ValueError:
                                pass
        except (OSError, FileNotFoundError):
            pass
        return ports

    async def run(self) -> list[Finding]:
        self.logger.info("Scanning internal ports via pingback.ping...")

        common_ports = self.resolve_wordlist_or_fallback(
            config_key="common_ports",
            defaults=self.DEFAULT_COMMON_PORTS,
            name="common ports wordlist",
            loader=self.load_ports_from_file,
        )
        if not common_ports:
            return self.findings

        url = self.urljoin("xmlrpc.php")
        open_ports = []
        scanned_count = 0
        blocked_count = 0

        for port in common_ports:
            target_host = f"{self.target.domain}:{port}"

            if is_safe_target(self.target.domain, port):
                self.logger.debug(f"Skipping port {port} - target is in SSRF blocklist")
                blocked_count += 1
                continue

            try:
                pingback_request = f"""<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://{self.target.domain}:{port}/</string></value></param>
<param><value><string>{self.target.url}</string></value></param>
</params>
</methodCall>"""

                response = await self.http.post(
                    url, content=pingback_request, headers={"Content-Type": "text/xml"}
                )

                content = response.text
                scanned_count += 1

                if (
                    "<faultCode>0</faultCode>" in content
                    and self._extract_fault_code(content) > 0
                ):
                    open_ports.append(port)
                    self.logger.debug(f"Port {port} appears to be open")
                elif response.status_code == 200 and "pingback.ping" in content.lower():
                    open_ports.append(port)

                await asyncio.sleep(self.REQUEST_DELAY)

            except Exception as e:
                self.logger.debug(f"Error checking port {port}: {e}")

        self.logger.info(
            f"Scanned {scanned_count} ports, blocked {blocked_count} by SSRF protection"
        )

        if open_ports:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Open ports detected via SSRF",
                description=f"Found {len(open_ports)} open port(s) via pingback.ping SSRF. "
                f"Scanned {scanned_count} ports, {blocked_count} blocked by SSRF protection.",
                evidence=", ".join(str(p) for p in open_ports),
                recommendation="Ensure internal services are not exposed to the WordPress server. "
                "Disable XML-RPC if not needed.",
                raw={
                    "open_ports": open_ports,
                    "scanned_count": scanned_count,
                    "blocked_count": blocked_count,
                },
            )
            self.logger.info(f"Open ports: {open_ports}")

        return self.findings

    def _extract_fault_code(self, content: str) -> int:
        """Safely extract fault code from XML response."""
        try:
            if "<faultCode>" in content:
                start = content.find("<faultCode>") + len("<faultCode>")
                end = content.find("</faultCode>", start)
                if start > len("<faultCode>") and end > start:
                    return int(content[start:end].strip())
        except (ValueError, TypeError):
            pass
        return 0
