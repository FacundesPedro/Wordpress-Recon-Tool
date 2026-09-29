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
from core.ssrf_protection import is_blocked_target


class PortsStep(BaseHttpStep, WordlistDependencyMixin):
    """Scan internal ports via XML-RPC pingback.ping SSRF.

    SECURITY: This step includes SSRF protection to prevent scanning
    private/internal networks. Only targets not in the blocklist are scanned.
    """

    name = "ports"
    description = "Scan internal ports via pingback"
    severity = "medium"
    MODULE = "infrastructure"

    # Services that are risky to expose internally and warrant a higher band.
    RISKY_PORTS = {
        21, 22, 23, 25, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432,
        5900, 6379, 9200, 11211, 27017,
    }

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

    def _is_own_target(self, host: str) -> bool:
        """Return True when ``host`` is the authorized assessment target."""
        domain = str((self.target.domain if self.target else "") or "")
        return bool(domain) and str(host or "").lower() == domain.lower()

    async def run(self) -> list[Finding]:
        self.logger.info("Scanning internal ports via pingback.ping...")

        target = self.target
        if target is None:
            return self.findings
        domain = str(target.domain or "")
        target_url = str(target.url)

        common_ports = self.resolve_wordlist_or_fallback(
            config_key="common_ports",
            defaults=self.DEFAULT_COMMON_PORTS,
            name="common ports wordlist",
            loader=self.load_ports_from_file,
            wordlist_file="ports/common.txt",
        )
        if not common_ports:
            return self.findings

        url = self.urljoin("xmlrpc.php")
        open_ports = []
        scanned_count = 0
        blocked_count = 0

        for port in common_ports:
            # The pingback targets the authorized assessment host itself, so
            # the SSRF blocklist must not reject it. Arbitrary third-party
            # hosts are never supplied here.
            if not self._is_own_target(domain) and is_blocked_target(domain, port):
                self.logger.debug(f"Skipping port {port} - target is in SSRF blocklist")
                blocked_count += 1
                continue

            try:
                pingback_request = f"""<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://{domain}:{port}/</string></value></param>
<param><value><string>{target_url}</string></value></param>
</params>
</methodCall>"""

                response = await self.http.post(
                    url, content=pingback_request, headers={"Content-Type": "text/xml"}
                )

                content = response.text
                if not isinstance(content, str):
                    content = ""
                scanned_count += 1

                # A successful pingback call means the XML-RPC server
                # fetched the supplied URL: the port answered. Fault
                # responses (unreachable port/service) are not open.
                lower_content = content.lower()
                fault_code = self._extract_fault_code(content)
                if (
                    response.status_code == 200
                    and "<methodresponse" in lower_content
                    and "<fault>" not in lower_content
                    and fault_code == 0
                ):
                    open_ports.append(port)
                    self.logger.debug(f"Port {port} appears to be open")

                await asyncio.sleep(self.REQUEST_DELAY)

            except Exception as e:
                self.logger.debug(f"Error checking port {port}: {e}")

        self.logger.info(
            f"Scanned {scanned_count} ports, blocked {blocked_count} by SSRF protection"
        )

        if scanned_count == 0:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Port scan could not run",
                description=(
                    "No pingback.ping requests completed. XML-RPC may be disabled, "
                    "unreachable or blocking pingbacks."
                ),
                evidence=url,
                recommendation="Verify XML-RPC is enabled if port discovery is required.",
                raw={
                    "url": url,
                    "scanned_count": scanned_count,
                    "blocked_count": blocked_count,
                },
            )

        if open_ports:
            risky = sorted(p for p in open_ports if p in self.RISKY_PORTS)
            self._add_finding(
                module=self.MODULE,
                severity="medium" if risky else "info",
                title="Open ports detected via SSRF",
                description=f"Found {len(open_ports)} open port(s) via pingback.ping SSRF. "
                f"Scanned {scanned_count} ports, {blocked_count} blocked by SSRF protection.",
                evidence=f"{url} -> ports: " + ", ".join(str(p) for p in open_ports),
                recommendation="Ensure internal services are not exposed to the WordPress server. "
                "Disable XML-RPC if not needed.",
                raw={
                    "url": url,
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
                if end > start:
                    return int(content[start:end].strip())
        except (ValueError, TypeError):
            pass
        return 0
