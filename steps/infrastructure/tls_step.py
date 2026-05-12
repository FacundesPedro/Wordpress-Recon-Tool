# recon_wp/steps/infrastructure/tls_step.py
"""
TLS configuration enumeration.

Checks SSL/TLS version and cipher suite.
"""

# WHAT: Analyzes TLS configuration of the target
# HOW: Python ssl module to inspect certificate and cipher
# WHY: Weak TLS config or expired certs are security issues

import socket
import ssl

from base.http_step import BaseHttpStep
from core.finding import Finding


class TlsStep(BaseHttpStep):
    """Check TLS configuration of the target."""

    name = "tls"
    description = "Check TLS configuration"
    severity = "info"
    MODULE = "infrastructure"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking TLS configuration...")

        try:
            hostname = (
                self.target.domain.split(":")[0]
                if self.target.domain
                else self.target.url.split("//")[1].split("/")[0]
            )
            port = 443

            if ":" in self.target.domain:
                parts = self.target.domain.split(":")
                hostname = parts[0]
                port = int(parts[1])
            elif self.target.url.startswith("http://"):
                self.logger.debug("Skipping TLS check for HTTP target")
                return self.findings

            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="TLS configuration info",
                        description=f"TLS version: {version}, Cipher: {cipher[0] if cipher else 'unknown'}",
                        evidence=f"Hostname: {hostname}:{port}",
                        recommendation="Ensure modern TLS versions (1.2, 1.3) are used",
                        raw={
                            "hostname": hostname,
                            "port": port,
                            "tls_version": version,
                            "cipher": cipher[0] if cipher else None,
                        },
                    )
                    self.logger.info(
                        f"TLS: {version} with {cipher[0] if cipher else 'unknown'}"
                    )

        except ssl.SSLCertVerificationError as e:
            self.logger.debug(f"TLS certificate error: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="TLS certificate issue",
                description="TLS certificate verification failed",
                evidence=str(e),
                recommendation="Fix or replace the TLS certificate",
                raw={"error": str(e)},
            )
        except Exception as e:
            self.logger.debug(f"Error checking TLS: {e}")

        return self.findings
