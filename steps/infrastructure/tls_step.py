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

    # Certificate verification failures that warrant a high rating: the
    # certificate exists but is unusable for a live HTTPS service.
    _HIGH_CERT_MARKERS = (
        "certificate has expired",
        "has expired",
        "hostname mismatch",
        "ip address mismatch",
        "doesn't match",
        "does not match",
    )

    @classmethod
    def _classify_cert_error(cls, error: Exception) -> tuple[str, str]:
        """Map a certificate verification error to (severity, description)."""
        message = str(error).lower()
        if any(marker in message for marker in cls._HIGH_CERT_MARKERS):
            return "high", "TLS certificate is expired or does not match the hostname"
        return "medium", "TLS certificate could not be verified (untrusted/self-signed)"

    def _emit_tls_info(self, ssock, hostname: str, port: int) -> None:
        cipher = ssock.cipher()
        version = ssock.version()
        self._add_finding(
            module=self.MODULE,
            severity="info",
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
        self.logger.info(f"TLS: {version} with {cipher[0] if cipher else 'unknown'}")

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
        except Exception as e:
            self.logger.debug(f"Could not determine TLS target: {e}")
            return self.findings

        # First attempt honours certificate validation so verification
        # failures are surfaced as findings instead of being silently ignored.
        verified = ssl.create_default_context()

        try:
            with socket.create_connection(
                (hostname, port), timeout=10
            ) as sock, verified.wrap_socket(sock, server_hostname=hostname) as ssock:
                self._emit_tls_info(ssock, hostname, port)
            return self.findings
        except ssl.SSLCertVerificationError as e:
            self.logger.debug(f"TLS certificate error: {e}")
            severity, description = self._classify_cert_error(e)
            self._add_finding(
                module=self.MODULE,
                severity=severity,
                title="TLS certificate issue",
                description=description,
                evidence=str(e),
                recommendation=(
                    "Renew the certificate / correct the hostname, or install a "
                    "trusted certificate chain"
                ),
                raw={"error": str(e), "hostname": hostname, "port": port},
            )
        except Exception as e:
            self.logger.debug(f"Error checking TLS: {e}")
            return self.findings

        # The certificate failed validation; retry without verification so the
        # negotiated version/cipher can still be reported.
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (hostname, port), timeout=10
            ) as sock, context.wrap_socket(sock, server_hostname=hostname) as ssock:
                self._emit_tls_info(ssock, hostname, port)
        except Exception as e:
            self.logger.debug(f"Error gathering TLS info: {e}")

        return self.findings
