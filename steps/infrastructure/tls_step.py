# recon_wp/steps/infrastructure/tls_step.py
"""
TLS configuration enumeration.

Checks SSL/TLS version and cipher suite, classifies certificate failures
precisely (expired vs hostname mismatch vs self-signed vs untrusted chain), and
- when the scan targets a pinned IP - records the default no-SNI certificate
that a bare-IP client receives.
"""

# WHAT: Analyzes TLS configuration of the target
# HOW: Python ssl module to inspect certificate and cipher
# WHY: Weak TLS config or expired certs are security issues

import contextlib
import os
import socket
import ssl
import tempfile
import time
from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding


class TlsStep(BaseHttpStep):
    """Check TLS configuration of the target."""

    name = "tls"
    description = "Check TLS configuration"
    severity = "info"
    MODULE = "infrastructure"

    @classmethod
    def _classify_cert_error(cls, error: Exception) -> tuple[str, str, str]:
        """Map a verification error to ``(severity, description, kind)``.

        Distinct labels matter: a private-CA chain that validates the correct
        hostname is not "self-signed", and an expired default certificate is a
        different problem from a hostname mismatch.
        """
        message = str(error).lower()
        if "expired" in message:
            return "high", "TLS certificate has expired", "expired"
        if any(
            marker in message
            for marker in (
                "hostname mismatch",
                "ip address mismatch",
                "doesn't match",
                "does not match",
            )
        ):
            return (
                "high",
                "TLS certificate does not match the target hostname",
                "hostname_mismatch",
            )
        if "self-signed" in message or "self signed" in message:
            return (
                "medium",
                "TLS certificate is self-signed (not trusted)",
                "self_signed",
            )
        return (
            "medium",
            "TLS certificate chain is not trusted (private or unknown CA)",
            "chain_untrusted",
        )

    @staticmethod
    def _decode_cert(ssock) -> dict:
        """Decode the peer certificate (DER) into a stdlib certificate dict."""
        try:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                return {}
            pem = ssl.DER_cert_to_PEM_cert(der)
            path = ""
            try:
                with tempfile.NamedTemporaryFile(
                    "w", suffix=".pem", delete=False, encoding="ascii"
                ) as handle:
                    handle.write(pem)
                    path = handle.name
                return dict(ssl._ssl._test_decode_cert(path))  # type: ignore[attr-defined]
            finally:
                if path:
                    with contextlib.suppress(OSError):
                        os.unlink(path)
        except Exception:
            return {}

    @staticmethod
    def _cert_expired(cert: dict) -> bool:
        not_after = cert.get("notAfter")
        if not not_after:
            return False
        try:
            return ssl.cert_time_to_seconds(not_after) < time.time()
        except Exception:
            return False

    @staticmethod
    def _common_name(cert: dict) -> str:
        for rdn in cert.get("subject", ()):  # type: ignore[union-attr]
            for key, value in rdn:
                if key == "commonName":
                    return str(value)
        return ""

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

        pinned = getattr(self.target, "connect_ip", None)
        connect_host = (
            pinned if isinstance(pinned, str) and pinned.strip() else hostname
        )
        sni_der: Optional[bytes] = None
        verification_error: Optional[Exception] = None

        # First attempt honours certificate validation so verification
        # failures are surfaced as findings instead of being silently ignored.
        verified = ssl.create_default_context()
        try:
            with socket.create_connection(
                (connect_host, port), timeout=10
            ) as sock, verified.wrap_socket(
                sock, server_hostname=hostname
            ) as ssock:
                sni_der = ssock.getpeercert(binary_form=True)
                self._emit_tls_info(ssock, hostname, port)
        except ssl.SSLCertVerificationError as e:
            verification_error = e
            self.logger.debug(f"TLS certificate error: {e}")
            severity, description, kind = self._classify_cert_error(e)
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
                raw={
                    "error": str(e),
                    "classification": kind,
                    "hostname": hostname,
                    "port": port,
                },
            )
        except Exception as e:
            self.logger.debug(f"Error checking TLS: {e}")
            return self.findings

        if verification_error is not None:
            # Retry without verification so the negotiated version/cipher and
            # the presented certificate can still be reported.
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection(
                    (connect_host, port), timeout=10
                ) as sock, context.wrap_socket(
                    sock, server_hostname=hostname
                ) as ssock:
                    sni_der = ssock.getpeercert(binary_form=True)
                    self._emit_tls_info(ssock, hostname, port)
            except Exception as e:
                self.logger.debug(f"Error gathering TLS info: {e}")

        if connect_host != hostname:
            self._check_default_cert(connect_host, hostname, port, sni_der)

        return self.findings

    def _check_default_cert(
        self, connect_ip: str, hostname: str, port: int, sni_der: Optional[bytes]
    ) -> None:
        """Record the certificate served without SNI when targeting an IP.

        A front tier may serve a valid SNI certificate for the hostname while
        the default (no-SNI) certificate on the IP is expired. Clients that
        connect by IP see the latter, so it must be reported separately.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(
                (connect_ip, port), timeout=10
            ) as sock, context.wrap_socket(sock, server_hostname=None) as ssock:
                default_der = ssock.getpeercert(binary_form=True)
                cert = self._decode_cert(ssock)
        except Exception as e:
            self.logger.debug(f"No-SNI certificate probe failed: {e}")
            return

        if not default_der or (sni_der and default_der == sni_der):
            # Same certificate as the SNI connection: nothing new to report.
            return

        expired = self._cert_expired(cert)
        common_name = self._common_name(cert)
        not_after = cert.get("notAfter", "unknown")
        if expired:
            severity = "high"
            title = f"Expired default TLS certificate on {connect_ip} (no SNI)"
            description = (
                f"Clients that connect to {connect_ip} without SNI receive an "
                f"expired certificate (CN={common_name}, expired {not_after})."
            )
        else:
            severity = "medium"
            title = f"Default TLS certificate on {connect_ip} differs from the SNI certificate"
            description = (
                f"Clients that connect to {connect_ip} without SNI receive a "
                f"different certificate (CN={common_name}, valid until "
                f"{not_after})."
            )

        self._add_finding(
            module=self.MODULE,
            severity=severity,
            title=title,
            description=description,
            evidence=(
                f"connect_ip: {connect_ip}:{port} (no SNI)\n"
                f"subject CN: {common_name or 'unknown'}\n"
                f"notAfter: {not_after}"
            ),
            recommendation=(
                "Replace the default certificate on the IP with a valid one, "
                "or ensure clients always send SNI"
            ),
            raw={
                "classification": "expired" if expired else "default_cert_mismatch",
                "connect_ip": connect_ip,
                "sni_hostname": hostname,
                "common_name": common_name,
                "not_after": not_after,
                "expired": expired,
            },
        )
        self.logger.info(
            f"Default (no-SNI) certificate on {connect_ip}: "
            f"CN={common_name}, expired={expired}"
        )
