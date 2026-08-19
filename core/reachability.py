"""Pre-flight reachability check for scan targets.

Performs lightweight DNS + TCP + TLS probes before launching a full scan.
Returns a ReachabilityResult that the caller can use to abort early with a
friendly message instead of letting every step fail silently.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from core.logger import Logger

logger = Logger("Reachability")


@dataclass
class ReachabilityResult:
    """Outcome of a reachability probe."""

    reachable: bool
    domain: str
    ip: Optional[str] = None
    dns_ms: float = 0.0
    tcp_ms: float = 0.0
    tls_ms: float = 0.0
    error: Optional[str] = None
    error_category: Optional[str] = None  # dns / tcp / tls / unknown


def _friendly_error(exc: Exception, category: str) -> str:
    """Produce a one-line human-readable error string."""
    name = type(exc).__name__
    detail = str(exc).strip()

    if category == "dns":
        if "Name or service not known" in detail or "nodename" in detail:
            return f"DNS resolution failed — domain does not exist or is unreachable: {detail}"
        return f"DNS resolution failed ({name}): {detail}"

    if category == "tls":
        if "certificate has expired" in detail.lower():
            return f"TLS certificate has expired: {detail}"
        if "CERTIFICATE_VERIFY_FAILED" in name or "certificate verify failed" in detail.lower():
            return f"TLS certificate verification failed: {detail}"
        return f"TLS handshake failed ({name}): {detail}"

    if category == "tcp":
        if "Connection refused" in detail:
            return f"TCP connection refused — no service listening on target port: {detail}"
        if "timed out" in detail.lower() or "timeout" in detail.lower():
            return f"TCP connection timed out — host may be unreachable or firewalled: {detail}"
        if "No route to host" in detail:
            return f"No route to host — network path unreachable: {detail}"
        return f"TCP connection failed ({name}): {detail}"

    return f"Reachability check failed ({name}): {detail}"


async def check_reachability(
    url: str,
    timeout: float = 5.0,
    insecure: bool = False,
) -> ReachabilityResult:
    """Probe DNS → TCP → TLS for the target URL.

    Returns a ReachabilityResult with timing and error details.
    Does NOT raise — errors are captured in the result.
    """
    parsed = urlparse(url)
    domain = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https" or port == 443

    result = ReachabilityResult(reachable=False, domain=domain)

    # ── DNS ──────────────────────────────────────────────────────────
    t0 = time.monotonic()
    try:
        loop = asyncio.get_running_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
    except Exception as exc:
        result.dns_ms = (time.monotonic() - t0) * 1000
        result.error = _friendly_error(exc, "dns")
        result.error_category = "dns"
        logger.warning(result.error)
        return result
    result.ip = ip
    result.dns_ms = (time.monotonic() - t0) * 1000
    logger.debug(f"DNS {domain} → {ip} ({result.dns_ms:.0f}ms)")

    # ── TCP ──────────────────────────────────────────────────────────
    t1 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        result.tcp_ms = (time.monotonic() - t1) * 1000
        result.error = _friendly_error(exc, "tcp")
        result.error_category = "tcp"
        logger.warning(result.error)
        return result
    result.tcp_ms = (time.monotonic() - t1) * 1000
    logger.debug(f"TCP {ip}:{port} open ({result.tcp_ms:.0f}ms)")

    # ── TLS (only for HTTPS) ────────────────────────────────────────
    if use_tls:
        t2 = time.monotonic()
        try:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            def _tls_handshake() -> None:
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        ssock.getpeercert()

            await loop.run_in_executor(None, _tls_handshake)
        except Exception as exc:
            result.tls_ms = (time.monotonic() - t2) * 1000
            result.error = _friendly_error(exc, "tls")
            result.error_category = "tls"
            logger.warning(result.error)
            return result
        result.tls_ms = (time.monotonic() - t2) * 1000
        logger.debug(f"TLS OK ({result.tls_ms:.0f}ms)")

    result.reachable = True
    return result
