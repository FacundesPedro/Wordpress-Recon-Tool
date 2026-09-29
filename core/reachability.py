"""Pre-flight reachability check for scan targets.

Performs lightweight DNS + TCP + TLS probes before launching a full scan.
Returns a ReachabilityResult that the caller can use to abort early with a
friendly message instead of letting every step fail silently.

Transient failures (timeout, connection reset, a refused port during a
restart) are retried with exponential backoff. Permanent failures (NXDOMAIN,
certificate verification) are not retried - retrying cannot help.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from core.logger import Logger

logger = Logger("Reachability")


@dataclass
class ReachabilityResult:
    """Outcome of a reachability probe."""

    reachable: bool
    domain: str
    ip: str | None = None
    dns_ms: float = 0.0
    tcp_ms: float = 0.0
    tls_ms: float = 0.0
    error: str | None = None
    error_category: str | None = None  # dns / tcp / tls / unknown
    attempts: int = 1
    permanent: bool = False


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
        if "Connection reset" in detail:
            return f"TCP connection reset by peer: {detail}"
        return f"TCP connection failed ({name}): {detail}"

    return f"Reachability check failed ({name}): {detail}"


def is_permanent_failure(result: ReachabilityResult) -> bool:
    """Return True when retrying the probe cannot plausibly change the outcome.

    Permanent: DNS resolution failures (NXDOMAIN) and TLS certificate
    verification errors (expired / wrong hostname) unless ``insecure`` was
    requested. Everything else (timeouts, resets, refused ports) is treated as
    transient and retried.
    """
    if result.error_category == "dns":
        return True
    if result.error_category == "tls":
        msg = (result.error or "").lower()
        return "certificate" in msg or "verify failed" in msg
    return False


async def _probe_once(
    url: str,
    timeout: float,
    insecure: bool,
    connect_ip: str | None = None,
    server_hostname: str | None = None,
) -> ReachabilityResult:
    """Run a single DNS → TCP → TLS probe."""
    parsed = urlparse(url)
    domain = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https" or port == 443
    sni_hostname = server_hostname or domain

    result = ReachabilityResult(reachable=False, domain=domain)

    # ── DNS (or an explicit IP override) ─────────────────────────────
    if connect_ip:
        result.ip = connect_ip
        logger.debug(f"Using pinned IP {connect_ip} for {domain} (DNS skipped)")
    else:
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

    ip = result.ip or domain

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
                with (
                    socket.create_connection((ip, port), timeout=timeout) as sock,
                    ctx.wrap_socket(
                        sock, server_hostname=sni_hostname
                    ) as ssock,
                ):
                    ssock.getpeercert()

            loop = asyncio.get_running_loop()
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


async def check_reachability(
    url: str,
    timeout: float = 5.0,
    insecure: bool = False,
    attempts: int = 1,
    retry_delay: float = 1.0,
    connect_ip: str | None = None,
    server_hostname: str | None = None,
) -> ReachabilityResult:
    """Probe DNS → TCP → TLS for the target URL, retrying transient failures.

    Returns a ReachabilityResult with timing and error details.
    Does NOT raise — errors are captured in the result.

    Args:
        attempts: Total number of probes to make (>= 1). The default of 1 is
            the legacy single-shot behaviour used by existing callers/tests.
        retry_delay: Base delay between retries; grows exponentially
            (delay * 2**(attempt-1), capped at 30s). Not applied after the
            final attempt or after a permanent failure.
        connect_ip: When set, skip DNS and connect to this IP while keeping
            ``url``'s hostname for TLS SNI (split-horizon targets).
        server_hostname: Override the TLS SNI/verification hostname.
    """
    total_attempts = max(1, attempts)
    last: ReachabilityResult | None = None

    for attempt in range(1, total_attempts + 1):
        result = await _probe_once(
            url,
            timeout=timeout,
            insecure=insecure,
            connect_ip=connect_ip,
            server_hostname=server_hostname,
        )
        result.attempts = attempt
        last = result

        if result.reachable:
            return result
        if is_permanent_failure(result):
            break
        if attempt < total_attempts:
            delay = min(retry_delay * (2 ** (attempt - 1)), 30.0)
            logger.warning(
                f"Reachability attempt {attempt}/{total_attempts} failed "
                f"({result.error_category}); retrying in {delay:.1f}s"
            )
            await asyncio.sleep(delay)

    assert last is not None
    last.permanent = is_permanent_failure(last)
    if total_attempts > 1 and not last.reachable:
        logger.warning(
            f"Reachability check failed after {last.attempts} attempt(s): "
            f"{last.error}"
        )
    return last
