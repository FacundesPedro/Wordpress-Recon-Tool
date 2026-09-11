# recon_wp/steps/active/request_smuggling_step.py
"""
HTTP request smuggling detection - CL.TE timing differential probe.

Covers WSTG 4.7.16 (Testing for HTTP Request Smuggling): sends raw requests
with conflicting Content-Length / Transfer-Encoding framing over a raw socket
and measures response timing differences. Results are reported as
"suspected - manual verification required" because timing probes are noisy.

Gated twice: `WP_ACTIVE_ENABLED` (active module) AND `WP_ACTIVE_SMUGGLING`.
"""

# WHAT: Detects potential request smuggling via framing-conflict timing
# HOW: Raw socket CL.TE/TE.CL probes with timing differential measurement
# WHY: Smuggling desync enables cache poisoning and auth bypass at proxies

import asyncio
import ssl
import time
from urllib.parse import urlparse

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

MAX_FINDINGS = 2
TIMEOUT = 8.0
DELAY_THRESHOLD = 2.0


async def _raw_request(host: str, port: int, use_tls: bool,
                       payload: bytes) -> tuple[float, bytes]:
    """Send raw bytes over a socket; return (elapsed_seconds, response_bytes)."""
    start = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=use_tls), timeout=TIMEOUT
    )
    try:
        writer.write(payload)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), timeout=TIMEOUT)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return time.monotonic() - start, data


def build_clte_payload(host: str) -> bytes:
    """CL.TE framing-conflict request (detection-only, benign body)."""
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"1\r\nZ\r\n0\r\n\r\n"
    ).encode()


def build_tecl_payload(host: str) -> bytes:
    """TE.CL framing-conflict request (detection-only, benign body)."""
    body = "0\r\n\r\n"
    return (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 100\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n{body}"
    ).encode()


def build_baseline_payload(host: str) -> bytes:
    """Well-formed GET request for timing baseline."""
    return f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()


class RequestSmugglingStep(ActiveHttpStep):
    """Detect potential request smuggling via timing differentials."""

    name = "request_smuggling"
    description = "Detect request smuggling via CL.TE/TE.CL timing probes (suspected-only)"
    severity = "high"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings
        if not getattr(self.config, "active_smuggling", False):
            self.logger.info(
                "Smuggling probe disabled (WP_ACTIVE_SMUGGLING) - skipping"
            )
            return self.findings

        self.logger.warning("Probing request smuggling (timing differentials)...")

        parsed = urlparse(self.target.url)
        host = parsed.hostname or ""
        if not host:
            return self.findings
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        try:
            baseline_elapsed, _ = await _raw_request(
                host, port, use_tls, build_baseline_payload(host)
            )
        except Exception as e:
            self.logger.debug(f"Smuggling baseline failed: {e}")
            return self.findings

        for label, builder in (("CL.TE", build_clte_payload),
                               ("TE.CL", build_tecl_payload)):
            if len(self.findings) >= MAX_FINDINGS:
                break
            try:
                elapsed, data = await _raw_request(
                    host, port, use_tls, builder(host)
                )
            except Exception as e:
                self.logger.debug(f"Smuggling {label} probe failed: {e}")
                continue

            delta = elapsed - baseline_elapsed
            if delta < DELAY_THRESHOLD:
                continue
            self.add_finding(
                "medium",
                f"Possible request smuggling ({label}) - suspected",
                (
                    f"A {label} framing-conflict request took {elapsed:.1f}s "
                    f"vs a {baseline_elapsed:.1f}s baseline (delta {delta:.1f}s). "
                    f"This timing differential can indicate front-end/back-end "
                    f"desync, but timing probes are noisy - manual "
                    f"verification with a differential payload is required."
                ),
                f"{label} probe to {host}:{port} -> {elapsed:.1f}s "
                f"(baseline {baseline_elapsed:.1f}s)",
                "Normalize framing at the front end (reject dual framing); "
                "verify manually before reporting as exploitable",
                raw={"technique": label, "elapsed": round(elapsed, 2),
                     "baseline": round(baseline_elapsed, 2),
                     "delta": round(delta, 2)},
            )

        self.logger.info(
            f"Smuggling probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
