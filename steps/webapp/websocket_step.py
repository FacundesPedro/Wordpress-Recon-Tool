# recon_wp/steps/webapp/websocket_step.py
"""
WebSocket security check - endpoint discovery and cross-origin handshake.

Covers WSTG 4.11.10 (Testing WebSockets): discovers ws:// and wss:// endpoints
in HTML/JS and performs a raw handshake with a canary Origin header. A 101
response to a foreign Origin indicates a cross-site WebSocket hijacking (CSWSH)
surface. No frames are exchanged beyond the handshake.
"""

# WHAT: Discovers WebSocket endpoints and tests Origin validation on handshake
# HOW: Extracts ws(s):// URLs from HTML/JS; performs a raw asyncio handshake
#      with a canary Origin; a 101 acceptance is a CSWSH signal
# WHY: WebSockets often skip origin validation, enabling cross-site hijacking

import asyncio
import re
import secrets
import ssl
from typing import Optional
from urllib.parse import urlparse

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.source_discovery import extract_asset_urls, fetch_assets

WS_URL_RE = re.compile(r"(?:wss?|https?)://[^\s\"'<>\\]+", re.I)

CANARY_ORIGIN = "https://ws-canary-7q4.example"
TIMEOUT = 6.0
MAX_ENDPOINTS = 5
MAX_FINDINGS = 5


def extract_ws_endpoints(text: str, target_origin: str) -> list[str]:
    """Extract ws:// or wss:// URLs from text, deduplicated."""
    endpoints: list[str] = []
    seen: set[str] = set()
    for match in WS_URL_RE.findall(text or ""):
        parsed = urlparse(match)
        if parsed.scheme not in ("ws", "wss"):
            # convert https(same host) references with upgrade hints? keep strict
            continue
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if url in seen:
            continue
        seen.add(url)
        endpoints.append(url)
    return endpoints[:MAX_ENDPOINTS]


async def ws_handshake(url: str, origin: str) -> Optional[tuple[int, str]]:
    """Perform a minimal WebSocket handshake; return (status, reason) or None.

    Sends Upgrade headers with the supplied Origin and reads the response
    head. No frames are exchanged.
    """
    parsed = urlparse(url)
    if parsed.scheme == "wss":
        port = parsed.port or 443
        use_tls = True
    else:
        port = parsed.port or 80
        use_tls = False
    host = parsed.hostname
    if not host:
        return None
    path = parsed.path or "/"
    key = secrets.token_hex(12)  # arbitrary 16-byte value, base64-ish

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        f"\r\n"
    )

    try:
        ssl_context = ssl.create_default_context() if use_tls else None
        if use_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=TIMEOUT,
        )
    except Exception as e:
        raise ConnectionError(f"connect failed: {e}") from e

    try:
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=TIMEOUT)
    except Exception as e:
        raise ConnectionError(f"handshake failed: {e}") from e
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    head = data.decode("latin-1", errors="replace")
    first_line = head.split("\r\n", 1)[0]
    parts = first_line.split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("HTTP"):
        return int(parts[1]), (parts[2] if len(parts) > 2 else "")
    return None


class WebSocketStep(BaseHttpStep):
    """Discover WebSocket endpoints and test Origin validation."""

    name = "websocket"
    description = "Discover WebSocket endpoints and test cross-origin handshakes"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        if not getattr(self.config, "webapp_websocket_probe", True):
            self.logger.debug("WebSocket probe disabled by config")
            return self.findings

        self.logger.info("Probing WebSocket endpoints (handshake only)...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        text = response.text or ""
        endpoints = extract_ws_endpoints(text, self.target.url)
        try:
            asset_urls = extract_asset_urls(text, self.target.url)
            assets = await fetch_assets(
                self.http, self.target.url, asset_urls,
                max_files=int(getattr(self.config, "source_scan_max_js", 20)),
                max_bytes=int(getattr(self.config, "source_scan_max_bytes", 1000000)),
            )
            for _url, content in assets:
                endpoints.extend(extract_ws_endpoints(content, self.target.url))
        except Exception as e:
            self.logger.debug(f"JS asset fetch failed: {e}")

        if not endpoints:
            self.logger.info("WebSocket probe: no ws:// endpoints found")
            return self.findings

        for endpoint in list(dict.fromkeys(endpoints))[:MAX_ENDPOINTS]:
            try:
                result = await ws_handshake(endpoint, CANARY_ORIGIN)
            except ConnectionError as e:
                self.logger.debug(f"WebSocket {endpoint}: {e}")
                continue

            if result is None:
                continue
            status, reason = result
            if status == 101:
                self.add_finding(
                    "medium",
                    f"WebSocket accepts cross-origin handshake at {endpoint}",
                    (
                        f"The WebSocket endpoint completed a 101 upgrade with "
                        f"Origin: {CANARY_ORIGIN} (unrelated origin). If the "
                        f"connection carries session cookies, cross-site "
                        f"WebSocket hijacking may be possible."
                    ),
                    f"Handshake to {endpoint} with foreign Origin -> 101 {reason}",
                    "Validate the Origin header against an allowlist before "
                    "completing the upgrade; require per-message auth",
                    raw={"endpoint": endpoint, "status": status},
                )
            else:
                self.logger.debug(
                    f"WebSocket {endpoint}: handshake returned {status} (origin rejected)"
                )

        self.logger.info(
            f"WebSocket probe done: {len(self.findings)} finding(s) across "
            f"{len(endpoints)} endpoint(s)"
        )
        return self.findings

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: str, recommendation: str,
                    raw: Optional[dict] = None) -> None:
        self._add_finding(
            module=self.MODULE,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            raw=raw or {},
        )
