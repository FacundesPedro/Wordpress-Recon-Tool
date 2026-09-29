"""httpx transport that pins a hostname to an explicit IP.

WHY: Split-horizon targets resolve to a different (often public) IP inside a
container than on the analyst's intranet. ``--target-ip`` / ``--resolve`` let
the scan connect to the intended IP while the request still carries the real
``Host`` header and TLS SNI/verification hostname.

HOW: httpx/httpcore support connecting to a different address than the URL host
via the ``sni_hostname`` request extension and an explicit ``Host`` header.
Rewriting the URL host on the *transport* (rather than once per request) also
covers redirects, since every hop goes through ``handle_async_request``.

Reference: https://www.python-httpx.org/advanced/extensions/#sni_hostname
"""

from __future__ import annotations

import httpx


class PinnedTransport(httpx.AsyncHTTPTransport):
    """Connect to ``connect_ip`` while using ``server_hostname`` for Host/SNI."""

    def __init__(self, connect_ip: str, server_hostname: str, **kwargs):
        super().__init__(**kwargs)
        self._connect_ip = connect_ip
        self._server_hostname = server_hostname

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        host = (url.host or "").lower()
        if host and host == self._server_hostname.lower():
            netloc = url.netloc
            if isinstance(netloc, bytes):  # pragma: no cover - httpx returns str
                netloc = netloc.decode("ascii", "replace")
            # The server must still see the original hostname in the Host header.
            request.headers["Host"] = netloc
            request.url = url.copy_with(host=self._connect_ip)
            request.extensions = {
                **request.extensions,
                "sni_hostname": self._server_hostname,
            }
        return await super().handle_async_request(request)
