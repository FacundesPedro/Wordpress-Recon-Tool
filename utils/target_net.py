# recon_wp/utils/target_net.py
"""Helpers for split-horizon / pinned-IP targets.

When ``--target-ip`` or ``--resolve host:ip`` pins a target to an explicit IP,
stdlib HTTP steps connect through ``core.pinned_transport`` and keep the
hostname for Host/SNI. External tools (nmap/ffuf/nuclei/opendoor) need the same
treatment via their own flags: they scan/fuzz the IP while sending the real
hostname in the ``Host`` header where the tool supports it.

These helpers are defensive: unit tests often pass ``MagicMock`` targets, so
non-string values are treated as "not pinned".
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def pinned_ip(target) -> str | None:
    """Return the pinned connect IP for a target, or None."""
    ip = getattr(target, "connect_ip", None)
    return ip if isinstance(ip, str) and ip.strip() else None


def _domain(target) -> str:
    domain = getattr(target, "domain", "") or ""
    return domain if isinstance(domain, str) else ""


def _url(target) -> str:
    url = getattr(target, "url", "") or ""
    return url if isinstance(url, str) else ""


def scan_host(target) -> str:
    """Host for direct-connect tools (nmap): the pinned IP, else the domain."""
    return pinned_ip(target) or _domain(target) or _url(target)


def host_header(target) -> str | None:
    """Value for a ``Host`` header when pinned, else None.

    Includes the non-standard port when the target URL carries one so vhost
    routing matches the original request.
    """
    ip = pinned_ip(target)
    if not ip:
        return None
    domain = _domain(target)
    if not domain:
        return None
    try:
        port = urlsplit(_url(target)).port
    except ValueError:
        port = None
    return f"{domain}:{port}" if port else domain


def sni_hostname(target) -> str | None:
    """TLS SNI value when the target is pinned, else None.

    Tools that connect to the pinned IP derive the TLS SNI from the URL host
    (= the IP), which fails vhost routing. This returns the real hostname
    (no port) to pass as the tool's ``-sni``/``--sni`` value.
    """
    if not pinned_ip(target):
        return None
    return _domain(target) or None


def pinned_url(target) -> str:
    """Target URL with the host swapped for the pinned IP (scheme/port kept)."""
    ip = pinned_ip(target)
    url = _url(target)
    if not ip or not url:
        return url
    parsed = urlsplit(url)
    if not parsed.hostname:
        return url
    netloc = f"{ip}:{parsed.port}" if parsed.port else ip
    return urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )


def restore_public_host(url: str, target) -> str:
    """Rewrite a pinned connect IP back to the public hostname in a URL.

    Pinned transports make ``response.url`` carry the internal IP; reports must
    never leak it, so any URL whose host is the pinned IP is rewritten to the
    real domain (port preserved).
    """
    ip = pinned_ip(target)
    domain = _domain(target)
    if not ip or not domain or not url:
        return url
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    if parsed.hostname != ip:
        return url
    netloc = f"{domain}:{parsed.port}" if parsed.port else domain
    return urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )
