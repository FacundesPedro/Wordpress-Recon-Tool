# recon_wp/core/ssrf_protection.py
"""SSRF Protection - validates URLs and targets against Server-Side Request Forgery attacks.

This module provides utilities to prevent SSRF by blocking requests to:
- Private IP ranges (RFC 1918, loopback, link-local)
- Cloud metadata endpoints (AWS, GCP, Azure, etc.)
- Localhost addresses
- Invalid URL schemes

Usage:
    from core.ssrf_protection import is_blocked_target, validate_target

    # Check if a target is blocked (for port scanning, SSRF testing)
    if is_blocked_target("192.168.1.1", 80):
        # Target is in blocklist, skip
        pass

    # Validate before making outbound requests
    validate_target("http://169.254.169.254")  # Raises ValueError
"""

import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse

# Private IP ranges (RFC 1918, RFC 4193, RFC 3927, loopback)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8", strict=False),
    ipaddress.ip_network("172.16.0.0/12", strict=False),
    ipaddress.ip_network("192.168.0.0/16", strict=False),
    ipaddress.ip_network("127.0.0.0/8", strict=False),
    ipaddress.ip_network("169.254.0.0/16", strict=False),
    ipaddress.ip_network("0.0.0.0/8", strict=False),
    ipaddress.ip_network("::1/128", strict=False),
    ipaddress.ip_network("fc00::/7", strict=False),
    ipaddress.ip_network("fe80::/10", strict=False),
    ipaddress.ip_network("ff00::/8", strict=False),
]

# Cloud provider metadata IPs
CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "169.254.170.2",
    "169.254.170.23",
    "100.100.100.200",
    "fd00:ec2::254",
    "fd00:ec2::23",
    "fe80::a9fe:a9fe",
}

# Cloud provider metadata hostnames
CLOUD_METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

# Localhost variations
LOCALHOST_NAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


def _normalize_ip(ip_str: str) -> str:
    """Normalize IP strings for consistent SSRF checks.

    Args:
        ip_str: IP address as a string.

    Returns:
        Canonical string form, converting IPv6-mapped IPv4 to plain IPv4.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        return ip_str


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private range.

    Args:
        ip_str: IP address as a string (e.g., "192.168.1.1")

    Returns:
        True if IP is in a private range, False otherwise
    """
    try:
        ip = ipaddress.ip_address(_normalize_ip(ip_str))
        return any(ip in ip_network for ip_network in PRIVATE_IP_RANGES)
    except ValueError:
        return False


def is_cloud_metadata(hostname: str, ip_str: Optional[str] = None) -> bool:
    """Check if hostname or IP is a cloud metadata endpoint.

    Args:
        hostname: Hostname to check
        ip_str: Optional IP address to check

    Returns:
        True if hostname or IP is a known cloud metadata endpoint
    """
    if hostname.lower() in CLOUD_METADATA_HOSTNAMES:
        return True

    if ip_str:
        normalized_ip = _normalize_ip(ip_str)
        if normalized_ip in CLOUD_METADATA_IPS:
            return True

    return False


def is_localhost(hostname: str, ip_str: Optional[str] = None) -> bool:
    """Check if hostname or IP is localhost.

    Args:
        hostname: Hostname to check
        ip_str: Optional IP address to check

    Returns:
        True if hostname or IP is localhost
    """
    if hostname.lower() in LOCALHOST_NAMES:
        return True

    if ip_str:
        try:
            normalized_ip = _normalize_ip(ip_str)
            ip = ipaddress.ip_address(normalized_ip)
            if ip.is_loopback:
                return True
            if normalized_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                return True
        except ValueError:
            pass

    return False


def resolve_hostname(hostname: str, port: int = 80) -> list[str]:
    """Resolve hostname to all IP addresses.

    Args:
        hostname: Hostname to resolve
        port: Port number for connection

    Returns:
        List of IP address strings, empty list on failure
    """
    try:
        addr_info = socket.getaddrinfo(
            hostname,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        return list(set(result[4][0] for result in addr_info))
    except (socket.gaierror, OSError):
        return []


def is_blocked_target(host: str, port: Optional[int] = None) -> bool:
    """Check if a target (host:port) is in the SSRF blocklist.

    This is used for port scanning and SSRF testing where we want to
    prevent scanning/attacking internal infrastructure.

    Note: DNS resolution is performed at check time only. DNS rebinding
    attacks (where the DNS response changes between this check and the
    actual request) are not defended against. For high-security use
    cases, pin DNS resolution at connection time or use connect-and-check.

    Args:
        host: Hostname or IP address to check
        port: Optional port number

    Returns:
        True if target is blocked (private IP, localhost, cloud metadata),
        False if target is safe to scan
    """
    normalized_host = _normalize_ip(host)

    if is_localhost(normalized_host):
        return True
    if is_private_ip(normalized_host):
        return True
    if normalized_host in CLOUD_METADATA_IPS:
        return True

    hostname = host
    if is_cloud_metadata(hostname, normalized_host):
        return True

    if port:
        ips = resolve_hostname(hostname, port)
        for ip in ips:
            if is_private_ip(ip) or ip in CLOUD_METADATA_IPS:
                return True

    return False


def validate_safe_url(
    url: str,
    allow_private: bool = False,
    allow_http: bool = True,
) -> str:
    """Validate a URL for SSRF protection.

    This validates URLs to prevent SSRF attacks by blocking requests
    to private networks and cloud metadata endpoints.

    Args:
        url: The URL to validate
        allow_private: If True, allows private IPs and localhost
        allow_http: If True, allows both HTTP and HTTPS

    Returns:
        The validated URL as a string

    Raises:
        ValueError: If URL is invalid or potentially dangerous

    Examples:
        >>> validate_safe_url("https://hooks.slack.com/services/xxx")
        'https://hooks.slack.com/services/xxx'

        >>> validate_safe_url("http://127.0.0.1:8080")
        ValueError: Localhost URLs are not allowed

        >>> validate_safe_url("http://169.254.169.254/latest/meta-data/")
        ValueError: URL resolves to cloud metadata IP
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only HTTP/HTTPS URLs are allowed, got: {parsed.scheme}")

    if not allow_http and parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are allowed")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a valid hostname")

    if is_cloud_metadata(hostname):
        raise ValueError(f"Cloud metadata endpoints are not allowed: {hostname}")

    if is_localhost(hostname) and not allow_private:
        raise ValueError(f"Localhost URLs are not allowed: {hostname}")

    try:
        addr_info = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for result in addr_info:
            ip_str = result[4][0]
            normalized_ip = _normalize_ip(ip_str)

            if is_cloud_metadata(hostname, normalized_ip):
                raise ValueError(f"URL resolves to cloud metadata IP: {normalized_ip}")

            if is_localhost(hostname, normalized_ip) and not allow_private:
                raise ValueError(f"URL resolves to localhost IP: {normalized_ip}")

            if not allow_private and is_private_ip(normalized_ip):
                raise ValueError(f"URL resolves to private IP: {normalized_ip}")

    except socket.gaierror as e:
        raise ValueError(f"Failed to resolve hostname '{hostname}': {e}") from e
    except OSError as e:
        raise ValueError(f"Network error while validating URL: {e}") from e

    return url


def is_safe_url(
    url: str,
    allow_private: bool = False,
    allow_http: bool = True,
) -> bool:
    """Check if a URL is safe (non-throwing version of validate_safe_url).

    Args:
        url: The URL to check
        allow_private: If True, allows private IPs and localhost
        allow_http: If True, allows both HTTP and HTTPS

    Returns:
        True if URL is safe, False otherwise
    """
    try:
        validate_safe_url(url, allow_private=allow_private, allow_http=allow_http)
        return True
    except ValueError:
        return False


def sanitize_target_for_logging(target: str) -> str:
    """Sanitize a target string for safe logging.

    Args:
        target: Target string (hostname, IP, or URL)

    Returns:
        Sanitized string safe for logging
    """
    if not target:
        return "[empty]"

    sanitized = re.sub(r"\d+\.\d+\.\d+\.\d+", "[REDACTED_IP]", target)
    sanitized = re.sub(r":\d+", ":[PORT]", sanitized)

    sensitive_patterns = [
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?\S+', "[API_KEY]"),
        (r'token["\']?\s*[:=]\s*["\']?\S+', "[TOKEN]"),
        (r'password["\']?\s*[:=]\s*["\']?\S+', "[PASSWORD]"),
        (r'secret["\']?\s*[:=]\s*["\']?\S+', "[SECRET]"),
    ]

    for pattern, replacement in sensitive_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    return sanitized
