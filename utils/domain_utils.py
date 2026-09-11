# recon_wp/utils/domain_utils.py
"""Domain scope helpers - classify targets that cannot have public DNS.

WHAT: Identifies domains where DNS/email checks are not applicable
HOW: Checks for IP literals, localhost variants, reserved TLDs, and
     single-label hostnames
WHY: Scanning http://localhost:3000 should not report "No SPF record" -
     DNS-based findings are meaningless for local/reserved targets
"""

import ipaddress
from urllib.parse import urlparse

# RFC 6761/6762/2606 reserved names and common internal suffixes
_RESERVED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".test", ".example",
    ".invalid", ".lan", ".home", ".corp",
)


def extract_hostname(url: str) -> str:
    """Extract the hostname (no port) from a URL."""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_ip_literal(hostname: str) -> bool:
    """True when the hostname is an IPv4/IPv6 address literal."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_non_public_domain(domain: str) -> bool:
    """True when DNS/email checks are not meaningful for this domain.

    Covers: IP literals, localhost and reserved suffixes (.local,
    .internal, .test, ...), and single-label hostnames without dots
    (e.g. "mypc") which cannot have public DNS records.
    """
    domain = (domain or "").lower().rstrip(".")
    if not domain:
        return True
    if is_ip_literal(domain):
        return True
    if domain == "localhost" or domain.endswith(_RESERVED_SUFFIXES):
        return True
    if "." not in domain:
        return True
    return False
