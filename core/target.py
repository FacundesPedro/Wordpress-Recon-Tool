# recon_wp/core/target.py
"""Target class - represents the scan target.

SECURITY:
- Validates URL format before accepting
- Auto-prepends https:// if no scheme provided
- Extracts and validates domain
"""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from core.exceptions import ValidationError


@dataclass
class Target:
    """Encapsulate target information with URL validation.

    SECURITY:
    - Validates URL format
    - Ensures scheme is present (auto-adds https://)
    - Extracts domain safely
    """

    url: str
    domain: str = ""
    scope: Optional[list[str]] = None

    def __post_init__(self):
        if self.scope is None:
            self.scope = []

        validated = self._validate_and_normalize(self.url)
        if validated:
            self.url = validated["url"]
            self.domain = validated["domain"]
            if not self.scope:
                self.scope = [self.domain]
        elif self.url:
            raise ValidationError(f"Invalid target URL: {self.url}")

    @staticmethod
    def _split_host_port(netloc: str) -> tuple[str, Optional[int]]:
        if netloc.startswith("["):
            bracket = netloc.find("]")
            if bracket == -1:
                return netloc, None
            host = netloc[: bracket + 1]
            rest = netloc[bracket + 1 :]
            port = int(rest[1:]) if rest.startswith(":") else None
            return host, port
        if ":" in netloc:
            host, port_str = netloc.rsplit(":", 1)
            if port_str.isdigit():
                return host, int(port_str)
            return netloc, None
        return netloc, None

    def _validate_and_normalize(self, url: str) -> dict:
        """Validate and normalize URL.

        Returns:
            dict with 'url' and 'domain' keys, or empty dict on failure
        """
        if not url:
            return {}

        url = url.strip()

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            parsed = urlparse(url)

            if not parsed.scheme or parsed.scheme not in ("http", "https"):
                return {}

            if not parsed.netloc:
                domain = (
                    parsed.path.split("/")[0] if "/" in parsed.path else parsed.path
                )
                parsed = urlparse(f"{parsed.scheme}://{domain}")

            if not parsed.netloc:
                return {}

            host, port = self._split_host_port(parsed.netloc)

            host_ok = bool(
                re.match(
                    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
                    host,
                )
            )
            ipv4_ok = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
            ipv6_ok = bool(
                re.match(r"^\[[a-fA-F0-9:]+\]$", host)
            )

            if not host_ok and not ipv4_ok and not ipv6_ok:
                return {}

            domain = host.strip("[]")
            port_suffix = f":{port}" if port is not None else ""

            return {
                "url": f"{parsed.scheme}://{host}{port_suffix}",
                "domain": domain,
            }

        except Exception:
            return {}

    def __str__(self) -> str:
        return self.url

    def __repr__(self) -> str:
        return f"Target(url='{self.url}', domain='{self.domain}')"
