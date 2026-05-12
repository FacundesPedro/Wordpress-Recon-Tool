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

            domain = parsed.netloc

            if not re.match(
                r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
                domain,
            ):
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                    return {}

            return {
                "url": f"{parsed.scheme}://{domain}",
                "domain": domain,
            }

        except Exception:
            return {}

    def __str__(self) -> str:
        return self.url

    def __repr__(self) -> str:
        return f"Target(url='{self.url}', domain='{self.domain}')"
