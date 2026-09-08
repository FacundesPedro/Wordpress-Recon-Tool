# recon_wp/steps/webapp/cookie_flags_step.py
"""
Cookie security flags - audits Set-Cookie attributes.

Covers WSTG 4.6.2 (Testing for Cookies Attributes): Secure, HttpOnly,
and SameSite flags on session cookies.
"""

# WHAT: Audits cookie security attributes (Secure/HttpOnly/SameSite)
# HOW: Fetches common entry paths, parses Set-Cookie headers
# WHY: Missing flags enable XSS session theft (no HttpOnly), MITM
#      (no Secure), and CSRF (no SameSite)

from base.http_step import BaseHttpStep
from core.finding import Finding

COOKIE_SCAN_PATHS = ["/", "/login", "/signin", "/wp-login.php"]


def parse_set_cookie(header: str) -> dict:
    """Parse a Set-Cookie header into name/value and boolean attributes.

    Returns a dict with `name`, `secure`, `httponly`, `samesite` (boolean:
    attribute present), and `samesite_value` (lowercased value or "").
    """
    parts = [p.strip() for p in header.split(";")]
    name_value = parts[0] if parts else ""
    if "=" in name_value:
        name, _value = name_value.split("=", 1)
    else:
        name = name_value
    attrs = {p.lower() for p in parts[1:]}
    samesite_value = ""
    for attr in attrs:
        if attr.startswith("samesite="):
            samesite_value = attr.split("=", 1)[1].strip().lower()

    return {
        "name": name.strip(),
        "secure": any(a == "secure" for a in attrs),
        "httponly": any(a == "httponly" for a in attrs),
        "samesite": any(a.startswith("samesite=") for a in attrs),
        "samesite_value": samesite_value,
    }


def collect_set_cookies(response) -> list[str]:
    """Collect all Set-Cookie header values from a response."""
    headers = getattr(response, "headers", None)
    if headers is None:
        return []
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        try:
            return getter("set-cookie")
        except Exception:
            return []
    try:
        value = headers.get("set-cookie")
    except Exception:
        return []
    return [value] if value else []


class CookieFlagsStep(BaseHttpStep):
    """Audit Set-Cookie security attributes on common entry paths."""

    name = "cookie_flags"
    description = "Audit cookie security flags (Secure, HttpOnly, SameSite)"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Auditing cookie security flags...")

        is_https = self.target.url.lower().startswith("https")
        seen: dict[str, dict] = {}

        for path in COOKIE_SCAN_PATHS:
            try:
                response = await self.fetch(path)
            except Exception as e:
                self.logger.debug(f"Cookie scan failed for {path}: {e}")
                continue
            for header in collect_set_cookies(response):
                cookie = parse_set_cookie(header)
                key = f"{path}:{cookie['name']}"
                if cookie["name"] and key not in seen:
                    seen[key] = cookie

        if not seen:
            self.logger.info("No Set-Cookie headers observed")
            return self.findings

        missing_httponly = []
        missing_secure = []
        missing_samesite = []

        for key, cookie in seen.items():
            label = f"{cookie['name']} ({key.split(':')[0]})"
            if not cookie["httponly"]:
                missing_httponly.append(label)
            if is_https and not cookie["secure"]:
                missing_secure.append(label)
            if not cookie["samesite"]:
                missing_samesite.append(label)

        if missing_httponly:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Cookies without HttpOnly flag",
                description=(
                    "Cookie(s) are set without HttpOnly, allowing JavaScript "
                    "access and theft via XSS: " + ", ".join(missing_httponly)
                ),
                evidence=", ".join(missing_httponly),
                recommendation="Set the HttpOnly attribute on all session cookies",
                raw={"cookies": missing_httponly},
            )

        if missing_secure:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Cookies without Secure flag",
                description=(
                    "Cookie(s) are set without Secure on an HTTPS target, "
                    "allowing transmission over unencrypted connections: "
                    + ", ".join(missing_secure)
                ),
                evidence=", ".join(missing_secure),
                recommendation="Set the Secure attribute on all cookies for HTTPS sites",
                raw={"cookies": missing_secure},
            )

        if missing_samesite:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Cookies without SameSite attribute",
                description=(
                    "Cookie(s) are set without SameSite, weakening CSRF "
                    "protections: " + ", ".join(missing_samesite)
                ),
                evidence=", ".join(missing_samesite),
                recommendation="Set SameSite=Lax (or Strict) on session cookies",
                raw={"cookies": missing_samesite},
            )

        samesite_none_insecure = [
            f"{cookie['name']} ({key.split(':')[0]})"
            for key, cookie in seen.items()
            if cookie["samesite_value"] == "none" and not cookie["secure"]
        ]

        if samesite_none_insecure:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Cookies with SameSite=None but no Secure flag",
                description=(
                    "Cookie(s) use SameSite=None without the Secure flag, which "
                    "browsers reject and which indicates a broken CSRF "
                    "mitigation: " + ", ".join(samesite_none_insecure)
                ),
                evidence=", ".join(samesite_none_insecure),
                recommendation=(
                    "Add the Secure attribute to cookies using SameSite=None "
                    "(or switch to SameSite=Lax/Strict)"
                ),
                raw={"cookies": samesite_none_insecure},
            )

        return self.findings
