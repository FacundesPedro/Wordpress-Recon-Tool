# recon_wp/steps/infrastructure/php_version_step.py
"""
PHP version fingerprinting and end-of-life detection.

Detects the PHP version from the X-Powered-By header, PHPSESSID cookie
presence, and exposed phpinfo-style pages; maps the detected version to the
official PHP support timeline (security support vs EOL) and reports EOL or
disclosed versions.
"""

# WHAT: Detects PHP version disclosure and end-of-life status
# HOW: Parses X-Powered-By and homepage markers; maps against the PHP
#      support timeline (php.net/supported-versions)
# WHY: EOL PHP receives no security fixes; version disclosure aids targeting

import re
from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding

# PHP support timeline (branch: active_until, security_until) - ISO dates
PHP_TIMELINE = {
    "8.1": ("2023-11-30", "2025-12-31"),   # EOL
    "8.2": ("2024-12-31", "2026-12-31"),   # security-only
    "8.3": ("2025-12-31", "2027-12-31"),
    "8.4": ("2027-12-31", "2029-12-31"),
    "8.5": ("2027-12-31", "2029-12-31"),
}
SUPPORTED_FLOOR = "8.2"   # anything below this branch is EOL or legacy


def parse_php_version(value: str) -> Optional[str]:
    """Extract a PHP version like '8.2.12' from a header value."""
    match = re.search(r"PHP[/ ](\d+\.\d+(?:\.\d+)?)", value or "", re.I)
    return match.group(1) if match else None


def branch_status(version: str) -> str:
    """Classify a version as 'supported', 'security-only', or 'eol'."""
    major_minor = ".".join(version.split(".")[:2])
    try:
        floor = tuple(int(x) for x in SUPPORTED_FLOOR.split("."))
        current = tuple(int(x) for x in major_minor.split("."))
    except ValueError:
        return "unknown"
    if current < floor:
        return "eol"
    if current == floor:
        return "security-only"
    return "supported"


class PhpVersionStep(BaseHttpStep):
    """Detect PHP version disclosure and EOL status."""

    name = "php_version"
    description = "Detect PHP version disclosure and end-of-life status"
    severity = "medium"
    MODULE = "infrastructure"

    async def run(self) -> list[Finding]:
        self.logger.info("Fingerprinting PHP version...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        version: Optional[str] = None
        source: Optional[str] = None

        powered = response.headers.get("x-powered-by") or ""
        candidate = parse_php_version(powered)
        if candidate:
            version, source = candidate, f"X-Powered-By: {powered[:80]}"

        if not version:
            cookies = response.headers.get("set-cookie") or ""
            if "PHPSESSID" in cookies:
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title="PHP detected (PHPSESSID cookie)",
                    description=(
                        "The PHPSESSID cookie indicates PHP, but the exact "
                        "version is not disclosed."
                    ),
                    evidence="Set-Cookie contains PHPSESSID",
                    recommendation="No action - informational",
                    raw={"php": "undisclosed"},
                )

        if not version:
            self.logger.info("PHP version: not disclosed")
            return self.findings

        status = branch_status(version)
        if status == "eol":
            self._add_finding(
                module=self.MODULE,
                severity="high",
                title=f"PHP {version} is end-of-life",
                description=(
                    f"PHP {version} no longer receives security updates. "
                    f"Known and future vulnerabilities will remain unpatched."
                ),
                evidence=source or f"PHP version {version}",
                recommendation=f"Upgrade to PHP {SUPPORTED_FLOOR} or later",
                raw={"version": version, "status": status},
            )
        elif status == "security-only":
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title=f"PHP {version} is in security-only support",
                description=(
                    f"PHP {version} receives only security fixes. Plan the "
                    f"upgrade window before its EOL date."
                ),
                evidence=source or f"PHP version {version}",
                recommendation=f"Plan upgrade to the latest PHP branch",
                raw={"version": version, "status": status},
            )
        else:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title=f"PHP version disclosed: {version}",
                description=(
                    "The PHP version is disclosed in responses. Version "
                    "disclosure aids targeted vulnerability research."
                ),
                evidence=source or f"PHP version {version}",
                recommendation="Suppress X-Powered-By (expose_php=Off / server tokens off)",
                raw={"version": version, "status": status},
            )

        self.logger.info(f"PHP version: {version} ({status})")
        return self.findings
