# recon_wp/steps/passive/subdomain_takeover_step.py
"""
Subdomain takeover detection - dangling DNS records + service fingerprints.

Covers WSTG 4.2.10 (Test for Subdomain Takeover): collects candidate
subdomains from crt.sh, resolves CNAMEs via the system `dig` binary, and
matches HTTP responses against the can-i-take-over-xyz fingerprint database
(`wordlists/takeover/fingerprints.json`). Detection-only: never claims
resources.
"""

# WHAT: Detects dangling DNS records pointing to unclaimed third-party services
# HOW: crt.sh subdomain candidates -> dig CNAME -> fingerprint DB match on
#      HTTP response body; NXDOMAIN targets are the strongest signal
# WHY: Takeover allows serving content on a victim subdomain (cookie scope,
#      CSP, OAuth redirect allowlists)

import asyncio
import json
import re
from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.wordlist_loader import get_wordlist_path

DEFAULT_FINGERPRINTS: list[dict] = [
    {"service": "GitHub Pages", "cname": r"\.github\.io$", "fingerprint": "There isn't a GitHub Pages site here.", "status": "vulnerable"},
    {"service": "Heroku", "cname": r"\.herokuapp\.com$", "fingerprint": "No such app", "status": "vulnerable"},
    {"service": "AWS S3", "cname": r"\.s3\.amazonaws\.com$|\.s3-website[-.]", "fingerprint": "NoSuchBucket", "status": "vulnerable"},
    {"service": "Azure App Service", "cname": r"\.azurewebsites\.net$", "fingerprint": "404 Web Site not found.", "status": "vulnerable"},
    {"service": "Netlify", "cname": r"\.netlify\.app$|\.netlify\.com$", "fingerprint": "Not Found - Request ID", "status": "vulnerable"},
    {"service": "Shopify", "cname": r"\.myshopify\.com$", "fingerprint": "Sorry, this shop is currently unavailable.", "status": "vulnerable"},
    {"service": "Pantheon", "cname": r"\.pantheonsite\.io$", "fingerprint": "The gods are wise, but do not know of the site which you seek.", "status": "vulnerable"},
    {"service": "Fastly", "cname": r"\.fastly\.net$", "fingerprint": "Fastly error: unknown domain", "status": "vulnerable"},
]

_CRT_MAX_ENTRIES = 200


def parse_dig_cname(output: str) -> Optional[str]:
    """Extract the CNAME target from dig output; None if absent.

    Handles both `dig +short` (bare target line) and full dig rows.
    """
    for line in (output or "").splitlines():
        line = line.strip()
        if line.upper().startswith("CNAME") and " " in line:
            target = line.split(None, 1)[1].rstrip(".").strip()
            if target:
                return target
    parts = (output or "").split()
    for i, part in enumerate(parts):
        if part.upper() == "CNAME" and i + 1 < len(parts):
            target = parts[i + 1].rstrip(".").strip()
            if target:
                return target
    # dig +short fallback: a single bare hostname line (IPs are A records)
    lines = [l.strip().rstrip(".") for l in (output or "").splitlines() if l.strip()]
    if len(lines) == 1 and " " not in lines[0] and "." in lines[0]:
        candidate = lines[0]
        if not re.fullmatch(r"[\d.]+|[\da-fA-F:]+", candidate):
            return candidate
    return None


def match_fingerprint(
    cname: Optional[str], body: str, fingerprints: list[dict]
) -> Optional[dict]:
    """Match a CNAME + response body against fingerprint entries."""
    for entry in fingerprints:
        if entry.get("status") == "not-vulnerable":
            continue
        cname_pattern = entry.get("cname", "")
        fingerprint = entry.get("fingerprint", "")
        if fingerprint == "NXDOMAIN":
            continue  # handled separately (needs no body)
        cname_match = False
        if cname and cname_pattern:
            try:
                cname_match = re.search(cname_pattern, cname, re.I) is not None
            except re.error:
                cname_match = False
        body_match = bool(fingerprint) and fingerprint.lower() in (body or "").lower()
        if cname_match and body_match:
            return entry
    return None


def match_nxdomain(cname: str, fingerprints: list[dict]) -> Optional[dict]:
    """Match a CNAME target against NXDOMAIN-style fingerprint entries."""
    for entry in fingerprints:
        if entry.get("status") == "not-vulnerable":
            continue
        pattern = entry.get("cname", "")
        if not pattern or entry.get("fingerprint") != "NXDOMAIN":
            continue
        try:
            if re.search(pattern, cname, re.I):
                return entry
        except re.error:
            continue
    return None


class SubdomainTakeoverStep(BaseHttpStep):
    """Detect subdomain takeover via dangling DNS + fingerprint matching."""

    name = "subdomain_takeover"
    description = "Detect subdomain takeover via dangling DNS records and fingerprints"
    severity = "critical"
    MODULE = "passive"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking subdomain takeover (passive DNS + fingerprints)...")

        fingerprints = self._load_fingerprints()
        subdomains = await self._collect_subdomains()
        if not subdomains:
            self.logger.info("Takeover check: no candidate subdomains found")
            return self.findings

        max_subs = int(getattr(self.config, "takeover_max_subdomains", 25))
        checked = 0
        for sub in subdomains[:max_subs]:
            cname = await self._dig_cname(sub)
            body = await self._fetch_body(sub)
            checked += 1

            if body is None and cname:
                entry = match_nxdomain(cname, fingerprints)
                if entry:
                    self._report(sub, cname, entry, "NXDOMAIN target")
                continue
            if body is None:
                continue
            entry = match_fingerprint(cname, body, fingerprints)
            if entry:
                self._report(sub, cname, entry, "fingerprint match")

        self.logger.info(
            f"Takeover check: {checked} subdomain(s) checked, "
            f"{len(self.findings)} finding(s)"
        )
        return self.findings

    # -- helpers ----------------------------------------------------------

    def _load_fingerprints(self) -> list[dict]:
        path = get_wordlist_path("takeover/fingerprints.json")
        if path and path.exists():
            try:
                data = json.loads(path.read_text())
                if isinstance(data, list) and data:
                    return data
            except Exception as e:
                self.logger.warning(f"Failed to load takeover fingerprints: {e}")
        self.logger.warning(
            "Takeover fingerprints not found - using limited built-in set"
        )
        return DEFAULT_FINGERPRINTS

    async def _collect_subdomains(self) -> list[str]:
        """Collect candidate subdomains from crt.sh for the target domain."""
        domain = self.target.domain
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            response = await self.http.request("GET", url, track_breaker=False)
        except Exception as e:
            self.logger.debug(f"crt.sh query failed: {e}")
            return []
        if getattr(response, "status_code", None) != 200:
            return []
        try:
            entries = json.loads(response.text or "[]")
        except Exception:
            return []

        names: set[str] = set()
        for entry in entries[:_CRT_MAX_ENTRIES]:
            raw = str(entry.get("name_value", ""))
            for line in raw.split("\n"):
                name = line.strip().lstrip("*.").lower()
                if name.endswith("." + domain) and name != domain:
                    names.add(name)
        return sorted(names)

    async def _dig_cname(self, subdomain: str) -> Optional[str]:
        """Query CNAME via dig; return target or None."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            return parse_dig_cname(stdout.decode(errors="replace"))
        except Exception as e:
            self.logger.debug(f"dig CNAME {subdomain} failed: {e}")
            return None

    async def _fetch_body(self, subdomain: str) -> Optional[str]:
        """Fetch the subdomain over HTTP(S); None when unreachable/NXDOMAIN.

        Uses track_breaker=False: subdomain failures (NXDOMAIN, refused)
        are expected and say nothing about the primary target.
        """
        for scheme in ("https", "http"):
            try:
                response = await self.http.request(
                    "GET", f"{scheme}://{subdomain}/",
                    follow_redirects=True,
                    track_breaker=False,
                )
                status = getattr(response, "status_code", None)
                if status is None:
                    continue
                if 200 <= status < 400 or status in (404, 410):
                    return response.text or ""
            except Exception:
                continue
        return None

    def _report(self, subdomain: str, cname: Optional[str],
                entry: dict, signal: str) -> None:
        service = entry.get("service", "unknown")
        status = entry.get("status", "vulnerable")
        severity = "critical" if status == "vulnerable" else "medium"
        self._add_finding(
            module=self.MODULE,
            severity=severity,
            title=f"Possible subdomain takeover at {subdomain} ({service})",
            description=(
                f"{subdomain} has a CNAME to {cname} ({service}) and the "
                f"response matches the unclaimed-resource fingerprint "
                f"({signal}). The service resource may be claimable by an "
                f"attacker. Detection only - do not claim the resource."
            ),
            evidence=(
                f"{subdomain} CNAME {cname}; body fingerprint: "
                f"'{entry.get('fingerprint', '')[:80]}'"
            ),
            recommendation=(
                "Remove the dangling DNS record or re-claim the resource on "
                f"{service}"
            ),
            raw={"subdomain": subdomain, "cname": cname,
                 "service": service, "status": status, "signal": signal},
        )
