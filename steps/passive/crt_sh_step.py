# recon_wp/steps/passive/crt_sh_step.py
"""
Certificate Transparency (crt.sh) enumeration.

Queries crt.sh to discover subdomains from SSL/TLS certificates.
"""

# WHAT: Discovers subdomains via Certificate Transparency logs
# HOW: Queries crt.sh API, parses certificate data for subdomains
# WHY: Reveals subdomains not found via DNS enumeration

import asyncio
import re
from typing import TYPE_CHECKING, Literal, Optional

if TYPE_CHECKING:
    from config import Config
    from core.http_client import HttpClient
    from core.target import Target

from base.step import BaseStep
from core.finding import Finding


class CrtShStep(BaseStep):
    """Discover subdomains via Certificate Transparency logs.

    Queries the crt.sh API to find SSL/TLS certificates associated with
    the target domain, revealing subdomains that may not be found
    through DNS enumeration alone.

    Uses multiple query patterns and retry logic for better coverage.
    """

    name = "crt_sh"
    description = "Certificate transparency enumeration"
    severity = "info"
    MODULE = "passive"

    CRTSH_API = "https://crt.sh/?q={pattern}&output=json&exclude=expired"
    REQUEST_TIMEOUT = 60
    MAX_RETRIES = 2
    RETRY_DELAY = 5

    def __init__(
        self,
        target: Optional["Target"] = None,
        config: Optional["Config"] = None,
        http: Optional["HttpClient"] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            http=http,
            name=self.name,
            description=self.description,
        )
        self._domains: set = set()
        self._errors: list = []

    async def run(self) -> list[Finding]:
        self.logger.debug("Starting Certificate Transparency enumeration...")

        if not self.target or not self.target.domain:
            self.logger.warning("No target domain provided")
            return self.findings

        if not self.http:
            self.logger.warning("HTTP client not available, skipping crt.sh lookup")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Certificate Transparency skipped",
                description="HTTP client not available",
                evidence="Cannot query crt.sh API without HTTP client",
                recommendation="Ensure HTTP client is properly initialized",
            )
            return self.findings

        domain = self.target.domain
        patterns = self._build_query_patterns(domain)

        for pattern in patterns:
            self.logger.debug(f"Querying crt.sh with pattern: {pattern}")
            success = await self._query_with_retry(pattern)
            if self._domains:
                break

        if self._domains:
            self._create_findings(domain)
        elif not self._errors:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="No certificates found",
                description="No SSL/TLS certificates found for this domain in CT logs",
                evidence=f"Domain: {domain}",
                recommendation="The domain may not have recent SSL certificates or CT logs are unavailable",
                raw={"domain": domain, "patterns_tried": patterns},
            )

        return self.findings

    def _build_query_patterns(self, domain: str) -> list[str]:
        """Build multiple query patterns for better coverage."""
        import urllib.parse

        patterns = [
            urllib.parse.quote(f"%.{domain}"),
            urllib.parse.quote(domain),
            urllib.parse.quote(f"%._domainkey.{domain}"),
        ]
        return patterns

    async def _query_with_retry(self, pattern: str) -> bool:
        """Query crt.sh with retry logic."""
        url = self.CRTSH_API.format(pattern=pattern)

        for attempt in range(self.MAX_RETRIES):
            try:
                self.logger.debug(f"Attempt {attempt + 1}/{self.MAX_RETRIES}: {url}")
                response = await self.http.request(
                    "GET", url, timeout=self.REQUEST_TIMEOUT
                )

                if response.status_code == 200:
                    self._parse_response(response.text)
                    if self._domains:
                        return True
                elif response.status_code == 429:
                    self.logger.warning(
                        f"Rate limited by crt.sh (attempt {attempt + 1})"
                    )
                    self._errors.append(f"Rate limited on attempt {attempt + 1}")
                    if attempt < self.MAX_RETRIES - 1:
                        await asyncio.sleep(self.RETRY_DELAY * (attempt + 1))
                else:
                    self.logger.debug(f"crt.sh returned status {response.status_code}")
                    self._errors.append(f"HTTP {response.status_code}")

            except asyncio.TimeoutError:
                self.logger.warning(f"crt.sh request timed out (attempt {attempt + 1})")
                self._errors.append(f"Timeout on attempt {attempt + 1}")
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_DELAY)
            except Exception as e:
                self.logger.error(f"Error querying crt.sh: {e}")
                self._errors.append(str(e))

        return False

    def _parse_response(self, response_text: str) -> None:
        """Parse crt.sh JSON response."""
        import json

        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            self.logger.debug("Response is not JSON, trying HTML parse...")
            self._parse_html(response_text)
            return

        if isinstance(data, list):
            for cert in data:
                self._extract_domains_from_cert(cert)

        self.logger.debug(f"Found {len(self._domains)} unique subdomains so far")

    def _extract_domains_from_cert(self, cert: dict) -> None:
        """Extract domains from a certificate record."""
        name_value = cert.get("name_value", "")
        if name_value:
            subdomains = name_value.split("\n")
            for subdomain in subdomains:
                subdomain = subdomain.strip().lower()
                if subdomain:
                    self._domains.add(subdomain)

        common_name = cert.get("common_name", "")
        if common_name:
            self._domains.add(common_name.lower())

        alternate_names = cert.get("alternate_names", "")
        if alternate_names:
            for name in alternate_names.split("\n"):
                name = name.strip().lower()
                if name:
                    self._domains.add(name)

    def _parse_html(self, html: str) -> None:
        """Parse crt.sh HTML response as fallback."""
        pattern = r'<td class="outer">([^<]+)</td>'
        matches = re.findall(pattern, html)
        for match in matches:
            match = match.strip().lower()
            self._domains.add(match)

    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Check if subdomain is valid and belongs to target domain."""
        if not subdomain or len(subdomain) < 3:
            return False

        if subdomain.startswith("*."):
            return True

        if subdomain.endswith(f".{domain}"):
            return True

        if subdomain == domain:
            return True

        return False

    def _create_findings(self, domain: str) -> None:
        """Create findings from discovered subdomains."""
        if not self._domains:
            return

        sorted_domains = sorted(self._domains)
        total_count = len(sorted_domains)

        valid_domains = [
            d for d in sorted_domains if self._is_valid_subdomain(d, domain)
        ]
        wildcard_count = sum(1 for d in valid_domains if d.startswith("*."))

        evidence_lines = [
            f"Total certificates/subdomains: {total_count}",
            f"Valid subdomains for {domain}: {len(valid_domains)}",
            f"Wildcard certificates: {wildcard_count}",
            "",
        ]

        evidence_lines.append("Sample subdomains (first 25):")
        for sub in valid_domains[:25]:
            evidence_lines.append(f"  - {sub}")

        if len(valid_domains) > 25:
            evidence_lines.append(f"  ... and {len(valid_domains) - 25} more")

        severity: Literal["info", "low", "medium", "high", "critical"] = "info"
        if wildcard_count > 10:
            severity = "low"

        self._add_finding(
            module=self.MODULE,
            severity=severity,
            title="Subdomains Discovered via Certificate Transparency",
            description=f"Found {len(valid_domains)} subdomain(s) through CT logs",
            evidence="\n".join(evidence_lines),
            recommendation="Investigate discovered subdomains for additional attack surface",
            raw={
                "domain": domain,
                "subdomains": valid_domains,
                "total_count": total_count,
                "valid_count": len(valid_domains),
                "wildcard_count": wildcard_count,
            },
        )

        if wildcard_count > 5:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="High Wildcard Certificate Usage",
                description=f"Found {wildcard_count} wildcard certificates, indicating broad subdomain infrastructure",
                evidence=f"Wildcard certs: {wildcard_count}/{len(valid_domains)}",
                recommendation="This is normal for large organizations but confirms infrastructure scope",
                raw={"wildcard_count": wildcard_count},
            )
