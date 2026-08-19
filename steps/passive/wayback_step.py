# recon_wp/steps/passive/wayback_step.py
"""
Wayback Machine enumeration.

Queries web.archive.org to discover historical URLs and endpoints.
"""

# WHAT: Discovers archived URLs via Wayback Machine
# HOW: Queries CDX API for historical endpoints
# WHY: Finds forgotten admin panels, backups, debug pages

import asyncio
import re
from typing import TYPE_CHECKING, Literal, Optional

if TYPE_CHECKING:
    from config import Config
    from core.http_client import HttpClient
    from core.target import Target

from base.step import BaseStep
from core.finding import Finding


class WaymachineStep(BaseStep):
    """Discover historical URLs via Wayback Machine.

    Queries the Internet Archive's CDX API to find archived pages
    and endpoints that may reveal hidden attack surface.
    """

    name = "wayback"
    description = "Wayback Machine archive enumeration"
    severity = "info"
    MODULE = "passive"

    WAYBACK_API = "https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&limit=1000&filter=statuscode:200"
    REQUEST_TIMEOUT = 45

    TIMESTAMP_START = "20200101000000"
    TIMESTAMP_END = "20250101000000"

    def __init__(
        self,
        target: Optional["Target"] = None,
        config: Optional["Config"] = None,
        http: Optional["HttpClient"] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self.http = http
        self._urls: set = set()
        self._errors: list = []

    async def run(self) -> list[Finding]:
        self.logger.debug("Starting Wayback Machine enumeration...")

        if not self.target or not self.target.domain:
            self.logger.warning("No target domain provided")
            return self.findings

        if not self.http:
            self.logger.warning("HTTP client not available, skipping Wayback lookup")
            return self.findings

        domain = self.target.domain
        wildcard_domain = f"*.{domain}"

        query_urls = [
            self._build_url(domain),
            self._build_url(wildcard_domain),
        ]

        for url in query_urls:
            self.logger.debug(f"Querying: {url[:80]}...")
            try:
                response = await self.http.request(
                    "GET", url, timeout=self.REQUEST_TIMEOUT
                )
                if response.status_code == 200:
                    self._parse_response(response.text)
            except asyncio.TimeoutError:
                self.logger.debug("Wayback request timed out")
                self._errors.append("Timeout")
            except Exception as e:
                self.logger.debug(f"Wayback query error: {e}")
                self._errors.append(str(e))

        if self._urls:
            self._create_findings(domain)
        elif not self._errors:
            self.logger.debug(f"No Wayback archives found for {domain}")

        return self.findings

    def _build_url(self, domain: str) -> str:
        """Build Wayback CDX API URL."""
        base_url = self.WAYBACK_API.format(domain=domain)
        return f"{base_url}&from={self.TIMESTAMP_START}&to={self.TIMESTAMP_END}"

    def _parse_response(self, response_text: str) -> None:
        """Parse Wayback CDX JSON response."""
        import json

        try:
            data = json.loads(response_text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, list) and len(item) > 0:
                        url = item[0]
                        self._urls.add(url)
                    elif isinstance(item, str):
                        self._urls.add(item)
        except json.JSONDecodeError:
            lines = response_text.strip().split("\n")
            for line in lines:
                if line and not line.startswith("#"):
                    self._urls.add(line.strip())

        self.logger.debug(f"Found {len(self._urls)} URLs so far")

    def _create_findings(self, domain: str) -> None:
        """Create findings from discovered URLs."""
        if not self._urls:
            return

        sorted_urls = sorted(self._urls)
        total_count = len(sorted_urls)

        categories = self._categorize_urls(sorted_urls)

        summary_lines = [f"Total archived URLs: {total_count}", ""]
        for category, count in categories.items():
            summary_lines.append(f"  {category}: {count}")

        summary_lines.append("")
        summary_lines.append("Sample URLs (first 20):")
        for url in sorted_urls[:20]:
            summary_lines.append(f"  - {url}")

        if total_count > 20:
            summary_lines.append(f"  ... and {total_count - 20} more")

        self._add_finding(
            module=self.MODULE,
            severity="info",
            title="Historical URLs Discovered via Wayback Machine",
            description=f"Found {total_count} archived URL(s) for {domain}",
            evidence="\n".join(summary_lines),
            recommendation="Review archived URLs for forgotten endpoints, backups, and debug pages",
            raw={
                "domain": domain,
                "urls": sorted_urls,
                "total_count": total_count,
                "categories": categories,
            },
        )

        sensitive_endpoints = self._check_sensitive_endpoints(sorted_urls)
        if sensitive_endpoints:
            severity: Literal["info", "low", "medium", "high", "critical"] = "low"
            if len(sensitive_endpoints) > 5:
                severity = "medium"

            self._add_finding(
                module=self.MODULE,
                severity=severity,
                title="Potential Sensitive Endpoints Found",
                description=f"Found {len(sensitive_endpoints)} endpoint(s) that may reveal sensitive information",
                evidence="\n".join(f"  - {url}" for url in sensitive_endpoints[:15]),
                recommendation="Review these endpoints - they may contain backup files, debug pages, or old admin panels",
                raw={
                    "sensitive_endpoints": sensitive_endpoints,
                },
            )

    def _categorize_urls(self, urls: list[str]) -> dict[str, int]:
        """Categorize URLs by type."""
        categories = {
            "Admin/Panel": 0,
            "API/JSON": 0,
            "Backup/Archive": 0,
            "Config/Env": 0,
            "Login/Auth": 0,
            "Debug/Info": 0,
            "Upload": 0,
            "Other": 0,
        }

        for url in urls:
            url_lower = url.lower()
            if any(
                p in url_lower for p in ["/admin", "/panel", "/manage", "/dashboard"]
            ):
                categories["Admin/Panel"] += 1
            elif any(p in url_lower for p in [".json", "/api", "/rest", "/graphql"]):
                categories["API/JSON"] += 1
            elif any(
                p in url_lower
                for p in [".zip", ".tar", ".gz", ".bak", ".backup", "/backup"]
            ):
                categories["Backup/Archive"] += 1
            elif any(
                p in url_lower for p in [".env", ".config", ".cfg", ".ini", "config"]
            ):
                categories["Config/Env"] += 1
            elif any(
                p in url_lower
                for p in ["/login", "/signin", "/auth", "/wp-login", "/admin.php"]
            ):
                categories["Login/Auth"] += 1
            elif any(
                p in url_lower
                for p in ["/debug", "/info", "/phpinfo", "/status", "/health"]
            ):
                categories["Debug/Info"] += 1
            elif any(
                p in url_lower for p in ["/upload", "/uploads", "/files", "/images"]
            ):
                categories["Upload"] += 1
            else:
                categories["Other"] += 1

        return {k: v for k, v in categories.items() if v > 0}

    def _check_sensitive_endpoints(self, urls: list[str]) -> list[str]:
        """Check for potentially sensitive endpoints."""
        sensitive = []
        patterns = [
            (r"wp-admin", "WordPress admin"),
            (r"admin\.php", "Admin panel"),
            (r"phpmyadmin", "phpMyAdmin"),
            (r"\.env", "Environment file"),
            (r"config", "Configuration"),
            (r"backup", "Backup file"),
            (r"debug", "Debug endpoint"),
            (r"\.sql", "SQL dump"),
            (r"\.log", "Log file"),
            (r"\.xmlrpc", "XML-RPC"),
            (r"upload", "Upload area"),
            (r"\.git", "Git repository"),
            (r"\.json", "JSON file"),
            (r"api", "API endpoint"),
        ]

        for url in urls:
            url_lower = url.lower()
            for pattern, name in patterns:
                if re.search(pattern, url_lower):
                    sensitive.append(f"{url} ({name})")
                    break

        return sensitive[:50]
