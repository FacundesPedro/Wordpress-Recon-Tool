# WHAT: Check WordPress Site Health endpoint for debug info
# HOW: Authenticated GET to wp-admin/site-health-info.php via cookie auth, parse JSON
# WHY: Reveals server config, file permissions, and known site health issues

import json
import re

from base.http_step import BaseHttpStep
from core.auth import AdminSession
from core.finding import Finding


class SiteHealthStep(BaseHttpStep):
    name = "site_health"
    description = "Extract debug info from /wp-admin/site-health-info.php via cookie auth"
    severity = "info"
    MODULE = "access"

    async def run(self) -> list[Finding]:
        self.logger.info("Attempting cookie-based admin session for site health...")

        if not self.config.wp_user or not self.config.wp_application_password:
            self.logger.debug(
                "WP auth not configured, skipping cookie-based site health step"
            )
            return self.findings

        raw_client = getattr(self.http, "_client", None)
        if raw_client is None:
            self.logger.debug("HTTP client not yet initialized")
            return self.findings

        if self.target is None:
            return self.findings
        session = AdminSession(raw_client, self.target.url.rstrip("/"))

        logged_in = await session.login(
            self.config.wp_user, self.config.wp_application_password
        )
        if not logged_in:
            self.logger.warning(
                "Cookie login failed — cannot fetch site health info"
            )
            return self.findings

        self.logger.info("Cookie session established, fetching site health debug info...")

        try:
            resp = await session.get("wp-admin/site-health-info.php?tab=debug")
        except Exception as e:
            self.logger.error(f"Error fetching site health page: {e}")
            return self.findings

        if resp.status_code != 200:
            self.logger.debug(
                f"Site health page returned {resp.status_code}"
            )
            return self.findings

        health_data = self._parse_site_health(resp.text)
        if not health_data:
            self.logger.debug("Could not parse site health data from page")
            return self.findings

        self._add_finding(
            module=self.MODULE,
            severity="info",
            title="WordPress Site Health debug information",
            description="Extracted server configuration via /wp-admin/site-health-info.php",
            evidence=self._format_health_evidence(health_data),
            recommendation=(
                "Restrict access to /wp-admin/site-health-info.php. "
                "This page leaks PHP extensions, server paths, and "
                "active plugin/theme details to authenticated users."
            ),
            raw=health_data,
        )

        return self.findings

    def _parse_site_health(self, html: str) -> dict:
        """Extract the siteHealth JSON payload embedded in the admin page."""
        patterns = [
            r"var siteHealth\s*=\s*(\{.+?\});",
            r"wp\.data\.dispatch\(.*?\)\.setSiteHealthData\(\s*(\{.+?\})\s*\)",
            r'siteHealth\s*=\s*(\{.+?\});',
            r'"siteHealth".*?:\s*(\{.+?\})',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except (json.JSONDecodeError, KeyError):
                    continue

        return {}

    def _format_health_evidence(self, data: dict) -> str:
        lines = []
        if "wp-values" in data:
            wp = data["wp-values"]
            lines.append(f"  WP version: {wp.get('version', 'unknown')}")
            lines.append(f"  Site URL: {wp.get('siteurl', 'unknown')}")
            lines.append(f"  Home URL: {wp.get('home', 'unknown')}")
            lines.append(f"  Active plugins: {len(wp.get('active_plugins', []))}")
            lines.append(f"  Active theme: {wp.get('active_theme', 'unknown')}")

        if "server" in data:
            srv = data["server"]
            lines.append(f"  Server: {srv.get('name', 'unknown')}")
            lines.append(f"  PHP version: {srv.get('php_version', 'unknown')}")
            lines.append(f"  PHP extensions: {len(srv.get('php_extensions', []))}")
            lines.append(f"  Document root: {srv.get('document_root', 'unknown')}")

        return "\n".join(lines)
