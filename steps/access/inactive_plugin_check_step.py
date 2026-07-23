# WHAT: Probe readme.txt for deactivated plugins to assess exposure
# HOW: HTTP GET to known plugin readme paths, check for 200 responses
# WHY: Inactive plugins are often unpatched and can be an easy RCE vector

from base.http_step import BaseHttpStep
from core.auth import get_wp_auth_header
from core.finding import Finding


class InactivePluginCheckStep(BaseHttpStep):
    name = "inactive_plugin_check"
    description = "Check if inactive plugin files are accessible on disk"
    severity = "medium"
    MODULE = "access"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking inactive plugin file accessibility...")

        auth = get_wp_auth_header(
            self.config.wp_user, self.config.wp_application_password
        )
        if not auth:
            self.logger.debug(
                "WP auth not configured, skipping inactive plugin check"
            )
            return self.findings

        inactive = await self._get_inactive_plugins(auth)
        if not inactive:
            self.logger.info("No inactive plugins found")
            return self.findings

        accessible = []
        for slug in inactive:
            if await self._is_readable(slug):
                accessible.append(slug)
                self.logger.debug(f"Inactive plugin files accessible: {slug}")

        if not accessible:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Inactive plugin files not accessible",
                description=(
                    f"Checked {len(inactive)} inactive plugin(s) — "
                    "none have publicly readable files"
                ),
                evidence=f"Inactive plugins checked: {', '.join(inactive)}",
                recommendation=(
                    "Remove unused plugins entirely rather than leaving them "
                    "deactivated"
                ),
                raw={"checked": inactive, "accessible": []},
            )
            return self.findings

        self._add_finding(
            module=self.MODULE,
            severity=self.severity,
            title="Inactive plugin files are publicly accessible",
            description=(
                f"Found {len(accessible)} inactive plugin(s) whose files "
                "are still readable on the web server"
            ),
            evidence="\n".join(
                f"  - {s}: /wp-content/plugins/{s}/readme.txt (HTTP 200)"
                for s in accessible
            ),
            recommendation=(
                "Remove unused plugins entirely. Inactive plugins with "
                "accessible files can still be exploited if they contain "
                "known vulnerabilities."
            ),
            raw={
                "inactive_total": len(inactive),
                "accessible": accessible,
                "protected": [s for s in inactive if s not in accessible],
            },
        )

        return self.findings

    async def _get_inactive_plugins(self, auth: dict) -> list[str]:
        try:
            resp = await self.http.get(
                self.urljoin("wp-json/wp/v2/plugins"), headers=auth
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        inactive = []
        for p in data:
            if p.get("status") != "active":
                slug = p.get("plugin", "")
                if "/" in slug:
                    slug = slug.split("/")[0]
                if slug:
                    inactive.append(slug)
        return inactive

    async def _is_readable(self, slug: str) -> bool:
        path = f"wp-content/plugins/{slug}/readme.txt"
        try:
            resp = await self.http.get(self.urljoin(path))
            return resp.status_code == 200
        except Exception:
            return False
