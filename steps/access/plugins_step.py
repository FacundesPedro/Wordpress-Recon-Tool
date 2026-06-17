# recon_wp/steps/access/plugins_step.py
"""
Authenticated plugin inventory via WP REST API.

Queries /wp-json/wp/v2/plugins for an authoritative list of
installed plugins (including inactive ones) with exact versions.
"""

# WHAT: Lists all installed plugins via authenticated REST API
# HOW: GET /wp-json/wp/v2/plugins with Application Password Basic Auth
# WHY: Eliminates fingerprint false-negatives; finds inactive/hidden plugins

from base.http_step import BaseHttpStep
from core.auth import get_wp_auth_header
from core.finding import Finding


class WpJsonPluginsStep(BaseHttpStep):
    """Enumerate installed plugins via authenticated WP REST API.

    Requires a WordPress user with install_plugins/activate_plugins
    capability and an Application Password (WP >= 5.6).
    """

    name = "wp_json_plugins"
    description = "Authenticated plugin inventory via REST API"
    severity = "info"
    MODULE = "access"

    async def run(self) -> list[Finding]:
        auth = get_wp_auth_header(
            self.config.wp_user, self.config.wp_application_password
        )
        if not auth:
            self.logger.debug("WP auth not configured, skipping authenticated plugin step")
            return self.findings

        self.logger.info("Fetching plugin inventory via /wp-json/wp/v2/plugins...")
        url = self.urljoin("wp-json/wp/v2/plugins")

        try:
            response = await self.get(url, headers=auth)
        except Exception as e:
            self.logger.error(f"Error querying plugins endpoint: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Plugin inventory unavailable",
                description=f"Could not query /wp-json/wp/v2/plugins: {e}",
                evidence=str(e),
                recommendation="Verify the Application Password is valid and the user has install_plugins capability",
            )
            return self.findings

        if response.status_code == 200:
            try:
                data = response.json()
            except Exception as e:
                self.logger.debug(f"Failed to parse plugin response: {e}")
                return self.findings

            if not isinstance(data, list) or len(data) == 0:
                return self.findings

            plugins = []
            for p in data:
                plugin = p.get("plugin", "")
                name = p.get("name", "") or plugin.split("/")[0] if "/" in plugin else plugin
                status = p.get("status", "unknown")
                version = p.get("version", "")
                description = (p.get("description", "") or "")[:120]
                plugins.append({
                    "name": name,
                    "plugin": plugin,
                    "status": status,
                    "version": version,
                    "description": description,
                })

            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="WordPress Plugin Inventory (Authenticated)",
                description=(
                    f"Found {len(plugins)} installed plugin(s) via "
                    f"/wp-json/wp/v2/plugins (authenticated)"
                ),
                evidence=self._format_plugin_evidence(plugins),
                recommendation=(
                    "Review all installed plugins, remove unused ones, "
                    "and keep active plugins updated to their latest versions"
                ),
                raw={"plugins": plugins, "total": len(plugins)},
            )

            inactive = [p for p in plugins if p["status"] != "active"]
            if inactive:
                self._add_finding(
                    module=self.MODULE,
                    severity="medium",
                    title="Inactive Plugins Detected",
                    description=(
                        f"Found {len(inactive)} inactive plugin(s) that "
                        f"may still be accessible"
                    ),
                    evidence="\n".join(
                        f"  - {p['name']} ({p['version']})"
                        for p in inactive
                    ),
                    recommendation=(
                        "Remove unused plugins entirely; inactive plugins "
                        "can still be exploited if their files are accessible"
                    ),
                    raw={"inactive_plugins": inactive},
                )

        elif response.status_code == 401:
            self.logger.warning("REST API rejected credentials — verify Application Password")
        elif response.status_code == 404:
            self.logger.debug("/wp-json/wp/v2/plugins endpoint not found (WP < 5.5?)")
        else:
            self.logger.debug(
                f"Plugins endpoint returned {response.status_code}"
            )

        return self.findings

    def _format_plugin_evidence(self, plugins: list[dict]) -> str:
        lines = []
        for p in sorted(plugins, key=lambda x: x["name"]):
            status_mark = "[active]" if p["status"] == "active" else "[inactive]"
            line = f"  {p['name']} {p['version']} {status_mark}"
            if p["description"]:
                line += f" — {p['description']}"
            lines.append(line)
        return "\n".join(lines)
