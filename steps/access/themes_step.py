# recon_wp/steps/access/themes_step.py
"""
Authenticated theme inventory via WP REST API.

Queries /wp-json/wp/v2/themes for an authoritative list of
installed themes (including inactive ones) with exact versions.
"""

# WHAT: Lists all installed themes via authenticated REST API
# HOW: GET /wp-json/wp/v2/themes with Application Password Basic Auth
# WHY: Eliminates fingerprint false-negatives; finds inactive themes

from base.http_step import BaseHttpStep
from core.auth import get_wp_auth_header
from core.finding import Finding


class WpJsonThemesStep(BaseHttpStep):
    """Enumerate installed themes via authenticated WP REST API.

    Requires a WordPress user with switch_themes capability and an
    Application Password (WP >= 5.6).
    """

    name = "wp_json_themes"
    description = "Authenticated theme inventory via REST API"
    severity = "info"
    MODULE = "access"

    async def run(self) -> list[Finding]:
        auth = get_wp_auth_header(
            self.config.wp_user, self.config.wp_application_password
        )
        if not auth:
            self.logger.debug("WP auth not configured, skipping authenticated theme step")
            return self.findings

        self.logger.info("Fetching theme inventory via /wp-json/wp/v2/themes...")
        url = self.urljoin("wp-json/wp/v2/themes")

        try:
            response = await self.get(url, headers=auth)
        except Exception as e:
            self.logger.error(f"Error querying themes endpoint: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Theme inventory unavailable",
                description=f"Could not query /wp-json/wp/v2/themes: {e}",
                evidence=str(e),
                recommendation="Verify the Application Password is valid and the user has switch_themes capability",
            )
            return self.findings

        if response.status_code == 200:
            try:
                data = response.json()
            except Exception as e:
                self.logger.debug(f"Failed to parse theme response: {e}")
                return self.findings

            if not isinstance(data, list) or len(data) == 0:
                return self.findings

            themes = []
            for t in data:
                text_domain = t.get("stylesheet", "") or t.get("textdomain", "")
                name = t.get("name", "") or text_domain
                status = t.get("status", "unknown")
                version = t.get("version", "")
                author = (t.get("author", "") or {}).get("name", "") if isinstance(t.get("author"), dict) else t.get("author", "")
                themes.append({
                    "name": name,
                    "stylesheet": text_domain,
                    "status": status,
                    "version": version,
                    "author": author,
                })

            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="WordPress Theme Inventory (Authenticated)",
                description=(
                    f"Found {len(themes)} installed theme(s) via "
                    f"/wp-json/wp/v2/themes (authenticated)"
                ),
                evidence=self._format_theme_evidence(themes),
                recommendation=(
                    "Review all installed themes, remove unused ones, "
                    "and keep active themes updated"
                ),
                raw={"themes": themes, "total": len(themes)},
            )

            inactive = [t for t in themes if t["status"] != "active"]
            if inactive:
                self._add_finding(
                    module=self.MODULE,
                    severity="medium",
                    title="Inactive Themes Detected",
                    description=(
                        f"Found {len(inactive)} inactive theme(s) that "
                        f"may still be accessible"
                    ),
                    evidence="\n".join(
                        f"  - {t['name']} ({t['version']})"
                        for t in inactive
                    ),
                    recommendation=(
                        "Remove unused themes entirely; inactive themes "
                        "can still be exploited if their files are accessible"
                    ),
                    raw={"inactive_themes": inactive},
                )

        elif response.status_code == 401:
            self.logger.warning("REST API rejected credentials — verify Application Password")
        elif response.status_code == 404:
            self.logger.debug("/wp-json/wp/v2/themes endpoint not found (WP < 5.7?)")
        else:
            self.logger.debug(f"Themes endpoint returned {response.status_code}")

        return self.findings

    def _format_theme_evidence(self, themes: list[dict]) -> str:
        lines = []
        for t in sorted(themes, key=lambda x: x["name"]):
            status_mark = "[active]" if t["status"] == "active" else "[inactive]"
            line = f"  {t['name']} {t['version']} {status_mark}"
            if t["author"]:
                line += f" by {t['author']}"
            lines.append(line)
        return "\n".join(lines)
