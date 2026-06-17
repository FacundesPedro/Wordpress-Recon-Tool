# recon_wp/steps/access/users_step.py
"""
Authenticated user enumeration via WP REST API.

Queries /wp-json/wp/v2/users with authentication to retrieve
full user details including email addresses and roles.
"""

# WHAT: Enumerates users with full details via authenticated REST API
# HOW: GET /wp-json/wp/v2/users with Application Password Basic Auth
# WHY: Authenticated access reveals emails and roles hidden from public API

from base.http_step import BaseHttpStep
from core.auth import get_wp_auth_header
from core.finding import Finding


class WpJsonUsersStep(BaseHttpStep):
    """Enumerate users with full details via authenticated WP REST API."""

    name = "wp_json_users"
    description = "Authenticated user enumeration via REST API"
    severity = "info"
    MODULE = "access"

    async def run(self) -> list[Finding]:
        auth = get_wp_auth_header(
            self.config.wp_user, self.config.wp_application_password
        )
        if not auth:
            self.logger.debug("WP auth not configured, skipping authenticated user step")
            return self.findings

        self.logger.info("Fetching user list via /wp-json/wp/v2/users with auth...")
        url = self.urljoin("wp-json/wp/v2/users")

        try:
            response = await self.get(url, headers=auth)
        except Exception as e:
            self.logger.error(f"Error querying users endpoint: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Authenticated user enumeration unavailable",
                description=f"Could not query /wp-json/wp/v2/users: {e}",
                evidence=str(e),
                recommendation="Verify the Application Password is valid",
            )
            return self.findings

        if response.status_code == 200:
            try:
                data = response.json()
            except Exception as e:
                self.logger.debug(f"Failed to parse users response: {e}")
                return self.findings

            if not isinstance(data, list) or len(data) == 0:
                return self.findings

            users = []
            for u in data:
                roles = u.get("roles", [])
                users.append({
                    "id": u.get("id"),
                    "name": u.get("name", ""),
                    "slug": u.get("slug", ""),
                    "email": u.get("email", ""),
                    "roles": roles,
                    "registered": u.get("registered_date", ""),
                })

            has_emails = any(u["email"] for u in users)

            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Authenticated User Enumeration",
                description=(
                    f"Found {len(users)} user(s) via authenticated "
                    f"/wp-json/wp/v2/users"
                ),
                evidence=self._format_user_evidence(users),
                recommendation=(
                    "Review all user accounts, remove unused ones, "
                    "and ensure appropriate role assignments"
                ),
                raw={"users": users, "total": len(users)},
            )

            if has_emails:
                admin_users = [u for u in users if "administrator" in u["roles"]]
                if admin_users:
                    self._add_finding(
                        module=self.MODULE,
                        severity="medium",
                        title="Administrator Email Addresses Exposed",
                        description=(
                            f"Email addresses of {len(admin_users)} "
                            f"administrator(s) exposed via authenticated API"
                        ),
                        evidence="\n".join(
                            f"  - {u['name']} ({u['slug']}): {u['email']}"
                            for u in admin_users
                        ),
                        recommendation=(
                            "Administrator emails should be protected; "
                            "consider restricting REST API access"
                        ),
                        raw={"admin_emails": [
                            {"name": u["name"], "email": u["email"]}
                            for u in admin_users
                        ]},
                    )

        elif response.status_code == 401:
            self.logger.warning("REST API rejected credentials — verify Application Password")
        elif response.status_code == 404:
            self.logger.debug("Users endpoint not found")
        else:
            self.logger.debug(f"Users endpoint returned {response.status_code}")

        return self.findings

    def _format_user_evidence(self, users: list[dict]) -> str:
        lines = []
        for u in sorted(users, key=lambda x: x.get("id", 0)):
            roles = ", ".join(u["roles"]) if u["roles"] else "none"
            line = f"  #{u['id']} {u['name']} ({u['slug']}) — {roles}"
            if u["email"]:
                line += f" — {u['email']}"
            lines.append(line)
        return "\n".join(lines)
