# recon_wp/steps/users/rest_api_users_step.py
"""
REST API users enumeration - queries /wp-json/wp/v2/users.

Retrieves user list from WordPress REST API.
"""

# WHAT: Enumerates users via WordPress REST API
# HOW: GET /wp-json/wp/v2/users
# WHY: REST API can expose usernames without authentication

import json

from base.http_step import BaseHttpStep
from core.finding import Finding


class RestApiUsersStep(BaseHttpStep):
    """Enumerate WordPress users via REST API at /wp-json/wp/v2/users."""

    name = "rest_api_users"
    description = "Enumerate users via REST API"
    severity = "info"
    MODULE = "users"

    async def run(self) -> list[Finding]:
        self.logger.info("Enumerating users via REST API...")

        url = self.urljoin("wp-json/wp/v2/users")

        try:
            response = await self.http.get(url)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 0:
                        users = [
                            {
                                "id": u.get("id"),
                                "name": u.get("name"),
                                "slug": u.get("slug"),
                            }
                            for u in data
                        ]

                        self._add_finding(
                            module=self.MODULE,
                            severity=self.severity,
                            title="Users enumerated via REST API",
                            description=f"Found {len(users)} user(s) via /wp-json/wp/v2/users",
                            evidence=", ".join(
                                [f"{u['name']} ({u['slug']})" for u in users]
                            ),
                            recommendation="Consider restricting REST API user enumeration",
                            raw={"users": users, "url": url},
                        )
                        self.logger.info(f"Found {len(users)} users via REST API")
                    else:
                        self.logger.debug("REST API returned empty user list")

                except json.JSONDecodeError:
                    self.logger.debug("Failed to parse REST API response")
            elif response.status_code == 401:
                self.logger.debug("REST API requires authentication")
            elif response.status_code == 404:
                self.logger.debug("REST API users endpoint not found")
            else:
                self.logger.debug(f"REST API returned status {response.status_code}")

        except Exception as e:
            self.logger.error(f"Error enumerating users via REST API: {e}")

        return self.findings
