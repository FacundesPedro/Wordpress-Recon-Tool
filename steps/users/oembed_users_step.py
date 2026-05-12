# recon_wp/steps/users/oembed_users_step.py
"""
oEmbed users enumeration - queries /wp-json/oembed/1.0/embed.

Discovers authors via oEmbed API.
"""

# WHAT: Enumerates users who have published content via oEmbed
# HOW: Queries /wp-json/oembed/1.0/embed for various post IDs
# WHY: oEmbed can reveal author names without authentication

import json

from base.http_step import BaseHttpStep
from core.finding import Finding


class OembedUsersStep(BaseHttpStep):
    """
    Enumerate users who have posted content via oEmbed API.
    Only users who have made posts with oEmbed support will be exposed.
    """

    name = "oembed_users"
    description = "Enumerate users via oEmbed API"
    severity = "info"
    MODULE = "users"

    async def run(self) -> list[Finding]:
        self.logger.info("Enumerating users via oEmbed...")

        found_users = []
        from urllib.parse import quote

        for post_id in range(1, 11):
            try:
                target_url_encoded = quote(f"{self.target.url}/?p={post_id}", safe="")
                url = self.urljoin(f"wp-json/oembed/1.0/embed?url={target_url_encoded}")
                response = await self.http.get(url)

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "author_name" in data:
                            author = data.get("author_name")
                            if author and author not in [
                                u["name"] for u in found_users
                            ]:
                                found_users.append(
                                    {
                                        "name": author,
                                        "url": data.get("author_url", ""),
                                        "post_id": post_id,
                                    }
                                )
                                self.logger.debug(f"Found author: {author}")
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                self.logger.debug(f"Error checking oEmbed for post {post_id}: {e}")

        if found_users:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Users enumerated via oEmbed",
                description=f"Found {len(found_users)} user(s) via oEmbed API",
                evidence=", ".join([u["name"] for u in found_users]),
                recommendation="Consider restricting oEmbed if user exposure is a concern",
                raw={"users": found_users},
            )
            self.logger.info(f"Found {len(found_users)} users via oEmbed")

        return self.findings
