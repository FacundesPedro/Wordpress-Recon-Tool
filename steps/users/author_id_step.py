# recon_wp/steps/users/author_id_step.py
"""
Author ID enumeration - brute forces author IDs via /?author=N.

Discovers valid user IDs by testing author redirects.
"""

# WHAT: Enumerates user IDs via /?author=N redirects
# HOW: Tests author IDs 1-20, checks for redirect away from login
# WHY: Author IDs are needed for targeted attacks and username enumeration

from base.http_step import BaseHttpStep
from core.finding import Finding


class AuthorIdStep(BaseHttpStep):
    """
    Enumerate valid WordPress user IDs by checking /?author=N redirects.
    """

    name = "author_id"
    description = "Enumerate user IDs via author pages"
    severity = "info"
    MODULE = "users"

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping author ID enumeration"
            )
            return self.findings

        self.logger.info("Enumerating author IDs...")

        found_ids = []

        for author_id in range(1, 21):
            try:
                url = self.urljoin(f"?author={author_id}")
                response = await self.http.get(url, follow_redirects=True)

                if response.status_code in (200, 301, 302, 303):
                    content_lower = response.text.lower()
                    if "wp-login" not in content_lower and response.status_code != 400:
                        found_ids.append(author_id)
                        self.logger.debug(f"Found valid author ID: {author_id}")

            except Exception as e:
                self.logger.debug(f"Error checking author ID {author_id}: {e}")

        if found_ids:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Author IDs enumerated",
                description=f"Found {len(found_ids)} valid author ID(s)",
                evidence=", ".join(str(i) for i in found_ids),
                recommendation="Consider using /?author= redirect to hide user IDs",
                raw={"author_ids": found_ids},
            )
            self.logger.info(f"Found author IDs: {found_ids}")

        return self.findings
