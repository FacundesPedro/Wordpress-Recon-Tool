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
from utils.soft404 import Soft404Detector


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

        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        found_ids: list[int] = []
        found_urls: list[str] = []
        final_urls: list[str] = []

        for author_id in range(1, 21):
            try:
                url = self.urljoin(f"?author={author_id}")
                response = await self.http.get(url, follow_redirects=True)

                if response.status_code in (200, 301, 302, 303):
                    if detector.is_soft404(response):
                        self.logger.debug(
                            f"Author ID {author_id}: catch-all shell - skipped"
                        )
                        continue
                    content_lower = response.text.lower()
                    if "wp-login" not in content_lower:
                        found_ids.append(author_id)
                        found_urls.append(url)
                        final_urls.append(
                            str(getattr(response, "url", None) or url)
                        )
                        self.logger.debug(f"Found valid author ID: {author_id}")

            except Exception as e:
                self.logger.debug(f"Error checking author ID {author_id}: {e}")

        if found_ids:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Author IDs enumerated",
                description=f"Found {len(found_ids)} valid author ID(s)",
                evidence=", ".join(found_urls),
                recommendation="Consider using /?author= redirect to hide user IDs",
                raw={
                    "author_ids": found_ids,
                    "urls": found_urls,
                    "final_urls": final_urls,
                },
            )
            self.logger.info(f"Found author IDs: {found_ids}")

        return self.findings
