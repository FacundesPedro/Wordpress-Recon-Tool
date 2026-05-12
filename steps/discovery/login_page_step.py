# recon_wp/steps/discovery/login_page_step.py
"""
Login page detection - checks for WordPress login endpoints.

Discovers WordPress admin/login URLs.
"""

# WHAT: Checks multiple paths for WordPress login pages
# HOW: HTTP GET to wp-login.php, wp-admin/, login/, wp-admin/login.php
# WHY: Identifies login entry points for further testing

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class LoginPageStep(BaseHttpStep, WordlistDependencyMixin):
    """Detect WordPress login pages."""

    name = "login_page"
    description = "Detect WordPress login pages"
    severity = "info"
    MODULE = "discovery"

    DEFAULT_LOGIN_PATHS = [
        "/wp-login.php",
        "/wp-admin/",
        "/wp-admin/login.php",
        "/login/",
        "/wp-login/",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for WordPress login pages...")

        login_paths = self.resolve_wordlist_or_fallback(
            config_key="login_pages",
            defaults=self.DEFAULT_LOGIN_PATHS,
            name="login pages wordlist",
        )
        if not login_paths:
            return self.findings

        found_logins = []

        for path in login_paths:
            try:
                url = self.urljoin(path.lstrip("/"))
                response = await self.http.get(url)
                if response.status_code in (200, 302, 303):
                    if (
                        "wordpress" in response.text.lower()
                        or "wp-login" in response.text.lower()
                    ):
                        found_logins.append(
                            {
                                "path": path,
                                "status": response.status_code,
                                "url": url,
                            }
                        )
                        self.logger.info(f"Found login page: {path}")
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")

        if found_logins:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="WordPress login page detected",
                description=f"Found {len(found_logins)} WordPress login endpoint(s)",
                evidence=", ".join([f["path"] for f in found_logins]),
                recommendation="Consider restricting access to login pages",
                raw={"login_pages": found_logins},
            )

        return self.findings
