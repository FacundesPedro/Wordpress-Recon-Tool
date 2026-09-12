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

_LOGIN_MARKERS = (
    'id="loginform"',
    "id='loginform'",
    'name="log"',
    "name='log'",
    'name="user_login"',
    "name='user_login'",
    'id="wp-submit"',
    "id='wp-submit'",
    'name="wp-submit"',
    "name='wp-submit'",
    'action="wp-login.php',
    "action='wp-login.php",
    "lostpassword",
)


def is_login_page_content(content: str) -> bool:
    """True when the body contains a WordPress login form.

    A generic "wordpress" substring is not enough: SPA/CMS catch-alls
    and WordPress homepages (generator meta, wp-includes assets) also
    contain it, which made every arbitrary path look like a login page.
    """
    if not content or not isinstance(content, str):
        return False
    lowered = content.lower()
    return any(marker in lowered for marker in _LOGIN_MARKERS)


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
            wordlist_file="discovery/login_pages.txt",
        )
        if not login_paths:
            return self.findings

        found_logins = []

        for path in login_paths:
            try:
                url = self.urljoin(path.lstrip("/"))
                response = await self.http.get(url)
                if response.status_code in (200, 302, 303):
                    if is_login_page_content(response.text):
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
                evidence=", ".join([f["url"] for f in found_logins]),
                recommendation="Consider restricting access to login pages",
                raw={"login_pages": found_logins},
            )

        return self.findings
