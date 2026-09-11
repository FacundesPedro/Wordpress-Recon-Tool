# recon_wp/steps/secrets/phpinfo_step.py
"""
PHPInfo enumeration - checks for phpinfo.php files.

Looks for exposed PHP configuration pages.
"""

# WHAT: Checks for phpinfo files
# HOW: Tries phpinfo.php, info.php, test.php, wp-content/phpinfo.php
# WHY: phpinfo exposes server paths, versions, and configuration

from base.http_step import BaseHttpStep
from core.finding import Finding


def is_phpinfo_content(content: str) -> bool:
    """True when the body looks like phpinfo() output, not an SPA shell.

    phpinfo pages contain 'PHP Version' plus phpinfo()-specific markup;
    HTML shells mentioning 'system' in JS bundles no longer match.
    """
    from utils.soft404 import is_html_body

    if not content:
        return False
    lowered = content.lower()
    if is_html_body(content) and "phpinfo()" not in lowered:
        return False
    return "php version" in lowered and "php.ini" in lowered


class PhpinfoStep(BaseHttpStep):
    """Check for phpinfo.php which exposes PHP configuration."""

    name = "phpinfo"
    description = "Check for phpinfo.php exposure"
    severity = "medium"
    MODULE = "secrets"

    PHPINFO_PATHS = [
        "phpinfo.php",
        "info.php",
        "test.php",
        "phpinfo.html",
        "wp-content/phpinfo.php",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for phpinfo files...")

        found_phpinfo = []

        for path in self.PHPINFO_PATHS:
            try:
                response = await self.fetch(path)
                if response.status_code == 200 and \
                        is_phpinfo_content(response.text or ""):
                    found_phpinfo.append(path)
                    self.logger.info(f"Found phpinfo: {path}")
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")

        if found_phpinfo:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="phpinfo file found",
                description=f"Found {len(found_phpinfo)} phpinfo file(s) which expose PHP configuration",
                evidence=", ".join(found_phpinfo),
                recommendation="Remove phpinfo files from web root",
                raw={"phpinfo_files": found_phpinfo},
            )

        return self.findings
