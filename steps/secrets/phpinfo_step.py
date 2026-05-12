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
                response = await self.http.get(path)
                if response.status_code == 200:
                    content = response.text.lower()
                    if (
                        "php version" in content
                        or "system" in content
                        or "php.ini" in content
                    ):
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
