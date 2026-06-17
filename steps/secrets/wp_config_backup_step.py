# recon_wp/steps/secrets/wp_config_backup_step.py
"""
WP-Config backup enumeration - checks for wp-config.php backups.

Looks for exposed wp-config.php backup files.
"""

# WHAT: Checks for wp-config.php backup files
# HOW: Tries common backup extensions (.bak, ~, .old, .save, etc.)
# WHY: wp-config contains database credentials and auth keys

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class WpConfigBackupStep(BaseHttpStep, WordlistDependencyMixin):
    """Check for wp-config.php backup files."""

    name = "wp_config_backup"
    description = "Check for wp-config.php-backups"
    severity = "high"
    MODULE = "secrets"

    DEFAULT_BACKUP_PATTERNS = [
        "wp-config.php.bak",
        "wp-config.php~",
        "wp-config.php.old",
        "wp-config.php.save",
        "wp-config.php.swp",
        ".wp-config.php.v1",
        "wp-config.php.debian",
        "wp-config.php.backup",
        "wp-config backup.php",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for wp-config.php backups...")

        backup_patterns = self.resolve_wordlist_or_fallback(
            config_key="wp_config_backups",
            defaults=self.DEFAULT_BACKUP_PATTERNS,
            name="WP-config backup patterns wordlist",
            wordlist_file="secrets/wp_config_backups.txt",
        )
        if not backup_patterns:
            return self.findings

        found_backups = []

        for pattern in backup_patterns:
            try:
                response = await self.http.get(pattern)
                if response.status_code == 200:
                    content = response.text.lower()
                    if (
                        "dbname" in content
                        or "database" in content
                        or "define(" in content
                    ):
                        found_backups.append(pattern)
                        self.logger.info(f"Found wp-config backup: {pattern}")
            except Exception as e:
                self.logger.debug(f"Error checking {pattern}: {e}")

        if found_backups:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="wp-config.php backup found",
                description=f"Found {len(found_backups)} backup file(s) of wp-config.php",
                evidence=", ".join(found_backups),
                recommendation="Remove wp-config.php backup files immediately",
                raw={"backups": found_backups},
            )

        return self.findings
