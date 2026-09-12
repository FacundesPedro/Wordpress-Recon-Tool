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
from utils.http_validation import is_php_config


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

        found_backups: list[dict] = []

        for pattern in backup_patterns:
            path = pattern.lstrip("/")
            try:
                response = await self.fetch(path)
                if response.status_code == 200 and is_php_config(response):
                    url = self.urljoin(path)
                    found_backups.append(
                        {
                            "path": path,
                            "url": url,
                            "final_url": str(
                                getattr(response, "url", None) or url
                            ),
                        }
                    )
                    self.logger.info(f"Found wp-config backup: {path}")
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")

        if found_backups:
            urls = [b["url"] for b in found_backups]
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="wp-config.php backup found",
                description=f"Found {len(found_backups)} backup file(s) of wp-config.php",
                evidence=", ".join(urls),
                recommendation="Remove wp-config.php backup files immediately",
                raw={
                    "backups": [b["path"] for b in found_backups],
                    "urls": urls,
                    "final_urls": [b["final_url"] for b in found_backups],
                },
            )

        return self.findings
