# recon_wp/steps/secrets/env_file_step.py
"""
Environment file enumeration - checks for .env files.

Looks for exposed environment configuration files.
"""

# WHAT: Checks for .env files
# HOW: Tries common .env paths (.env, .env.local, .env.production, etc.)
# WHY: .env files contain API keys, database credentials, secrets

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class EnvFileStep(BaseHttpStep, WordlistDependencyMixin):
    """Check for .env files which may contain secrets."""

    name = "env_file"
    description = "Check for .env files"
    severity = "high"
    MODULE = "secrets"

    DEFAULT_ENV_PATHS = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.backup",
        ".env.bak",
        "wp-content/.env",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for .env files...")

        env_paths = self.resolve_wordlist_or_fallback(
            config_key="env_files",
            defaults=self.DEFAULT_ENV_PATHS,
            name="environment files wordlist",
            wordlist_file="secrets/env_files.txt",
        )
        if not env_paths:
            return self.findings

        found_envs = []

        for path in env_paths:
            try:
                response = await self.fetch(path)
                if response.status_code == 200:
                    content = response.text
                    if (
                        "=" in content
                        or "APP_" in content
                        or "DB_" in content
                        or "WP_" in content
                    ):
                        found_envs.append(path)
                        self.logger.info(f"Found .env file: {path}")
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")

        if found_envs:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title=".env file found",
                description=f"Found {len(found_envs)} .env file(s) which may contain sensitive data",
                evidence=", ".join(found_envs),
                recommendation="Remove .env files from web root and use server-side only storage",
                raw={"env_files": found_envs},
            )

        return self.findings
