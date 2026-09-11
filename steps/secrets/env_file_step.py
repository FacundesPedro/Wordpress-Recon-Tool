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
from utils.soft404 import is_html_body

import re

# A real .env file: KEY=VALUE lines (optionally comments), no HTML markup
_ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=", re.M)


def is_env_content(content: str) -> bool:
    """True when the body looks like a real .env file, not an SPA shell.

    Requires at least one KEY=VALUE line and rejects HTML documents
    (SPA catch-alls return the app shell with 200 for every path, and
    shells contain '=' signs in attributes/JS that defeated the old
    '"=" in content' check).
    """
    if not content:
        return False
    if is_html_body(content):
        return False
    return bool(_ENV_LINE_RE.search(content))


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
                    if is_env_content(content):
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
