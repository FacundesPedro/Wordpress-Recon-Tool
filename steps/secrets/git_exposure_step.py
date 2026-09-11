# recon_wp/steps/secrets/git_exposure_step.py
"""
Git exposure enumeration - checks for .git directory exposure.

Looks for exposed .git repository files.
"""

# WHAT: Checks if .git directory is accessible
# HOW: Tries to fetch .git/config, .git/HEAD, .git/index
# WHY: Git exposure can reveal full source code and commit history

from base.http_step import BaseHttpStep
from core.finding import Finding


class GitExposureStep(BaseHttpStep):
    """Check if .git directory is exposed via web server."""

    name = "git_exposure"
    description = "Check for .git directory exposure"
    severity = "high"
    MODULE = "secrets"

    GIT_FILES = [
        ".git/config",
        ".git/HEAD",
        ".git/index",
        ".git/refs/heads/main",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for .git directory exposure...")

        found_git = []

        for path in self.GIT_FILES:
            try:
                response = await self.fetch(path)
                if response.status_code == 200:
                    found_git.append(path)
                    self.logger.info(f"Found .git file: {path}")
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")

        if found_git:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title=".git directory exposed",
                description=f"Found {len(found_git)} .git file(s) exposed via web server. "
                "This can allow attackers to download the entire repository.",
                evidence=", ".join(found_git),
                recommendation="Block access to .git directory in web server config",
                raw={"git_files": found_git},
            )

        return self.findings
