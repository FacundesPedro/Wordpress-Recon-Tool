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
from utils.soft404 import is_html_body

import re

# Content signatures per .git file: a real file matches, an SPA shell
# (served with 200 for every path) does not.
_GIT_SIGNATURES = {
    ".git/config": re.compile(r"\[core\]|\[remote|repositoryformatversion", re.I),
    ".git/HEAD": re.compile(r"^ref: refs/|^[0-9a-f]{40}", re.M | re.I),
    ".git/index": None,  # binary DIRC format checked separately
    ".git/refs/heads/main": re.compile(r"^[0-9a-f]{40}", re.M),
    ".git/refs/heads/master": re.compile(r"^[0-9a-f]{40}", re.M),
}


def is_git_file_content(path: str, content: str) -> bool:
    """True when the body matches the expected .git file signature.

    .git/index is binary and starts with the magic 'DIRC'; everything
    else is text. HTML bodies (SPA shells) never match.
    """
    if not content:
        return False
    if is_html_body(content):
        return False
    if path.endswith("/index"):
        return content[:4] == "DIRC"
    signature = _GIT_SIGNATURES.get(path)
    if signature is None:
        # unknown .git path: require non-HTML, non-trivial content
        return len(content) > 10
    return bool(signature.search(content))


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
                if response.status_code == 200 and \
                        is_git_file_content(path, response.text or ""):
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
