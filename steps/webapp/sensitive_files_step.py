# recon_wp/steps/webapp/sensitive_files_step.py
"""
Sensitive file exposure - generic (non-WP) backup/config file probing.

Covers WSTG 4.2.3 (File Extensions Handling) and 4.2.4 (Old Backup and
Unreferenced Files): probes a wordlist of common backup/config/credential
file paths and reports anything that responds 200 with non-HTML content.
"""

# WHAT: Detects exposed backup/config/credential files on any web app
# HOW: Probes wordlist paths (wordlists/webapp/sensitive_files.txt), flags
#      200 responses that don't look like a soft-404 page
# WHY: Forgotten backups and config files are a frequent direct path to
#      credentials and source code

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import is_html_body

DEFAULT_FILES = [
    ".DS_Store",
    ".svn/entries",
    "backup.zip",
    "backup.sql",
    "database.sql",
    "db.sql",
    "config.php.bak",
    "web.config.bak",
    "appsettings.json.bak",
    "credentials.json",
    "secrets.json",
    ".idea/workspace.xml",
    ".vscode/sftp.json",
    "composer.lock",
    "error.log",
    "id_rsa",
    "swagger.json",
    "openapi.json",
]

MAX_FINDINGS = 10


def looks_like_soft_404(body: str) -> bool:
    """Heuristic: generic 200 pages that are actually 'not found' routes."""
    lowered = (body or "").lower()[:2000]
    markers = (
        "page not found", "404 not found", "not found", "nothing found",
        "<!doctype html><html lang=", "cannot be found", "doesn't exist",
    )
    # a tiny body with no markers is more likely a real file listing/json
    if len(lowered) < 100 and not any(m in lowered for m in markers):
        return False
    return any(m in lowered for m in markers)


def looks_like_html(body: str, content_type: str = "") -> bool:
    """True when the body is an HTML document (SPA fallback shell, etc.).

    Shared implementation lives in utils/soft404.py (is_html_body); this
    alias keeps the step-level helper name for tests and callers.
    """
    return is_html_body(body, content_type)


def is_interesting_content(
    body: str, path: str, content_type: str = ""
) -> bool:
    """True when the body looks like real file content rather than HTML.

    SPA servers (Angular/React/Next) return the index.html shell with HTTP
    200 for every unknown path. A real .sql/.bak/.json file is never an
    HTML document, so an HTML body on a file path is a soft-404 fallback.
    """
    if not body:
        return False
    if path.endswith((".DS_Store", ".zip")):
        # binary formats: check magic regardless of HTML shape
        if path.endswith(".DS_Store"):
            return body[:8] == "\x00\x00\x00\x01Bud1"
        return body[:2] == "PK"
    if looks_like_html(body, content_type):
        return False
    if looks_like_soft_404(body):
        return False
    if path.endswith((".json", ".lock", ".log", ".sql", ".xml", ".yml", ".yaml")):
        return True
    if path.endswith(("id_rsa", ".bak", "~", ".old", ".swp")):
        return True
    return False


class SensitiveFilesStep(BaseHttpStep):
    """Probe common backup/config file paths (generic, non-WP)."""

    name = "sensitive_files"
    description = "Probe for exposed backup/config/credential files"
    severity = "high"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Probing for exposed sensitive files...")

        paths = self._resolve_paths()
        for path in paths:
            if len(self.findings) >= MAX_FINDINGS:
                break
            try:
                response = await self.fetch(path)
            except Exception as e:
                self.logger.debug(f"Probe {path} failed: {e}")
                continue
            if getattr(response, "status_code", None) != 200:
                continue
            body = response.text or ""
            content_type = response.headers.get("content-type") or ""
            if not is_interesting_content(body, path, content_type):
                continue
            url = self.urljoin(path)
            snippet = " ".join(body.split())[:120]
            self._add_finding(
                module=self.MODULE,
                severity="high",
                title=f"Sensitive file exposed at {url}",
                description=(
                    f"The file {path} is publicly accessible and contains "
                    f"non-HTML content that may include credentials, source "
                    f"code, or configuration."
                ),
                evidence=f"GET {url} -> 200 ({len(body)} bytes, "
                         f"{content_type or 'unknown type'}): {snippet}",
                recommendation="Remove the file from the web root and add "
                               "deployment steps to exclude backups/artifacts",
                raw={"path": path, "url": url, "size": len(body),
                     "content_type": content_type},
            )

        self.logger.info(f"Sensitive files: {len(self.findings)} finding(s)")
        return self.findings

    def _resolve_paths(self) -> list[str]:
        """Resolve the sensitive-files wordlist with hardcoded fallback."""
        try:
            from base.dependencies import WordlistDependencyMixin  # noqa
        except Exception:
            pass
        from utils.wordlist_loader import get_wordlist_path, load_lines

        path = get_wordlist_path("webapp/sensitive_files.txt")
        if path and path.exists():
            items = [line.strip() for line in load_lines(path) if line.strip()]
            if items:
                return items
        self.logger.warning(
            "sensitive_files wordlist not found - using built-in fallback"
        )
        return DEFAULT_FILES
