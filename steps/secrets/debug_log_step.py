# recon_wp/steps/secrets/debug_log_step.py
"""
Debug log enumeration - checks for wp-content/debug.log.

Looks for exposed WordPress debug logs.
"""

# WHAT: Checks for debug.log files
# HOW: Tries wp-content/debug.log, wp-content/debug.txt
# WHY: Debug logs can expose paths, errors, and sensitive info

from base.http_step import BaseHttpStep
from core.finding import Finding


def is_debug_log_content(content: str) -> bool:
    """True when the body looks like a PHP debug log, not an SPA shell.

    Real WP debug logs carry PHP log lines ([date] PHP Notice: ... in
    /path on line N). HTML bodies (SPA catch-alls) never match.
    """
    from utils.soft404 import is_html_body
    import re as _re

    if not content:
        return False
    if is_html_body(content):
        return False
    log_line = _re.compile(
        r"\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4}.*\]\s+PHP\s+"
        r"(Notice|Warning|Error|Fatal|Deprecated)"
    )
    return bool(log_line.search(content))


class DebugLogStep(BaseHttpStep):
    """Check for wp-content/debug.log which may expose sensitive info."""

    name = "debug_log"
    description = "Check for debug.log exposure"
    severity = "medium"
    MODULE = "secrets"

    DEBUG_PATHS = [
        "wp-content/debug.log",
        "wp-content/debug.txt",
        "wp-content/uploads/debug.log",
    ]

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for debug log files...")

        found_logs = []

        for path in self.DEBUG_PATHS:
            try:
                response = await self.fetch(path)
                if response.status_code == 200 and \
                        is_debug_log_content(response.text or ""):
                    found_logs.append(path)
                    self.logger.info(f"Found debug log: {path}")
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")

        if found_logs:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Debug log found",
                description=f"Found {len(found_logs)} debug log file(s) which may expose sensitive information",
                evidence=", ".join(found_logs),
                recommendation="Disable debug mode or move debug log to secure location",
                raw={"debug_logs": found_logs},
            )

        return self.findings
