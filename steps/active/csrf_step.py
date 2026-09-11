# recon_wp/steps/active/csrf_step.py
"""
CSRF protection detection - form token analysis.

Covers WSTG 4.6.5 (Testing for CSRF): parses forms on the homepage and
discovered pages, and flags state-changing (POST) forms that carry
password/email/submission fields but no recognizable CSRF token field.
Detection-only: no token stripping or state-changing submission.
"""

# WHAT: Detects POST forms lacking CSRF token fields
# HOW: Parses <form> elements from fetched pages; checks for token-named
#      hidden fields
# WHY: Missing CSRF tokens allow cross-site state changes

import re
from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
METHOD_RE = re.compile(r'method\s*=\s*["\'](\w+)["\']', re.I)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.I)
INPUT_NAME_RE = re.compile(r"<input[^>]+name\s*=\s*[\"']([^\"']+)[\"']", re.I)

TOKEN_NAMES = {
    "csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken", "csrf_token_hash",
    "authenticity_token", "nonce", "_nonce", "_wpnonce", "xsrf", "xsrf-token",
    "token", "__requestverificationtoken", "_token", "antiforgerytoken",
    "__anti-forgery-token", "anticsrf", "yii_csrf", "authenticity",
}

STATEFUL_HINTS = ("password", "email", "register", "submit", "comment",
                  "message", "contact", "user", "name")

MAX_FINDINGS = 5


def parse_forms(html: str) -> list[dict]:
    """Parse forms into dicts with method, action, and field names."""
    forms = []
    for match in FORM_RE.finditer(html or ""):
        block = match.group(1)
        method_match = METHOD_RE.search(match.group(0))
        action_match = ACTION_RE.search(match.group(0))
        forms.append({
            "method": (method_match.group(1).upper() if method_match else "GET"),
            "action": (action_match.group(1) if action_match else ""),
            "fields": [n.lower() for n in INPUT_NAME_RE.findall(block)],
        })
    return forms


def has_token(fields: list[str]) -> bool:
    """True when any field name looks like a CSRF token."""
    return any(name in TOKEN_NAMES or "csrf" in name or "nonce" in name
               for name in fields)


class CsrfStep(ActiveHttpStep):
    """Detect POST forms lacking CSRF token fields."""

    name = "csrf"
    description = "Detect POST forms without CSRF token fields (detection-only)"
    severity = "medium"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Auditing forms for CSRF tokens...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        forms = parse_forms(response.text or "")
        flagged = 0
        for form in forms:
            if flagged >= MAX_FINDINGS:
                break
            if form["method"] != "POST":
                continue
            if has_token(form["fields"]):
                continue
            if not any(hint in " ".join(form["fields"]) for hint in STATEFUL_HINTS):
                continue
            action = form["action"] or "(self)"
            self.add_finding(
                "medium",
                f"POST form without CSRF token at {action}",
                (
                    f"A state-changing POST form at '{action}' contains no "
                    f"recognizable CSRF token field. Cross-site request "
                    f"forgery may be possible (verify SameSite cookies too)."
                ),
                f"Form action={action} fields={form['fields'][:8]}",
                "Add per-session CSRF tokens to state-changing forms and "
                "verify them server-side",
                raw={"action": action, "fields": form["fields"]},
            )
            flagged += 1

        self.logger.info(
            f"CSRF audit done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
