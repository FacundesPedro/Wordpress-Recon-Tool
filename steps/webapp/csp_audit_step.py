# recon_wp/steps/webapp/csp_audit_step.py
"""
Content-Security-Policy audit - evaluates the quality of a present CSP.

Covers WSTG 4.2.12 (Test for Content Security Policy): flags weak directives
(unsafe-inline, unsafe-eval) and missing hardening directives (object-src,
base-uri, form-action, violation reporting).
"""

# WHAT: Audits a present Content-Security-Policy for weak/missing directives
# HOW: Fetches homepage, parses CSP into directives, evaluates known weaknesses
# WHY: A present-but-weak CSP gives a false sense of XSS protection; the
#      infrastructure headers step only reports whether a CSP is present

from base.http_step import BaseHttpStep
from core.finding import Finding


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header into a directive -> sources mapping.

    Args:
        value: Raw Content-Security-Policy header value

    Returns:
        Dict mapping lowercase directive names to lists of source values
    """
    directives: dict[str, list[str]] = {}
    for part in (value or "").split(";"):
        tokens = part.split()
        if not tokens:
            continue
        directives.setdefault(tokens[0].lower(), []).extend(tokens[1:])
    return directives


def _script_sources(directives: dict[str, list[str]]) -> list[str]:
    """Sources governing scripts: explicit script-src or default-src fallback."""
    return directives.get("script-src", directives.get("default-src", []))


def audit_csp(directives: dict[str, list[str]]) -> list[dict]:
    """Evaluate a parsed CSP; return a list of issue dicts (severity/title/.../)."""
    issues: list[dict] = []
    script_sources = _script_sources(directives)
    joined = " ".join(script_sources).lower()

    if "unsafe-inline" in joined:
        issues.append(
            {
                "severity": "medium",
                "title": "CSP allows inline scripts (unsafe-inline)",
                "description": (
                    "The Content-Security-Policy permits inline scripts via "
                    "unsafe-inline, which greatly weakens XSS protection."
                ),
                "recommendation": (
                    "Remove unsafe-inline from script-src and use nonces or "
                    "hashes for the few inline scripts that remain"
                ),
            }
        )
    if "unsafe-eval" in joined:
        issues.append(
            {
                "severity": "medium",
                "title": "CSP allows eval (unsafe-eval)",
                "description": (
                    "The Content-Security-Policy permits dynamic code evaluation "
                    "via unsafe-eval, expanding the impact of any XSS."
                ),
                    "recommendation": (
                        "Remove unsafe-eval from script-src and refactor the "
                        "code that relies on eval"
                    ),
            }
        )
    if "unsafe-hashes" in joined:
        issues.append(
            {
                "severity": "info",
                "title": "CSP uses unsafe-hashes for scripts",
                "description": (
                    "The Content-Security-Policy relies on unsafe-hashes, which "
                    "is deprecated and easier to bypass than nonces."
                ),
                "recommendation": "Prefer nonces over unsafe-hashes for script-src",
            }
        )

    object_src = directives.get("object-src")
    if object_src is None:
        issues.append(
            {
                "severity": "low",
                "title": "CSP missing object-src 'none'",
                "description": (
                    "The Content-Security-Policy does not set object-src 'none', "
                    "leaving plugin content (Flash/Java/Applets) unrestricted."
                ),
                "recommendation": "Add object-src 'none' to the Content-Security-Policy",
            }
        )
    elif "none" not in [s.strip("'\"").lower() for s in object_src]:
        issues.append(
            {
                "severity": "low",
                "title": "CSP object-src is not 'none'",
                "description": (
                    "The Content-Security-Policy sets object-src to something "
                    "other than 'none', allowing plugin content."
                ),
                "recommendation": "Set object-src 'none' unless plugin content is required",
            }
        )

    if "base-uri" not in directives:
        issues.append(
            {
                "severity": "low",
                "title": "CSP missing base-uri directive",
                "description": (
                    "The Content-Security-Policy does not restrict <base> "
                    "elements, which can be abused to redirect relative URLs."
                ),
                "recommendation": "Add base-uri 'self' (or 'none') to the Content-Security-Policy",
            }
        )
    if "form-action" not in directives:
        issues.append(
            {
                "severity": "low",
                "title": "CSP missing form-action directive",
                "description": (
                    "The Content-Security-Policy does not restrict form "
                    "submission targets, allowing forms to post data anywhere."
                ),
                "recommendation": "Add form-action 'self' to the Content-Security-Policy",
            }
        )

    if "script-src" not in directives:
        if "default-src" in directives:
            issues.append(
                {
                    "severity": "info",
                    "title": "CSP script-src falls back to default-src",
                    "description": (
                        "The Content-Security-Policy has no explicit script-src; "
                        "scripts are governed by default-src, which is often too "
                        "broad for script sources."
                    ),
                    "recommendation": "Define an explicit script-src directive for scripts",
                }
            )
        else:
            issues.append(
                {
                    "severity": "low",
                    "title": "CSP defines no script restrictions",
                    "description": (
                        "The Content-Security-Policy sets neither script-src nor "
                        "default-src, so it does not restrict script loading."
                    ),
                    "recommendation": (
                        "Add script-src 'self' (or stricter) to the "
                        "Content-Security-Policy"
                    ),
                }
            )

    if "report-uri" not in directives and "report-to" not in directives:
        issues.append(
            {
                "severity": "info",
                "title": "CSP has no violation reporting",
                "description": (
                    "The Content-Security-Policy has no report-uri or report-to "
                    "directive, so policy violations are not observable."
                ),
                "recommendation": (
                    "Add report-to (or report-uri) to collect CSP violation "
                    "reports for monitoring"
                ),
            }
        )
    if "upgrade-insecure-requests" not in directives:
        issues.append(
            {
                "severity": "info",
                "title": "CSP missing upgrade-insecure-requests",
                "description": (
                    "The Content-Security-Policy does not set "
                    "upgrade-insecure-requests, so legacy http:// resource "
                    "references are not auto-upgraded."
                ),
                "recommendation": "Add upgrade-insecure-requests to the Content-Security-Policy",
            }
        )

    return issues


class CspAuditStep(BaseHttpStep):
    """Check quality of a present Content-Security-Policy."""

    name = "csp_audit"
    description = "Audit Content-Security-Policy for weak or missing directives"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Auditing Content-Security-Policy...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Failed to fetch homepage: {e}")
            return self.findings

        csp = (response.headers.get("content-security-policy") or "").strip()
        if not csp:
            self.logger.info(
                "CSP audit: no Content-Security-Policy header (see headers step)"
            )
            return self.findings

        directives = parse_csp(csp)
        issues = audit_csp(directives)
        evidence = csp[:300]
        for issue in issues:
            self._add_finding(
                module=self.MODULE,
                severity=issue["severity"],
                title=issue["title"],
                description=issue["description"],
                evidence=evidence,
                recommendation=issue["recommendation"],
                raw={"csp": csp, "directives": directives},
            )

        if issues:
            self.logger.info(f"CSP audit: {len(issues)} weakness(es) in policy")
        else:
            self.logger.info("CSP audit: policy looks well hardened")
        return self.findings
