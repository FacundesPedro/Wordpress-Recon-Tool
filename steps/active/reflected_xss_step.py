# recon_wp/steps/active/reflected_xss_step.py
"""
Reflected XSS detection - canary reflection with context analysis.

Covers WSTG 4.7.1 (Testing for Reflected Cross Site Scripting): injects a
unique marker containing HTML-breaking characters into discovered parameters
and reports raw (unescaped) reflection. Detection-only: no exploit payloads,
no script execution.
"""

# WHAT: Detects unescaped reflection of an HTML-breaking canary marker
# HOW: Injects a unique marker into discovered params, inspects reflection
#      context (raw tag injection vs attribute vs encoded)
# WHY: Raw reflection of <> and quotes is the prerequisite for XSS

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

MARKER = "xsscanary7q4"
PAYLOAD = f"'\"><{MARKER}>"

MAX_FINDINGS = 10


def reflection_context(body: str, marker: str) -> str:
    """Classify how the marker is reflected in the response body.

    Returns one of: "raw-tag" (dangerous), "attribute", "encoded", "none".
    """
    if marker not in body:
        return "none"
    if f"<{marker}>" in body:
        return "raw-tag"
    # marker present but escaped/encoded
    if f"&lt;{marker}&gt;" in body or f"\\u003c{marker}" in body:
        return "encoded"
    return "attribute"


class ReflectedXssStep(ActiveHttpStep):
    """Detect unescaped reflection of a canary marker in query parameters."""

    name = "reflected_xss"
    description = "Detect reflected XSS via unescaped canary reflection (detection-only)"
    severity = "high"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing for reflected XSS (canary reflection)...")

        params = await self.discover_params()
        if not params:
            self.logger.info("XSS probe: no query parameters discovered")
            return self.findings

        for path, param in params:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                break
            separator = "&" if "?" in path else "?"
            probe_path = f"{path}{separator}{param}={PAYLOAD}"
            response = await self.probe(probe_path)
            if response is None:
                continue
            context = reflection_context(response.text or "", MARKER)
            if context == "none" or context == "encoded":
                continue

            severity = "high" if context == "raw-tag" else "medium"
            self.add_finding(
                severity,
                f"Unescaped reflection of canary in {param} ({context})",
                (
                    f"Parameter '{param}' at {path} reflects the canary marker "
                    f"unescaped ({context} context). An attacker may be able to "
                    f"inject markup or script depending on the surrounding context."
                ),
                f"GET {probe_path[:200]} -> reflection context: {context}",
                "HTML-encode all reflected user input; apply context-aware "
                "output encoding and a restrictive CSP",
                raw={"path": path, "param": param, "context": context,
                     "marker": MARKER},
            )

        self.logger.info(
            f"XSS probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
