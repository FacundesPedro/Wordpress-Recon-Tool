# recon_wp/steps/active/crlf_injection_step.py
"""
CRLF injection / HTTP response splitting detection - header canaries.

Covers WSTG 4.7.15 (Testing for HTTP Splitting): appends CRLF sequences with
a canary header to discovered parameters and reports when the canary header
appears in the response headers (header injection achieved).
"""

# WHAT: Detects CRLF injection via canary response headers
# HOW: Appends %0d%0a + canary header to discovered params; checks response
#      headers for the injected canary
# WHY: Reflected CRLF enables response splitting, header injection, and
#      cache poisoning

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

CANARY_HEADER = "X-Canary-Probe"
CANARY_VALUE = "crlf7q4"

PAYLOADS = [
    f"%0d%0a{CANARY_HEADER}: {CANARY_VALUE}",
    f"%0a{CANARY_HEADER}: {CANARY_VALUE}",
    f"%0d%0aSet-Cookie: canary={CANARY_VALUE}",
]

MAX_FINDINGS = 5


class CrlfInjectionStep(ActiveHttpStep):
    """Detect CRLF injection via canary header reflection in responses."""

    name = "crlf_injection"
    description = "Detect CRLF injection via canary header reflection (detection-only)"
    severity = "medium"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing for CRLF injection (header canaries)...")

        params = await self.discover_params()
        if not params:
            self.logger.info("CRLF probe: no query parameters discovered")
            return self.findings

        for path, param in params:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                break
            for payload in PAYLOADS:
                if not self.budget_left():
                    break
                separator = "&" if "?" in path else "?"
                probe_path = f"{path}{separator}{param}={payload}"
                response = await self.probe(probe_path)
                if response is None:
                    continue
                injected = CANARY_HEADER.lower() in {
                    k.lower() for k in response.headers
                }
                cookie_set = "canary=crlf7q4" in (
                    response.headers.get("set-cookie") or ""
                ).lower()
                if not injected and not cookie_set:
                    continue
                evidence_header = (
                    f"{CANARY_HEADER}: {response.headers.get(CANARY_HEADER, '')}"
                    if injected
                    else f"Set-Cookie: {response.headers.get('set-cookie', '')[:100]}"
                )
                self.add_finding(
                    "medium",
                    f"CRLF injection via {param}",
                    (
                        f"Parameter '{param}' at {path} allows CRLF injection: "
                        f"the response contains an attacker-controlled header. "
                        f"This enables response splitting and cache poisoning."
                    ),
                    f"GET {probe_path[:200]} -> {evidence_header}",
                    "Reject CR/LF characters in user input before reflecting "
                    "into headers; use framework header APIs",
                    raw={"path": path, "param": param, "payload": payload},
                )
                break

        self.logger.info(
            f"CRLF probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
