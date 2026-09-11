# recon_wp/steps/active/ssti_step.py
"""
Server-side template injection detection - arithmetic canaries.

Covers WSTG 4.7.18 (Testing for Server-side Template Injection): injects
template expressions across common template engines and reports when the
arithmetic result appears in the response. Detection-only: no RCE payloads.
"""

# WHAT: Detects SSTI via arithmetic canaries ({{7*7}} -> 49, etc.)
# HOW: Injects engine-specific expressions into discovered params, checks for
#      the computed result appearing where the baseline lacks it
# WHY: Template expression evaluation indicates full SSTI (RCE class)

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

# (payload, expected_result, engine_label)
PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Thymeleaf/EL"),
    ("<%= 7*7 %>", "49", "ERB"),
    ("#{7*7}", "49", "Ruby/Handlebars-style"),
    ("{{7*'7'}}", "49", "Jinja2 (string-mult)"),
    ("{{7*7}}", "49", "generic-braces"),
]

MAX_FINDINGS = 5


class SstiStep(ActiveHttpStep):
    """Detect server-side template injection via arithmetic canaries."""

    name = "ssti"
    description = "Detect SSTI via arithmetic template canaries (detection-only)"
    severity = "critical"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing for SSTI (arithmetic canaries)...")

        params = await self.discover_params()
        if not params:
            self.logger.info("SSTI probe: no query parameters discovered")
            return self.findings

        for path, param in params:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                break
            separator = "&" if "?" in path else "?"
            for payload, expected, engine in PAYLOADS:
                if not self.budget_left():
                    break
                probe_path = f"{path}{separator}{param}={payload}"
                response = await self.probe(probe_path)
                if response is None:
                    continue
                body = response.text or ""
                if expected not in body:
                    continue
                # confirm the raw expression did NOT evaluate on a clean page:
                # fetch baseline with the param unset to reduce false positives
                baseline = await self.probe(path)
                if baseline is not None and expected in (baseline.text or ""):
                    continue
                self.add_finding(
                    "high",
                    f"Possible SSTI via {param} ({engine})",
                    (
                        f"Parameter '{param}' at {path} reflects the arithmetic "
                        f"result of a template expression ({payload} -> {expected}), "
                        f"suggesting server-side template evaluation."
                    ),
                    f"GET {probe_path[:200]} -> '{expected}' in response",
                    "Never evaluate user input as template code; use sandboxed "
                    "rendering or data-only template variables",
                    raw={"path": path, "param": param, "payload": payload,
                         "engine": engine, "result": expected},
                )
                break

        self.logger.info(
            f"SSTI probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
