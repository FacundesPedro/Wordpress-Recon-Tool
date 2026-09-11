# recon_wp/steps/active/http_parameter_pollution_step.py
"""
HTTP parameter pollution detection - duplicate-parameter behavior diff.

Covers WSTG 4.7.4 (Testing for HTTP Parameter Pollution): sends duplicate
parameters and compares the response against the single-parameter baseline.
A significant behavioral difference indicates the backend trusts one
occurrence while validation inspects another (HPP surface).
"""

# WHAT: Detects HPP by comparing duplicate-param responses to baselines
# HOW: For each discovered param: GET baseline, GET duplicate; compare status
#      and body length deltas
# WHY: Duplicate-parameter handling differences enable validation bypass

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

MAX_FINDINGS = 5
LENGTH_DELTA_RATIO = 0.5


class HttpParameterPollutionStep(ActiveHttpStep):
    """Detect HPP by comparing duplicate-parameter responses to baselines."""

    name = "http_parameter_pollution"
    description = "Detect HTTP parameter pollution via duplicate-param diffs"
    severity = "low"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing for HTTP parameter pollution...")

        params = await self.discover_params()
        if not params:
            self.logger.info("HPP probe: no query parameters discovered")
            return self.findings

        for path, param in params:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                break
            separator = "&" if "?" in path else "?"
            baseline = await self.probe(f"{path}{separator}{param}=1")
            if baseline is None:
                continue
            polluted = await self.probe(f"{path}{separator}{param}=1&{param}=2")
            if polluted is None:
                continue

            status_diff = polluted.status_code != baseline.status_code
            base_len = len(baseline.text or "")
            poll_len = len(polluted.text or "")
            length_diff = (
                base_len > 0
                and abs(poll_len - base_len) / base_len > LENGTH_DELTA_RATIO
            )
            if not (status_diff or length_diff):
                continue
            self.add_finding(
                "info",
                f"Duplicate-parameter behavior differs for {param}",
                (
                    f"Sending '{param}' twice produces a different response "
                    f"(status {baseline.status_code} -> {polluted.status_code}, "
                    f"length {base_len} -> {poll_len}). Review whether validation "
                    f"and application logic read the same occurrence."
                ),
                (
                    f"GET {path}?{param}=1 -> {baseline.status_code}/{base_len}B; "
                    f"GET {path}?{param}=1&{param}=2 -> {polluted.status_code}/{poll_len}B"
                ),
                "Join duplicate parameters explicitly and validate the "
                "occurrence the application actually uses",
                raw={"path": path, "param": param,
                     "baseline_status": baseline.status_code,
                     "polluted_status": polluted.status_code,
                     "baseline_len": base_len, "polluted_len": poll_len},
            )

        self.logger.info(
            f"HPP probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
