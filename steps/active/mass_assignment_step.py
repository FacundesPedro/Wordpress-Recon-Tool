# recon_wp/steps/active/mass_assignment_step.py
"""
Mass assignment detection - extra-privilege field injection.

Covers WSTG 4.7.20 (Testing for Mass Assignment): posts a baseline request
and a request carrying extra privilege fields (role, is_admin, admin) to an
operator-supplied endpoint and reports when the server accepts and reflects
the elevated fields.

Requires `WP_ACTIVE_MASS_ASSIGN_ENDPOINT` to be set (app-specific surface).
"""

# WHAT: Detects mass assignment via extra privilege-field injection
# HOW: POST baseline vs extra-fields variant to a configured endpoint; flags
#      acceptance + reflection of elevated fields
# WHY: Unfiltered field binding enables privilege escalation on registration
#      and profile-update endpoints

import json as jsonlib
from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

EXTRA_FIELDS = [
    {"role": "administrator"},
    {"is_admin": "true"},
    {"admin": "true"},
    {"role": "admin", "is_admin": "true"},
]

REFLECTION_MARKERS = ("administrator", "is_admin", '"admin"', "role")
MAX_FINDINGS = 2


class MassAssignmentStep(ActiveHttpStep):
    """Detect mass assignment via extra privilege fields on a configured endpoint."""

    name = "mass_assignment"
    description = "Detect mass assignment via extra privilege fields (endpoint required)"
    severity = "high"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        endpoint = (getattr(self.config, "active_mass_assign_endpoint", "") or "").strip()
        if not endpoint:
            self.logger.info(
                "Mass assignment probe skipped: WP_ACTIVE_MASS_ASSIGN_ENDPOINT not set"
            )
            return self.findings

        self.logger.info(f"Probing mass assignment at {endpoint}...")

        baseline = await self.probe(
            endpoint, method="POST",
            content=jsonlib.dumps({"username": "recon-canary-x9"}),
            headers={"Content-Type": "application/json"},
        )
        if baseline is None:
            self.logger.info("Mass assignment: baseline request failed")
            return self.findings

        for extra in EXTRA_FIELDS:
            if len(self.findings) >= MAX_FINDINGS or not self.budget_left():
                break
            payload = {"username": "recon-canary-x9", **extra}
            response = await self.probe(
                endpoint, method="POST",
                content=jsonlib.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            if response is None:
                continue
            if not (200 <= response.status_code < 300):
                continue
            body = response.text or ""
            reflected = [m for m in REFLECTION_MARKERS if m in body.lower()]
            if not reflected:
                continue
            fields = ", ".join(f"{k}={v}" for k, v in extra.items())
            self.add_finding(
                "high",
                f"Possible mass assignment at {endpoint}",
                (
                    f"Posting extra fields ({fields}) to {endpoint} was "
                    f"accepted (HTTP {response.status_code}) and the response "
                    f"reflects elevated-field markers ({', '.join(reflected)}). "
                    f"Verify whether the privilege fields were actually bound."
                ),
                f"POST {endpoint} {fields} -> {response.status_code}",
                "Use explicit DTOs/allowlists for bindable fields; never bind "
                "client input directly to role/permission attributes",
                raw={"endpoint": endpoint, "fields": extra,
                     "status": response.status_code,
                     "reflected": reflected},
            )

        self.logger.info(
            f"Mass assignment probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
