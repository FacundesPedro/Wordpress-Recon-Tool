# recon_wp/steps/active/auth_bypass_step.py
"""
Authentication/authorization bypass detection - forced browsing and header
bypass probes.

Covers WSTG 4.4.4 (Bypassing Authentication Schema) and 4.5.2 (Bypassing
Authorization Schema): for admin paths that return 401/403, tries common
bypass techniques (path suffixes, case variants, header spoofing) and
reports when access is granted.
"""

# WHAT: Detects auth bypass on protected admin paths
# HOW: Baselines admin paths; if 401/403, probes path-confusion suffixes and
#      trust-forwarding headers (X-Forwarded-For, X-Original-URL)
# WHY: 403 bypasses on admin surfaces are a direct path to compromise

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

ADMIN_PATHS = [
    "/admin",
    "/admin.php",
    "/administrator",
    "/wp-admin/",
    "/panel",
    "/dashboard",
    "/manager",
    "/console",
    "/admin/login",
]

# (suffix appended to baseline path)
PATH_BYPASSES = [
    "/.",
    "/./",
    "/;/",
    "%20",
    "%2e",
    "..;/",
]

HEADER_BYPASSES = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

MAX_FINDINGS = 8


class AuthBypassStep(ActiveHttpStep):
    """Detect auth bypass via path confusion and header spoofing."""

    name = "auth_bypass"
    description = "Detect auth bypass via path confusion and header spoofing"
    severity = "critical"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing for auth bypass on admin paths...")

        protected: list[str] = []
        for path in ADMIN_PATHS:
            if not self.budget_left():
                break
            response = await self.probe(path)
            if response is None:
                continue
            if response.status_code in (401, 403):
                protected.append(path)

        if not protected:
            self.logger.info("Auth bypass: no protected admin paths found")
            return self.findings

        for path in protected:
            if len(self.findings) >= MAX_FINDINGS:
                break
            await self._probe_path_bypasses(path)
            await self._probe_header_bypasses(path)

        self.logger.info(
            f"Auth bypass done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings

    async def _probe_path_bypasses(self, path: str) -> None:
        for suffix in PATH_BYPASSES:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                return
            bypass_path = f"{path}{suffix}"
            response = await self.probe(bypass_path)
            if response is None:
                continue
            if 200 <= response.status_code < 300:
                self.add_finding(
                    "high",
                    f"Auth bypass via path confusion at {path}",
                    (
                        f"{path} returns 401/403 but {bypass_path} returns "
                        f"HTTP {response.status_code}. Path normalization "
                        f"differences allow bypassing authorization."
                    ),
                    f"GET {bypass_path} -> {response.status_code} "
                    f"(baseline {path} -> 401/403)",
                    "Normalize paths before authorization checks; validate "
                    "at the router level, not middleware-only",
                    raw={"path": path, "bypass": bypass_path,
                         "status": response.status_code},
                )

    async def _probe_header_bypasses(self, path: str) -> None:
        for headers in HEADER_BYPASSES:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                return
            response = await self.probe(path, headers=headers)
            if response is None:
                continue
            if 200 <= response.status_code < 300:
                header_name = next(iter(headers))
                self.add_finding(
                    "high",
                    f"Auth bypass via {header_name} header at {path}",
                    (
                        f"{path} returns 401/403 normally but returns "
                        f"HTTP {response.status_code} when {header_name} is "
                        f"spoofed. Trust-forwarding headers influence "
                        f"authorization."
                    ),
                    f"GET {path} with {header_name}: "
                    f"{headers[header_name]} -> {response.status_code}",
                    "Do not derive authorization from spoofable headers; "
                    "strip or validate them at the edge",
                    raw={"path": path, "header": header_name,
                         "value": headers[header_name],
                         "status": response.status_code},
                )
