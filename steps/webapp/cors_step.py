# recon_wp/steps/webapp/cors_step.py
"""
CORS misconfiguration check - tests Cross-Origin Resource Sharing policy.

Covers WSTG 4.11.7 (Testing Cross Origin Resource Sharing): wildcard origins,
origin reflection, and reflection combined with credentials.
"""

# WHAT: Tests CORS policy for wildcard/reflection misconfiguration
# HOW: Sends canary Origin on preflight and simple requests, inspects responses
# WHY: Permissive CORS with credentials enables cross-origin data theft

from base.http_step import BaseHttpStep
from core.finding import Finding

CANARY_ORIGIN = "https://evil.attacker.example"
CORS_PROBE_PATHS = [
    "/",
    "/api",
    "/api/v1",
    "/graphql",
    "/account",
    "/me",
    "/user",
    "/profile",
]


class CorsStep(BaseHttpStep):
    """Check CORS headers for wildcard or origin-reflection misconfiguration."""

    name = "cors"
    description = "Check CORS policy for misconfiguration"
    severity = "high"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking CORS policy...")

        checked = 0
        # observations: (policy_class, acao, acac) -> list of "path (label)"
        observations: dict[tuple[str, str, str], list[str]] = {}
        methods_by_policy: dict[tuple[str, str, str], str] = {}

        for path in CORS_PROBE_PATHS:
            preflight = await self._probe(
                path,
                method="OPTIONS",
                headers={
                    "Origin": CANARY_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                },
            )
            simple = await self._probe(path, method="GET", headers={"Origin": CANARY_ORIGIN})

            for label, response in (("preflight", preflight), ("simple", simple)):
                if response is None:
                    continue
                checked += 1
                acao = (response.headers.get("access-control-allow-origin") or "").strip()
                acac = (
                    response.headers.get("access-control-allow-credentials") or ""
                ).strip().lower()
                acam = (
                    response.headers.get("access-control-allow-methods") or ""
                ).strip()
                if not acao:
                    continue
                policy_class = self._classify(acao, acac)
                if policy_class is None:
                    continue
                key = (policy_class, acao, acac)
                observations.setdefault(key, []).append(
                    f"{self.urljoin(path)} ({label})"
                )
                if acam and key not in methods_by_policy:
                    methods_by_policy[key] = acam

        for (policy_class, acao, acac), locations in observations.items():
            self._emit(policy_class, acao, acac, locations,
                       methods_by_policy.get((policy_class, acao, acac), ""))

        if checked == 0:
            self.logger.info("CORS check: no CORS headers observed")
        elif not self.findings:
            self.logger.info("CORS check: no misconfigured policies observed")
        return self.findings

    async def _probe(self, path: str, method: str, headers: dict):
        try:
            return await self.fetch(path, method, headers=headers)
        except Exception as e:
            self.logger.debug(f"CORS probe failed for {path} ({method}): {e}")
            return None

    @staticmethod
    def _classify(acao: str, acac: str):
        """Classify a CORS observation into a policy class (or None)."""
        credentials = acac == "true"
        if acao == "*":
            return "wildcard-creds" if credentials else "wildcard"
        if acao == CANARY_ORIGIN or acao.lower() == "null":
            return "reflection-creds" if credentials else "reflection"
        return None

    def _emit(self, policy_class: str, acao: str, acac: str,
              locations: list[str], acam: str) -> None:
        """Emit one aggregated finding per unique CORS policy."""
        sample = ", ".join(locations[:5])
        extra = len(locations) - 5
        if extra > 0:
            sample += f" (+{extra} more)"
        acac_label = acac if acac else "absent"

        if policy_class == "wildcard-creds":
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Wildcard CORS with credentials",
                description=(
                    "Access-Control-Allow-Origin: * combined with "
                    "Access-Control-Allow-Credentials: true (browsers reject "
                    "this combination, but it indicates a misconfigured policy)."
                ),
                evidence=f"ACAO=*, ACAC=true at: {sample}",
                recommendation="Use an explicit allowlist of trusted origins instead of *",
                raw={"acao": acao, "acac": acac, "acam": acam,
                     "locations": locations},
            )
        elif policy_class == "wildcard":
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Wildcard CORS policy",
                description=(
                    "Access-Control-Allow-Origin: * allows any origin to read "
                    f"responses from {len(locations)} probed location(s)."
                ),
                evidence=f"ACAO=* at: {sample}",
                recommendation=(
                    "Restrict Access-Control-Allow-Origin to trusted origins "
                    "where responses contain sensitive data"
                ),
                raw={"acao": acao, "acac": acac, "acam": acam,
                     "locations": locations},
            )
        elif policy_class in ("reflection-creds", "reflection"):
            credentials = policy_class == "reflection-creds"
            description = (
                f"The server reflected the untrusted Origin header ({acao}) "
                f"at {len(locations)} probed location(s)."
            )
            if credentials:
                description += (
                    " It also allows credentialed requests, enabling "
                    "cross-origin data theft with victim cookies."
                )
            self._add_finding(
                module=self.MODULE,
                severity="high" if credentials else "medium",
                title="CORS origin reflection"
                + (" with credentials" if credentials else ""),
                description=description,
                evidence=f"ACAO={acao}, ACAC={acac_label} at: {sample}",
                recommendation=(
                    "Validate the Origin against an explicit allowlist before "
                    "setting Access-Control-Allow-Origin"
                ),
                raw={"acao": acao, "acac": acac, "acam": acam,
                     "locations": locations},
            )
