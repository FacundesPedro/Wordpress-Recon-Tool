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
        for path in CORS_PROBE_PATHS:
            findings_here = 0

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
                findings_here += self._evaluate(path, label, acao, acac, acam)

        if checked == 0:
            self.logger.info("CORS check: no CORS headers observed")
        return self.findings

    async def _probe(self, path: str, method: str, headers: dict):
        try:
            return await self.fetch(path, method, headers=headers)
        except Exception as e:
            self.logger.debug(f"CORS probe failed for {path} ({method}): {e}")
            return None

    def _evaluate(self, path: str, label: str, acao: str, acac: str, acam: str = "") -> int:
        """Evaluate one CORS response; emit finding(s) and return count."""
        credentials = acac == "true"
        full_path = f"{self.target.url}{path} ({label})"

        if acao == "*":
            if credentials:
                self._add_finding(
                    module=self.MODULE,
                    severity="medium",
                    title="Wildcard CORS with credentials",
                    description=(
                        "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true (browsers reject "
                        "this combination, but it indicates a misconfigured policy)."
                    ),
                    evidence=f"{full_path}: ACAO=*, ACAC=true",
                    recommendation="Use an explicit allowlist of trusted origins instead of *",
                    raw={"acao": acao, "acac": acac, "acam": acam, "path": path},
                )
            else:
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title="Wildcard CORS policy",
                    description=(
                        "Access-Control-Allow-Origin: * allows any origin to read "
                        "responses from this endpoint."
                    ),
                    evidence=f"{full_path}: ACAO=*",
                    recommendation=(
                        "Restrict Access-Control-Allow-Origin to trusted origins "
                        "where responses contain sensitive data"
                    ),
                    raw={"acao": acao, "acac": acac, "acam": acam, "path": path},
                )
            return 1

        if acao == CANARY_ORIGIN or acao.lower() == "null":
            severity = "high" if credentials else "medium"
            self._add_finding(
                module=self.MODULE,
                severity=severity,
                title="CORS origin reflection"
                + (" with credentials" if credentials else ""),
                description=(
                    "The server reflected the untrusted Origin header "
                    f"({acao})"
                    + " and allows credentialed requests."
                    if credentials
                    else f"The server reflected the untrusted Origin header ({acao})."
                ),
                evidence=f"{full_path}: ACAO={acao}, ACAC={acac or 'absent'}",
                recommendation=(
                    "Validate the Origin against an explicit allowlist before "
                    "setting Access-Control-Allow-Origin"
                ),
                    raw={"acao": acao, "acac": acac, "acam": acam, "path": path},
            )
            return 1

        return 0
