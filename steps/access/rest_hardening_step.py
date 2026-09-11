# WHAT: Audit REST API hardening — CORS, auth bypass, and route leakage
# HOW: Probe wp-json endpoints, check auth headers, CORS, and permissions
# WHY: Unauthenticated API access is a common WordPress misconfiguration

from base.http_step import BaseHttpStep
from core.finding import Finding


class RestHardeningStep(BaseHttpStep):
    name = "rest_hardening"
    description = "Audit REST API for CORS, auth bypass, and route leakage"
    severity = "medium"
    MODULE = "access"

    SUSPICIOUS_ORIGINS = [
        "https://evil.com",
        "null",
    ]

    COMMON_PLUGIN_ENDPOINTS = [
        "wp-json/contact-form-7/v1/contact-forms",
        "wp-json/elementor/v1/",
        "wp-json/woocommerce/v2/",
        "wp-json/yoast/v1/",
        "wp-json/redirection/v1/",
        "wp-json/wordfence/v1/",
        "wp-json/akismet/v1/",
        "wp-json/jetpack/v4/",
        "wp-json/wp/v2/posts",
        "wp-json/wp/v2/pages",
    ]

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping REST hardening"
            )
            return self.findings

        self.logger.info("Auditing REST API hardening...")

        await self._check_cors()
        await self._check_route_leakage()
        await self._check_user_endpoint()
        await self._check_plugin_endpoints()

        return self.findings

    async def _check_cors(self) -> None:
        for origin in self.SUSPICIOUS_ORIGINS:
            try:
                resp = await self.http.get(
                    self.urljoin("wp-json/"),
                    headers={"Origin": origin},
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*":
                    self._add_finding(
                        module=self.MODULE,
                        severity="high",
                        title="REST API CORS allows any origin",
                        description=(
                            "The REST API responds with "
                            "Access-Control-Allow-Origin: *, allowing "
                            "cross-origin requests from any website"
                        ),
                        evidence=(
                            f"Origin: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}"
                        ),
                        recommendation=(
                            "Restrict CORS to trusted origins only. "
                            "Avoid using wildcard (*) with the REST API."
                        ),
                        raw={
                            "origin": origin,
                            "access_control_allow_origin": acao,
                        },
                    )
                    return
            except Exception as e:
                self.logger.debug(f"CORS check failed for {origin}: {e}")

    async def _check_route_leakage(self) -> None:
        try:
            resp = await self.http.get(self.urljoin("wp-json/"))
        except Exception as e:
            self.logger.debug(f"Route discovery failed: {e}")
            return

        if resp.status_code != 200:
            return

        try:
            data = resp.json()
        except Exception:
            return

        routes = data.get("routes", {})
        if not isinstance(routes, dict):
            return

        namespaces: dict[str, list[str]] = {}
        for route_path in routes:
            parts = route_path.lstrip("/").split("/")
            if parts:
                ns = parts[0]
                if ns != "wp":
                    namespaces.setdefault(ns, []).append(route_path)

        if namespaces:
            total = sum(len(v) for v in namespaces.values())
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="REST API route leakage",
                description=(
                    f"Discovered {total} non-core route(s) across "
                    f"{len(namespaces)} namespace(s) via /wp-json/"
                ),
                evidence="\n".join(
                    f"  {ns}: {len(routes)} route(s)" for ns, routes in namespaces.items()
                ),
                recommendation=(
                    "Review exposed plugin REST API routes. "
                    "Some plugins expose endpoints that should require "
                    "authentication."
                ),
                raw={"namespaces": {ns: rts for ns, rts in namespaces.items()}},
            )

    async def _check_user_endpoint(self) -> None:
        try:
            resp = await self.http.get(
                self.urljoin("wp-json/wp/v2/users"),
                follow_redirects=False,
            )
        except Exception as e:
            self.logger.debug(f"User endpoint check failed: {e}")
            return

        if resp.status_code in (200,):
            try:
                data = resp.json()
            except Exception:
                data = []
            user_count = len(data) if isinstance(data, list) else 1

            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="User list publicly accessible via REST API",
                description=(
                    f"GET /wp-json/wp/v2/users returned {resp.status_code} "
                    f"with {user_count} user(s) — no authentication required"
                ),
                evidence=(
                    f"Status: {resp.status_code}\n"
                    f"Users exposed: {user_count}"
                ),
                recommendation=(
                    "WordPress blocks the users endpoint by default. "
                    "A plugin or theme is likely overriding this. "
                    "Add 'if (is_user_logged_in())' checks or use a "
                    "rest_endpoints hook to restrict access."
                ),
                raw={"status": resp.status_code, "user_count": user_count},
            )

    async def _check_plugin_endpoints(self) -> None:
        accessible = []
        for path in self.COMMON_PLUGIN_ENDPOINTS:
            try:
                resp = await self.http.get(
                    self.urljoin(path),
                    follow_redirects=False,
                )
                if resp.status_code == 200:
                    accessible.append(path)
            except Exception:
                continue

        if accessible:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Plugin REST API endpoints accessible without auth",
                description=(
                    f"Found {len(accessible)} plugin REST API endpoint(s) "
                    f"that return 200 without authentication"
                ),
                evidence="\n".join(f"  - {p}" for p in accessible),
                recommendation=(
                    "Review each plugin's REST API permission callbacks. "
                    "Endpoints should verify user capabilities before "
                    "returning data."
                ),
                raw={"accessible_endpoints": accessible},
            )
