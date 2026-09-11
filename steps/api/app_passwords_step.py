# recon_wp/steps/api/app_passwords_step.py
"""
Application passwords enumeration - checks for application passwords API access.

WordPress 5.6+ supports application passwords for REST API authentication.
This step checks if the application passwords endpoint is accessible and
whether it leaks any information.
"""

# WHAT: Checks if the Application Passwords REST API endpoint is accessible
# HOW: Probes /wp-json/application-passwords/1.0/ endpoints
# WHY: Exposed application passwords API may allow brute-force or enumeration

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.http_validation import is_json_body, rest_route_fallbacks


class AppPasswordsStep(BaseHttpStep):
    """Check if Application Passwords API endpoint is accessible."""

    name = "app_passwords"
    description = "Check Application Passwords API endpoint"
    severity = "info"
    MODULE = "api"

    APP_PASSWORDS_ROUTES = [
        "wp-json/application-passwords/1.0/",
        "wp-json/wp/v2/users/application-passwords",
    ]

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping application passwords"
            )
            return self.findings

        self.logger.info("Checking Application Passwords API endpoints...")

        found_routes = []

        for route in self.APP_PASSWORDS_ROUTES:
            result = await self._probe_route(route)
            if result:
                found_routes.append(result)
                self.logger.debug(
                    f"Found Application Passwords endpoint: {route} "
                    f"({'auth required' if result['auth_required'] else 'public'})"
                )

        if found_routes:
            public_routes = [r for r in found_routes if not r["auth_required"]]

            description_parts = []
            if public_routes:
                description_parts.append(
                    f"{len(public_routes)} endpoint(s) publicly accessible"
                )

            auth_routes = [r for r in found_routes if r["auth_required"]]
            if auth_routes:
                description_parts.append(
                    f"{len(auth_routes)} endpoint(s) exist but require authentication"
                )

            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Application Passwords API detected",
                description="; ".join(description_parts),
                evidence=", ".join(
                    [f"{r['route']} ({r['status']})" for r in found_routes]
                ),
                recommendation=(
                    "Ensure Application Passwords API endpoints are properly "
                    "authenticated. If not needed, consider disabling the "
                    "application-passwords feature."
                ),
                raw={
                    "routes_found": found_routes,
                    "has_public_access": len(public_routes) > 0,
                },
            )
            self.logger.info(
                f"Found {len(found_routes)} Application Passwords endpoint(s)"
            )
        else:
            self.logger.info("Application Passwords API not detected")

        return self.findings

    async def _probe_route(self, route: str) -> dict | None:
        """Probe pretty- and plain-permalink forms; only JSON counts.

        200 JSON means the endpoint is public, 401/403 JSON means it
        exists behind auth, anything else (HTML shells) is not a route.
        """
        for path in rest_route_fallbacks(route):
            try:
                response = await self.http.get(self.urljoin(path))
            except Exception as e:
                self.logger.debug(f"Error probing {route}: {e}")
                continue

            status = getattr(response, "status_code", None)
            if not is_json_body(response):
                continue
            if status in (200, 401, 403):
                return {
                    "route": route,
                    "status": status,
                    "auth_required": status in (401, 403),
                }
            if status == 404:
                return None
        return None
