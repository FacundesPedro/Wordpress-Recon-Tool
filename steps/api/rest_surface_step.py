# recon_wp/steps/api/rest_surface_step.py
"""
REST API surface discovery - probes common WordPress REST API endpoints.

Discovers accessible REST API namespaces and endpoints that may expose
sensitive information or functionality.
"""

# WHAT: Probes common REST API endpoints to map the API surface
# HOW: Sends HEAD/GET requests to known REST routes
# WHY: Exposed API endpoints can reveal sensitive data and attack vectors

from base.http_step import BaseHttpStep
from core.finding import Finding


class RestSurfaceStep(BaseHttpStep):
    """Discover WordPress REST API endpoints and namespaces."""

    name = "rest_surface"
    description = "Discover REST API endpoints"
    severity = "info"
    MODULE = "api"

    # Common REST API routes to probe
    REST_ROUTES = [
        "wp-json/",
        "wp-json/wp/v2/",
        "wp-json/wp/v2/users",
        "wp-json/wp/v2/posts",
        "wp-json/wp/v2/pages",
        "wp-json/wp/v2/media",
        "wp-json/wp/v2/types",
        "wp-json/wp/v2/statuses",
        "wp-json/wp/v2/taxonomies",
        "wp-json/wp/v2/categories",
        "wp-json/wp/v2/tags",
        "wp-json/wp/v2/comments",
        "wp-json/wp/v2/settings",
        "wp-json/wp/v2/themes",
        "wp-json/wp/v2/plugins",
        "wp-json/wp/v2/block-types",
        "wp-json/wp/v2/block-renderer",
        "wp-json/oembed/1.0/",
        "wp-json/application-passwords/1.0/",
        "rest_route/",
    ]

    # Response codes considered as "found"
    INTERESTING_CODES = {200, 201, 301, 302, 307, 401, 403}

    async def run(self) -> list[Finding]:
        self.logger.info("Probing REST API endpoints...")

        found_endpoints = []

        for route in self.REST_ROUTES:
            try:
                url = self.urljoin(route)
                response = await self.http.head(url)

                if response.status_code in self.INTERESTING_CODES:
                    found_endpoints.append({
                        "route": route,
                        "status": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                    })
                    self.logger.debug(f"Found API endpoint: {route} ({response.status_code})")

            except Exception as e:
                self.logger.debug(f"Error probing {route}: {e}")

        if found_endpoints:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="REST API surface detected",
                description=f"Found {len(found_endpoints)} accessible REST API endpoint(s)",
                evidence=", ".join(
                    [f"{e['route']} ({e['status']})" for e in found_endpoints]
                ),
                recommendation=(
                    "Review exposed REST API endpoints and restrict access "
                    "to only necessary routes. Consider using authentication "
                    "for sensitive endpoints."
                ),
                raw={
                    "endpoints": found_endpoints,
                    "total_found": len(found_endpoints),
                },
            )
            self.logger.info(f"Found {len(found_endpoints)} REST API endpoints")
        else:
            self.logger.info("No REST API endpoints detected")

        return self.findings
