# recon_wp/steps/webapp/http_methods_step.py
"""
HTTP methods test - checks for dangerous or verbose HTTP methods.

Covers WSTG 4.2.6 (Test HTTP Methods): TRACE exposure, write-capable
methods (PUT/DELETE), and WebDAV (PROPFIND) on the target.
"""

# WHAT: Tests HTTP methods (OPTIONS/TRACE/PUT/DELETE/PROPFIND)
# HOW: Issues each method at /, evaluates status codes and the Allow header
# WHY: TRACE can enable XST; PUT/DELETE may allow unauthenticated writes

from base.http_step import BaseHttpStep
from core.finding import Finding

RISKY_METHODS = ("TRACE", "PUT", "DELETE", "PROPFIND")


class HttpMethodsStep(BaseHttpStep):
    """Check for dangerous or verbose HTTP methods."""

    name = "http_methods"
    description = "Test HTTP methods (TRACE, PUT, DELETE, PROPFIND)"
    severity = "low"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Testing HTTP methods...")

        path = "/"

        try:
            options_resp = await self.fetch(path, "OPTIONS")
        except Exception as e:
            self.logger.debug(f"OPTIONS request failed: {e}")
            options_resp = None

        if options_resp is not None:
            allow = (options_resp.headers.get("allow") or "").strip()
            if not allow:
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title="Missing Allow header on OPTIONS",
                    description=(
                        "The server did not advertise supported methods via the "
                        "Allow header, limiting method enumeration."
                    ),
                    evidence=f"OPTIONS {self.target.url}{path} (no Allow header)",
                    recommendation="Set an accurate Allow header on OPTIONS responses",
                    raw={"status": options_resp.status_code},
                )

        for method in RISKY_METHODS:
            try:
                response = await self.fetch(path, method)
            except Exception as e:
                self.logger.debug(f"{method} request failed: {e}")
                continue

            status = response.status_code
            if status >= 405 or status in (403, 404):
                self.logger.debug(f"{method} blocked (HTTP {status})")
                continue
            if status >= 400:
                self.logger.debug(f"{method} rejected (HTTP {status})")
                continue

            if method == "TRACE":
                severity = "medium"
                title = "TRACE method enabled"
                description = (
                    "TRACE is enabled (HTTP "
                    f"{status}), which can facilitate cross-site tracing (XST) attacks."
                )
                recommendation = (
                    "Disable the TRACE method at the web server or WAF level"
                )
            elif method == "PUT":
                severity = "medium"
                title = "PUT method allowed"
                description = (
                    f"PUT is allowed on the root path (HTTP {status}), which may "
                    "permit unauthenticated resource creation or upload."
                )
                recommendation = "Restrict PUT to authenticated, validated endpoints only"
            elif method == "DELETE":
                severity = "medium"
                title = "DELETE method allowed"
                description = (
                    f"DELETE is allowed on the root path (HTTP {status}), which may "
                    "permit unauthenticated resource removal."
                )
                recommendation = "Restrict DELETE to authenticated endpoints with validation"
            else:  # PROPFIND
                severity = "low"
                title = "WebDAV PROPFIND method enabled"
                description = (
                    f"PROPFIND is enabled (HTTP {status}), indicating WebDAV "
                    "support which may allow directory introspection."
                )
                recommendation = "Disable WebDAV methods if not required"

            self._add_finding(
                module=self.MODULE,
                severity=severity,
                title=title,
                description=description,
                evidence=f"{method} {self.target.url}{path} -> HTTP {status}",
                recommendation=recommendation,
                raw={"method": method, "status": status},
            )

        return self.findings
