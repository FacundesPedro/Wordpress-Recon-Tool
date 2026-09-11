# recon_wp/steps/webapp/http_methods_step.py
"""
HTTP methods test - checks for dangerous or verbose HTTP methods.

Covers WSTG 4.2.6 (Test HTTP Methods): TRACE exposure, write-capable
methods (PUT/DELETE), and WebDAV (PROPFIND) on the target.

Method detection is calibrated: each risky method is probed against a
nonexistent canary path and compared with a GET on the same path. When
the responses match (e.g. an SPA catch-all serving the same shell for
every method), the method is not actually being processed and no
finding is emitted.
"""

# WHAT: Tests HTTP methods (OPTIONS/TRACE/PUT/DELETE/PROPFIND) with
#       canary calibration to avoid SPA catch-all false positives
# HOW: Issues each method at a canary path, compares with the GET baseline
# WHY: TRACE can enable XST; PUT/DELETE may allow unauthenticated writes

import secrets

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import Soft404Detector

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

        # Calibrate on a nonexistent canary path: GET baseline + soft-404
        # detector. A method whose canary response matches the GET baseline
        # is just the catch-all handler, not a genuinely enabled method.
        canary = f"/recon-methods-{secrets.token_hex(6)}"
        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        try:
            baseline = await self.fetch(canary)
        except Exception as e:
            self.logger.debug(f"Canary GET failed: {e}")
            baseline = None

        for method in RISKY_METHODS:
            try:
                response = await self.fetch(canary, method)
            except Exception as e:
                self.logger.debug(f"{method} request failed: {e}")
                continue

            status = response.status_code
            if status >= 400 or status in (403, 404):
                self.logger.debug(f"{method} blocked/rejected (HTTP {status})")
                continue

            # Suppress catch-all false positives: if the risky method's
            # response is the same shell the server serves for GET on the
            # same nonexistent path, the method is not being processed.
            if detector.is_soft404(response):
                self.logger.debug(
                    f"{method} response matches SPA/soft-404 baseline - skipped"
                )
                continue
            if baseline is not None and self._same_response(response, baseline):
                self.logger.debug(f"{method} response identical to GET baseline")
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
                    f"PUT is processed differently from GET (HTTP {status} on a "
                    "nonexistent path), which may permit unauthenticated "
                    "resource creation or upload."
                )
                recommendation = "Restrict PUT to authenticated, validated endpoints only"
            elif method == "DELETE":
                severity = "medium"
                title = "DELETE method allowed"
                description = (
                    f"DELETE is processed differently from GET (HTTP {status} on "
                    "a nonexistent path), which may permit unauthenticated "
                    "resource removal."
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
                evidence=f"{method} {self.urljoin(canary)} -> HTTP {status} "
                         f"(GET baseline: {baseline.status_code if baseline else 'n/a'})",
                recommendation=recommendation,
                raw={"method": method, "status": status,
                     "baseline_status": baseline.status_code if baseline else None},
            )

        return self.findings

    @staticmethod
    def _same_response(a, b) -> bool:
        """True when two responses are effectively identical."""
        if a.status_code != b.status_code:
            return False
        body_a = (getattr(a, "text", "") or "").strip()
        body_b = (getattr(b, "text", "") or "").strip()
        if not body_a and not body_b:
            return True
        if not body_a or not body_b:
            return False
        shorter = min(len(body_a), len(body_b))
        if shorter == 0:
            return True
        delta = abs(len(body_a) - len(body_b)) / max(len(body_a), len(body_b))
        return delta <= 0.1 and body_a[:100] == body_b[:100]
