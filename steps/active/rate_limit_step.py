# recon_wp/steps/active/rate_limit_step.py
"""
Rate limiting / lockout detection - rapid failed-login probe.

Covers WSTG 4.4.3 (Testing for Weak Lock Out Mechanism): sends a small burst
of failed login attempts to the login endpoint and reports whether any
rate-limiting or lockout signal (429, lockout message) is observed.
"""

# WHAT: Detects missing rate limiting on login endpoints
# HOW: Sends a capped burst of failed logins; looks for 429/lockout signals
# WHY: Absent rate limiting enables credential stuffing and brute force

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import Soft404Detector

from steps.active.base_active import ActiveHttpStep

LOGIN_PATHS = [
    "/wp-login.php",
    "/login",
    "/signin",
    "/sign-in",
    "/user/login",
    "/account/login",
    "/auth",
]

LOCKOUT_PATTERNS = [
    "too many",
    "locked",
    "try again later",
    "attempts",
    "temporarily blocked",
    "captcha",
    "rate limit",
    "throttl",
]

BURST = 10
MAX_FINDINGS = 3


class RateLimitStep(ActiveHttpStep):
    """Detect missing rate limiting on login endpoints via a capped burst."""

    name = "rate_limit"
    description = "Detect missing rate limiting/lockout on login endpoints"
    severity = "medium"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing login rate limiting (capped burst)...")

        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        for path in LOGIN_PATHS:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                break
            # baseline: does the login endpoint exist and process POSTs?
            baseline = await self.probe(path)
            if baseline is None or baseline.status_code >= 400:
                continue
            if detector.is_soft404(baseline):
                # catch-all shell: this login endpoint does not exist
                self.logger.debug(
                    f"Rate limit probe {path}: SPA/soft-404 shell - skipped"
                )
                continue

            saw_limit = False
            statuses: list[int] = []
            for i in range(BURST):
                if not self.budget_left():
                    break
                response = await self.probe(
                    path,
                    method="POST",
                    data={"username": "recon-canary-x9",
                          "password": f"wrong-pass-{i}",
                          "log": "recon-canary-x9",
                          "pwd": f"wrong-pass-{i}"},
                )
                if response is None:
                    continue
                statuses.append(response.status_code)
                if response.status_code == 429:
                    saw_limit = True
                    break
                body = (response.text or "").lower()
                if any(p in body for p in LOCKOUT_PATTERNS):
                    saw_limit = True
                    break

            if saw_limit:
                self.logger.info(f"Rate limit probe: {path} shows limiting signals")
                continue

            self.add_finding(
                "medium",
                f"No rate limiting observed on {path}",
                (
                    f"{BURST} rapid failed login attempts produced no 429, "
                    f"lockout message, or CAPTCHA challenge. Credential "
                    f"stuffing and brute force are viable."
                ),
                f"POST {self.urljoin(path)} x{BURST} -> statuses: {statuses[:10]}",
                "Rate-limit per identity (not spoofable IP), add exponential "
                "backoff/lockout and monitor failed-login anomalies",
                raw={"path": path, "url": self.urljoin(path),
                     "attempts": len(statuses), "statuses": statuses},
            )

        self.logger.info(
            f"Rate limit probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
