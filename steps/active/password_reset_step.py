# recon_wp/steps/active/password_reset_step.py
"""
Password reset flow checks - enumeration surface and Host-header injection.

Covers WSTG 4.4.9 (Testing for Weak Password Change or Reset Functionalities):
detects reset endpoints, probes for missing rate limiting, and tests whether
a canary Host header is reflected in the reset page (reset-link poisoning
surface). Token entropy/reuse cannot be verified without mailbox access.
"""

# WHAT: Checks password reset endpoints for enumeration/poisoning surface
# HOW: Discovers reset paths; probes rate limiting; sends canary Host header
#      and checks reflection
# WHY: Reset flows are a primary account-takeover vector

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import Soft404Detector

from steps.active.base_active import ActiveHttpStep

RESET_PATHS = [
    "/wp-login.php?action=lostpassword",
    "/lostpassword",
    "/forgot-password",
    "/forgot",
    "/password/reset",
    "/reset",
    "/reset-password",
]

CANARY_HOST = "reset-canary-7q4.example"
MAX_FINDINGS = 3


class PasswordResetStep(ActiveHttpStep):
    """Check reset endpoints for rate limiting and Host reflection."""

    name = "password_reset"
    description = "Check password reset endpoints (rate limit, Host reflection)"
    severity = "medium"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing password reset endpoints...")

        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        for path in RESET_PATHS:
            if len(self.findings) >= MAX_FINDINGS or not self.budget_left():
                break
            baseline = await self.probe(path)
            if baseline is None or baseline.status_code >= 400:
                continue
            if detector.is_soft404(baseline):
                self.logger.debug(
                    f"Password reset probe {path}: SPA/soft-404 shell - skipped"
                )
                continue

            # 1. Rate limiting on reset requests
            saw_limit = False
            for i in range(5):
                if not self.budget_left():
                    break
                response = await self.probe(
                    path,
                    method="POST",
                    data={"user_login": "recon-canary-x9@example.com",
                          "email": "recon-canary-x9@example.com"},
                )
                if response is None:
                    continue
                if response.status_code == 429:
                    saw_limit = True
                    break
                body = (response.text or "").lower()
                if any(p in body for p in
                       ("too many", "try again later", "throttl", "locked")):
                    saw_limit = True
                    break
            if not saw_limit:
                self.add_finding(
                    "medium",
                    f"No rate limiting observed on password reset ({path})",
                    (
                        "Multiple reset requests produced no 429 or throttle "
                        "signal. Reset flooding enables mail-bombing and "
                        "token brute-force support."
                    ),
                    f"POST {path} x5 -> no limiting signal",
                    "Rate-limit reset requests per identity and add "
                    "exponential backoff",
                    raw={"path": path},
                )

            # 2. Host header reflection (reset-link poisoning surface)
            if self.budget_left():
                response = await self.probe(
                    path,
                    method="POST",
                    headers={"Host": CANARY_HOST},
                    data={"user_login": "recon-canary-x9@example.com"},
                )
                if response is not None and CANARY_HOST in (response.text or ""):
                    self.add_finding(
                        "medium",
                        f"Canary Host reflected on reset page ({path})",
                        (
                            "The reset flow reflects the Host header in its "
                            "response. If reset links are built from Host, "
                            "password-reset link poisoning is possible."
                        ),
                        f"POST {path} with Host: {CANARY_HOST} -> reflected in body",
                        "Generate reset links from server-side configuration, "
                        "never from the Host header",
                        raw={"path": path, "canary_host": CANARY_HOST},
                    )

        self.logger.info(
            f"Password reset probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
