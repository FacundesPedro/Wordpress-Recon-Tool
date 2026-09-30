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

from core.finding import Finding
from steps.active.base_active import ActiveHttpStep
from utils.soft404 import Soft404Detector

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

    @staticmethod
    def _looks_like_login(response) -> bool:
        """True when a response plausibly processes credentials.

        Guards against concluding "no rate limiting" from a static HTML page or
        an unauthenticated catch-all: require an auth challenge (401/403), a
        JSON error, or a password input field.
        """
        status = getattr(response, "status_code", 0)
        if status in (401, 403):
            return True
        try:
            content_type = (response.headers.get("content-type") or "").lower()
        except Exception:
            content_type = ""
        body = (getattr(response, "text", "") or "").lower()
        if "json" in content_type:
            return any(
                token in body
                for token in ("error", "invalid", "unauthor", "credential", "password")
            )
        return any(
            token in body
            for token in ('type="password"', "type='password'", "invalid", "incorrect")
        )

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
            # Do NOT follow redirects: a 301/302 means this is not a login
            # endpoint (the SPA catch-all would otherwise return 200 HTML).
            baseline = await self.probe(path, follow_redirects=False)
            if baseline is None or baseline.status_code >= 400:
                continue
            if baseline.status_code in (301, 302, 303, 307, 308):
                self.logger.debug(
                    f"Rate limit probe {path}: redirect "
                    f"({baseline.status_code}) - not a credential endpoint"
                )
                continue
            if detector.is_soft404(baseline):
                # catch-all shell: this login endpoint does not exist
                self.logger.debug(
                    f"Rate limit probe {path}: SPA/soft-404 shell - skipped"
                )
                continue

            if not self._looks_like_login(baseline):
                self.logger.debug(
                    f"Rate limit probe {path}: no credential-processing signals - skipped"
                )
                continue

            saw_limit = False
            redirected = False
            statuses: list[int] = []
            last_url = ""
            last_ct = ""
            snippet = ""
            for i in range(BURST):
                if not self.budget_left():
                    break
                response = await self.probe(
                    path,
                    method="POST",
                    follow_redirects=False,
                    data={"username": "recon-canary-x9",
                          "password": f"wrong-pass-{i}",
                          "log": "recon-canary-x9",
                          "pwd": f"wrong-pass-{i}"},
                )
                if response is None:
                    continue
                statuses.append(response.status_code)
                last_url = self.public_url(response, self.urljoin(path))
                last_ct = (
                    (response.headers.get("content-type") or "")
                    if getattr(response, "headers", None)
                    else ""
                )
                snippet = (response.text or "")[:200]
                if response.status_code in (301, 302, 303, 307, 308):
                    redirected = True
                    break
                if response.status_code == 429:
                    saw_limit = True
                    break
                body = (response.text or "").lower()
                if any(p in body for p in LOCKOUT_PATTERNS):
                    saw_limit = True
                    break

            if redirected:
                self.logger.debug(
                    f"Rate limit probe {path}: burst redirected - skipped"
                )
                continue
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
                     "final_url": last_url, "content_type": last_ct,
                     "snippet": snippet,
                     "attempts": len(statuses), "statuses": statuses},
            )

        self.logger.info(
            f"Rate limit probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
