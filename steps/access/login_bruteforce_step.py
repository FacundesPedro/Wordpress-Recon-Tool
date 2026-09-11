# WHAT: Brute-force WordPress login via wp-login.php with credential pairs
# HOW: Sequential POSTs with a canary baseline; success requires a response
#      that differs from the invalid-credential baseline (redirect to
#      wp-admin, or a 200 body that differs from the catch-all shell)
# WHY: Tests weak credentials; SPA catch-all servers return 200 for every
#      POST, so an uncalibrated "200 without error text" heuristic would
#      report every credential as valid

import asyncio
import secrets

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import ResponseFingerprint, Soft404Detector


class LoginBruteforceStep(BaseHttpStep, WordlistDependencyMixin):
    name = "login_bruteforce"
    description = "Brute-force wp-login.php with credential pairs"
    severity = "high"
    MODULE = "access"

    SLEEP_BETWEEN_ATTEMPTS = 1.5

    async def run(self) -> list[Finding]:
        self.logger.info("Running login brute-force on wp-login.php...")

        credentials = self.resolve_credentials_with_fallback(
            config_key="login_wordlist"
        )
        if not credentials:
            return self.findings

        # Baseline: POST with a guaranteed-invalid canary credential. The
        # failure response (status + body fingerprint) defines what "wrong
        # password" looks like on this server. On SPA catch-alls this is
        # the app shell served for every POST.
        baseline = await self._baseline_response()
        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        self.logger.info(
            f"Testing {len(credentials)} credential pair(s) against wp-login.php"
        )

        found = []
        total = len(credentials)
        for i, (username, password) in enumerate(credentials):
            success, detail = await self._try_login(
                username, password, baseline, detector
            )
            if success:
                found.append({"username": username, "password": password, "detail": detail})
                self.logger.warning(f"Valid credentials found: {username}:{password}")

            if (i + 1) % 5 == 0 or i == total - 1:
                self.logger.info(
                    f"Login brute-force progress: {i + 1}/{total} attempt(s)"
                )

            if i < total - 1:
                await asyncio.sleep(self.SLEEP_BETWEEN_ATTEMPTS)

        if found:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Valid WordPress credentials found on wp-login.php",
                description=(
                    f"Found {len(found)} valid credential pair(s) via "
                    f"POST to wp-login.php"
                ),
                evidence="\n".join(
                    f"  - {c['username']}:{c['password']} ({c['detail']})"
                    for c in found
                ),
                recommendation=(
                    "Strengthen all user passwords, enable 2FA, and consider "
                    "a login rate-limiter or CAPTCHA plugin. Remove any "
                    "default or test accounts."
                ),
                raw={
                    "valid_credentials": found,
                    "total_attempts": len(credentials),
                },
            )
        else:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Login brute-force completed — no valid credentials found",
                description=(
                    f"Tested {len(credentials)} credential pair(s) against "
                    f"wp-login.php — none succeeded"
                ),
                evidence=f"Total attempts: {len(credentials)}",
                recommendation=(
                    "No action needed. Continue monitoring for brute-force "
                    "attempts via audit logs."
                ),
                raw={"total_attempts": len(credentials), "valid": []},
            )

        return self.findings

    async def _baseline_response(self) -> ResponseFingerprint:
        """Fingerprint the response for a guaranteed-invalid credential."""
        canary_user = f"recon-canary-{secrets.token_hex(4)}"
        try:
            resp = await self.http.post(
                self.urljoin("wp-login.php"),
                data={
                    "log": canary_user,
                    "pwd": f"canary-{secrets.token_hex(8)}",
                    "wp-submit": "Log In",
                    "testcookie": "1",
                    "redirect_to": self.urljoin("wp-admin/"),
                },
                follow_redirects=False,
            )
            return ResponseFingerprint.from_response(resp)
        except Exception as e:
            self.logger.debug(f"Login baseline failed: {e}")
            return ResponseFingerprint()

    async def _try_login(self, username: str, password: str,
                         baseline: ResponseFingerprint,
                         detector: Soft404Detector) -> tuple[bool, str]:
        try:
            resp = await self.http.post(
                self.urljoin("wp-login.php"),
                data={
                    "log": username,
                    "pwd": password,
                    "wp-submit": "Log In",
                    "testcookie": "1",
                    "redirect_to": self.urljoin("wp-admin/"),
                },
                follow_redirects=False,
            )

            location = resp.headers.get("location", "")

            # Strong signal: authenticated redirect to the admin area
            if resp.status_code == 302 and "wp-admin" in location:
                return True, "redirect_to_wp_admin"

            # 302 elsewhere: compare against the baseline redirect (some
            # catch-alls redirect every POST to the same location)
            if resp.status_code in (301, 302, 303, 307, 308):
                baseline_status = baseline.status
                baseline_location = ""
                if baseline.status in (301, 302, 303, 307, 308):
                    # baseline fingerprint does not carry headers; treat a
                    # differing status as signal, same status as suspect
                    if resp.status_code != baseline_status:
                        return True, f"redirect_differs_from_baseline ({location[:80]})"
                    return False, ""
                if baseline_status != resp.status_code:
                    return True, f"redirect_to_{location[:80]}"
                return False, ""

            if resp.status_code == 200:
                if baseline.status == 200 and not baseline.empty:
                    # Catch-all suppression: identical to the invalid-
                    # credential baseline (or the SPA shell) means the
                    # credential was not actually processed.
                    if detector is not None and detector.is_soft404(resp):
                        return False, ""
                    fp = ResponseFingerprint.from_response(resp)
                    if fp.title == baseline.title and \
                            abs(fp.length - baseline.length) <= 64:
                        return False, ""
                    return True, "response_differs_from_baseline"
                # No baseline (baseline request failed): a bare 200 is NOT
                # success - require explicit failure markers to reject.
                lowered = resp.text.lower()
                if "login_error" in lowered or "invalid" in lowered \
                        or "incorrect" in lowered:
                    return False, ""
                return False, "ambiguous_200_no_baseline"

            return False, ""

        except Exception as e:
            self.logger.debug(f"Error testing {username}:{password}: {e}")
            return False, ""
