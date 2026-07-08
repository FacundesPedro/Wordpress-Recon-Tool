import asyncio

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


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

        self.logger.info(
            f"Testing {len(credentials)} credential pair(s) against wp-login.php"
        )

        found = []
        for i, (username, password) in enumerate(credentials):
            success, detail = await self._try_login(username, password)
            if success:
                found.append({"username": username, "password": password, "detail": detail})
                self.logger.warning(f"Valid credentials found: {username}:{password}")

            if i < len(credentials) - 1:
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

    async def _try_login(self, username: str, password: str) -> tuple[bool, str]:
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

            if resp.status_code == 302 and "wp-admin" in location:
                return True, "redirect_to_wp_admin"

            if resp.status_code == 302:
                return True, f"redirect_to_{location}"

            if resp.status_code == 200 and "login_error" not in resp.text:
                return True, "no_error_in_response"

            return False, ""

        except Exception as e:
            self.logger.debug(f"Error testing {username}:{password}: {e}")
            return False, ""
