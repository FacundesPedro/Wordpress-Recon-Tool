# recon_wp/steps/users/login_verbosity_step.py
"""
Login verbosity enumeration - checks if wp-login.php reveals valid usernames.

Tests if login error messages differ for valid vs invalid usernames.
"""

# WHAT: Checks if login page reveals username validity
# HOW: Analyzes wp-login.php error messages for "invalid username" patterns
# WHY: Username enumeration aids credential attacks

from base.http_step import BaseHttpStep
from core.finding import Finding


# WordPress default error text for a username that does not exist. The generic
# login page returned by a GET never contains these; they appear only after a
# login POST, so the check must submit a bogus username.
_USERNAME_ORACLE_MARKERS = (
    "unknown username",
    "is not registered",
    "username is incorrect",
)


class LoginVerbosityStep(BaseHttpStep):
    """
    Check if WordPress login reveals valid usernames via error messages.
    """

    name = "login_verbosity"
    description = "Check login page for username disclosure"
    severity = "medium"
    MODULE = "users"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking login page for username disclosure...")

        bogus_user = "wprecon_nouser_zzq4"
        try:
            response = await self.http.post(
                self.urljoin("wp-login.php"),
                data={
                    "log": bogus_user,
                    "pwd": "not-a-real-password",
                    "wp-submit": "Log In",
                    "testcookie": "1",
                },
            )
            if getattr(response, "status_code", None) in (200, 403):
                content = (getattr(response, "text", "") or "").lower()
                if any(marker in content for marker in _USERNAME_ORACLE_MARKERS):
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="Login page reveals username validity",
                        description=(
                            "Submitting a non-existent username produces a "
                            "distinct error message, revealing which usernames exist"
                        ),
                        evidence=(
                            f"POST wp-login.php with log={bogus_user} returned a "
                            "username-validity error"
                        ),
                        recommendation=(
                            "Return a generic 'Invalid username or password' "
                            "message for all failures"
                        ),
                        raw={"url": self.urljoin("wp-login.php")},
                    )
                    self.logger.info("Login page has verbose error messages")

        except Exception as e:
            self.logger.error(f"Error checking login page: {e}")

        return self.findings
