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


class LoginVerbosityStep(BaseHttpStep):
    """
    Check if WordPress login page reveals valid usernames via error messages.
    """

    name = "login_verbosity"
    description = "Check login page for username disclosure"
    severity = "info"
    MODULE = "users"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking login page for username disclosure...")

        try:
            response = await self.http.get(self.urljoin("wp-login.php"))
            if response.status_code == 200:
                content = response.text.lower()

                if "incorrect username" in content or "invalid username" in content:
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title="Login page reveals username validity",
                        description="The login page error messages reveal whether a username exists",
                        evidence="Error messages differ for valid vs invalid usernames",
                        recommendation="Use a generic error message like 'Invalid username or password'",
                        raw={"url": self.urljoin("wp-login.php")},
                    )
                    self.logger.info("Login page has verbose error messages")

        except Exception as e:
            self.logger.error(f"Error checking login page: {e}")

        return self.findings
