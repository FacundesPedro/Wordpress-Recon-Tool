# recon_wp/steps/users/registration_step.py
"""
User registration exposure - open registration detection.

Checks whether WordPress user registration is open (`wp-login.php?
action=register` renders the registration form) and whether multisite
signup (`wp-signup.php`) is exposed. Open registration expands the
authenticated attack surface (WSTG 4.3.2).
"""

# WHAT: Detects open user registration on WordPress
# HOW: GET wp-login.php?action=register and wp-signup.php; look for the
#      registration form markers
# WHY: Open registration lets anyone obtain an authenticated account

import re

from base.http_step import BaseHttpStep
from core.finding import Finding

REGISTER_PATH = "wp-login.php?action=register"
SIGNUP_PATH = "wp-signup.php"

REGISTRATION_MARKERS = [
    "registration confirmation will be emailed",
    "id=\"user_login\"",
    "name=\"user_login\"",
    "action=register",
    "create a new account",
    "registerform",
]

SIGNUP_MARKERS = [
    "create a new site",
    "sitesetup",
    "signup_for",
    "signup_user",
]


def looks_like_registration(html: str, markers: list[str]) -> bool:
    """True when the page contains registration-form markers."""
    lowered = (html or "").lower()
    hits = sum(1 for m in markers if m.lower() in lowered)
    return hits >= 2


class RegistrationStep(BaseHttpStep):
    """Detect open WordPress user registration."""

    name = "registration"
    description = "Detect open user registration (wp-login.php?action=register)"
    severity = "medium"
    MODULE = "users"

    async def run(self) -> list[Finding]:
        self.logger.info("Checking user registration exposure...")

        try:
            response = await self.fetch(REGISTER_PATH)
        except Exception as e:
            self.logger.debug(f"Register probe failed: {e}")
            return self.findings

        status = getattr(response, "status_code", None)
        body = response.text or ""
        register_url = self.urljoin(REGISTER_PATH)

        if status == 200 and looks_like_registration(body, REGISTRATION_MARKERS):
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Open user registration enabled",
                description=(
                    "wp-login.php?action=register renders a registration "
                    "form. Anyone can create an account and reach the "
                    "authenticated attack surface."
                ),
                evidence=f"GET {register_url} -> 200 with registration form",
                recommendation="Disable open registration (Settings > General) "
                               "unless self-serve signup is required",
                raw={
                    "path": REGISTER_PATH,
                    "url": register_url,
                    "status": status,
                },
            )
        elif status == 200:
            self.logger.debug("Register endpoint returned 200 but no form markers")

        # multisite signup
        try:
            response = await self.fetch(SIGNUP_PATH)
            if getattr(response, "status_code", None) == 200 and \
                    looks_like_registration(response.text or "", SIGNUP_MARKERS):
                signup_url = self.urljoin(SIGNUP_PATH)
                self._add_finding(
                    module=self.MODULE,
                    severity="medium",
                    title="Multisite signup exposed (wp-signup.php)",
                    description=(
                        "wp-signup.php renders the multisite signup flow. "
                        "Anyone can create sites/users on the network."
                    ),
                    evidence=f"GET {signup_url} -> 200 with signup form",
                    recommendation="Restrict wp-signup.php or disable open multisite signup",
                    raw={"path": SIGNUP_PATH, "url": signup_url},
                )
        except Exception as e:
            self.logger.debug(f"Signup probe failed: {e}")

        self.logger.info(f"Registration check: {len(self.findings)} finding(s)")
        return self.findings
