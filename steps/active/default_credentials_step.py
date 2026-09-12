# recon_wp/steps/active/default_credentials_step.py
"""
Default credentials testing - small capped probe against login forms.

Covers WSTG 4.4.2 (Testing for Default Credentials): probes discovered login
endpoints with a small set of common default/administrator credential pairs.
Stops on the first success; hard-capped at 10 attempts total.
"""

# WHAT: Tests common default credentials on discovered login endpoints
# HOW: Small fixed pair list; WP-style (log/pwd) and generic (username/password)
#      field names; success = redirect to admin area
# WHY: Default credentials remain one of the fastest paths to compromise

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

LOGIN_PATHS = [
    "/wp-login.php",
    "/login",
    "/signin",
    "/user/login",
    "/admin/login",
    "/administrator",
]

# (user, password)
DEFAULT_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("user", "user"),
]

MAX_ATTEMPTS = 10
MAX_FINDINGS = 3

# Passwords used to fingerprint the failure response for each endpoint.
INVALID_USER = "recon-invalid-7f3a"
INVALID_PASSWORD = "recon-invalid-7f3a"


class DefaultCredentialsStep(ActiveHttpStep):
    """Probe login endpoints with common default credential pairs."""

    name = "default_credentials"
    description = "Test default credentials on login endpoints (capped, stops on success)"
    severity = "critical"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing default credentials (capped)...")

        for path in LOGIN_PATHS:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                break
            url = self.urljoin(path)
            baseline = await self.probe(path)
            if baseline is None or baseline.status_code >= 400:
                continue

            # Fingerprint the failure response with obviously invalid
            # credentials: a catch-all redirect (e.g. every POST -> /home)
            # must not be mistaken for a successful login.
            invalid_baseline = await self.probe(
                path,
                method="POST",
                data={
                    "log": INVALID_USER,
                    "pwd": INVALID_PASSWORD,
                    "username": INVALID_USER,
                    "password": INVALID_PASSWORD,
                },
                follow_redirects=False,
            )
            if not self.budget_left():
                break

            for user, password in DEFAULT_PAIRS:
                if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                    break
                response = await self.probe(
                    path,
                    method="POST",
                    data={"log": user, "pwd": password,
                          "username": user, "password": password},
                    follow_redirects=False,
                )
                if response is None:
                    continue
                if self._login_success(response, invalid_baseline):
                    self.add_finding(
                        "critical",
                        f"Default credentials accepted at {path}",
                        (
                            f"Login with '{user}:{password}' succeeded at "
                            f"{path}. Default or weak administrative "
                            f"credentials are in use."
                        ),
                        f"POST {url} ({user}/{password}) -> "
                        f"{response.status_code} "
                        f"Location: {response.headers.get('location', '')[:100]}",
                        "Change default credentials immediately; enforce "
                        "strong passwords and MFA",
                        raw={"path": path, "url": url, "user": user,
                             "final_url": str(
                                 getattr(response, "url", None) or url
                             )},
                    )
                    break  # stop probing this endpoint on success

        self.logger.info(
            f"Default credentials probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings

    @staticmethod
    def _login_success(response, invalid_baseline=None) -> bool:
        """Heuristic login success: 302 redirect to an admin-ish location.

        Responses that match the invalid-credential baseline are failures.
        """
        if response.status_code not in (301, 302, 303, 307, 308):
            return False
        location = (response.headers.get("location") or "").lower()
        admin_markers = ("wp-admin", "admin", "dashboard", "panel",
                         "account", "home", "profile")
        if not any(marker in location for marker in admin_markers):
            return False
        if invalid_baseline is not None:
            baseline_status = getattr(invalid_baseline, "status_code", None)
            baseline_headers = getattr(invalid_baseline, "headers", None) or {}
            try:
                baseline_location = (
                    baseline_headers.get("location") or ""
                ).lower()
            except Exception:
                baseline_location = ""
            if (
                response.status_code == baseline_status
                and location == baseline_location
            ):
                return False
        return True
