"""WordPress authentication helpers — Application Passwords and Cookie-based session."""

import base64
from typing import Optional

import httpx


def get_wp_auth_header(
    wp_user: str = "",
    wp_application_password: str = "",
) -> Optional[dict[str, str]]:
    """Build Authorization header for WordPress Application Password auth.

    Args:
        wp_user: WordPress username
        wp_application_password: Application Password (WP >= 5.6)

    Returns:
        Headers dict with Authorization, or None if credentials are empty
    """
    if not wp_user or not wp_application_password:
        return None
    token = base64.b64encode(
        f"{wp_user.strip()}:{wp_application_password.strip()}".encode()
    ).decode()
    return {"Authorization": f"Basic {token}"}


def has_wp_auth(
    wp_user: str = "",
    wp_application_password: str = "",
) -> bool:
    """Check if WordPress auth credentials are configured."""
    return bool(wp_user and wp_application_password)


class AdminSession:
    """Cookie-based WordPress admin session.

    Logs in via wp-login.php POST and stores cookies for subsequent
    admin-page requests. Used only when ``wp_auth_method == "cookie"``.
    """

    def __init__(self, http: httpx.AsyncClient, base_url: str):
        self.http = http
        self.base_url = base_url.rstrip("/")
        self._logged_in = False

    @property
    def is_authenticated(self) -> bool:
        return self._logged_in

    async def login(self, username: str, password: str) -> bool:
        """POST to wp-login.php and store session cookies.

        Returns:
            True if login succeeded (redirect to wp-admin detected).
        """
        login_url = f"{self.base_url}/wp-login.php"
        try:
            resp = await self.http.post(
                login_url,
                data={
                    "log": username,
                    "pwd": password,
                    "wp-submit": "Log In",
                    "testcookie": "1",
                    "redirect_to": f"{self.base_url}/wp-admin/",
                },
                follow_redirects=False,
            )

            location = resp.headers.get("location", "")
            has_session_cookie = any(
                "wordpress_logged_in" in str(k)
                for k in resp.cookies
            )

            if (
                (resp.status_code == 302 and "wp-admin" in location)
                or has_session_cookie
            ):
                self._logged_in = True
                return True

            self._logged_in = False
            return False

        except httpx.HTTPError:
            self._logged_in = False
            return False

    async def get(self, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated GET request to an admin page."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        return await self.http.get(url, **kwargs)

    async def post(self, path: str, data: Optional[dict] = None, **kwargs) -> httpx.Response:
        """Make an authenticated POST request to an admin page."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        return await self.http.post(url, data=data, **kwargs)
