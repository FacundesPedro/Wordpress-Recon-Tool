# recon_wp/core/auth.py
"""WordPress Application Password authentication helpers."""

import base64
from typing import Optional


def get_wp_auth_header(
    wp_user: str = "",
    wp_application_password: str = "",
) -> Optional[dict[str, str]]:
    """
    Build Authorization header for WordPress Application Password auth.

    Args:
        wp_user: WordPress username
        wp_application_password: Application Password (WP >= 5.6)

    Returns:
        Headers dict with Authorization, or None if credentials are empty
    """
    if not wp_user or not wp_application_password:
        return None
    token = base64.b64encode(
        f"{wp_user}:{wp_application_password}".encode()
    ).decode()
    return {"Authorization": f"Basic {token}"}


def has_wp_auth(
    wp_user: str = "",
    wp_application_password: str = "",
) -> bool:
    """Check if WordPress auth credentials are configured."""
    return bool(wp_user and wp_application_password)
