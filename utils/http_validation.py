# recon_wp/utils/http_validation.py
"""Shared response-body validators for web probes.

Catch-all servers (SPA shells, plain-permalink WordPress) answer 200
with the same HTML page for unknown paths. Steps that classify a
response by status code alone report false positives; these helpers
verify that the body actually matches the expected format.
"""

import json

from utils.soft404 import is_html_body

__all__ = [
    "is_json_body",
    "is_xml_body",
    "json_body",
    "rest_route_fallbacks",
    "is_php_config",
    "is_wp_readme",
    "is_wp_license",
    "is_robots",
    "is_plugin_readme",
]


def _body_text(response) -> str:
    """Return the response body as a string, or "" for non-string bodies."""
    text = getattr(response, "text", "") or ""
    return text if isinstance(text, str) else ""


def is_json_body(response) -> bool:
    """True when a response body parses as JSON."""
    text = getattr(response, "text", "") or ""
    if not isinstance(text, str):
        return False
    text = text.lstrip()
    if not text or text[0] not in "[{":
        return False
    try:
        json.loads(text)
    except (TypeError, ValueError):
        return False
    return True


def json_body(response):
    """Return the parsed JSON body of a response, or None."""
    if not is_json_body(response):
        return None
    try:
        return json.loads(response.text)
    except (TypeError, ValueError):
        return None


def is_xml_body(response) -> bool:
    """True when a response is an XML document (sitemap, feeds)."""
    text = getattr(response, "text", "") or ""
    if not isinstance(text, str):
        return False
    text = text.lstrip()
    if not text:
        return False
    headers = getattr(response, "headers", None) or {}
    try:
        content_type = (headers.get("content-type") or "").lower()
    except Exception:
        content_type = ""
    if "xml" in content_type:
        return True
    if not text.startswith("<"):
        return False
    return "<urlset" in text or "<sitemapindex" in text


def rest_route_fallbacks(route: str) -> list[str]:
    """Candidate request paths for a WordPress REST route.

    Pretty permalinks serve ``wp-json/<route>``; plain permalinks serve
    ``?rest_route=/<route>``. The pretty form is returned first, then
    the query form, so callers can probe in order.
    """
    cleaned = route.strip().lstrip("/")
    if cleaned.startswith("wp-json"):
        rest = cleaned[len("wp-json"):]
    else:
        rest = "/" + cleaned
    rest = rest.lstrip("/")
    pretty = f"wp-json/{rest}" if rest else "wp-json/"
    return [pretty, f"?rest_route=/{rest}"]


def is_php_config(response) -> bool:
    """True when the body looks like a PHP wp-config file.

    Real wp-config backups define multiple database/auth constants;
    catch-all HTML shells and generic error pages do not. HTML bodies are
    always rejected.
    """
    text = _body_text(response)
    if not text or is_html_body(text):
        return False
    lower = text.lower()
    if "define(" not in lower:
        return False
    constants = (
        "db_name",
        "db_user",
        "db_password",
        "db_host",
        "auth_key",
        "table_prefix",
    )
    return sum(1 for name in constants if name in lower) >= 2


def is_wp_readme(response) -> bool:
    """True when the body is the WordPress core readme.html document.

    A soft-404 homepage shell also contains the word "WordPress", so the
    core readme markers must be present too.
    """
    text = _body_text(response)
    if not text:
        return False
    lower = text.lower()
    if "wordpress" not in lower:
        return False
    return (
        "semantic personal publishing platform" in lower
        or "wordpress &#8250; readme" in lower
        or "wordpress » readme" in lower
        or ("readme" in lower and "install.css" in lower)
    )


def is_wp_license(response) -> bool:
    """True when the body is the WordPress license.txt document."""
    text = _body_text(response)
    if not text:
        return False
    lower = text.lower()
    if "wordpress" not in lower:
        return False
    return (
        "web publishing software" in lower
        or "gnu general public license" in lower
    )


def is_robots(response) -> bool:
    """True when the body is a robots.txt document.

    Requires a User-agent group and at least one directive line; an HTML
    shell or empty soft-404 body never matches.
    """
    text = _body_text(response)
    if not text or is_html_body(text):
        return False
    lower = text.lower()
    if "user-agent" not in lower:
        return False
    return any(
        line.strip().startswith(("disallow:", "allow:", "sitemap:"))
        for line in lower.splitlines()
    )


def is_plugin_readme(response) -> bool:
    """True when the body is a WordPress plugin/theme readme.txt.

    Real readmes carry the wp.org header (``=== Name ===``) or metadata
    fields (``Stable tag:`` / ``Requires at least:``); HTML shells do not.
    """
    text = _body_text(response)
    if not text or is_html_body(text):
        return False
    lower = text.lower()
    if "stable tag:" in lower or "requires at least:" in lower:
        return True
    stripped = lower.lstrip()
    return stripped.startswith("===") and "===" in stripped[3:]
