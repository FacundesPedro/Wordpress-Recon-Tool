# recon_wp/utils/http_validation.py
"""Shared response-body validators for web probes.

Catch-all servers (SPA shells, plain-permalink WordPress) answer 200
with the same HTML page for unknown paths. Steps that classify a
response by status code alone report false positives; these helpers
verify that the body actually matches the expected format.
"""

import json

__all__ = ["is_json_body", "is_xml_body", "json_body", "rest_route_fallbacks"]


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
