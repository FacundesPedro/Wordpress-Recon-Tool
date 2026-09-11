# recon_wp/utils/wordpress_detect.py
"""WordPress detection gate for WP-specific steps.

WHAT: Determines whether a target actually runs WordPress
HOW: Cheap marker checks - /wp-json/ REST root returning JSON with
     namespaces, wp-content/ paths in HTML, or the generator meta tag
WHY: WordPress-only steps (plugin brute-force, wp-json enumeration,
     xmlrpc, WooCommerce...) produce hundreds of false positives on
     non-WP targets whose catch-all serves the SPA shell for every
     wp-* path.
"""

import re
from typing import Optional

import httpx

_GENERATOR_RE = re.compile(
    r'name="generator"[^>]*content="WordPress ([\d.]+)"', re.I
)
_WP_CONTENT_RE = re.compile(r"/wp-content/(?:themes|plugins|includes)/")

# Cache per (url) for the process lifetime of a scan
_detected: dict[str, Optional[bool]] = {}


async def is_wordpress(http, target_url: str, logger=None) -> bool:
    """Return True when the target shows WordPress markers.

    Checks (any one is sufficient):
    1. /wp-json/ returns JSON with a "namespaces" key (WP REST API)
    2. Homepage HTML references wp-content/ paths
    3. Homepage has the WordPress generator meta tag

    Results are cached per target URL. On network errors, returns
    False (fail-closed: WP-only steps skip rather than FPs).
    """
    key = target_url.rstrip("/")
    if key in _detected:
        return _detected[key]

    result = False

    # 1. REST root
    try:
        resp = await http.request("GET", f"{key}/wp-json/")
        if getattr(resp, "status_code", None) == 200:
            content_type = ""
            headers = getattr(resp, "headers", None) or {}
            try:
                content_type = headers.get("content-type") or ""
            except Exception:
                pass
            if "json" in content_type.lower():
                try:
                    data = resp.json()
                    if isinstance(data, dict) and "namespaces" in data:
                        result = True
                except Exception:
                    pass
    except Exception as e:
        if logger:
            logger.debug(f"wp-json probe failed: {e}")

    # 2/3. Homepage markers (only if REST check was inconclusive)
    if not result:
        try:
            resp = await http.request("GET", key)
            if getattr(resp, "status_code", None) == 200:
                text = getattr(resp, "text", "") or ""
                if _WP_CONTENT_RE.search(text) or _GENERATOR_RE.search(text):
                    result = True
        except Exception as e:
            if logger:
                logger.debug(f"homepage probe failed: {e}")

    _detected[key] = result
    if logger:
        state = "WordPress detected" if result else "not WordPress"
        logger.debug(f"WordPress detection for {key}: {state}")
    return result
