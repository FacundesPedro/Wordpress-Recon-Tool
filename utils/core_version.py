"""WordPress core version detection from page HTML.

The ``generator`` meta tag is commonly stripped for security. Core assets
registered without an explicit version use the WordPress version as ``?ver=``,
so those query strings still reveal it:

    /wp-includes/js/wp-emoji-release.min.js?ver=7.1.2
    /wp-includes/css/dist/block-library/style.min.css?ver=7.1.2

Theme and plugin assets carry *their own* versions and must not be used as a
core-version signal.
"""

from __future__ import annotations

import re
from typing import Optional

_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([0-9.]+)',
    re.I,
)
_GENERATOR_CONTENT_RE = re.compile(r'content=["\']WordPress\s+([0-9.]+)', re.I)

# Core asset patterns, most specific first. Each group(1) is the ?ver= value.
_CORE_ASSET_PATTERNS = (
    r"/wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9.]+)",
    r"/wp-includes/js/wp-util(?:\.min)?\.js\?ver=([0-9.]+)",
    r"/wp-includes/css/dist/block-library/style(?:\.min)?\.css\?ver=([0-9.]+)",
    r"/wp-includes/css/dist/block-library/theme(?:\.min)?\.css\?ver=([0-9.]+)",
    r"/wp-includes/css/dashicons(?:\.min)?\.css\?ver=([0-9.]+)",
    r"/wp-includes/js/dist/hooks(?:\.min)?\.js\?ver=([0-9.]+)",
    r"/wp-includes/js/dist/i18n(?:\.min)?\.js\?ver=([0-9.]+)",
    r"/wp-includes/css/dist/components/style(?:\.min)?\.css\?ver=([0-9.]+)",
)


def detect_core_version(html: str) -> tuple[Optional[str], Optional[str]]:
    """Return ``(version, source)`` detected from ``html``.

    ``source`` is a short human-readable label (``meta generator`` or the
    matched core asset path). Returns ``(None, None)`` when nothing matches.
    """
    content = html or ""
    match = _GENERATOR_RE.search(content) or _GENERATOR_CONTENT_RE.search(content)
    if match:
        return match.group(1), "meta generator"
    for pattern in _CORE_ASSET_PATTERNS:
        asset_match = re.search(pattern, content, re.I)
        if asset_match:
            label = pattern.split(r"\?ver=")[0].replace("\\", "")
            return asset_match.group(1), f"core asset {label}"
    return None, None
