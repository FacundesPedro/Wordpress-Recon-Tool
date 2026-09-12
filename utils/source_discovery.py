# recon_wp/utils/source_discovery.py
"""Source discovery helpers for generic web application checks.

WHAT: Extracts asset/page URLs from HTML, fuzzes common asset paths, and
      fetches assets with bounded size/count.
HOW: Regex extraction from raw HTML + optional wordlist-driven path probing
     + same-origin normalization before any fetch.
WHY: Shared discovery logic for SourceReviewStep, SourcemapStep, and
     ContentLeakStep so each step stays small and consistent.
"""

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from utils.soft404 import is_html_body

ASSET_EXTENSIONS = (".js", ".mjs", ".css", ".map")

_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
_LINK_HREF_RE = re.compile(
    r"<link[^>]+(?:rel=[\"'](?:import|modulepreload|stylesheet)[\"']|href=[\"'])[^>]*"
    r"href=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_LINK_HREF_ANY_RE = re.compile(r"<link[^>]+href=[\"']([^\"']+)[\"']", re.IGNORECASE)
_CSS_URL_RE = re.compile(r"url\(\s*[\"']?([^\"')]+)[\"']?\s*\)", re.IGNORECASE)
_INLINE_ASSET_RE = re.compile(
    r"[\"']([^\"'\s]+\.(?:js|mjs|css|map))(?:\?[^\"']*)?[\"']", re.IGNORECASE
)
_ANCHOR_HREF_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"']", re.IGNORECASE)

_SKIP_SCHEMES = ("data:", "javascript:", "blob:", "mailto:", "tel:", "ftp:")


def normalize_url(raw: str, base_url: str) -> Optional[str]:
    """Resolve a raw URL against base_url, keeping only same-origin http(s).

    Args:
        raw: Raw URL fragment from HTML (may be relative, quoted, or scheme-prefixed)
        base_url: Base URL to resolve against (e.g. https://example.com)

    Returns:
        Absolute same-origin URL, or None if external/skippable
    """
    raw = raw.strip().strip("\"'`")
    if not raw or raw.startswith("#") or raw.startswith(_SKIP_SCHEMES):
        return None

    url = urljoin(base_url, raw)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    if parsed.netloc != urlparse(base_url).netloc:
        return None
    return url


def extract_asset_urls(html: str, base_url: str) -> list[str]:
    """Extract same-origin asset URLs (JS/CSS/maps) from HTML.

    Args:
        html: Raw HTML content
        base_url: Base URL for relative resolution

    Returns:
        Deduplicated list of absolute asset URLs, document order
    """
    if not html:
        return []

    candidates: list[str] = []
    for regex in (_SCRIPT_SRC_RE, _LINK_HREF_RE, _LINK_HREF_ANY_RE, _CSS_URL_RE, _INLINE_ASSET_RE):
        candidates.extend(regex.findall(html))

    urls: list[str] = []
    seen: set[str] = set()
    for raw in candidates:
        url = normalize_url(raw, base_url)
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def extract_link_urls(html: str, base_url: str) -> list[str]:
    """Extract same-origin page links from <a href> tags.

    Args:
        html: Raw HTML content
        base_url: Base URL for relative resolution

    Returns:
        Deduplicated list of absolute page URLs, document order
    """
    if not html:
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for raw in _ANCHOR_HREF_RE.findall(html):
        if raw.startswith(_SKIP_SCHEMES) or raw.startswith("#"):
            continue
        url = normalize_url(raw, base_url)
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def strip_query(url: str) -> str:
    """Remove query string and fragment from a URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _is_shell_response(response) -> bool:
    """True when a 200 asset response is actually an HTML catch-all shell."""
    text = getattr(response, "text", "") or ""
    if not isinstance(text, str):
        return False
    try:
        headers = getattr(response, "headers", None) or {}
        content_type = headers.get("content-type") or ""
    except Exception:
        content_type = ""
    if not isinstance(content_type, str):
        content_type = ""
    return is_html_body(text, content_type)


async def fetch_assets(
    http,
    base_url: str,
    urls: list[str],
    max_files: int = 20,
    max_bytes: int = 1000000,
) -> list[tuple[str, str]]:
    """Fetch same-origin assets with count and size bounds.

    Args:
        http: HttpClient instance (must have async request(method, url))
        base_url: Base URL for relative resolution
        urls: Raw or absolute asset URLs
        max_files: Maximum number of files to fetch
        max_bytes: Maximum bytes to keep per file

    Returns:
        List of (absolute_url, content) tuples for successfully fetched assets
    """
    fetched: list[tuple[str, str]] = []
    seen: set[str] = set()

    for raw in urls:
        if len(fetched) >= max_files:
            break
        url = normalize_url(raw, base_url)
        if not url or url in seen:
            continue
        seen.add(url)
        try:
            response = await http.request("GET", url)
        except Exception:
            continue
        if getattr(response, "status_code", None) != 200:
            continue
        if _is_shell_response(response):
            continue
        text = getattr(response, "text", "") or ""
        fetched.append((url, text[:max_bytes]))

    return fetched


async def fuzz_common_assets(
    http,
    base_url: str,
    paths: list[str],
    max_probes: int = 60,
) -> list[str]:
    """Probe common asset paths and return URLs that exist (HTTP 200).

    Args:
        http: HttpClient instance
        base_url: Base URL for path resolution
        paths: Asset path candidates (relative, e.g. "app.js")
        max_probes: Maximum number of paths to probe

    Returns:
        List of absolute URLs that returned 200
    """
    found: list[str] = []
    seen: set[str] = set()
    probed = 0

    for path in paths:
        if probed >= max_probes:
            break
        url = normalize_url(path.strip(), base_url)
        if not url or url in seen:
            continue
        seen.add(url)
        probed += 1
        try:
            response = await http.request("GET", url)
        except Exception:
            continue
        if getattr(response, "status_code", None) == 200:
            if _is_shell_response(response):
                continue
            found.append(url)

    return found
