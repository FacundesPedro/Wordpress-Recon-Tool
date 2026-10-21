"""Asset-hash plugin version fingerprinting.

WHAT: Determine a plugin's version when ``readme.txt``/``changelog.txt`` are
      blocked (WAF 403) and WPScan cannot report a version.
HOW:  Hash a stable static asset served by the target (CSS/JS), then hash the
      same asset in the plugin's recent numeric SVN tags and intersect the
      candidates across multiple assets. Release dates from the wordpress.org
      changelog + the target file's ``Last-Modified`` pick the version that was
      current when the plugin was installed.
WHY:  "version: None" made WPScan emit nine false ``high`` findings on a
      target whose plugins were all up to date (hml-kitsdidaticos retest #2/#3).
      Hash comparison is read-only and never downloads entire plugins.

Caveat: an asset that is unchanged across releases yields a version *range*;
the newest matching tag is reported with ``confidence="medium"`` and every
candidate is preserved in ``raw.candidates`` for triage.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

SVN_BASE = "https://plugins.svn.wordpress.org"
API_INFO = "https://api.wordpress.org/plugins/info/1.2/"

NUMERIC_TAG_RE = re.compile(r"^\d+(?:\.\d+)*$")
_TAG_HREF_RE = re.compile(r'href="([^"]+)/"')
_DATE_RE = re.compile(
    r"(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}|\d{4}-\d{2}-\d{2})"
)

DEFAULT_MAX_TAGS = 30
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_REQUESTS = 80
_CONCURRENCY = 8

# Stable front-end assets used when the caller cannot derive paths from the
# target's HTML. Keep this list short: it is only a fallback.
DEFAULT_ASSETS: dict[str, list[str]] = {
    "contact-form-7": ["includes/css/styles.css", "includes/js/index.js"],
    "custom-post-type-ui": ["build/cptui-styles.min.css", "build/cptui-editor.js"],
    "advanced-custom-fields": [
        "assets/build/css/acf-input.min.css",
        "assets/build/js/acf.min.js",
    ],
    "all-in-one-wp-migration": [
        "lib/view/assets/css/backups.min.css",
        "lib/view/assets/css/export.min.css",
    ],
    "wp-file-manager": ["css/fm_common.css", "css/fm_custom.css"],
    "wordpress-seo": ["css/dist/yoast-seo-frontend.css", "js/dist/yoast-seo-frontend.js"],
    "woocommerce": ["assets/css/woocommerce.css", "assets/js/frontend/woocommerce.js"],
    "elementor": ["assets/css/frontend.min.css", "assets/js/frontend.min.js"],
    "wordfence": ["css/wordfenceBox.css", "js/wordfence.js"],
    "updraftplus": ["css/updraftplus-admin.css", "js/updraftplus-admin.js"],
}

# (target_url, slug, YYYY-MM-DD) -> fingerprint, so a scan that instantiates the
# fingerprinter twice does not hammer the SVN server.
_CACHE: dict[tuple[str, str, str], PluginFingerprint] = {}


def clear_cache() -> None:
    """Drop the per-day fingerprint cache (used by tests)."""
    _CACHE.clear()


def version_key(version: str) -> tuple[int, ...]:
    """Sort key for dotted numeric versions (``1.10`` > ``1.9``)."""
    return tuple(int(part) for part in version.split("."))


def parse_tags(html: str) -> list[str]:
    """Extract numeric tag names from an SVN ``tags/`` directory listing."""
    names = [n for n in _TAG_HREF_RE.findall(html or "") if NUMERIC_TAG_RE.match(n)]
    names.sort(key=version_key)
    return names


def assets_from_html(html: str, slug: str, limit: int = 3) -> list[str]:
    """Return relative CSS/JS asset paths referenced for ``slug`` in HTML."""
    pattern = re.compile(
        rf"/wp-content/plugins/{re.escape(slug)}/([^\"'?#<>]+\.(?:css|js))"
    )
    out: list[str] = []
    for match in pattern.findall(html or ""):
        if match not in out:
            out.append(match)
        if len(out) >= limit:
            break
    return out


def _looks_like_html(data: bytes) -> bool:
    """Reject SPA/soft-404 HTML shells masquerading as a static asset."""
    head = data[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_date(value: str) -> datetime | None:
    """Parse the date formats found in WordPress changelogs."""
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%d %B %Y", "%d %b %Y", "%Y-%m-%d", "%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@dataclass
class PluginFingerprint:
    """Result of an asset-hash lookup for one plugin."""

    slug: str
    version: str | None = None
    confidence: str = "low"  # high | medium | low
    method: str = "asset-hash"
    candidates: list[str] = field(default_factory=list)
    assets: dict[str, str] = field(default_factory=dict)  # asset -> sha256
    matched_assets: dict[str, list[str]] = field(default_factory=dict)
    release_dates: dict[str, str] = field(default_factory=dict)
    target_modified: str | None = None
    error: str = ""
    requests_made: int = 0

    @property
    def found(self) -> bool:
        return bool(self.version or self.candidates)

    def to_raw(self) -> dict:
        """Serializable detail for a finding's ``raw`` field."""
        raw = {
            "method": self.method,
            "confidence": self.confidence,
            "candidates": self.candidates[:10],
            "assets": dict(list(self.assets.items())[:3]),
            "matched_assets": {
                k: v[:10] for k, v in list(self.matched_assets.items())[:3]
            },
        }
        if self.version:
            raw["version"] = self.version
        if self.release_dates:
            raw["release_dates"] = self.release_dates
        if self.target_modified:
            raw["target_last_modified"] = self.target_modified
        if self.error:
            raw["error"] = self.error
        return raw


class PluginFingerprinter:
    """Look up plugin versions by hashing static assets against SVN tags.

    ``fetch_target`` is an async callable ``(relative_path) -> bytes | None``
    that fetches ``/wp-content/plugins/<slug>/<relative_path>`` from the scan
    target. Supplying it keeps the scan's pinning/stealth/auth behavior; when
    omitted, plain ``httpx`` requests are used against ``target_url``.
    """

    def __init__(
        self,
        target_url: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        max_tags: int = DEFAULT_MAX_TAGS,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        client: httpx.AsyncClient | None = None,
        use_cache: bool = True,
    ):
        self.target_url = (target_url or "").rstrip("/")
        self.timeout = timeout
        self.max_tags = max(1, int(max_tags))
        self.max_requests = max(1, int(max_requests))
        self._client = client
        self._own_client = client is None
        self._use_cache = use_cache
        self._semaphore = asyncio.Semaphore(_CONCURRENCY)
        self._requests = 0
        self._tags_cache: dict[str, list[str]] = {}
        self._asset_cache: dict[tuple[str, str, str], str | None] = {}

    async def __aenter__(self) -> PluginFingerprinter:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; wp-recon-fingerprint)"},
            )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._own_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- HTTP --------------------------------------------------------------

    async def _get(self, url: str) -> bytes | None:
        if self._client is None:
            await self.__aenter__()
        if self._requests >= self.max_requests:
            return None
        self._requests += 1
        try:
            async with self._semaphore:
                resp = await self._client.get(url)  # type: ignore[union-attr]
            if resp.status_code != 200:
                return None
            return resp.content
        except Exception:
            return None

    async def _list_tags(self, slug: str) -> list[str]:
        if slug in self._tags_cache:
            return self._tags_cache[slug]
        data = await self._get(f"{SVN_BASE}/{slug}/tags/")
        tags = parse_tags(data.decode("utf-8", "replace")) if data else []
        tags = tags[-self.max_tags :]
        self._tags_cache[slug] = tags
        return tags

    async def _upstream_hash(
        self, slug: str, version: str, asset: str
    ) -> str | None:
        key = (slug, version, asset)
        if key in self._asset_cache:
            return self._asset_cache[key]
        data = await self._get(
            f"{SVN_BASE}/{slug}/tags/{version}/{asset}"
        )
        digest = _sha256(data) if data else None
        self._asset_cache[key] = digest
        return digest

    async def _release_dates(self, slug: str) -> dict[str, str]:
        """Best-effort version -> release date map from the wordpress.org API."""
        params = {
            "action": "plugin_information",
            "request[slug]": slug,
        }
        try:
            async with self._semaphore:
                resp = await self._client.get(API_INFO, params=params)  # type: ignore[union-attr]
            if resp.status_code != 200:
                return {}
            data = resp.json()
        except Exception:
            return {}
        changelog = ((data.get("sections") or {}).get("changelog") or "")
        text = re.sub(r"<[^>]+>", "", changelog)
        lines = [ln.strip() for ln in text.splitlines()]
        out: dict[str, str] = {}
        for index, line in enumerate(lines):
            match = re.match(r"^=?\s*(\d+(?:\.\d+)*)\s*=?$", line)
            if not match:
                continue
            window = " ".join(lines[index + 1 : index + 4])
            date_match = _DATE_RE.search(window)
            if date_match:
                out[match.group(1)] = date_match.group(1)
        return out

    # -- public API --------------------------------------------------------

    async def fingerprint(
        self,
        slug: str,
        asset_paths: list[str] | None = None,
        fetch_target: Callable[[str], Awaitable[bytes | None]] | None = None,
        target_modified: datetime | None = None,
    ) -> PluginFingerprint:
        """Resolve ``slug``'s version, or return a low-confidence range."""
        result = PluginFingerprint(slug=slug)
        cache_key = (
            self.target_url,
            slug,
            datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        )
        if self._use_cache and cache_key in _CACHE:
            return _CACHE[cache_key]

        assets = list(asset_paths or DEFAULT_ASSETS.get(slug) or ["index.php"])
        assets = assets[:3]

        tags = await self._list_tags(slug)
        if not tags:
            result.error = "no numeric upstream tags found"
            result.requests_made = self._requests
            self._remember(cache_key, result)
            return result

        matched: dict[str, list[str]] = {}
        for asset in assets:
            target_hash = await self._target_hash(
                slug, asset, fetch_target
            )
            if not target_hash:
                continue
            result.assets[asset] = target_hash
            hashes = await asyncio.gather(
                *(self._upstream_hash(slug, v, asset) for v in tags)
            )
            versions = [v for v, h in zip(tags, hashes) if h == target_hash]
            if versions:
                matched[asset] = versions

        result.matched_assets = matched
        result.requests_made = self._requests

        if not matched:
            result.error = "target assets did not match any upstream tag"
            self._remember(cache_key, result)
            return result

        sets = [set(v) for v in matched.values()]
        common = set.intersection(*sets)
        if common:
            candidates = sorted(common, key=version_key)
            result.candidates = candidates
        else:
            # Assets disagree: a trunk/dev build, or one asset is stale.
            union = sorted(set().union(*sets), key=version_key)
            result.candidates = union
            result.error = "assets disagree across upstream tags"

        if target_modified is not None:
            result.target_modified = target_modified.isoformat()
            dates = await self._release_dates(slug)
            result.release_dates = {
                v: d for v, d in dates.items() if v in result.candidates
            }
            before = _versions_before(result.release_dates, target_modified)
            if before:
                result.candidates = before

        if result.candidates:
            result.version = result.candidates[-1]
            # Exact single-version intersection from two or more assets is the
            # only high-confidence outcome; a range stays medium.
            if len(result.candidates) == 1 and len(sets) >= 2:
                result.confidence = "high"
            elif result.error:
                result.confidence = "low"
            else:
                result.confidence = "medium"

        self._remember(cache_key, result)
        return result

    async def _target_hash(
        self,
        slug: str,
        asset: str,
        fetch_target: Callable[[str], Awaitable[bytes | None]] | None,
    ) -> str | None:
        try:
            if fetch_target is not None:
                data = await fetch_target(asset)
            elif self.target_url:
                data = await self._get(
                    f"{self.target_url}/wp-content/plugins/{slug}/{asset}"
                )
            else:
                return None
        except Exception:
            return None
        if not data:
            return None
        # Soft-404/SPA shells must not be hashed as if they were the asset.
        if asset.endswith((".css", ".js")) and _looks_like_html(data):
            return None
        return _sha256(data)

    @staticmethod
    def _remember(key: tuple[str, str, str], result: PluginFingerprint) -> None:
        # Only cache resolved lookups; a transient network failure should be
        # retried by a later step in the same scan.
        if result.candidates or result.error.startswith("no numeric"):
            _CACHE[key] = result


def _versions_before(
    release_dates: dict[str, str], installed_at: datetime
) -> list[str]:
    """Keep versions released at/before the target file's mtime."""
    kept: list[str] = []
    for version, date_text in release_dates.items():
        parsed = _parse_date(date_text)
        if parsed is not None and parsed <= installed_at:
            kept.append(version)
    kept.sort(key=version_key)
    return kept
