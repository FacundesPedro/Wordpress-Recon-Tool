# recon_wp/core/scan_context.py
"""Shared per-target scan context (blackboard) and lazy web artifacts.

WHAT: A single object, created once per target by the Runner, that steps use to
      share data instead of each re-fetching the same resources.
HOW:  - ``ScanContext`` stores named computed artifacts (``set``/``get``/``wait``)
        and publishes a ``WebArtifacts`` fetcher for raw HTTP responses.
      - ``WebArtifacts`` memoizes common responses (homepage, /wp-json/,
        robots.txt) and is single-flight: concurrent callers asking for the
        same resource trigger exactly one HTTP request.
WHY:  ~30 steps re-fetch the homepage and many re-query /wp-json/; the context
      removes that duplicate traffic without changing step semantics.

Only anonymous GET/HEAD responses are memoized. Callers that pass an
``Authorization``/``Cookie`` header bypass the cache, and a successful login
step can call ``ctx.web.invalidate()`` so later authenticated reads are fresh.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import Any

from core.logger import Logger
from utils.soft404 import Soft404Detector

_GENERATOR_RE = re.compile(
    r'name="generator"[^>]*content="WordPress ([\d.]+)"', re.I
)
_WP_CONTENT_RE = re.compile(r"/wp-content/(?:themes|plugins|includes)/")

# Artifacts WebArtifacts can resolve lazily, so a step may ``requires`` them
# without a dedicated producer step existing.
LAZY_ARTIFACTS = frozenset({"homepage", "wp_json", "robots", "wordpress"})


class WebArtifacts:
    """Lazy, memoized, single-flight access to common target responses."""

    def __init__(
        self,
        http,
        target_url: str,
        config: Any = None,
        logger: Logger | None = None,
    ):
        self._http = http
        self._target_url = (target_url or "").rstrip("/")
        self._config = config
        self._logger = logger or Logger("WebArtifacts")
        self._memo: dict[str, Any] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self.requests_made = 0
        self.requests_saved = 0

    @property
    def target_url(self) -> str:
        return self._target_url

    def _url(self, path: str = "") -> str:
        path = (path or "").lstrip("/")
        return f"{self._target_url}/{path}" if path else self._target_url

    @staticmethod
    def _has_auth(headers: Any) -> bool:
        if not headers:
            return False
        try:
            return any(
                str(key).lower() in ("authorization", "cookie") for key in headers
            )
        except TypeError:
            return False

    async def _request(self, method: str, url: str, **kwargs):
        return await self._http.request(method, url, **kwargs)

    async def _memoized(self, key: str, factory: Callable[[], Awaitable[Any]]):
        if key in self._memo:
            self.requests_saved += 1
            return self._memo[key]
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        async with lock:
            if key in self._memo:  # another task completed while we waited
                self.requests_saved += 1
                return self._memo[key]
            response = await factory()
            self._memo[key] = response
            self.requests_made += 1
            return response

    async def response(
        self,
        method: str,
        url: str,
        *,
        cache: bool = True,
        **kwargs,
    ):
        """Generic request. Memoizes idempotent anonymous requests by default."""
        method = method.upper()
        if method not in ("GET", "HEAD") or not cache:
            return await self._request(method, url, **kwargs)
        if self._has_auth(kwargs.get("headers")):
            return await self._request(method, url, **kwargs)
        key = f"{method} {url}"
        return await self._memoized(key, lambda: self._request(method, url, **kwargs))

    async def get(self, path: str = "", **kwargs):
        url = self._url(path)
        return await self.response("GET", url, **kwargs)

    async def homepage(self, **kwargs):
        # Canonical root URL with a trailing slash, matching the common
        # ``fetch("/")`` call convention so all homepage readers share one key.
        url = f"{self._target_url}/"
        return await self.response("GET", url, **kwargs)

    async def wp_json(self, **kwargs):
        return await self.get("wp-json/", **kwargs)

    async def robots(self, **kwargs):
        return await self.get("robots.txt", **kwargs)

    async def wordpress(self) -> bool:
        """Detect WordPress from /wp-json/ namespaces or homepage markers.

        Results are memoized by the underlying response cache. Fails closed
        (returns False) on network errors, matching the previous detector.
        """
        try:
            response = await self.wp_json()
            if getattr(response, "status_code", None) == 200:
                headers = getattr(response, "headers", None) or {}
                try:
                    content_type = headers.get("content-type") or ""
                except Exception:
                    content_type = ""
                if "json" in str(content_type).lower():
                    try:
                        data = response.json()
                        if isinstance(data, dict) and "namespaces" in data:
                            return True
                    except Exception:
                        pass
        except Exception as exc:
            self._logger.debug(f"wp-json probe failed: {exc}")

        try:
            response = await self.homepage()
            if getattr(response, "status_code", None) == 200:
                text = getattr(response, "text", "") or ""
                if _WP_CONTENT_RE.search(text) or _GENERATOR_RE.search(text):
                    return True
        except Exception as exc:
            self._logger.debug(f"homepage probe failed: {exc}")

        return False

    def invalidate(self, *keys: str) -> None:
        """Drop memoized responses (all, or only the given cache keys)."""
        if not keys:
            self._memo.clear()
            return
        for key in keys:
            self._memo.pop(key, None)


class ScanContext:
    """Per-target blackboard shared across every step in a scan.

    Attach to the HttpClient (``http.scan_context``) so steps and helpers such
    as ``utils.wordpress_detect.is_wordpress`` can reach it without a
    constructor change.
    """

    def __init__(
        self,
        http=None,
        target_url: str = "",
        config: Any = None,
        logger: Logger | None = None,
    ):
        self.http = http
        self.config = config
        self.target_url = (target_url or "").rstrip("/")
        self._logger = logger or Logger("ScanContext")
        self._artifacts: dict[str, Any] = {}
        self._missing: set[str] = set()
        self._events: dict[str, asyncio.Event] = {}
        self._soft404: dict[str, Soft404Detector] = {}
        # Set once a 200 catch-all shell is detected on any probed base URL.
        self.enumeration_unreliable: bool = False
        self.web: WebArtifacts | None = None
        if http is not None:
            self.web = WebArtifacts(
                http, self.target_url, config=config, logger=self._logger
            )

    # ── artifact store ──────────────────────────────────────────────
    def set(self, key: str, value: Any) -> None:
        self._artifacts[key] = value
        self._missing.discard(key)
        event = self._events.get(key)
        if event is not None:
            event.set()

    def get(self, key: str, default: Any = None) -> Any:
        return self._artifacts.get(key, default)

    def has(self, key: str) -> bool:
        return key in self._artifacts

    def mark_missing(self, *keys: str) -> None:
        """Mark keys whose producer failed so waiters unblock with None."""
        for key in keys:
            self._missing.add(key)
            event = self._events.get(key)
            if event is not None:
                event.set()

    def is_missing(self, key: str) -> bool:
        return key in self._missing

    async def wait(self, key: str, timeout: float | None = None) -> Any:
        """Return the artifact, waiting up to ``timeout`` for a producer."""
        if key in self._artifacts:
            return self._artifacts[key]
        if key in self._missing:
            return None
        event = self._events.get(key)
        if event is None:
            event = asyncio.Event()
            self._events[key] = event
        if timeout is None:
            await event.wait()
        else:
            try:
                await asyncio.wait_for(event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return None
        return self._artifacts.get(key)

    @property
    def stats(self) -> dict[str, int]:
        if self.web is None:
            return {"requests_made": 0, "requests_saved": 0}
        return {
            "requests_made": self.web.requests_made,
            "requests_saved": self.web.requests_saved,
        }

    # ── soft-404 / catch-all capability ─────────────────────────────
    async def soft404_detector(
        self, base_url: str | None = None, scope_prefix: str = ""
    ) -> Soft404Detector:
        """Return a calibrated soft-404 detector for ``base_url``.

        ``scope_prefix`` narrows the calibration canaries to a directory
        (e.g. ``wp-content/plugins``) so a path-scoped catch-all/denial is
        detected where it actually occurs. The detector is memoized per
        (base URL, scope) and calibrated once, so multiple discovery steps
        share the canary probes. When a 200 catch-all shell is found,
        ``enumeration_unreliable`` is set so callers can annotate the report
        (path enumeration by status code is meaningless there).
        """
        base = (base_url or self.target_url or "").rstrip("/")
        scope = (scope_prefix or "").strip("/")
        key = f"{base}#{scope}" if scope else base
        detector = self._soft404.get(key)
        if detector is not None:
            return detector

        detector = Soft404Detector(
            self.http, base, self._logger, scope_prefix=scope
        )
        try:
            await detector.calibrate()
        except Exception as exc:  # never fail a step on calibration
            self._logger.debug(f"Soft-404 calibration failed for {key}: {exc}")
        self._soft404[key] = detector
        if detector.calibrated:
            self.enumeration_unreliable = True
            self._logger.info(
                f"Catch-all/soft-404 detected for {key}; content comparison "
                "required for path enumeration"
            )
        return detector

    @property
    def enumeration_is_unreliable(self) -> bool:
        """True once any calibrated base URL served a 200 catch-all shell."""
        return self.enumeration_unreliable
