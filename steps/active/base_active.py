# recon_wp/steps/active/base_active.py
"""
Shared base for active (intrusive) testing steps.

Provides:
- Master-switch gating (`WP_ACTIVE_ENABLED`)
- Hard request caps (`WP_ACTIVE_MAX_REQUESTS`) and inter-probe delay
  (`WP_ACTIVE_DELAY`)
- Query-parameter discovery from the homepage (links + form inputs)

Every active step must call `self.gate()` at the start of run() and use
`self.probe()` for all requests so caps and delays are enforced.
"""

# WHAT: Base class for intrusive active testing steps
# HOW: Gate check + request cap/delay accounting + param extraction helpers
# WHY: Active probes can stress a target; caps and delays keep them bounded

import asyncio
import re
from typing import Optional
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx

from base.http_step import BaseHttpStep
from utils.raw_output import RawArtifactWriter

_PARAM_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.I)
_ACTION_RE = re.compile(r'<form[^>]+action\s*=\s*["\']([^"\']*)["\']', re.I)
_INPUT_RE = re.compile(r"<input[^>]+>", re.I)
_NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.I)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
_API_PATH_RE = re.compile(
    r'["\'`](/[A-Za-z0-9_\-/]*(?:api|rest|graphql|auth|search|user)[A-Za-z0-9_\-/]*)["\'`]',
    re.I,
)
_JS_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_\-]{2,})\s*=")
_JS_PARAMS_OBJ_RE = re.compile(r"params\s*:\s*\{([^}]{0,200})\}")

# Generic parameter names worth testing on a discovered API path when the
# bundle does not reveal specific ones.
COMMON_API_PARAMS = (
    "id", "q", "search", "page", "url", "redirect", "file", "path", "name", "user",
)


def extract_query_params(html: str) -> list[tuple[str, str]]:
    """Extract (path, param) pairs from links carrying query strings."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for href in _PARAM_HREF_RE.findall(html or ""):
        parsed = urlparse(href)
        if not parsed.query:
            continue
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
            key = (parsed.path or "/", name)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs


def extract_form_fields(html: str) -> list[tuple[str, str]]:
    """Extract (action, field_name) pairs from forms."""
    pairs: list[tuple[str, str]] = []
    actions = _ACTION_RE.findall(html or "") or ["/"]
    for action in actions:
        for tag in _INPUT_RE.findall(html or ""):
            match = _NAME_RE.search(tag)
            if match:
                pairs.append((action or "/", match.group(1)))
    return pairs


class ActiveHttpStep(BaseHttpStep):
    """Base class for active testing steps with gating and caps."""

    MODULE = "active"

    def __init_subclass__(cls, **kwargs):
        """Wrap each subclass's run() so request evidence is always persisted."""
        super().__init_subclass__(**kwargs)
        run = cls.__dict__.get("run")
        if run is None or getattr(run, "_recon_evidence_wrapped", False):
            return

        async def wrapped(self, *args, **kw):
            try:
                return await run(self, *args, **kw)
            finally:
                self.persist_evidence()

        wrapped._recon_evidence_wrapped = True
        wrapped.__name__ = getattr(run, "__name__", "run")
        cls.run = wrapped

    def __init__(self, target, config, http):
        super().__init__(target=target, config=config, http=http)
        self._requests_sent = 0
        self._evidence: list[dict] = []

    def persist_evidence(self) -> None:
        """Write this step's probe evidence to raw output (best-effort)."""
        if not self._evidence:
            return
        writer = RawArtifactWriter(config=self.config, logger=self.logger)
        writer.persist_evidence(
            step=self.name,
            records=self._evidence,
            extra={"requests_sent": self._requests_sent},
        )
        self._evidence = []

    def gate(self) -> bool:
        """Check the active-testing master switch.

        Returns True when active testing is enabled; otherwise logs and
        returns False so run() can bail out.
        """
        if getattr(self.config, "active_enabled", False):
            return True
        self.logger.info(
            "Active testing disabled (WP_ACTIVE_ENABLED) - skipping this step"
        )
        return False

    def max_requests(self) -> int:
        return int(getattr(self.config, "active_max_requests", 100))

    def max_params(self) -> int:
        return int(getattr(self.config, "active_max_params", 20))

    def probe_delay(self) -> float:
        return float(getattr(self.config, "active_delay", 0.5))

    def budget_left(self) -> bool:
        return self._requests_sent < self.max_requests()

    async def probe(
        self, path: str, method: str = "GET", **kwargs
    ) -> Optional[httpx.Response]:
        """Send a probe request honoring the request cap and inter-probe delay.

        Returns None when the budget is exhausted or the request fails.
        """
        if not self.budget_left():
            return None
        self._requests_sent += 1
        delay = self.probe_delay()
        if delay > 0:
            await asyncio.sleep(delay)
        try:
            response = await self.fetch(path, method, **kwargs)
        except Exception as e:
            self.logger.debug(f"Probe {method} {path} failed: {e}")
            return None
        self._record_evidence(path, method, response, kwargs)
        return response

    def _record_evidence(self, path, method, response, kwargs) -> None:
        """Append a compact, redactable record of one probe (see B4)."""
        try:
            headers = getattr(response, "headers", None)
            content_type = headers.get("content-type") if headers is not None else ""
        except Exception:
            content_type = ""
        body = getattr(response, "text", "") or ""
        record = {
            "method": method,
            "path": path,
            "url": self.urljoin(path),
            "status": getattr(response, "status_code", None),
            "length": len(body),
            "content_type": content_type or "",
            "snippet": body[:200],
        }
        payload = kwargs.get("data") or kwargs.get("json")
        if payload:
            record["payload"] = str(payload)[:500]
        self._evidence.append(record)

    async def discover_params(self) -> list[tuple[str, str]]:
        """Discover (path, param) pairs for injection testing.

        Homepage links/forms first; on client-rendered SPAs (where the shell
        exposes nothing) also parse same-origin JS bundles for API paths and
        parameter names, and honour operator-supplied ``WP_ACTIVE_PARAMS``
        (``path:param`` comma-separated).
        """
        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(path: str, param: str) -> None:
            key = (path or "/", param)
            if param and key not in seen:
                seen.add(key)
                pairs.append(key)

        html = ""
        try:
            response = await self.fetch("/")
            html = response.text or ""
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")

        for path, name in extract_query_params(html):
            add(path, name)
        for action, name in extract_form_fields(html):
            add(action, name)

        await self._discover_from_js(html, add)
        for path, name in self._operator_params():
            add(path, name)

        if pairs:
            self.logger.info(
                f"Discovered {len(pairs)} parameter target(s) "
                "(homepage/JS/operator)"
            )
        return pairs[: self.max_params()]

    def _operator_params(self) -> list[tuple[str, str]]:
        """Parse operator-supplied ``path:param`` pairs (WP_ACTIVE_PARAMS)."""
        raw = getattr(self.config, "active_params", "") or ""
        if not isinstance(raw, str) or not raw.strip():
            return []
        pairs: list[tuple[str, str]] = []
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            path, param = entry.rsplit(":", 1)
            path = path.strip() or "/"
            param = param.strip()
            if param:
                pairs.append((path, param))
        return pairs

    async def _discover_from_js(self, html: str, add) -> None:
        """Fetch same-origin JS bundles and mine API paths + param names."""
        from base.dependencies import config_int

        max_js = config_int(self.config, "active_js_max", 5)
        if max_js <= 0:
            return
        base_host = urlparse(self.target.url).netloc
        scripts: list[str] = []
        for src in _SCRIPT_SRC_RE.findall(html or ""):
            absolute = urljoin(self.target.url, src)
            if urlparse(absolute).netloc == base_host:
                scripts.append(absolute)
            if len(scripts) >= max_js:
                break
        if not scripts:
            return

        for absolute in scripts:
            path = urlparse(absolute).path.lstrip("/")
            try:
                response = await self.fetch(path)
            except Exception as e:
                self.logger.debug(f"JS fetch failed {path}: {e}")
                continue
            text = response.text or ""
            api_paths: list[str] = []
            for match in _API_PATH_RE.findall(text):
                if match not in api_paths:
                    api_paths.append(match)
            js_params: list[str] = list(_JS_PARAM_RE.findall(text))
            for obj in _JS_PARAMS_OBJ_RE.findall(text):
                js_params.extend(re.findall(r"([A-Za-z0-9_\-]{2,})\s*:", obj))
            for path_found in api_paths:
                params = js_params or list(COMMON_API_PARAMS)
                for param in params:
                    add(path_found, param)
            for param in js_params:
                add("/", param)

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: str, recommendation: str,
                    raw: Optional[dict] = None,
                    confidence: str = "high") -> None:
        self._add_finding(
            module=self.MODULE,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            raw=raw or {},
            confidence=confidence,  # type: ignore[arg-type]
        )
