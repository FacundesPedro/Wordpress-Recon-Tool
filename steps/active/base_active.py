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
from core.finding import Finding

_PARAM_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.I)
_ACTION_RE = re.compile(r'<form[^>]+action\s*=\s*["\']([^"\']*)["\']', re.I)
_INPUT_RE = re.compile(r"<input[^>]+>", re.I)
_NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.I)


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

    def __init__(self, target, config, http):
        super().__init__(target=target, config=config, http=http)
        self._requests_sent = 0

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
            return await self.fetch(path, method, **kwargs)
        except Exception as e:
            self.logger.debug(f"Probe {method} {path} failed: {e}")
            return None

    async def discover_params(self) -> list[tuple[str, str]]:
        """Discover (path, param) pairs from homepage links and forms."""
        pairs: list[tuple[str, str]] = []
        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return pairs
        html = response.text or ""
        pairs.extend(extract_query_params(html))
        seen = {(p, n) for p, n in pairs}
        for action, name in extract_form_fields(html):
            key = (action, name)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
        return pairs[: self.max_params()]

    def add_finding(self, severity: str, title: str, description: str,
                    evidence: str, recommendation: str,
                    raw: Optional[dict] = None) -> None:
        self._add_finding(
            module=self.MODULE,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            raw=raw or {},
        )
