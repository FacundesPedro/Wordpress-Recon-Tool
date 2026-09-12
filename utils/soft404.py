# recon_wp/utils/soft404.py
"""Soft-404 / SPA catch-all detection - shared calibration helper.

WHAT: Learns how a server responds to paths that do not exist and
      classifies later responses as "shell" (false positive) or real.
HOW:  Probes 1-2 random canary paths at calibration time, fingerprints the
      response (status, content-type, body length, HTML title, body head),
      and matches subsequent responses against that fingerprint.
WHY:  SPA servers (Angular/React/Next) and soft-404 handlers answer HTTP
      200 with the same shell for every unknown path. Without calibration,
      path-probing steps (admin_surface, sensitive_files, ...) report
      hundreds of false positives.

References:
- Wapiti soft-404 detection (github.com/wapiti-scanner/wapiti PR #809)
- ffuf autocalibration (github.com/ffuf/ffuf/wiki/Autocalibration)
- feroxbuster heuristics (epi052/feroxbuster src/heuristics.rs)
"""

import re
import secrets
from dataclasses import dataclass, field
from typing import Optional

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Body-length delta treated as "same page": the larger of 10% of the
# baseline length or an absolute 64-byte floor. The floor matters for
# small shells (a 150-byte error page with a dynamic nonce would exceed
# a pure 10% ratio while still being the same page).
LENGTH_TOLERANCE = 0.1
LENGTH_ABSOLUTE_FLOOR = 64

# Non-200 statuses that catch-all servers return for unknown paths.
_CATCHALL_STATUSES = frozenset({301, 302, 303, 307, 308, 401, 403})


def extract_title(text: str) -> str:
    """Extract a cleaned <title> from HTML, or "" if absent."""
    if not isinstance(text, str):
        return ""
    match = _TITLE_RE.search(text or "")
    if not match:
        return ""
    return " ".join(match.group(1).split())[:120]


@dataclass
class ResponseFingerprint:
    """Fingerprint of a baseline 'does not exist' response."""

    status: int = 0
    content_type: str = ""
    length: int = 0
    title: str = ""
    head: str = ""  # first N bytes of the body

    @classmethod
    def from_response(cls, response) -> "ResponseFingerprint":
        text = getattr(response, "text", "") or ""
        if not isinstance(text, str):
            text = ""
        headers = getattr(response, "headers", None) or {}
        try:
            content_type = headers.get("content-type") or ""
        except Exception:
            content_type = ""
        if not isinstance(content_type, str):
            content_type = ""
        return cls(
            status=getattr(response, "status_code", 0) or 0,
            content_type=content_type,
            length=len(text),
            title=extract_title(text),
            head=text[:200],
        )

    @property
    def empty(self) -> bool:
        return self.status == 0 and self.length == 0


def is_html_body(text: str, content_type: str = "") -> bool:
    """True when the payload is an HTML document.

    Checks the first ~500 bytes for HTML document markers rather than the
    exact prefix: many SPA shells start with a license/build comment block
    before <!doctype html> (e.g. Angular apps), which defeats startswith().
    The Content-Type header is a primary signal.
    """
    if "text/html" in (content_type or "").lower():
        return True
    head = (text or "")[:500].lower()
    return "<!doctype" in head or "<html" in head


class Soft404Detector:
    """Calibrates against canary paths and classifies responses.

    Usage:
        detector = Soft404Detector(http, base_url, logger)
        await detector.calibrate()
        ...
        if detector.is_soft404(response):
            continue  # SPA shell / soft-404 - skip
    """

    def __init__(self, http, base_url: str, logger, probes: int = 2):
        self.http = http
        self.base_url = base_url.rstrip("/")
        self.logger = logger
        self.probes = max(1, probes)
        self.baseline = ResponseFingerprint()
        self._catchall_baselines: dict[int, ResponseFingerprint] = {}
        self._token = secrets.token_hex(6)

    async def calibrate(self) -> ResponseFingerprint:
        """Probe random nonexistent paths and fingerprint the shell.

        A 200 response becomes the primary baseline. Other catch-all
        statuses (301/302/303/307/308/401/403) are recorded per status so
        blanket redirects and blanket denials are also suppressed.
        """
        canaries = [
            f"/recon-baseline-{self._token}",
            f"/recon-{self._token}.no-such-ext",
        ][: self.probes]
        for path in canaries:
            try:
                response = await self.http.request(
                    "GET", f"{self.base_url}{path}"
                )
            except Exception as e:
                self.logger.debug(f"Soft-404 calibration {path} failed: {e}")
                continue
            status = getattr(response, "status_code", None)
            fingerprint = ResponseFingerprint.from_response(response)
            if fingerprint.empty:
                continue
            if status == 200:
                self.baseline = fingerprint
                self.logger.debug(
                    f"Soft-404 baseline: status={fingerprint.status} "
                    f"len={fingerprint.length} "
                    f"title='{fingerprint.title[:40]}' "
                    f"ct='{fingerprint.content_type[:40]}'"
                )
                break
            if status in _CATCHALL_STATUSES:
                self._catchall_baselines.setdefault(status, fingerprint)
                self.logger.debug(
                    f"Soft-404 catch-all baseline: status={status} "
                    f"len={fingerprint.length} "
                    f"title='{fingerprint.title[:40]}'"
                )
        return self.baseline

    @property
    def calibrated(self) -> bool:
        """True when a 200-shell baseline was learned."""
        return not self.baseline.empty

    def is_soft404(self, response) -> bool:
        """Classify a response against the calibrated baseline.

        A response is a soft-404/catch-all when it matches the baseline for
        its status code on any of (in order of confidence):
        1. byte-identical body head
        2. same HTML title AND body length within tolerance
        3. same content-type AND body length within tolerance

        The primary baseline covers 200 shells; per-status baselines cover
        blanket redirects and blanket denials (301/302/303/307/308/401/403)
        recorded during calibration.
        """
        fingerprint = ResponseFingerprint.from_response(response)
        if self.calibrated and fingerprint.status == self.baseline.status:
            baseline = self.baseline
        else:
            baseline = self._catchall_baselines.get(fingerprint.status)
        if baseline is None or baseline.empty:
            return False
        return self._matches(fingerprint, baseline)

    @staticmethod
    def _matches(fingerprint: ResponseFingerprint, baseline: ResponseFingerprint) -> bool:
        # 0. both bodies empty (some servers return bare 200s)
        if fingerprint.length == 0 and baseline.length == 0:
            return True

        # Both pages carry titles: a different title means a different page,
        # even when the template boilerplate (head) and size match.
        if (
            baseline.title
            and fingerprint.title
            and fingerprint.title != baseline.title
        ):
            return False

        # 1. byte-identical head (strongest signal)
        if fingerprint.head and fingerprint.head == baseline.head:
            return True

        # 2. same title + similar length
        if (
            baseline.title
            and fingerprint.title == baseline.title
            and _similar_length(fingerprint.length, baseline.length)
        ):
            return True

        # 3. same content-type + similar length (title-less shells only;
        #    a differing title means a different page even at similar size)
        if (
            not baseline.title
            and baseline.content_type
            and fingerprint.content_type == baseline.content_type
            and _similar_length(fingerprint.length, baseline.length)
        ):
            return True

        return False

    def _similar_length(self, length: int) -> bool:
        return _similar_length(length, self.baseline.length)


def _similar_length(length: int, baseline_len: int) -> bool:
    if baseline_len <= 0:
        return length == 0
    tolerance = max(LENGTH_TOLERANCE * baseline_len, LENGTH_ABSOLUTE_FLOOR)
    return abs(length - baseline_len) <= tolerance
