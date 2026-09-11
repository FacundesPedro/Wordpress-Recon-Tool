# recon_wp/steps/webapp/js_library_step.py
"""
JavaScript library vulnerability audit - version detection + SRI check.

Covers WSTG 4.11.6 (Client-side Resource Manipulation) and supply-chain
risk: detects JS libraries and versions from script URLs and banner comments,
matches them against a vendored vulnerable-version database
(`wordlists/webapp/js_libraries.json`, derived from Retire.js), and flags
third-party scripts served without Subresource Integrity.
"""

# WHAT: Detects JS libraries with known-vulnerable versions and missing SRI
# HOW: Parses <script src> URLs and banner comments; compares versions to the
#      vendored library DB; flags cross-origin scripts without integrity=
# WHY: Outdated client-side libraries are a top exposure and cheap to detect

import json
import re
from typing import Optional
from urllib.parse import urlparse

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.wordlist_loader import get_wordlist_path

_SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
_INTEGRITY_RE = re.compile(r"integrity\s*=", re.I)
_BANNER_RES: list[tuple[str, re.Pattern]] = [
    ("jQuery", re.compile(r"jQuery (?:JavaScript Library )?v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("jQuery UI", re.compile(r"jQuery UI -? v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("Bootstrap", re.compile(r"Bootstrap v(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("lodash", re.compile(r"lodash(?:\.js)? v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("underscore", re.compile(r"Underscore\.js (\d+\.\d+(?:\.\d+)?)", re.I)),
    ("moment", re.compile(r"moment\.js v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("AngularJS", re.compile(r"AngularJS v(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("axios", re.compile(r"axios v(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("DOMPurify", re.compile(r"DOMPurify (\d+\.\d+(?:\.\d+)?)", re.I)),
    ("Handlebars", re.compile(r"Handlebars v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("marked", re.compile(r"marked v?(\d+\.\d+(?:\.\d+)?)", re.I)),
]

_VERSION_IN_URL_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_MAX_FINDINGS = 8


def version_tuple(version: str) -> tuple:
    """Parse '1.2.3' into a 3-component tuple for comparison."""
    parts = []
    for piece in version.split("."):
        digits = re.match(r"\d+", piece)
        parts.append(int(digits.group()) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def detect_from_url(url: str, libraries: list[dict]) -> Optional[dict]:
    """Match a script URL against library file patterns."""
    lowered = url.lower()
    for lib in libraries:
        pattern = lib.get("file_pattern", "")
        if not pattern:
            continue
        try:
            if re.search(pattern, lowered):
                return lib
        except re.error:
            continue
    return None


def detect_from_banner(content: str) -> Optional[tuple[str, str]]:
    """Detect (library, version) from a banner comment in JS content."""
    for name, regex in _BANNER_RES:
        match = regex.search(content or "")
        if match:
            return name, match.group(1)
    return None


def version_from_url(url: str) -> Optional[str]:
    """Extract a plausible version from a script URL path/query."""
    match = _VERSION_IN_URL_RE.search(urlparse(url).path or url)
    if not match:
        return None
    major, minor, patch = match.group(1), match.group(2), match.group(3) or "0"
    return f"{major}.{minor}.{patch}"


def is_vulnerable(version: str, below: str) -> bool:
    """True when version < below (component-wise)."""
    try:
        return version_tuple(version) < version_tuple(below)
    except Exception:
        return False


class JsLibraryStep(BaseHttpStep):
    """Detect JS libraries, vulnerable versions, and missing SRI."""

    name = "js_library"
    description = "Audit JS libraries for known-vulnerable versions and missing SRI"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Auditing JS libraries (versions + SRI)...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        html = response.text or ""
        scripts = _SCRIPT_RE.findall(html)
        if not scripts:
            self.logger.info("JS library audit: no scripts found")
            return self.findings

        libraries = self._load_libraries()
        reported: set[str] = set()

        for src in scripts[:30]:
            absolute = src if src.startswith("http") else None
            lib = detect_from_url(src, libraries)

            # 1. Version from URL path (e.g. jquery-3.4.1.min.js)
            if lib:
                version = version_from_url(src)
                if version and is_vulnerable(version, lib.get("vulnerable_below", "")):
                    self._report_version(lib, version, src)
                    reported.add(lib.get("name", ""))

            # 2. SRI check for cross-origin third-party scripts
            if absolute and not _INTEGRITY_RE.search(
                self._script_tag_for(html, src)
            ):
                parsed = urlparse(absolute)
                target_host = urlparse(self.target.url).netloc
                if parsed.netloc and parsed.netloc != target_host:
                    self._report_sri(absolute)

        # 3. Banner detection in fetched JS content
        try:
            from utils.source_discovery import extract_asset_urls, fetch_assets
            asset_urls = extract_asset_urls(html, self.target.url)
            assets = await fetch_assets(
                self.http, self.target.url, asset_urls,
                max_files=int(getattr(self.config, "source_scan_max_js", 20)),
                max_bytes=int(getattr(self.config, "source_scan_max_bytes", 1000000)),
            )
            for url, content in assets:
                detected = detect_from_banner(content)
                if not detected:
                    continue
                name, version = detected
                if name in reported:
                    continue
                lib = next(
                    (l for l in libraries
                     if l.get("name", "").lower() == name.lower()), None
                )
                if lib and is_vulnerable(version, lib.get("vulnerable_below", "")):
                    self._report_version(lib, version, url)
                    reported.add(name)
        except Exception as e:
            self.logger.debug(f"JS asset fetch failed: {e}")

        self.logger.info(f"JS library audit: {len(self.findings)} finding(s)")
        return self.findings

    def _load_libraries(self) -> list[dict]:
        path = get_wordlist_path("webapp/js_libraries.json")
        if path and path.exists():
            try:
                data = json.loads(path.read_text())
                if isinstance(data, list) and data:
                    return data
            except Exception as e:
                self.logger.warning(f"Failed to load JS library DB: {e}")
        self.logger.warning(
            "JS library DB not found - URL/SRI checks only (no version DB)"
        )
        return []

    def _script_tag_for(self, html: str, src: str) -> str:
        for match in _SCRIPT_RE.finditer(html):
            if match.group(1) == src:
                start = max(0, match.start() - 200)
                return html[start:match.end() + 100]
        return ""

    def _report_version(self, lib: dict, version: str, src: str) -> None:
        name = lib.get("name", "unknown")
        below = lib.get("vulnerable_below", "")
        cve = lib.get("cve", "")
        self._add_finding(
            module=self.MODULE,
            severity="medium",
            title=f"Vulnerable JS library: {name} {version} (< {below})",
            description=(
                f"{name} {version} is below the known-vulnerable threshold "
                f"{below} ({cve}): {lib.get('summary', '')}"
            ),
            evidence=f"script src: {src[:200]} (version {version})",
            recommendation=f"Upgrade {name} to >= {below}",
            raw={"library": name, "version": version,
                 "vulnerable_below": below, "cve": cve},
        )

    def _report_sri(self, url: str) -> None:
        self._add_finding(
            module=self.MODULE,
            severity="low",
            title="Third-party script without Subresource Integrity",
            description=(
                "A cross-origin script is loaded without an integrity "
                "attribute. If the third-party host is compromised, its "
                "code runs on your origin."
            ),
            evidence=f"script src: {url[:200]} (no integrity=)",
            recommendation="Add integrity/crossorigin attributes or self-host the script",
            raw={"url": url},
        )
