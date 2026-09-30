# recon_wp/steps/webapp/management_console_step.py
"""Management-console discovery, version fingerprinting and advisory matching.

WHAT: Probes well-known management/config UIs (Nginx Proxy Manager, Portainer,
      Grafana, Jenkins, Kibana, Jupyter, ...), fingerprints them from a
      signature and extracts the running version, then matches it against a
      local advisory database.
HOW:  A JSON database (``wordlists/webapp/management_consoles.json``) supplies
      probe paths, a signature regex, version paths/regex/header and affected
      ranges. Versions are compared with ``utils.version.cve_applies``.
WHY:  An exposed, outdated management console is frequently the highest-impact
      finding of an engagement (e.g. Nginx Proxy Manager <= 2.15.1, CVE-2026-40519).
      Discovery used to rely on the analyst curling ``/api/`` by hand.

The database is intentionally small and advisory-based; it is not a full
product CVE feed.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.target_net import pinned_ip
from utils.version import cve_applies
from utils.wordlist_loader import get_wordlist_path

_DB_FILE = "webapp/management_consoles.json"

# Service names that indicate an HTTP(S) endpoint worth probing (nmap).
_HTTP_SERVICE_RE = re.compile(r"(?i)^(https?|ssl/http|http-proxy|http-alt)$")

# Fallback DB used only when the wordlist file is missing.
_FALLBACK_CONSOLES = [
    {
        "name": "Nginx Proxy Manager",
        "kind": "management",
        "probe_paths": ["/api/", "/"],
        "signature": r"(?i)nginx\s*proxy\s*manager|nginx-proxy-manager",
        "version_paths": ["/api/"],
        "version_pattern": r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
        "advisories": [],
    },
    {
        "name": "Grafana",
        "kind": "management",
        "probe_paths": ["/api/health", "/login"],
        "signature": r"(?i)grafana",
        "version_paths": ["/api/health"],
        "version_pattern": r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
        "advisories": [],
    },
]

_MAX_BASES = 4


class ManagementConsoleStep(BaseHttpStep):
    """Discover management consoles and match their versions to advisories."""

    name = "management_console"
    description = "Fingerprint management consoles and match versions to advisories"
    severity = "high"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        if getattr(self.config, "webapp_mgmt_console_probe", True) is False:
            self.logger.info("Management-console probe disabled")
            return self.findings

        consoles = self._load_consoles()
        if not consoles:
            return self.findings

        self.logger.info(
            f"Probing {len(consoles)} management-console signature(s)..."
        )

        for base, headers in self._candidate_bases():
            for console in consoles:
                await self._probe_console(base, headers, console)

        self.logger.info(
            f"Management-console probe: {len(self.findings)} finding(s)"
        )
        return self.findings

    # -- database ---------------------------------------------------------

    def _load_consoles(self) -> list[dict]:
        path = get_wordlist_path(_DB_FILE)
        if path and path.exists():
            try:
                data = json.loads(path.read_text())
                if isinstance(data, list) and data:
                    return [c for c in data if isinstance(c, dict)]
            except Exception as exc:
                self.logger.warning(f"Failed to load management-console DB: {exc}")
        self.logger.warning(
            "Management-console DB not found - using the built-in fallback"
        )
        return _FALLBACK_CONSOLES

    # -- target bases -----------------------------------------------------

    def _candidate_bases(self) -> list[tuple[str, dict]]:
        """Return (base_url, extra_headers) pairs to probe.

        The primary target URL first, then any additional HTTP ports nmap
        discovered (so a console on e.g. port 81 is still found). For pinned
        targets the URL points at the connect IP and the real hostname travels
        in the Host header.
        """
        target_url = str(getattr(self.target, "url", "") or "").rstrip("/")
        bases: list[tuple[str, dict]] = []
        seen: set[str] = set()

        if target_url:
            bases.append((target_url, {}))
            seen.add(target_url)

        parsed = urlsplit(target_url)
        primary_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connect_ip = pinned_ip(self.target)
        host = connect_ip or parsed.hostname or ""
        domain = getattr(self.target, "domain", "") or ""
        if not isinstance(domain, str):
            domain = ""
        pinned = bool(connect_ip)

        ctx = self.ctx
        services = ctx.get("services") if ctx is not None else None
        if not isinstance(services, list):
            services = []

        for service in services:
            if len(bases) >= _MAX_BASES:
                break
            if not isinstance(service, dict):
                continue
            name = str(service.get("service") or "")
            if not _HTTP_SERVICE_RE.match(name):
                continue
            try:
                port = int(service.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if not port or port == primary_port:
                continue
            scheme = "https" if ("ssl" in name or port in (443, 8443)) else "http"
            url = f"{scheme}://{host}:{port}"
            if url in seen:
                continue
            seen.add(url)
            headers = {}
            if pinned and domain:
                headers["Host"] = f"{domain}:{port}"
            bases.append((url, headers))

        return bases

    # -- probing ----------------------------------------------------------

    async def _probe_console(
        self, base: str, headers: dict, console: dict
    ) -> None:
        name = console.get("name", "unknown")
        signature = console.get("signature") or ""
        response = None
        matched = False

        for path in console.get("probe_paths", []) or []:
            url = f"{base}/{path.lstrip('/')}"
            try:
                candidate = await self.http.request(
                    "GET", url, headers=headers or None, follow_redirects=True
                )
            except Exception as exc:
                self.logger.debug(f"Console probe {url} failed: {exc}")
                continue
            status = getattr(candidate, "status_code", None)
            if status not in (200, 401, 403):
                continue
            body = getattr(candidate, "text", "") or ""
            header_text = " ".join(
                f"{k}: {v}"
                for k, v in (getattr(candidate, "headers", None) or {}).items()
            )
            if signature and re.search(signature, f"{body}\n{header_text}", re.I):
                response = candidate
                matched = True
                break

        if not matched or response is None:
            return

        version = self._extract_version(response, console)
        if version is None and console.get("version_paths"):
            version = await self._probe_version_paths(base, headers, console)

        base_url = self.public_url(response, base)
        if version is None:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title=f"Management console detected: {name}",
                description=(
                    f"{name} is reachable at {base_url} but its version could "
                    "not be determined, so no advisory could be matched."
                ),
                evidence=f"{base_url} - signature matched",
                recommendation=(
                    "Restrict access to the console and verify it is patched."
                ),
                raw={"console": name, "url": base_url, "version": None},
            )
            return

        self._match_advisories(name, version, base_url, console)

    def _extract_version(self, response, console: dict) -> str | None:
        header_name = console.get("version_header")
        if header_name:
            value = (getattr(response, "headers", None) or {}).get(header_name)
            if value:
                version = self._search_version(console.get("version_pattern"), value)
                if version:
                    return version
        return self._search_version(
            console.get("version_pattern"), getattr(response, "text", "") or ""
        )

    async def _probe_version_paths(
        self, base: str, headers: dict, console: dict
    ) -> str | None:
        for path in console.get("version_paths", []) or []:
            url = f"{base}/{path.lstrip('/')}"
            try:
                resp = await self.http.request(
                    "GET", url, headers=headers or None, follow_redirects=True
                )
            except Exception:
                continue
            if getattr(resp, "status_code", None) != 200:
                continue
            version = self._search_version(
                console.get("version_pattern"), getattr(resp, "text", "") or ""
            )
            if version:
                return version
        return None

    @staticmethod
    def _search_version(pattern: str | None, text: str) -> str | None:
        if not pattern or not text:
            return None
        try:
            match = re.search(pattern, text)
        except re.error:
            return None
        if not match:
            return None
        return match.group(1) if match.groups() else match.group(0)

    def _match_advisories(
        self, name: str, version: str, base_url: str, console: dict
    ) -> None:
        matched_any = False
        for adv in console.get("advisories", []) or []:
            if not isinstance(adv, dict):
                continue
            applies = cve_applies(version, adv.get("fixed_in"))
            if applies is False:
                continue
            matched_any = True
            severity = str(adv.get("severity", "medium")).lower()
            if severity not in ("low", "medium", "high", "critical"):
                severity = "medium"
            confidence = "high" if applies else "low"
            cve = adv.get("cve", "advisory")
            self._add_finding(
                module=self.MODULE,
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                title=f"{name} {version} - {cve}",
                description=(
                    f"{name} {version} is exposed at {base_url} and is affected "
                    f"by {cve}: {adv.get('title', '')}. "
                    f"Fixed in {adv.get('fixed_in', 'a later release')}."
                ),
                evidence=(
                    f"URL: {base_url}\n"
                    f"Product: {name}\n"
                    f"Version: {version}\n"
                    f"CVE: {cve}\n"
                    f"Fixed in: {adv.get('fixed_in', 'N/A')}"
                ),
                recommendation=(
                    f"Update {name} to >= {adv.get('fixed_in', 'the latest release')}"
                    " and restrict the console to trusted networks/SSO."
                ),
                raw={
                    "console": name,
                    "version": version,
                    "url": base_url,
                    "cve": cve,
                    "fixed_in": adv.get("fixed_in"),
                },
            )

        if not matched_any:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title=f"Management console detected: {name} {version}",
                description=(
                    f"{name} {version} is reachable at {base_url}. No matching "
                    "advisory in the local database."
                ),
                evidence=f"{base_url} - version {version}",
                recommendation=(
                    "Restrict access and keep the console updated."
                ),
                raw={"console": name, "version": version, "url": base_url},
            )
