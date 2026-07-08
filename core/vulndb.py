import time
from dataclasses import dataclass
from typing import Literal, Optional

import httpx

BASE_WPVULN = "https://www.wpvulnerability.net"
BASE_WPSCAN_API = "https://wpscan.com/api/v3"

FindingSeverity = Literal["info", "low", "medium", "high", "critical"]


def cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass
class CveFinding:
    id: str
    title: str
    description: str
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    severity: str = "info"
    fixed_in: Optional[str] = None
    published: str = ""
    source: str = ""


class WPVulnerabilityClient:
    def __init__(self, cache_ttl: int = 300):
        self._cache: dict[str, tuple[float, list[CveFinding]]] = {}
        self._cache_ttl = cache_ttl
        self._http = httpx.AsyncClient(timeout=15)

    async def close(self) -> None:
        await self._http.aclose()

    def _cache_get(self, key: str) -> Optional[list[CveFinding]]:
        entry = self._cache.get(key)
        if entry is None:
            return None
        ts, data = entry
        if time.monotonic() - ts > self._cache_ttl:
            del self._cache[key]
            return None
        return data

    def _cache_set(self, key: str, data: list[CveFinding]) -> None:
        self._cache[key] = (time.monotonic(), data)

    def _get_cve_id(self, vuln: dict) -> str:
        cve = vuln.get("cve") or {}
        if isinstance(cve, dict):
            return cve.get("id", "") or ""
        return vuln.get("id", "") or ""

    def _get_desc(self, vuln: dict) -> str:
        cve = vuln.get("cve") or {}
        if not isinstance(cve, dict):
            return ""
        desc_data = cve.get("description") or {}
        if not isinstance(desc_data, dict):
            return ""
        val = desc_data.get("value", "")
        if val:
            return val
        items = desc_data.get("description_data") or []
        if items:
            return (items[0] or {}).get("value", "")
        return ""

    def _parse_vuln(self, vuln: dict, source: str) -> Optional[CveFinding]:
        cve_id = self._get_cve_id(vuln)
        if not cve_id:
            return None
        desc = self._get_desc(vuln)
        metrics = {}
        if isinstance(vuln.get("cve"), dict):
            metrics = vuln["cve"].get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0] if metrics else {}
        cvss_data = cvss_v31.get("cvssData", {}) if cvss_v31 else {}
        cvss_score: Optional[float] = cvss_data.get("baseScore")
        if cvss_score is not None:
            cvss_score = float(cvss_score)
        cvss_vector = cvss_data.get("vectorString", "")
        return CveFinding(
            id=cve_id,
            title=f"CVE-{cve_id}" if cve_id.startswith("CVE-") else cve_id,
            description=desc[:300] if desc else "",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=cvss_to_severity(cvss_score),
            fixed_in=vuln.get("fixed_in"),
            published=vuln.get("published", ""),
            source=source,
        )

    async def _get_wpvuln(self, endpoint: str, cache_key: str) -> list[CveFinding]:
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            resp = await self._http.get(f"{BASE_WPVULN}/{endpoint}")
            if resp.status_code != 200:
                self._cache_set(cache_key, [])
                return []
            data = resp.json()
        except Exception:
            return []
        raw = (data.get("data") or {}) if isinstance(data.get("data"), dict) else {}
        vulns_data = raw.get("vulnerabilities", [])
        results = []
        for v in vulns_data:
            parsed = self._parse_vuln(v, "wpvulnerability")
            if parsed:
                results.append(parsed)
        self._cache_set(cache_key, results)
        return results

    async def get_plugin_vulns(self, slug: str) -> list[CveFinding]:
        return await self._get_wpvuln(f"plugin/{slug}/", f"plugin:{slug}")

    async def get_theme_vulns(self, slug: str) -> list[CveFinding]:
        return await self._get_wpvuln(f"theme/{slug}/", f"theme:{slug}")

    async def get_core_vulns(self, version: str) -> list[CveFinding]:
        return await self._get_wpvuln(f"core/{version}/", f"core:{version}")


class WPScanClient:
    def __init__(self, api_token: str, cache_ttl: int = 300):
        self._api_token = api_token
        self._cache: dict[str, tuple[float, list[CveFinding]]] = {}
        self._cache_ttl = cache_ttl
        self._headers = {"Authorization": f"Token token={api_token}"}
        self._http = httpx.AsyncClient(timeout=15, headers=self._headers)

    async def close(self) -> None:
        await self._http.aclose()

    def _cache_get(self, key: str) -> Optional[list[CveFinding]]:
        entry = self._cache.get(key)
        if entry is None:
            return None
        ts, data = entry
        if time.monotonic() - ts > self._cache_ttl:
            del self._cache[key]
            return None
        return data

    def _cache_set(self, key: str, data: list[CveFinding]) -> None:
        self._cache[key] = (time.monotonic(), data)

    def _get_vulns_list(self, data) -> list[dict]:
        if isinstance(data, dict):
            return data.get("vulnerabilities", [])
        if isinstance(data, list):
            return data
        return []

    def _parse_vuln(self, vuln: dict) -> Optional[CveFinding]:
        cve_id = (vuln.get("cve") or vuln.get("id") or "").strip()
        if not cve_id:
            return None
        cvss_score: Optional[float] = vuln.get("cvss", {}).get("score")
        if cvss_score is not None:
            cvss_score = float(cvss_score)
        return CveFinding(
            id=cve_id,
            title=vuln.get("title", cve_id),
            description=(vuln.get("description") or "")[:300],
            cvss_score=cvss_score,
            cvss_vector=vuln.get("cvss", {}).get("vector", ""),
            severity=cvss_to_severity(cvss_score),
            fixed_in=vuln.get("fixed_in"),
            published=vuln.get("published_date", ""),
            source="wpscan",
        )

    async def get_plugin_vulns(self, slug: str) -> list[CveFinding]:
        cached = self._cache_get(f"plugin:{slug}")
        if cached is not None:
            return cached
        try:
            resp = await self._http.get(f"{BASE_WPSCAN_API}/plugins/{slug}/")
            if resp.status_code != 200:
                self._cache_set(f"plugin:{slug}", [])
                return []
            data = resp.json()
        except Exception:
            return []
        vulns = self._get_vulns_list(data)
        results = []
        for v in vulns:
            parsed = self._parse_vuln(v)
            if parsed:
                results.append(parsed)
        self._cache_set(f"plugin:{slug}", results)
        return results

    async def get_theme_vulns(self, slug: str) -> list[CveFinding]:
        cached = self._cache_get(f"theme:{slug}")
        if cached is not None:
            return cached
        try:
            resp = await self._http.get(f"{BASE_WPSCAN_API}/themes/{slug}/")
            if resp.status_code != 200:
                self._cache_set(f"theme:{slug}", [])
                return []
            data = resp.json()
        except Exception:
            return []
        vulns = self._get_vulns_list(data)
        results = []
        for v in vulns:
            parsed = self._parse_vuln(v)
            if parsed:
                results.append(parsed)
        self._cache_set(f"theme:{slug}", results)
        return results

    async def get_core_vulns(self, version: str) -> list[CveFinding]:
        ver_flat = version.replace(".", "")
        cached = self._cache_get(f"core:{ver_flat}")
        if cached is not None:
            return cached
        try:
            resp = await self._http.get(f"{BASE_WPSCAN_API}/wordpresses/{ver_flat}/")
            if resp.status_code != 200:
                self._cache_set(f"core:{ver_flat}", [])
                return []
            data = resp.json()
        except Exception:
            return []
        vulns = self._get_vulns_list(data)
        results = []
        for v in vulns:
            parsed = self._parse_vuln(v)
            if parsed:
                results.append(parsed)
        self._cache_set(f"core:{ver_flat}", results)
        return results


class VulnDB:
    def __init__(self, cache_ttl: int = 300, wpscan_token: str = ""):
        self._primary = WPVulnerabilityClient(cache_ttl=cache_ttl)
        self._secondary: Optional[WPScanClient] = None
        if wpscan_token:
            self._secondary = WPScanClient(wpscan_token, cache_ttl=cache_ttl)

    async def close(self) -> None:
        await self._primary.close()
        if self._secondary:
            await self._secondary.close()

    async def get_plugin_vulns(self, slug: str) -> list[CveFinding]:
        seen = set()
        results = []
        primary = await self._primary.get_plugin_vulns(slug)
        for v in primary:
            if v.id not in seen:
                seen.add(v.id)
                results.append(v)
        if self._secondary:
            secondary = await self._secondary.get_plugin_vulns(slug)
            for v in secondary:
                if v.id not in seen:
                    seen.add(v.id)
                    results.append(v)
        return results

    async def get_theme_vulns(self, slug: str) -> list[CveFinding]:
        seen = set()
        results = []
        primary = await self._primary.get_theme_vulns(slug)
        for v in primary:
            if v.id not in seen:
                seen.add(v.id)
                results.append(v)
        if self._secondary:
            secondary = await self._secondary.get_theme_vulns(slug)
            for v in secondary:
                if v.id not in seen:
                    seen.add(v.id)
                    results.append(v)
        return results

    async def get_core_vulns(self, version: str) -> list[CveFinding]:
        seen = set()
        results = []
        primary = await self._primary.get_core_vulns(version)
        for v in primary:
            if v.id not in seen:
                seen.add(v.id)
                results.append(v)
        if self._secondary:
            secondary = await self._secondary.get_core_vulns(version)
            for v in secondary:
                if v.id not in seen:
                    seen.add(v.id)
                    results.append(v)
        return results


_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def to_finding_severity(severity: str) -> FindingSeverity:
    return _SEVERITY_MAP.get(severity, "info")
