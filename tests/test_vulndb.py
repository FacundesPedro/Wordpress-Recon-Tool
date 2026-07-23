# tests/test_vulndb.py
"""Tests for VulnDB — CVSS mapping, caching, API clients, dedup facade."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.vulndb import (
    BASE_WPSCAN_API,
    CacheMixin,
    CveFinding,
    VulnDB,
    WPScanClient,
    WPVulnerabilityClient,
    cvss_to_severity,
    to_finding_severity,
)


# ---------------------------------------------------------------------------
# cvss_to_severity
# ---------------------------------------------------------------------------
class TestCvssToSeverity:
    def test_none_returns_info(self):
        assert cvss_to_severity(None) == "info"

    def test_zero_is_low(self):
        assert cvss_to_severity(0.0) == "low"

    def test_3_9_is_low(self):
        assert cvss_to_severity(3.9) == "low"

    def test_4_0_is_medium(self):
        assert cvss_to_severity(4.0) == "medium"

    def test_6_9_is_medium(self):
        assert cvss_to_severity(6.9) == "medium"

    def test_7_0_is_high(self):
        assert cvss_to_severity(7.0) == "high"

    def test_8_9_is_high(self):
        assert cvss_to_severity(8.9) == "high"

    def test_9_0_is_critical(self):
        assert cvss_to_severity(9.0) == "critical"

    def test_10_0_is_critical(self):
        assert cvss_to_severity(10.0) == "critical"

    def test_negative_is_low(self):
        assert cvss_to_severity(-1.0) == "low"


# ---------------------------------------------------------------------------
# CveFinding
# ---------------------------------------------------------------------------
class TestCveFinding:
    def test_creation_with_required_fields(self):
        f = CveFinding(id="CVE-2024-0001", title="Test", description="Desc")
        assert f.id == "CVE-2024-0001"
        assert f.title == "Test"

    def test_defaults(self):
        f = CveFinding(id="CVE-2024-0001", title="T", description="D")
        assert f.cvss_score is None
        assert f.cvss_vector == ""
        assert f.severity == "info"
        assert f.fixed_in is None
        assert f.published == ""
        assert f.source == ""

    def test_all_fields_set(self):
        f = CveFinding(
            id="CVE-2024-0001",
            title="Test",
            description="Desc",
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N",
            severity="high",
            fixed_in="1.0.1",
            published="2024-01-01",
            source="wpvulnerability",
        )
        assert f.cvss_score == 8.5
        assert f.fixed_in == "1.0.1"
        assert f.source == "wpvulnerability"


# ---------------------------------------------------------------------------
# CacheMixin
# ---------------------------------------------------------------------------
class TestCacheMixin:
    def test_cache_set_and_get(self):
        m = CacheMixin(cache_ttl=300)
        findings = [CveFinding(id="CVE-1", title="T", description="D")]
        m._cache_set("key1", findings)
        assert m._cache_get("key1") == findings

    def test_cache_miss_returns_none(self):
        m = CacheMixin(cache_ttl=300)
        assert m._cache_get("nonexistent") is None

    def test_cache_expires(self):
        m = CacheMixin(cache_ttl=0)
        m._cache_set("key1", [])
        time.sleep(0.01)
        assert m._cache_get("key1") is None

    def test_cache_refreshes_on_set(self):
        m = CacheMixin(cache_ttl=300)
        m._cache_set("key1", [CveFinding(id="v1", title="T", description="D")])
        m._cache_set("key1", [CveFinding(id="v2", title="T", description="D")])
        result = m._cache_get("key1")
        assert len(result) == 1
        assert result[0].id == "v2"

    def test_cache_empty_list(self):
        m = CacheMixin(cache_ttl=300)
        m._cache_set("key1", [])
        assert m._cache_get("key1") == []


# ---------------------------------------------------------------------------
# WPVulnerabilityClient._get_cve_id
# ---------------------------------------------------------------------------
class TestWPVulnGetCveId:
    def _client(self):
        return WPVulnerabilityClient.__new__(WPVulnerabilityClient)

    def test_extracts_from_cve_dict(self):
        c = self._client()
        assert c._get_cve_id({"cve": {"id": "CVE-2024-0001"}}) == "CVE-2024-0001"

    def test_falls_back_to_top_level_id_when_cve_not_dict(self):
        c = self._client()
        # When cve is a string (not dict), falls through to top-level id
        assert c._get_cve_id({"cve": "string", "id": "CVE-2024-0002"}) == "CVE-2024-0002"

    def test_empty_when_no_id(self):
        c = self._client()
        assert c._get_cve_id({}) == ""

    def test_cve_not_dict_returns_top_level_id(self):
        c = self._client()
        assert c._get_cve_id({"cve": "string", "id": "CVE-X"}) == "CVE-X"

    def test_empty_cve_dict_returns_empty(self):
        c = self._client()
        # When cve is empty dict, returns "" from the dict path
        assert c._get_cve_id({"cve": {}}) == ""

    def test_top_level_id_absent_when_cve_dict(self):
        c = self._client()
        # cve dict exists but has no id — top-level id is NOT checked
        assert c._get_cve_id({"cve": {}, "id": "CVE-X"}) == ""


# ---------------------------------------------------------------------------
# WPVulnerabilityClient._get_desc
# ---------------------------------------------------------------------------
class TestWPVulnGetDesc:
    def _client(self):
        return WPVulnerabilityClient.__new__(WPVulnerabilityClient)

    def test_value_field(self):
        c = self._client()
        vuln = {"cve": {"description": {"value": "A vuln"}}}
        assert c._get_desc(vuln) == "A vuln"

    def test_description_data_fallback(self):
        c = self._client()
        vuln = {"cve": {"description": {"description_data": [{"value": "Fallback"}]}}}
        assert c._get_desc(vuln) == "Fallback"

    def test_empty_when_no_description(self):
        c = self._client()
        assert c._get_desc({"cve": {}}) == ""

    def test_empty_when_cve_not_dict(self):
        c = self._client()
        assert c._get_desc({"cve": "string"}) == ""

    def test_empty_when_no_cve(self):
        c = self._client()
        assert c._get_desc({}) == ""


# ---------------------------------------------------------------------------
# WPVulnerabilityClient._parse_vuln
# ---------------------------------------------------------------------------
class TestWPVulnParseVuln:
    def _client(self):
        return WPVulnerabilityClient.__new__(WPVulnerabilityClient)

    def test_full_vuln(self):
        c = self._client()
        vuln = {
            "cve": {
                "id": "CVE-2024-0001",
                "description": {"value": "SQL injection"},
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N",
                            }
                        }
                    ]
                },
            },
            "fixed_in": "1.2.3",
            "published": "2024-01-15",
        }
        result = c._parse_vuln(vuln, "wpvulnerability")
        assert result is not None
        assert result.id == "CVE-2024-0001"
        assert result.title == "CVE-CVE-2024-0001"
        assert result.cvss_score == 9.8
        assert result.severity == "critical"
        assert result.fixed_in == "1.2.3"
        assert result.source == "wpvulnerability"

    def test_no_cvss(self):
        c = self._client()
        vuln = {"cve": {"id": "CVE-2024-0002", "description": {"value": "XSS"}}}
        result = c._parse_vuln(vuln, "wpvulnerability")
        assert result is not None
        assert result.cvss_score is None
        assert result.severity == "info"

    def test_returns_none_when_no_cve_id(self):
        c = self._client()
        assert c._parse_vuln({}, "wpvulnerability") is None

    def test_title_not_prefixed_when_not_cve_format(self):
        c = self._client()
        vuln = {"cve": {"id": "WPVULN-1234"}}
        result = c._parse_vuln(vuln, "wpvulnerability")
        assert result is not None
        assert result.title == "WPVULN-1234"

    def test_description_truncated_to_300_chars(self):
        c = self._client()
        long_desc = "A" * 500
        vuln = {"cve": {"id": "CVE-2024-0001", "description": {"value": long_desc}}}
        result = c._parse_vuln(vuln, "wpvulnerability")
        assert result is not None
        assert len(result.description) == 300


# ---------------------------------------------------------------------------
# WPVulnerabilityClient._get_wpvuln (API integration via mock)
# ---------------------------------------------------------------------------
class TestWPVulnGetWpvuln:
    @pytest.mark.asyncio
    async def test_caches_successful_response(self):
        client = WPVulnerabilityClient(cache_ttl=300)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-0001", "description": {"value": "Vuln"}}}
                ]
            }
        }
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_http.aclose = AsyncMock()
        client._http = mock_http

        result = await client._get_wpvuln("plugin/test/", "plugin:test")
        assert len(result) == 1
        assert result[0].id == "CVE-2024-0001"
        await client.close()

    @pytest.mark.asyncio
    async def test_returns_empty_on_non_200(self):
        client = WPVulnerabilityClient(cache_ttl=300)
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_http.aclose = AsyncMock()
        client._http = mock_http

        result = await client._get_wpvuln("plugin/missing/", "plugin:missing")
        assert result == []
        await client.close()

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(self):
        client = WPVulnerabilityClient(cache_ttl=300)
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(side_effect=Exception("timeout"))
        mock_http.aclose = AsyncMock()
        client._http = mock_http

        result = await client._get_wpvuln("plugin/err/", "plugin:err")
        assert result == []
        await client.close()

    @pytest.mark.asyncio
    async def test_uses_cache_on_second_call(self):
        client = WPVulnerabilityClient(cache_ttl=300)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"vulnerabilities": []}}
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_http.aclose = AsyncMock()
        client._http = mock_http

        await client._get_wpvuln("plugin/slow/", "plugin:slow")
        await client._get_wpvuln("plugin/slow/", "plugin:slow")
        mock_http.get.assert_called_once()
        await client.close()


# ---------------------------------------------------------------------------
# WPScanClient._parse_vuln
# ---------------------------------------------------------------------------
class TestWPScanParseVuln:
    def _client(self):
        return WPScanClient.__new__(WPScanClient)

    def test_full_vuln(self):
        c = self._client()
        vuln = {
            "cve": "CVE-2024-1001",
            "title": "XSS in Plugin",
            "description": "Reflected XSS",
            "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N"},
            "fixed_in": "2.0.0",
            "published_date": "2024-02-01",
        }
        result = c._parse_vuln(vuln)
        assert result is not None
        assert result.id == "CVE-2024-1001"
        assert result.cvss_score == 7.5
        assert result.severity == "high"
        assert result.source == "wpscan"

    def test_no_cve_uses_id(self):
        c = self._client()
        vuln = {"id": "WPSCAN-1234", "title": "Some vuln"}
        result = c._parse_vuln(vuln)
        assert result is not None
        assert result.id == "WPSCAN-1234"

    def test_returns_none_when_no_id(self):
        c = self._client()
        assert c._parse_vuln({}) is None

    def test_strips_whitespace_from_cve_id(self):
        c = self._client()
        vuln = {"cve": "  CVE-2024-1001  "}
        result = c._parse_vuln(vuln)
        assert result is not None
        assert result.id == "CVE-2024-1001"


# ---------------------------------------------------------------------------
# WPScanClient._get_vulns_list
# ---------------------------------------------------------------------------
class TestWPScanGetVulnsList:
    def _client(self):
        return WPScanClient.__new__(WPScanClient)

    def test_dict_with_vulnerabilities(self):
        c = self._client()
        result = c._get_vulns_list({"vulnerabilities": [{"cve": "CVE-1"}]})
        assert len(result) == 1

    def test_list_input(self):
        c = self._client()
        result = c._get_vulns_list([{"cve": "CVE-1"}, {"cve": "CVE-2"}])
        assert len(result) == 2

    def test_dict_without_key(self):
        c = self._client()
        result = c._get_vulns_list({"other": "data"})
        assert result == []

    def test_non_dict_non_list(self):
        c = self._client()
        result = c._get_vulns_list("string")
        assert result == []


# ---------------------------------------------------------------------------
# WPScanClient._fetch_and_parse (API integration via mock)
# ---------------------------------------------------------------------------
class TestWPScanFetchAndParse:
    @pytest.mark.asyncio
    async def test_caches_successful_response(self):
        client = WPScanClient("fake-token", cache_ttl=300)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [{"cve": "CVE-2024-5001", "title": "Test"}]
        }
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_http.aclose = AsyncMock()
        client._http = mock_http

        result = await client._fetch_and_parse(
            f"{BASE_WPSCAN_API}/plugins/test/", "plugin:test"
        )
        assert len(result) == 1
        assert result[0].id == "CVE-2024-5001"
        await client.close()

    @pytest.mark.asyncio
    async def test_returns_empty_on_non_200(self):
        client = WPScanClient("fake-token", cache_ttl=300)
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=mock_resp)
        mock_http.aclose = AsyncMock()
        client._http = mock_http

        result = await client._fetch_and_parse(
            f"{BASE_WPSCAN_API}/plugins/err/", "plugin:err"
        )
        assert result == []
        await client.close()

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(self):
        client = WPScanClient("fake-token", cache_ttl=300)
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(side_effect=Exception("network"))
        mock_http.aclose = AsyncMock()
        client._http = mock_http

        result = await client._fetch_and_parse(
            f"{BASE_WPSCAN_API}/plugins/err/", "plugin:err"
        )
        assert result == []
        await client.close()


# ---------------------------------------------------------------------------
# VulnDB facade — dedup and merge
# ---------------------------------------------------------------------------
class TestVulnDBMerge:
    @pytest.mark.asyncio
    async def test_merges_and_deduplicates(self):
        db = VulnDB(cache_ttl=300, wpscan_token="fake")
        v1 = CveFinding(id="CVE-2024-0001", title="T1", description="D1")
        v2 = CveFinding(id="CVE-2024-0002", title="T2", description="D2")
        v3 = CveFinding(id="CVE-2024-0001", title="T1-dup", description="D1-dup")

        db._primary = MagicMock()
        db._primary.get_plugin_vulns = AsyncMock(return_value=[v1, v2])
        db._secondary = MagicMock()
        db._secondary.get_plugin_vulns = AsyncMock(return_value=[v3])

        result = await db.get_plugin_vulns("test-plugin")
        assert len(result) == 2
        assert result[0].id == "CVE-2024-0001"
        assert result[1].id == "CVE-2024-0002"

    @pytest.mark.asyncio
    async def test_primary_only_when_no_secondary(self):
        db = VulnDB(cache_ttl=300)
        v1 = CveFinding(id="CVE-2024-0001", title="T", description="D")
        db._primary = MagicMock()
        db._primary.get_plugin_vulns = AsyncMock(return_value=[v1])

        result = await db.get_plugin_vulns("test")
        assert len(result) == 1
        assert result[0].id == "CVE-2024-0001"

    @pytest.mark.asyncio
    async def test_secondary_supplements_missing(self):
        db = VulnDB(cache_ttl=300, wpscan_token="fake")
        v1 = CveFinding(id="CVE-2024-0001", title="T1", description="D1")
        v2 = CveFinding(id="CVE-2024-0003", title="T3", description="D3")
        db._primary = MagicMock()
        db._primary.get_theme_vulns = AsyncMock(return_value=[v1])
        db._secondary = MagicMock()
        db._secondary.get_theme_vulns = AsyncMock(return_value=[v2])

        result = await db.get_theme_vulns("test-theme")
        assert len(result) == 2
        ids = [r.id for r in result]
        assert "CVE-2024-0001" in ids
        assert "CVE-2024-0003" in ids

    @pytest.mark.asyncio
    async def test_core_vulns(self):
        db = VulnDB(cache_ttl=300)
        v1 = CveFinding(id="CVE-2024-0010", title="T", description="D")
        db._primary = MagicMock()
        db._primary.get_core_vulns = AsyncMock(return_value=[v1])

        result = await db.get_core_vulns("6.4.2")
        assert len(result) == 1
        assert result[0].id == "CVE-2024-0010"

    @pytest.mark.asyncio
    async def test_close_calls_both(self):
        db = VulnDB(cache_ttl=300, wpscan_token="fake")
        db._primary.close = AsyncMock()
        db._secondary.close = AsyncMock()
        await db.close()
        db._primary.close.assert_called_once()
        db._secondary.close.assert_called_once()


# ---------------------------------------------------------------------------
# to_finding_severity
# ---------------------------------------------------------------------------
class TestToFindingSeverity:
    def test_known_levels(self):
        assert to_finding_severity("info") == "info"
        assert to_finding_severity("low") == "low"
        assert to_finding_severity("medium") == "medium"
        assert to_finding_severity("high") == "high"
        assert to_finding_severity("critical") == "critical"

    def test_unknown_defaults_to_info(self):
        assert to_finding_severity("unknown") == "info"
        assert to_finding_severity("") == "info"
