"""Tests for WaymachineStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


MOCK_WAYBACK_JSON = """[
    ["https://example.com/"],
    ["https://example.com/wp-admin/"],
    ["https://example.com/wp-login.php"],
    ["https://example.com/.env"],
    ["https://example.com/api/v1/users"],
    ["https://example.com/backup.zip"],
    ["https://example.com/config.php"],
    ["https://example.com/debug/"],
    ["https://example.com/uploads/image.jpg"],
    ["https://example.com/about"]
]"""


class TestSkipConditions:
    """Tests for early return conditions."""

    async def test_returns_empty_when_no_domain(self, mock_http):
        mock_target = MagicMock()
        mock_target.domain = None

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=mock_http)
        findings = await step.run()
        assert findings == []

    async def test_returns_empty_when_no_http(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=None)
        findings = await step.run()

        assert findings == []


class TestUrlBuilding:
    """Tests for _build_url."""

    async def test_build_url_includes_timestamps(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        url = step._build_url("example.com")
        assert "example.com" in url
        assert "from=" in url
        assert "to=" in url


class TestQueryAndParse:
    """Tests for query and parse logic."""

    async def test_200_with_json_finds_urls(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = MOCK_WAYBACK_JSON
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=mock_http)
        findings = await step.run()

        historical = [f for f in findings if "Historical URLs" in f.title]
        assert len(historical) == 1
        assert historical[0].module == "passive"
        assert historical[0].severity == "info"
        assert historical[0].raw["total_count"] == 10

    async def test_sensitive_endpoints_found(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = MOCK_WAYBACK_JSON
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=mock_http)
        findings = await step.run()

        sensitive = [f for f in findings if "Sensitive Endpoints" in f.title]
        assert len(sensitive) == 1
        assert sensitive[0].severity == "medium"

    async def test_empty_response_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = "[]"
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_timeout_handled_gracefully(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=TimeoutError("timed out"))

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0


class TestParseResponse:
    """Tests for _parse_response."""

    async def test_json_array_of_arrays(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        text = '[[ "https://example.com/page1" ], [ "https://example.com/page2" ]]'
        step._parse_response(text)
        assert "https://example.com/page1" in step._urls
        assert "https://example.com/page2" in step._urls

    async def test_json_array_of_strings(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        text = '["https://example.com/page1", "https://example.com/page2"]'
        step._parse_response(text)
        assert "https://example.com/page1" in step._urls
        assert "https://example.com/page2" in step._urls

    async def test_text_lines_fallback(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        text = "https://example.com/page1\nhttps://example.com/page2\n# comment\nhttps://example.com/page3"
        step._parse_response(text)
        assert "https://example.com/page1" in step._urls
        assert "https://example.com/page2" in step._urls
        assert "https://example.com/page3" in step._urls
        assert "# comment" not in step._urls

    async def test_invalid_json_falls_back(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        text = "https://example.com/page1\nhttps://example.com/page2"
        step._parse_response(text)
        assert "https://example.com/page1" in step._urls
        assert "https://example.com/page2" in step._urls


class TestCategorizeUrls:
    """Tests for _categorize_urls."""

    async def test_all_categories_detected(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        urls = [
            "https://example.com/admin/",
            "https://example.com/api/v1",
            "https://example.com/backup.zip",
            "https://example.com/.env",
            "https://example.com/login",
            "https://example.com/debug",
            "https://example.com/uploads/",
            "https://example.com/other",
        ]
        categories = step._categorize_urls(urls)
        assert "Admin/Panel" in categories
        assert "API/JSON" in categories
        assert "Backup/Archive" in categories
        assert "Config/Env" in categories
        assert "Login/Auth" in categories
        assert "Debug/Info" in categories
        assert "Upload" in categories
        assert "Other" in categories

    async def test_empty_returns_empty_dict(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        categories = step._categorize_urls([])
        assert categories == {}


class TestCheckSensitiveEndpoints:
    """Tests for _check_sensitive_endpoints."""

    async def test_detects_multiple_patterns(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        urls = [
            "https://example.com/wp-admin/",
            "https://example.com/.env",
            "https://example.com/backup.zip",
            "https://example.com/debug.php",
        ]
        sensitive = step._check_sensitive_endpoints(urls)
        assert len(sensitive) == 4

    async def test_returns_empty_for_safe_urls(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        urls = [
            "https://example.com/about",
            "https://example.com/contact",
        ]
        sensitive = step._check_sensitive_endpoints(urls)
        assert sensitive == []

    async def test_capped_at_50(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"

        from steps.passive.wayback_step import WaymachineStep

        step = WaymachineStep(target=mock_target, http=MagicMock())
        urls = [f"https://example.com/wp-admin/page{i}" for i in range(100)]
        sensitive = step._check_sensitive_endpoints(urls)
        assert len(sensitive) == 50
