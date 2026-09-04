"""Tests for HeaderQualityStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.header_quality_step import HeaderQualityStep, parse_hsts


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key: str, default=None):
        return self._data.get(key.lower(), default)

    def items(self):
        return self._data.items()


def response(status, headers: dict, text=""):
    return MagicMock(status_code=status, headers=HeaderDict(headers), text=text)


def make_step(mock_http, mock_target, mock_config):
    return HeaderQualityStep(target=mock_target, config=mock_config, http=mock_http)


class TestParseHsts:
    def test_full(self):
        parsed = parse_hsts("max-age=31536000; includeSubDomains; preload")
        assert parsed["max_age"] == 31536000
        assert parsed["include_subdomains"] is True
        assert parsed["preload"] is True

    def test_min_age_only(self):
        parsed = parse_hsts("max-age=300")
        assert parsed["max_age"] == 300
        assert parsed["include_subdomains"] is False

    def test_invalid_max_age(self):
        parsed = parse_hsts("max-age=abc")
        assert parsed["max_age"] == 0


class TestHeaderQualityStep:
    async def test_weak_hsts(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(200, {"strict-transport-security": "max-age=300"})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        titles = {f.title for f in findings}
        assert "Weak HSTS max-age" in titles
        assert "HSTS without includeSubDomains" in titles

    async def test_strong_hsts_no_hsts_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(
                200,
                {"strict-transport-security": "max-age=31536000; includeSubDomains"},
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert not any("HSTS" in f.title for f in findings)

    async def test_xfo_none(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(200, {"x-frame-options": "NONE"})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        xfo = [f for f in findings if "X-Frame-Options" in f.title]
        assert xfo and xfo[0].severity == "medium"

    async def test_xfo_deny_ok(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(200, {"x-frame-options": "DENY"})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_csp_without_frame_ancestors(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(
                200, {"content-security-policy": "default-src 'self'"}
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("frame-ancestors" in f.title for f in findings)

    async def test_csp_with_frame_ancestors_ok(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(
                200,
                {"content-security-policy": "default-src 'self'; frame-ancestors 'self'"},
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_fetch_failure(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
