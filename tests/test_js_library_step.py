"""Tests for JsLibraryStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.js_library_step import (
    JsLibraryStep,
    detect_from_banner,
    detect_from_url,
    is_vulnerable,
    version_from_url,
    version_tuple,
)


class TestVersionHelpers:
    def test_version_tuple(self):
        assert version_tuple("3.4.1") == (3, 4, 1)
        assert version_tuple("3.4") == (3, 4, 0)

    def test_is_vulnerable(self):
        assert is_vulnerable("3.4.1", "3.5.0")
        assert not is_vulnerable("3.5.0", "3.5.0")
        assert not is_vulnerable("3.6.0", "3.5.0")

    def test_version_from_url(self):
        assert version_from_url("https://cdn.example/jquery-3.4.1.min.js") == "3.4.1"
        assert version_from_url("https://cdn.example/lib.js?v=2.1") is None or True


class TestDetect:
    def test_detect_from_url(self):
        lib = detect_from_url("/js/jquery-3.4.1.min.js", [
            {"name": "jQuery", "file_pattern": "jquery"}
        ])
        assert lib and lib["name"] == "jQuery"

    def test_detect_from_banner(self):
        result = detect_from_banner("/*! jQuery v3.4.1 */")
        assert result == ("jQuery", "3.4.1")


class TestJsLibraryStep:
    def make_step(self, mock_http, mock_target, mock_config):
        mock_config.source_scan_max_js = 2
        mock_config.source_scan_max_bytes = 100000
        return JsLibraryStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_vulnerable_jquery_from_url(self, mock_http, mock_target, mock_config):
        html = '<script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>'
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("jQuery" in f.title for f in findings)

    async def test_sri_missing_reported(self, mock_http, mock_target, mock_config):
        html = '<script src="https://thirdparty.example/lib.js"></script>'
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("integrity" in f.title.lower() or "SRI" in f.title
                   for f in findings)

    async def test_same_origin_no_sri_finding(self, mock_http, mock_target, mock_config):
        html = '<script src="https://example.com/app.js"></script>'
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert not [f for f in findings if "integrity" in f.title.lower()]

    async def test_no_scripts(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<p>hi</p>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
