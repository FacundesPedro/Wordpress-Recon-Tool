"""Tests for the shared soft-404 / SPA catch-all detector."""

from unittest.mock import AsyncMock, MagicMock

from utils.soft404 import (
    ResponseFingerprint,
    Soft404Detector,
    extract_title,
    is_html_body,
)

SPA_SHELL = (
    "<!--\n  ~ Copyright (c) 2026 someone\n  ~ SPDX-License: MIT\n-->\n"
    '<!doctype html>\n<html lang="en"><head><title>OWASP Juice Shop</title>'
    "</head><body></body></html>"
)


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)


def resp(status, text="", headers=None):
    return MagicMock(status_code=status, text=text,
                     headers=HeaderDict(headers or {}))


class TestExtractTitle:
    def test_title(self):
        assert extract_title("<title>  Hello </title>") == "Hello"

    def test_no_title(self):
        assert extract_title("<html></html>") == ""


class TestIsHtmlBody:
    def test_comment_prefix_detected(self):
        """Angular-style shells start with a comment before <!doctype>."""
        assert is_html_body(SPA_SHELL)

    def test_content_type_signal(self):
        assert is_html_body("anything", "text/html; charset=utf-8")

    def test_json_not_html(self):
        assert not is_html_body('{"key": "value"}', "application/json")

    def test_binary_not_html(self):
        assert not is_html_body("PK\x03\x04binary", "application/octet-stream")


class TestFingerprint:
    def test_from_response(self):
        fp = ResponseFingerprint.from_response(
            resp(200, SPA_SHELL, {"Content-Type": "text/html"})
        )
        assert fp.status == 200
        assert fp.title == "OWASP Juice Shop"
        assert fp.length == len(SPA_SHELL)
        assert fp.content_type == "text/html"
        assert not fp.empty


def make_detector(mock_http):
    logger = MagicMock()
    return Soft404Detector(mock_http, "http://t.example", logger), logger


class TestSoft404Detector:
    def make_step(self, mock_http):
        return make_detector(mock_http)

    async def test_calibrates_on_spa_shell(self, mock_http):
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        assert detector.calibrated
        assert detector.baseline.title == "OWASP Juice Shop"

    async def test_no_calibration_on_real_404(self, mock_http):
        mock_http.request = AsyncMock(return_value=resp(404, "Not Found"))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        assert not detector.calibrated
        # responses are never soft-404 without a baseline
        assert not detector.is_soft404(resp(200, SPA_SHELL))

    async def test_head_byte_match(self, mock_http):
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        assert detector.is_soft404(resp(200, SPA_SHELL))

    async def test_title_and_length_match(self, mock_http):
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        # same title, slightly different length (dynamic nonce) -> still shell
        variant = SPA_SHELL + "<span>nonce</span>"
        assert detector.is_soft404(resp(200, variant))

    async def test_different_page_not_flagged(self, mock_http):
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        real_page = "<!doctype html><html><head><title>Grafana</title></head>" \
                    "<body>" + "x" * 3000 + "</body></html>"
        assert not detector.is_soft404(resp(200, real_page))

    async def test_different_status_not_flagged(self, mock_http):
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        assert not detector.is_soft404(resp(403, SPA_SHELL))

    async def test_titleless_shell_matches_on_content_type(self, mock_http):
        shell = "<html><body>" + "x" * 900 + "</body></html>"
        mock_http.request = AsyncMock(
            return_value=resp(200, shell, {"Content-Type": "text/html"})
        )
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        variant = shell.replace("x" * 900, "y" * 905)
        assert detector.is_soft404(
            resp(200, variant, {"Content-Type": "text/html"})
        )


class TestNonAngularSoft404s:
    """The detector must generalize beyond Angular SPA shells."""

    async def test_php_custom_error_page(self, mock_http):
        """Classic PHP soft-404: custom 'not found' page with HTTP 200."""
        page = ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">"
                "<html><head><title>404 Not Found - MySite</title></head>"
                "<body><h1>Page not found</h1><p>Sorry, that page is gone."
                "</p></body></html>")
        mock_http.request = AsyncMock(return_value=resp(200, page))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        assert detector.calibrated
        # same page fetched again (any path) -> suppressed
        assert detector.is_soft404(resp(200, page))
        # a real admin page with different title/length -> kept
        real = "<html><head><title>phpMyAdmin</title></head><body>" + "x" * 800 + "</body></html>"
        assert not detector.is_soft404(resp(200, real))

    async def test_waf_block_page(self, mock_http):
        """WAF/honeypot: identical generic block page for every path."""
        block = ("<html><body><h1>Access Denied</h1>"
                 "<p>This request was blocked by the firewall.</p>"
                 "<!-- ref: " + "Z" * 60 + " --></body></html>")
        mock_http.request = AsyncMock(return_value=resp(200, block))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        assert detector.is_soft404(resp(200, block))

    async def test_empty_200_server(self, mock_http):
        """Some servers return an empty or near-empty 200 for everything."""
        mock_http.request = AsyncMock(return_value=resp(200, ""))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        assert detector.calibrated
        assert detector.is_soft404(resp(200, ""))
        # a real page with content -> kept
        assert not detector.is_soft404(resp(200, "<html><title>Real</title></html>"))

    async def test_json_api_soft404(self, mock_http):
        """API fronted by SPA fallback: unknown API paths return the shell."""
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        # shell served for an API-looking path -> suppressed
        assert detector.is_soft404(resp(200, SPA_SHELL))
        # real JSON response -> kept even at similar length
        api = '{"status": "ok", "items": [1, 2, 3]}'
        assert not detector.is_soft404(resp(200, api, {"Content-Type": "application/json"}))

    async def test_dynamic_nonce_in_shell(self, mock_http):
        """Shells with per-request nonces/tokens still match (absolute floor)."""
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        variant = SPA_SHELL + "<span>csrf=abc123def</span>"
        assert detector.is_soft404(resp(200, variant))

    async def test_real_page_similar_size_kept(self, mock_http):
        """A real page of similar size but different title is NOT suppressed."""
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        real = ("<!doctype html><html><head><title>Admin Login</title></head>"
                "<body><form><input name=user><input name=pass></form></body></html>")
        assert not detector.is_soft404(resp(200, real))

    async def test_directory_listing_not_suppressed(self, mock_http):
        """Directory listings (real findings) differ from the shell."""
        mock_http.request = AsyncMock(return_value=resp(200, SPA_SHELL))
        detector, _ = make_detector(mock_http)
        await detector.calibrate()
        listing = ("<html><head><title>Index of /backup/</title></head>"
                   "<body><h1>Index of /backup/</h1><hr><pre>"
                   "<a href=\"db.sql\">db.sql</a></pre><hr></body></html>")
        assert not detector.is_soft404(resp(200, listing))
