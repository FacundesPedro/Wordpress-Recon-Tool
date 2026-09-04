"""Tests for ContentLeakStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from steps.webapp.content_leak_step import ContentLeakStep

pytestmark = pytest.mark.asyncio


def make_step(mock_http, mock_target, mock_config, max_pages=10):
    mock_config.webapp_max_pages = max_pages
    return ContentLeakStep(target=mock_target, config=mock_config, http=mock_http)


def response(status, text=""):
    return MagicMock(status_code=status, text=text)


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp
        return response(404, "Not Found")

    return _respond


class TestContentLeakStep:
    async def test_internal_ip_leak(self, mock_http, mock_target, mock_config):
        html = "<html><body>backup at 192.168.1.50</body></html>"
        mock_http.request = AsyncMock(return_value=response(200, html))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Internal IP addresses" in f.title for f in findings)
        assert "192.168.1.50" in [f for f in findings if "IP" in f.title][0].evidence

    async def test_metadata_ip_leak(self, mock_http, mock_target, mock_config):
        html = "<html><body>instance data at http://169.254.169.254/latest/</body></html>"
        mock_http.request = AsyncMock(return_value=response(200, html))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Internal IP addresses" in f.title for f in findings)

    async def test_email_leak(self, mock_http, mock_target, mock_config):
        html = "<html><body>support: help@clientcorp.com</body></html>"
        mock_http.request = AsyncMock(return_value=response(200, html))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Email addresses" in f.title for f in findings)
        assert "help@clientcorp.com" in [f for f in findings if "Email" in f.title][0].evidence

    async def test_image_email_not_flagged(self, mock_http, mock_target, mock_config):
        html = '<html><body><img src="logo@2x.png"></body></html>'
        mock_http.request = AsyncMock(return_value=response(200, html))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert not any("Email" in f.title for f in findings)

    async def test_meta_generator_leak(self, mock_http, mock_target, mock_config):
        html = (
            "<html><head>"
            '<meta name="generator" content="WordPress 6.5">'
            "</head><body></body></html>"
        )
        mock_http.request = AsyncMock(return_value=response(200, html))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("meta generator" in f.title for f in findings)
        assert "WordPress 6.5" in [f for f in findings if "generator" in f.title][0].evidence

    async def test_config_comment_leak(self, mock_http, mock_target, mock_config):
        html = "<html><body><!-- TODO: remove admin panel password from here --></body></html>"
        mock_http.request = AsyncMock(return_value=response(200, html))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("HTML comments" in f.title for f in findings)

    async def test_crawls_discovered_links(self, mock_http, mock_target, mock_config):
        home = '<html><body><a href="/about">About</a></body></html>'
        about = "<html><body>staff: dev@clientcorp.com</body></html>"
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(200, home),
                    "/about": response(200, about),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        emails = [f for f in findings if "Email" in f.title]
        assert emails and "dev@clientcorp.com" in emails[0].evidence

    async def test_max_pages_respected(self, mock_http, mock_target, mock_config):
        links = " ".join(f'<a href="/p{i}">P</a>' for i in range(25))
        home = f"<html><body>{links}</body></html>"
        mock_http.request = AsyncMock(
            side_effect=responder({"/": response(200, home)})
        )
        step = make_step(mock_http, mock_target, mock_config, max_pages=5)
        await step.run()
        calls = [c.args[1] for c in mock_http.request.call_args_list]
        page_calls = [c for c in calls if "/p" in c]
        assert len(page_calls) <= 4

    async def test_clean_page_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=response(200, "<html><body>nothing here</body></html>")
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_homepage_failure(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
