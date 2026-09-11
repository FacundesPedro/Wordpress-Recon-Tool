"""Tests for ClientSideAuditStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.client_side_audit_step import (
    ClientSideAuditStep,
    audit_html,
    audit_js,
)


class TestAuditHtml:
    def test_tabnabbing_detected(self):
        issues = audit_html('<a href="https://x.com" target="_blank">link</a>')
        assert any("tabnabbing" in i["title"].lower() or "_blank" in i["title"] for i in issues)

    def test_noopener_ok(self):
        issues = audit_html(
            '<a href="https://x.com" target="_blank" rel="noopener noreferrer">link</a>'
        )
        assert not [i for i in issues if "_blank" in i["title"]]

    def test_postmessage_wildcard(self):
        issues = audit_html("window.parent.postMessage(data, '*')")
        assert any("postMessage" in i["title"] for i in issues)

    def test_localstorage_secret(self):
        issues = audit_html("localStorage.setItem('auth_token', value)")
        assert any("localStorage" in i["title"] for i in issues)

    def test_benign_html_clean(self):
        assert audit_html("<p>hello</p>") == []


class TestAuditJs:
    def test_dom_sink_with_source(self):
        js = "el.innerHTML = location.hash; eval(x);"
        issues = audit_js(js)
        assert any("DOM sink" in i["title"] for i in issues)

    def test_sink_without_source_not_flagged(self):
        assert not [i for i in audit_js("el.innerHTML = 'static'") if "DOM sink" in i["title"]]

    def test_message_listener_no_origin(self):
        js = "window.addEventListener('message', function(e) { handle(e.data) });"
        issues = audit_js(js)
        assert any("origin" in i["title"].lower() for i in issues)

    def test_postmessage_wildcard_in_js(self):
        issues = audit_js("win.postMessage(msg, '*')")
        assert any("postMessage" in i["title"] for i in issues)


class TestClientSideAuditStep:
    async def test_finds_issues_in_html(self, mock_http, mock_target, mock_config):
        mock_config.source_scan_max_js = 2
        mock_config.source_scan_max_bytes = 100000
        html = '<a href="https://x.com" target="_blank">l</a>'
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text=html)
        )
        step = ClientSideAuditStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert findings
        assert findings[0].module == "webapp"

    async def test_fetch_failure_clean(self, mock_http, mock_target, mock_config):
        mock_config.source_scan_max_js = 2
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = ClientSideAuditStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert findings == []
