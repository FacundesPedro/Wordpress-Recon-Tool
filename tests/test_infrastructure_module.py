"""Tests for infrastructure module steps."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


class TestHeadersStep:
    """Tests for HeadersStep — single GET, checks response headers."""

    async def test_missing_headers_detected(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
            text="",
        )
        mock_http.get.return_value = mock_resp

        from steps.infrastructure.headers_step import HeadersStep
        step = HeadersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "infrastructure"
        assert f.severity == "info"
        assert "Missing security headers" in f.title
        assert "X-XSS-Protection" in f.evidence
        assert "Strict-Transport-Security" in f.evidence

    async def test_all_headers_present(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "geolocation=()",
            },
            text="",
        )
        mock_http.get.return_value = mock_resp

        from steps.infrastructure.headers_step import HeadersStep
        step = HeadersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_wordlist_none_returns_empty(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.headers_step import HeadersStep
        step = HeadersStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)

        findings = await step.run()
        assert findings == []

    async def test_http_exception_returns_empty(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = Exception("Connection error")

        from steps.infrastructure.headers_step import HeadersStep
        step = HeadersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert findings == []


class TestTlsStep:
    """Tests for TlsStep — raw socket+ssl, no HTTP."""

    TLS_VERSION = "TLSv1.3"
    CIPHER = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    @staticmethod
    def _make_mock_ssock():
        ssock = MagicMock()
        ssock.getpeercert.return_value = b"cert_data"
        ssock.cipher.return_value = TestTlsStep.CIPHER
        ssock.version.return_value = TestTlsStep.TLS_VERSION
        ssock.__enter__.return_value = ssock
        return ssock

    async def test_successful_tls_check(self, mock_http, mock_target, mock_config):
        mock_sock = MagicMock()
        mock_ssock = self._make_mock_ssock()
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssock

        with (
            patch("steps.infrastructure.tls_step.socket.create_connection", return_value=mock_sock),
            patch("steps.infrastructure.tls_step.ssl.create_default_context", return_value=mock_context),
        ):
            from steps.infrastructure.tls_step import TlsStep
            step = TlsStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "infrastructure"
        assert f.severity == "info"
        assert "TLS configuration info" in f.title
        assert self.TLS_VERSION in f.description
        assert self.CIPHER[0] in f.description

    async def test_http_target_early_return(self, mock_http, mock_target, mock_config):
        mock_target.url = "http://example.com"
        mock_target.domain = "example.com"

        from steps.infrastructure.tls_step import TlsStep
        step = TlsStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert findings == []

    async def test_ssl_cert_error(self, mock_http, mock_target, mock_config):
        mock_sock = MagicMock()
        mock_context = MagicMock()
        mock_context.wrap_socket.side_effect = ConnectionError("SSL error")

        with (
            patch("steps.infrastructure.tls_step.socket.create_connection", return_value=mock_sock),
            patch("steps.infrastructure.tls_step.ssl.create_default_context", return_value=mock_context),
            patch("steps.infrastructure.tls_step.ssl.SSLCertVerificationError", ConnectionError),
        ):
            from steps.infrastructure.tls_step import TlsStep
            step = TlsStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()
            assert len(findings) == 1
            f = findings[0]
            assert f.severity == "medium"
            assert "TLS certificate issue" in f.title

    async def test_generic_exception_returns_empty(self, mock_http, mock_target, mock_config):
        with (
            patch("steps.infrastructure.tls_step.socket.create_connection", side_effect=OSError("No route to host")),
        ):
            from steps.infrastructure.tls_step import TlsStep
            step = TlsStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()
            assert findings == []


class TestWafStep:
    """Tests for WafStep — single GET, checks headers/cookies/body for WAF signatures."""

    async def test_detected_via_header(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            headers={"server": "cloudflare-nginx"},
            text="",
        )
        mock_http.get.return_value = mock_resp

        from steps.infrastructure.waf_step import WafStep
        step = WafStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value={"cloudflare": ["cloudflare"]}
        )
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "infrastructure"
        assert f.severity == "info"
        assert "WAF detected" in f.title
        assert "cloudflare" in f.evidence

    async def test_detected_via_cookie(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            headers={"set-cookie": "__cfduid=abc123"},
            text="",
        )
        mock_http.get.return_value = mock_resp

        from steps.infrastructure.waf_step import WafStep
        step = WafStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value={"cloudflare": ["__cfduid"]}
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "cloudflare" in findings[0].evidence

    async def test_detected_via_body(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            headers={"server": "nginx"},
            text="Protected by mod_security",
        )
        mock_http.get.return_value = mock_resp

        from steps.infrastructure.waf_step import WafStep
        step = WafStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value={"modsecurity": ["mod_security"]}
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "modsecurity" in findings[0].evidence

    async def test_no_waf_detected(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(
            status_code=200,
            headers={"server": "nginx", "content-type": "text/html"},
            text="Welcome to my WordPress site",
        )
        mock_http.get.return_value = mock_resp

        from steps.infrastructure.waf_step import WafStep
        step = WafStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value={"cloudflare": ["cf-ray"]}
        )
        findings = await step.run()

        assert findings == []

    async def test_wordlist_none_returns_empty(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.waf_step import WafStep
        step = WafStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)

        findings = await step.run()
        assert findings == []

    async def test_http_exception_returns_empty(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = Exception("Connection error")

        from steps.infrastructure.waf_step import WafStep
        step = WafStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert findings == []


class TestPortsStep:
    """Tests for PortsStep — N POSTs to xmlrpc.php with pingback payloads."""

    XMLRPC_URL = "https://example.com/xmlrpc.php"

    async def test_port_found_via_pingback_ping(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="""<?xml version="1.0"?>
<methodResponse>
<params><param><value><string>pingback.ping</string></value></param></params>
</methodResponse>""",
            )
        )

        from steps.infrastructure.ports_step import PortsStep
        with patch("steps.infrastructure.ports_step.is_blocked_target", return_value=False):
            step = PortsStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "Open ports detected" in findings[0].title

    async def test_port_blocked_by_ssrf(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="""<?xml version="1.0"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>0</int></value></member>
</struct></value></fault></methodResponse>""",
            )
        )

        from steps.infrastructure.ports_step import PortsStep
        with patch("steps.infrastructure.ports_step.is_blocked_target", return_value=True):
            step = PortsStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_no_open_ports(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="""<?xml version="1.0"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>0</int></value></member>
</struct></value></fault></methodResponse>""",
            )
        )

        from steps.infrastructure.ports_step import PortsStep
        with patch("steps.infrastructure.ports_step.is_blocked_target", return_value=False):
            step = PortsStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_wordlist_none_returns_empty(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.ports_step import PortsStep
        step = PortsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)

        findings = await step.run()
        assert findings == []

    async def test_request_exception_returns_empty(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(side_effect=Exception("Connection refused"))

        from steps.infrastructure.ports_step import PortsStep
        with patch("steps.infrastructure.ports_step.is_blocked_target", return_value=False):
            step = PortsStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []

    async def test_extract_fault_code(self, mock_http, mock_target, mock_config):
        from steps.infrastructure.ports_step import PortsStep

        step = PortsStep(target=mock_target, config=mock_config, http=mock_http)
        assert step._extract_fault_code("<faultCode>41</faultCode>") == 41
        assert step._extract_fault_code("<faultCode>0</faultCode>") == 0
        assert step._extract_fault_code("no fault code") == 0
        assert step._extract_fault_code("x<faultCode>99</faultCode>") == 99
