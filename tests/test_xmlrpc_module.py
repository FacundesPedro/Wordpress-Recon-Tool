"""Tests for XML-RPC module steps (5 step classes)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# XmlrpcDetectStep
# ---------------------------------------------------------------------------

class TestXmlrpcDetectStep:
    """XmlrpcDetectStep — POST system.listMethods, utility-parsed XML."""

    async def test_detected(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text="<methodResponse><params/></methodResponse>")
        )
        with (
            patch("steps.xmlrpc.xmlrpc_detect_step.check_xmlrpc_available", return_value=True),
            patch("steps.xmlrpc.xmlrpc_detect_step.parse_xmlrpc_response") as mock_parse,
        ):
            mock_parse.return_value.has_array = True
            from steps.xmlrpc.xmlrpc_detect_step import XmlrpcDetectStep
            step = XmlrpcDetectStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 1
        assert "XML-RPC is enabled" in findings[0].title

    async def test_not_detected_wrong_content(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html>not xml-rpc</html>")
        )
        with patch("steps.xmlrpc.xmlrpc_detect_step.check_xmlrpc_available", return_value=False):
            from steps.xmlrpc.xmlrpc_detect_step import XmlrpcDetectStep
            step = XmlrpcDetectStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 0

    async def test_not_detected_404(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.xmlrpc.xmlrpc_detect_step import XmlrpcDetectStep
        step = XmlrpcDetectStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_not_detected_403(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=403, text="Forbidden")
        )
        from steps.xmlrpc.xmlrpc_detect_step import XmlrpcDetectStep
        step = XmlrpcDetectStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(side_effect=ConnectionError("network error"))
        from steps.xmlrpc.xmlrpc_detect_step import XmlrpcDetectStep
        step = XmlrpcDetectStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# XmlrpcMethodsStep
# ---------------------------------------------------------------------------

class TestXmlrpcMethodsStep:
    """XmlrpcMethodsStep — POST system.listMethods, wordlist-based danger check."""

    METHODS_XML = """<?xml version="1.0"?>
<methodResponse>
<params><param><value><array><data>
<value><string>system.listMethods</string></value>
<value><string>system.multicall</string></value>
<value><string>wp.getUsersBlogs</string></value>
<value><string>wp.getPost</string></value>
</data></array></value></param></params>
</methodResponse>"""

    async def test_wordlist_none_skips(self, mock_http, mock_target, mock_config):
        from steps.xmlrpc.xmlrpc_methods_step import XmlrpcMethodsStep
        step = XmlrpcMethodsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)
        findings = await step.run()
        assert len(findings) == 0

    async def test_methods_found_with_dangerous(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.METHODS_XML)
        )
        from steps.xmlrpc.xmlrpc_methods_step import XmlrpcMethodsStep
        step = XmlrpcMethodsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp.getUsersBlogs", "system.multicall"]
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "methods enumerated" in findings[0].title
        assert "2 potentially dangerous" in findings[0].description

    async def test_methods_found_no_dangerous(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.METHODS_XML)
        )
        from steps.xmlrpc.xmlrpc_methods_step import XmlrpcMethodsStep
        step = XmlrpcMethodsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=["not.dangerous"])
        findings = await step.run()

        assert len(findings) == 1
        assert "0 potentially dangerous" in findings[0].description

    async def test_no_methods_in_response(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text="<methodResponse><params/></methodResponse>")
        )
        from steps.xmlrpc.xmlrpc_methods_step import XmlrpcMethodsStep
        step = XmlrpcMethodsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp.getUsersBlogs"]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_not_200_status(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.xmlrpc.xmlrpc_methods_step import XmlrpcMethodsStep
        step = XmlrpcMethodsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp.getUsersBlogs"]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(side_effect=ConnectionError("timeout"))
        from steps.xmlrpc.xmlrpc_methods_step import XmlrpcMethodsStep
        step = XmlrpcMethodsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp.getUsersBlogs"]
        )
        findings = await step.run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# XmlrpcCredsStep
# ---------------------------------------------------------------------------

class TestXmlrpcCredsStep:
    """XmlrpcCredsStep — POST wp.getUsersBlogs, per-creds, RetryLimiter."""

    SUCCESS_XML = (
        '<methodResponse><params><param><value><array><data><value>'
        '<isAdmin>1</isAdmin>'
        '<url>https://example.com</url>'
        '<blogid>1</blogid>'
        '</value></data></array></value></param></params></methodResponse>'
    )

    FAILURE_XML = (
        '<methodResponse><fault><value><struct>'
        '<member><name>faultCode</name><value><int>403</int></value></member>'
        '</struct></value></fault></methodResponse>'
    )

    async def test_credentials_none_skips(self, mock_http, mock_target, mock_config):
        from steps.xmlrpc.xmlrpc_creds_step import XmlrpcCredsStep
        step = XmlrpcCredsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(return_value=None)
        findings = await step.run()
        assert len(findings) == 0

    async def test_valid_credentials_found(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.SUCCESS_XML)
        )
        from steps.xmlrpc.xmlrpc_creds_step import XmlrpcCredsStep
        step = XmlrpcCredsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "password"), ("user", "pass")]
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "Valid credentials found" in findings[0].title
        # Both creds should be in evidence
        assert "admin:password" in findings[0].evidence
        assert "user:pass" in findings[0].evidence

    async def test_no_valid_credentials(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.FAILURE_XML)
        )
        from steps.xmlrpc.xmlrpc_creds_step import XmlrpcCredsStep
        step = XmlrpcCredsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "wrong")]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_lockout_path_direct(self, mock_http, mock_target, mock_config):
        """Lockout finding is reachable via consecutive_failures ≥ max.
        Note: In practice _test_credentials swallows exceptions, so this
        path is only exercised by setting _consecutive_failures directly."""
        from steps.xmlrpc.xmlrpc_creds_step import XmlrpcCredsStep
        step = XmlrpcCredsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("u1", "p1")]
        )
        step._limiter._consecutive_failures = 3
        findings = await step.run()

        assert len(findings) == 1
        assert "lockout protection" in findings[0].title.lower()

    async def test_mixed_credentials(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(side_effect=[
            MagicMock(status_code=200, text=self.SUCCESS_XML),
            MagicMock(status_code=200, text=self.FAILURE_XML),
            MagicMock(status_code=200, text=self.SUCCESS_XML),
        ])
        from steps.xmlrpc.xmlrpc_creds_step import XmlrpcCredsStep
        step = XmlrpcCredsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "ok"), ("user", "fail"), ("root", "ok2")]
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "2 valid" in findings[0].description
        assert "admin:ok" in findings[0].evidence

    async def test_exception_in_credentials(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(return_value=MagicMock(status_code=200, text=""))
        from steps.xmlrpc.xmlrpc_creds_step import XmlrpcCredsStep
        step = XmlrpcCredsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "password")]
        )
        result = await step._test_credentials("/xmlrpc.php", "admin", "password")
        assert result is None

    async def test_lockout_no_finding_when_creds_found(self, mock_http, mock_target, mock_config):
        """Lockout path not taken when credentials were found earlier."""
        mock_http.post = AsyncMock(side_effect=[
            MagicMock(status_code=200, text=self.SUCCESS_XML),
            ConnectionError("fail"),
            ConnectionError("fail"),
            ConnectionError("fail"),
        ])
        from steps.xmlrpc.xmlrpc_creds_step import XmlrpcCredsStep
        step = XmlrpcCredsStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "ok"), ("u2", "p2"), ("u3", "p3"), ("u4", "p4")]
        )
        findings = await step.run()
        # First cred succeeded (finding), then 3 consecutive failures → lockout
        # But cred finding takes priority
        assert len(findings) == 1
        assert "Valid credentials" in findings[0].title


# ---------------------------------------------------------------------------
# XmlrpcMulticallStep
# ---------------------------------------------------------------------------

class TestXmlrpcMulticallStep:
    """XmlrpcMulticallStep — POST system.multicall, batch creds, RetryLimiter."""

    SUCCESS_XML = (
        '<methodResponse><params><param><value><array><data><value>'
        '<array><data><value>'
        '<isAdmin>1</isAdmin>'
        '<blogid>1</blogid>'
        '<url>https://example.com</url>'
        '</value></data></array></value>'
        '</data></array></value></param></params></methodResponse>'
    )

    EMPTY_XML = (
        '<methodResponse><params><param><value><array><data>'
        '</data></array></value></param></params></methodResponse>'
    )

    async def test_credentials_none_skips(self, mock_http, mock_target, mock_config):
        from steps.xmlrpc.xmlrpc_multicall_step import XmlrpcMulticallStep
        step = XmlrpcMulticallStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(return_value=None)
        findings = await step.run()
        assert len(findings) == 0

    async def test_valid_credentials_found(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.SUCCESS_XML)
        )
        from steps.xmlrpc.xmlrpc_multicall_step import XmlrpcMulticallStep
        step = XmlrpcMulticallStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "ok")]
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "Valid credentials found" in findings[0].title
        assert "admin:ok" in findings[0].evidence

    async def test_no_valid_credentials(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.EMPTY_XML)
        )
        from steps.xmlrpc.xmlrpc_multicall_step import XmlrpcMulticallStep
        step = XmlrpcMulticallStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("admin", "wrong")]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_lockout_path_direct(self, mock_http, mock_target, mock_config):
        from steps.xmlrpc.xmlrpc_multicall_step import XmlrpcMulticallStep
        step = XmlrpcMulticallStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("u1", "p1")]
        )
        step._limiter._consecutive_failures = 3
        findings = await step.run()
        assert len(findings) == 1
        assert "lockout protection" in findings[0].title.lower()

    async def test_batch_size_splitting(self, mock_http, mock_target, mock_config):
        """BATCH_SIZE=10, fewer creds than batch → single batch."""
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.SUCCESS_XML)
        )
        from steps.xmlrpc.xmlrpc_multicall_step import XmlrpcMulticallStep
        step = XmlrpcMulticallStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_credentials_with_fallback = MagicMock(
            return_value=[("u1", "p1"), ("u2", "p2"), ("u3", "p3")]
        )
        findings = await step.run()
        assert len(findings) == 1
        # All 3 creds should match since response has isAdmin/blogid/url
        assert "3 valid" in findings[0].description


# ---------------------------------------------------------------------------
# XmlrpcSsrfStep
# ---------------------------------------------------------------------------

class TestXmlrpcSsrfStep:
    """XmlrpcSsrfStep — POST pingback.ping, XML-parsed fault codes."""

    FAULT_XML = """<?xml version="1.0"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>33</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>pingback.ping is available</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>"""

    SUCCESS_XML = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value><string>pingback.ping registered successfully</string></value>
    </param>
  </params>
</methodResponse>"""

    NOT_PINGBACK_XML = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value><string>some other method</string></value>
    </param>
  </params>
</methodResponse>"""

    async def test_pingback_available_via_fault_code(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.FAULT_XML)
        )
        from steps.xmlrpc.xmlrpc_ssrf_step import XmlrpcSsrfStep
        step = XmlrpcSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "pingback.ping" in findings[0].title

    async def test_pingback_available_via_success(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.SUCCESS_XML)
        )
        from steps.xmlrpc.xmlrpc_ssrf_step import XmlrpcSsrfStep
        step = XmlrpcSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "pingback.ping" in findings[0].title

    async def test_pingback_not_available(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.xmlrpc.xmlrpc_ssrf_step import XmlrpcSsrfStep
        step = XmlrpcSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_pingback_not_available_no_keywords(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=self.NOT_PINGBACK_XML)
        )
        from steps.xmlrpc.xmlrpc_ssrf_step import XmlrpcSsrfStep
        step = XmlrpcSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.post = AsyncMock(side_effect=ConnectionError("network error"))
        from steps.xmlrpc.xmlrpc_ssrf_step import XmlrpcSsrfStep
        step = XmlrpcSsrfStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0
