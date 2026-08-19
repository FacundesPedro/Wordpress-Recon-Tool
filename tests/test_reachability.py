"""Tests for core/reachability.py — pre-flight reachability probe."""

import socket
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.reachability import check_reachability, ReachabilityResult


def _mock_writer():
    """Return a writer mock whose wait_closed is awaitable."""
    writer = MagicMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return writer


class TestCheckReachability:
    @pytest.mark.asyncio
    async def test_success_http(self):
        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), _mock_writer())),
        ):
            result = await check_reachability("http://example.com")
        assert result.reachable is True
        assert result.ip == "1.2.3.4"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_success_https(self):
        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), _mock_writer())),
        ), patch(
            "core.reachability.socket.create_connection"
        ) as mock_conn:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {}
            with patch("core.reachability.ssl.create_default_context", return_value=mock_ctx):
                result = await check_reachability("https://example.com")
        assert result.reachable is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_dns_failure(self):
        with patch(
            "core.reachability.socket.gethostbyname",
            side_effect=socket.gaierror("[Errno 8] nodename nor servname provided"),
        ):
            result = await check_reachability("https://nonexistent.invalid")
        assert result.reachable is False
        assert result.error_category == "dns"
        assert result.error is not None
        assert "DNS" in result.error

    @pytest.mark.asyncio
    async def test_tcp_refused(self):
        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(side_effect=ConnectionRefusedError("[Errno 61] Connection refused")),
        ):
            result = await check_reachability("http://example.com")
        assert result.reachable is False
        assert result.error_category == "tcp"
        assert result.error is not None
        assert "refused" in result.error.lower()

    @pytest.mark.asyncio
    async def test_tcp_timeout(self):
        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(side_effect=TimeoutError("timed out")),
        ):
            result = await check_reachability("http://example.com")
        assert result.reachable is False
        assert result.error_category == "tcp"
        assert result.error is not None
        assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_tls_expired_certificate(self):
        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), _mock_writer())),
        ):
            cert_err = ssl.SSLCertVerificationError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired"
            )
            with patch(
                "core.reachability.socket.create_connection",
                side_effect=cert_err,
            ):
                result = await check_reachability("https://example.com")
        assert result.reachable is False
        assert result.error_category == "tls"
        assert result.error is not None
        assert "expired" in result.error.lower()

    @pytest.mark.asyncio
    async def test_insecure_skips_verification(self):
        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), _mock_writer())),
        ), patch(
            "core.reachability.socket.create_connection"
        ) as mock_conn:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {}
            with patch("core.reachability.ssl.create_default_context", return_value=mock_ctx) as mock_create:
                result = await check_reachability("https://example.com", insecure=True)
            assert mock_create.return_value.check_hostname is False
            assert mock_create.return_value.verify_mode == ssl.CERT_NONE
        assert result.reachable is True


class TestReachabilityResult:
    def test_defaults(self):
        r = ReachabilityResult(reachable=False, domain="example.com")
        assert r.reachable is False
        assert r.domain == "example.com"
        assert r.ip is None
        assert r.error is None
        assert r.error_category is None