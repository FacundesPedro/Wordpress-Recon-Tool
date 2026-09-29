"""Tests for core/reachability.py — pre-flight reachability probe."""

import socket
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.reachability import ReachabilityResult, check_reachability


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
        ):
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
        ):
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = {}
            with patch(
                "core.reachability.ssl.create_default_context", return_value=mock_ctx
            ) as mock_create:
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
        assert r.attempts == 1
        assert r.permanent is False


class TestRetriesAndPinning:
    @pytest.mark.asyncio
    async def test_transient_failure_is_retried(self):
        calls = {"n": 0}

        def flaky_open(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionResetError("Connection reset by peer")
            return (MagicMock(), _mock_writer())

        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(side_effect=flaky_open),
        ), patch("core.reachability.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            result = await check_reachability(
                "http://example.com", attempts=2, retry_delay=0.0
            )
        assert result.reachable is True
        assert result.attempts == 2
        assert calls["n"] == 2
        mock_sleep.assert_awaited()

    @pytest.mark.asyncio
    async def test_permanent_dns_failure_not_retried(self):
        with patch(
            "core.reachability.socket.gethostbyname",
            side_effect=socket.gaierror("[Errno 8] nodename nor servname provided"),
        ) as mock_dns, patch(
            "core.reachability.asyncio.sleep", new=AsyncMock()
        ) as mock_sleep:
            result = await check_reachability(
                "https://nonexistent.invalid", attempts=4, retry_delay=0.0
            )
        assert result.reachable is False
        assert result.permanent is True
        assert mock_dns.call_count == 1
        mock_sleep.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_permanent_cert_failure_not_retried(self):
        with patch(
            "core.reachability.socket.gethostbyname", return_value="1.2.3.4"
        ), patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), _mock_writer())),
        ), patch(
            "core.reachability.socket.create_connection",
            side_effect=ssl.SSLCertVerificationError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
            ),
        ) as mock_conn, patch(
            "core.reachability.asyncio.sleep", new=AsyncMock()
        ) as mock_sleep:
            result = await check_reachability(
                "https://example.com", attempts=3, retry_delay=0.0
            )
        assert result.permanent is True
        assert mock_conn.call_count == 1
        mock_sleep.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_connect_ip_skips_dns(self):
        with patch(
            "core.reachability.socket.gethostbyname"
        ) as mock_dns, patch(
            "core.reachability.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), _mock_writer())),
        ) as mock_open:
            result = await check_reachability(
                "http://example.com", connect_ip="10.0.0.5"
            )
        assert result.reachable is True
        assert result.ip == "10.0.0.5"
        assert result.dns_ms == 0.0
        mock_dns.assert_not_called()
        # The pinned IP, not the hostname, is used for the TCP connect.
        assert mock_open.call_args.args[0] == "10.0.0.5"
