"""Tests for PhpVersionStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.infrastructure.php_version_step import (
    PhpVersionStep,
    branch_status,
    parse_php_version,
)


class TestParsePhpVersion:
    def test_x_powered_by(self):
        assert parse_php_version("PHP/8.1.2") == "8.1.2"
        assert parse_php_version("PHP 8.2.1") == "8.2.1"

    def test_no_php(self):
        assert parse_php_version("Express") is None


class TestBranchStatus:
    def test_eol(self):
        assert branch_status("8.1.5") == "eol"
        assert branch_status("7.4.3") == "eol"

    def test_security_only(self):
        assert branch_status("8.2.1") == "security-only"

    def test_supported(self):
        assert branch_status("8.3.0") == "supported"


class TestPhpVersionStep:
    async def test_eol_php_high(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, headers={"x-powered-by": "PHP/7.4.3"},
                                   text="ok")
        )
        step = PhpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("end-of-life" in f.title.lower() for f in findings)
        assert any(f.severity == "high" for f in findings)

    async def test_disclosed_supported_low(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, headers={"x-powered-by": "PHP/8.3.1"},
                                   text="ok")
        )
        step = PhpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("disclosed" in f.title.lower() for f in findings)

    async def test_phpsessid_only_info(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200,
                                   headers={"set-cookie": "PHPSESSID=abc"},
                                   text="ok")
        )
        step = PhpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("PHPSESSID" in f.title for f in findings)

    async def test_no_php_clean(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, headers={}, text="ok")
        )
        step = PhpVersionStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []
