"""Tests for secrets module steps (5 step classes)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# WpConfigBackupStep
# ---------------------------------------------------------------------------

class TestWpConfigBackupStep:
    """WpConfigBackupStep — GET wp-config backup paths, content validation."""

    async def test_backup_found_valid_content(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="define( DB_NAME")
        )
        from steps.secrets.wp_config_backup_step import WpConfigBackupStep
        step = WpConfigBackupStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp-config.php.bak"]
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "wp-config.php backup found" in findings[0].title
        assert "wp-config.php.bak" in findings[0].evidence

    async def test_multiple_backups_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="dbname")
        )
        from steps.secrets.wp_config_backup_step import WpConfigBackupStep
        step = WpConfigBackupStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp-config.php.bak", "wp-config.php~", "wp-config.php.old"]
        )
        findings = await step.run()

        assert len(findings) == 1
        assert "3 backup" in findings[0].description

    async def test_backup_found_wrong_content(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="just some text")
        )
        from steps.secrets.wp_config_backup_step import WpConfigBackupStep
        step = WpConfigBackupStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp-config.php.bak"]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_no_backups_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.secrets.wp_config_backup_step import WpConfigBackupStep
        step = WpConfigBackupStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp-config.php.bak"]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_wordlist_none_skips(self, mock_http, mock_target, mock_config):
        from steps.secrets.wp_config_backup_step import WpConfigBackupStep
        step = WpConfigBackupStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)
        findings = await step.run()
        assert len(findings) == 0

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("timeout"))
        from steps.secrets.wp_config_backup_step import WpConfigBackupStep
        step = WpConfigBackupStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=["wp-config.php.bak"]
        )
        findings = await step.run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DebugLogStep
# ---------------------------------------------------------------------------

class TestDebugLogStep:
    """DebugLogStep — GET debug.log paths, case-sensitive content check."""

    async def test_debug_log_found_php_errors(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="[01-Jan-2026] PHP Notice:  Undefined variable"
            )
        )
        from steps.secrets.debug_log_step import DebugLogStep
        step = DebugLogStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "Debug log found" in findings[0].title

    async def test_debug_log_found_warning(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="PHP Warning:  cannot modify")
        )
        from steps.secrets.debug_log_step import DebugLogStep
        step = DebugLogStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1

    async def test_found_but_no_markers(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="just some log text")
        )
        from steps.secrets.debug_log_step import DebugLogStep
        step = DebugLogStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_no_logs_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.secrets.debug_log_step import DebugLogStep
        step = DebugLogStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_mixed_results(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200, text="PHP Error: something broke"),
            MagicMock(status_code=404, text="Not Found"),
            MagicMock(status_code=404, text="Not Found"),
        ])
        from steps.secrets.debug_log_step import DebugLogStep
        step = DebugLogStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("timeout"))
        from steps.secrets.debug_log_step import DebugLogStep
        step = DebugLogStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PhpinfoStep
# ---------------------------------------------------------------------------

class TestPhpinfoStep:
    """PhpinfoStep — GET phpinfo paths, case-insensitive content check."""

    async def test_phpinfo_found_php_version(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<h1>PHP Version 8.2</h1>")
        )
        from steps.secrets.phpinfo_step import PhpinfoStep
        step = PhpinfoStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "phpinfo file found" in findings[0].title

    async def test_phpinfo_found_system(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<td>System </td><td>Darwin</td>")
        )
        from steps.secrets.phpinfo_step import PhpinfoStep
        step = PhpinfoStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1

    async def test_found_but_no_markers(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html>nothing here</html>")
        )
        from steps.secrets.phpinfo_step import PhpinfoStep
        step = PhpinfoStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_none_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.secrets.phpinfo_step import PhpinfoStep
        step = PhpinfoStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_multiple_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="PHP Version")
        )
        from steps.secrets.phpinfo_step import PhpinfoStep
        step = PhpinfoStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("timeout"))
        from steps.secrets.phpinfo_step import PhpinfoStep
        step = PhpinfoStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GitExposureStep
# ---------------------------------------------------------------------------

class TestGitExposureStep:
    """GitExposureStep — GET .git paths, status-code-only check."""

    async def test_git_file_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="ref: refs/heads/main")
        )
        from steps.secrets.git_exposure_step import GitExposureStep
        step = GitExposureStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert ".git directory exposed" in findings[0].title

    async def test_multiple_git_files_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="[core]")
        )
        from steps.secrets.git_exposure_step import GitExposureStep
        step = GitExposureStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1
        assert ".git/config" in findings[0].evidence

    async def test_none_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.secrets.git_exposure_step import GitExposureStep
        step = GitExposureStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0

    async def test_mixed_results(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=[
            MagicMock(status_code=200, text="[core]"),
            MagicMock(status_code=200, text="ref: main"),
            MagicMock(status_code=404, text="Not Found"),
            MagicMock(status_code=404, text="Not Found"),
        ])
        from steps.secrets.git_exposure_step import GitExposureStep
        step = GitExposureStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 1

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("timeout"))
        from steps.secrets.git_exposure_step import GitExposureStep
        step = GitExposureStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# EnvFileStep
# ---------------------------------------------------------------------------

class TestEnvFileStep:
    """EnvFileStep — GET .env paths, content validation (case-sensitive)."""

    async def test_env_file_found_with_equals(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="DB_PASSWORD=supersecret"
            )
        )
        from steps.secrets.env_file_step import EnvFileStep
        step = EnvFileStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=[".env"]
        )
        findings = await step.run()

        assert len(findings) == 1
        assert ".env file found" in findings[0].title

    async def test_env_file_found_with_app_prefix(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="APP_DEBUG=true")
        )
        from steps.secrets.env_file_step import EnvFileStep
        step = EnvFileStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=[".env"]
        )
        findings = await step.run()
        assert len(findings) == 1

    async def test_env_file_found_with_wp_prefix(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="WP_DEBUG=true")
        )
        from steps.secrets.env_file_step import EnvFileStep
        step = EnvFileStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=[".env"]
        )
        findings = await step.run()
        assert len(findings) == 1

    async def test_found_but_no_markers(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="just some text")
        )
        from steps.secrets.env_file_step import EnvFileStep
        step = EnvFileStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=[".env"]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_none_found(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="Not Found")
        )
        from steps.secrets.env_file_step import EnvFileStep
        step = EnvFileStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=[".env"]
        )
        findings = await step.run()
        assert len(findings) == 0

    async def test_wordlist_none_skips(self, mock_http, mock_target, mock_config):
        from steps.secrets.env_file_step import EnvFileStep
        step = EnvFileStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)
        findings = await step.run()
        assert len(findings) == 0

    async def test_http_exception(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("timeout"))
        from steps.secrets.env_file_step import EnvFileStep
        step = EnvFileStep(target=mock_target, config=mock_config, http=mock_http)
        step.resolve_wordlist_or_fallback = MagicMock(
            return_value=[".env"]
        )
        findings = await step.run()
        assert len(findings) == 0
