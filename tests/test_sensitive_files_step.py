"""Tests for SensitiveFilesStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.sensitive_files_step import (
    SensitiveFilesStep,
    is_interesting_content,
    looks_like_soft_404,
)


class TestContentHeuristics:
    def test_soft_404_detected(self):
        assert looks_like_soft_404("<html><body>Page Not Found</body></html>")

    def test_real_content_not_soft_404(self):
        assert not looks_like_soft_404('Bud1\x00\x00\x00\x01')

    def test_json_is_interesting(self):
        assert is_interesting_content('{"db": "x"}', "credentials.json")

    def test_ds_store_magic(self):
        assert is_interesting_content("\x00\x00\x00\x01Bud1" + "x" * 50, ".DS_Store")

    def test_html_404_not_interesting(self):
        assert not is_interesting_content("<html>Page Not Found</html>", "backup.zip")

    def test_private_key_interesting(self):
        assert is_interesting_content("-----BEGIN", "id_rsa")

    def test_spa_fallback_not_interesting(self):
        """SPA servers return index.html (200) for unknown paths."""
        spa_shell = "<!doctype html>\n<html lang=\"en\"><head><title>App</title></head></html>"
        assert not is_interesting_content(spa_shell, "backup.sql")
        assert not is_interesting_content(spa_shell, "config.php.bak")
        assert not is_interesting_content(spa_shell, "credentials.json")
        assert not is_interesting_content(spa_shell, "id_rsa")

    def test_spa_fallback_with_comment_prefix(self):
        """Angular-style shells start with a comment block before <!doctype>."""
        shell = ("<!--\n  ~ Copyright (c) 2026 someone\n  ~ SPDX-License: MIT\n"
                 "-->\n<!doctype html>\n<html lang=\"en\"><head><title>App</title>"
                 "</head></html>")
        assert not is_interesting_content(shell, "backup.sql")
        assert not is_interesting_content(shell, "config.php.bak")
        assert not is_interesting_content(shell, "db.sql")

    def test_text_html_content_type_rejected(self):
        assert not is_interesting_content("anything", "backup.sql", "text/html; charset=utf-8")

    def test_html_body_on_file_path_rejected(self):
        assert not is_interesting_content("<html>anything at all</html>", "db.sql")


class TestSensitiveFilesStep:
    async def test_exposed_file_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "backup.zip" in url:
                return MagicMock(status_code=200, text="PK\x03\x04 binary-data")
            return MagicMock(status_code=404, text="not found")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = SensitiveFilesStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("backup.zip" in f.title for f in findings)
        assert findings[0].severity == "high"

    async def test_nothing_exposed(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="not found")
        )
        step = SensitiveFilesStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []

    async def test_soft_404_page_not_reported(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html>Page Not Found</html>")
        )
        step = SensitiveFilesStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []
