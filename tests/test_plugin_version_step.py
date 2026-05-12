# tests/test_plugin_version_step.py
"""Tests for PluginVersionStep."""

from unittest.mock import MagicMock

import pytest


class TestDetectPlugins:
    """Tests for _detect_plugins method."""

    @pytest.mark.asyncio
    async def test_detect_plugins_from_html(self, plugin_step, mock_http):
        """Test detecting a single plugin from HTML."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            <html>
                <link href="/wp-content/plugins/contact-form-7/style.css">
            </html>
        """
        mock_http.get.return_value = mock_response

        plugins = await plugin_step._detect_plugins()

        assert plugins == ["contact-form-7"]
        mock_http.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_detect_multiple_plugins(self, plugin_step, mock_http):
        """Test detecting multiple plugins from HTML."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            <html>
                <script src="/wp-content/plugins/akismet/_inc/form.js"></script>
                <link href="/wp-content/plugins/jetpack/modules/likes/style.css">
                <img src="/wp-content/plugins/contact-form-7/includes/css/styles.css">
            </html>
        """
        mock_http.get.return_value = mock_response

        plugins = await plugin_step._detect_plugins()

        assert len(plugins) == 3
        assert "akismet" in plugins
        assert "jetpack" in plugins
        assert "contact-form-7" in plugins

    @pytest.mark.asyncio
    async def test_detect_no_plugins(self, plugin_step, mock_http):
        """Test when no plugins are found in HTML."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>No plugins here</body></html>"
        mock_http.get.return_value = mock_response

        plugins = await plugin_step._detect_plugins()

        assert plugins == []

    @pytest.mark.asyncio
    async def test_detect_plugins_deduplication(self, plugin_step, mock_http):
        """Test that duplicate plugin names are deduplicated."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            <html>
                <link href="/wp-content/plugins/akismet/style1.css">
                <script src="/wp-content/plugins/akismet/script.js"></script>
                <img src="/wp-content/plugins/akismet/image.png">
            </html>
        """
        mock_http.get.return_value = mock_response

        plugins = await plugin_step._detect_plugins()

        assert plugins == ["akismet"]

    @pytest.mark.asyncio
    async def test_detect_plugins_http_error(self, plugin_step, mock_http):
        """Test handling HTTP errors when fetching homepage."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_http.get.return_value = mock_response

        plugins = await plugin_step._detect_plugins()

        assert plugins == []


class TestFetchVersion:
    """Tests for _fetch_version method."""

    @pytest.mark.asyncio
    async def test_fetch_version_from_readme_txt(self, plugin_step, mock_http):
        """Test extracting version from readme.txt."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            === Contact Form 7 ===
            Tags: forms, contact
            Stable tag: 5.8.2
            
            == Description ==
        """
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version("wp-content/plugins/cf7/readme.txt")

        assert version == "5.8.2"

    @pytest.mark.asyncio
    async def test_fetch_version_from_readme_md(self, plugin_step, mock_http):
        """Test extracting version from readme.md."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            # Contact Form 7
            
            **Stable tag:** 1.2.3
            
            A contact form plugin.
        """
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version("wp-content/plugins/cf7/readme.md")

        assert version == "1.2.3"

    @pytest.mark.asyncio
    async def test_fetch_version_from_php_header(self, plugin_step, mock_http):
        """Test extracting version from PHP file header."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            <?php
            /**
             * Plugin Name: My Plugin
             * Version: 2.0.0
             * Author: Developer
             */
            """
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version(
            "wp-content/plugins/my-plugin/my-plugin.php"
        )

        assert version == "2.0.0"

    @pytest.mark.asyncio
    async def test_fetch_version_not_found(self, plugin_step, mock_http):
        """Test when file exists but no version found."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
            Plugin Name: Test Plugin
            Description: A test plugin with no version info.
        """
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version("wp-content/plugins/test/readme.txt")

        assert version is None

    @pytest.mark.asyncio
    async def test_fetch_version_file_not_found(self, plugin_step, mock_http):
        """Test when file returns 404."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version(
            "wp-content/plugins/nonexistent/readme.txt"
        )

        assert version is None

    @pytest.mark.asyncio
    async def test_fetch_version_http_error(self, plugin_step, mock_http):
        """Test handling HTTP 500 error."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version("wp-content/plugins/test/readme.txt")

        assert version is None

    @pytest.mark.asyncio
    async def test_fetch_version_minor_only(self, plugin_step, mock_http):
        """Test version with only major.minor (no patch)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Stable tag: 1.2"
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version("wp-content/plugins/test/readme.txt")

        assert version == "1.2"

    @pytest.mark.asyncio
    async def test_fetch_version_prerelease(self, plugin_step, mock_http):
        """Test version with pre-release suffix (lowercase handled)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Stable tag: 5.8.2"
        mock_http.get.return_value = mock_response

        version = await plugin_step._fetch_version("wp-content/plugins/test/readme.txt")

        assert version == "5.8.2"


class TestGetPluginVersion:
    """Tests for _get_plugin_version method."""

    @pytest.mark.asyncio
    async def test_version_fallback_order(self, plugin_step, mock_http):
        """Test that sources are tried in correct order."""
        responses = [
            MagicMock(status_code=404),  # readme.txt not found
            MagicMock(
                status_code=200, text="Stable tag: 1.5.0"
            ),  # readme.md has version
        ]
        mock_http.get.side_effect = responses

        result = await plugin_step._get_plugin_version("test-plugin")

        assert result["version"] == "1.5.0"
        assert result["source"] == "readme.md"
        assert mock_http.get.call_count == 2

    @pytest.mark.asyncio
    async def test_version_from_php_fallback(self, plugin_step, mock_http):
        """Test fallback to PHP file when readme files missing."""
        responses = [
            MagicMock(status_code=404),  # readme.txt not found
            MagicMock(status_code=404),  # readme.md not found
            MagicMock(status_code=200, text="Version: 3.0.1"),  # PHP has version
        ]
        mock_http.get.side_effect = responses

        result = await plugin_step._get_plugin_version("test-plugin")

        assert result["version"] == "3.0.1"
        assert result["source"] == "test-plugin.php"

    @pytest.mark.asyncio
    async def test_version_all_sources_fail(self, plugin_step, mock_http):
        """Test when all version sources fail."""
        responses = [
            MagicMock(status_code=404),
            MagicMock(status_code=404),
            MagicMock(status_code=404),
        ]
        mock_http.get.side_effect = responses

        result = await plugin_step._get_plugin_version("test-plugin")

        assert result["version"] == "unknown"
        assert result["source"] is None


class TestRun:
    """Integration tests for run method."""

    @pytest.mark.asyncio
    async def test_run_with_known_versions(self, plugin_step, mock_http):
        """Test run with plugins that have known versions."""
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/">cf7</a></html>',
            ),
            MagicMock(status_code=200, text="Stable tag: 5.8.2"),
            MagicMock(status_code=404),
            MagicMock(status_code=200, text="Version: 5.8.2"),
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.module == "fingerprint"
        assert finding.step == "plugin_version"
        assert finding.severity == "info"
        assert "cf7" in finding.evidence
        assert "5.8.2" in finding.evidence

    @pytest.mark.asyncio
    async def test_run_with_unknown_versions(self, plugin_step, mock_http):
        """Test run when no versions can be determined."""
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/unknown/">unknown</a></html>',
            ),
            MagicMock(status_code=404),
            MagicMock(status_code=404),
            MagicMock(status_code=404),
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        assert len(findings) == 1
        finding = findings[0]
        assert "unknown" in finding.evidence
        assert finding.raw["summary"]["known"] == 0
        assert finding.raw["summary"]["unknown"] == 1

    @pytest.mark.asyncio
    async def test_run_with_mixed_versions(self, plugin_step, mock_http):
        """Test run with mix of known and unknown versions."""
        mock_http.get.reset_mock()
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/"></a><a href="/wp-content/plugins/akismet/"></a></html>',
            ),
            MagicMock(status_code=404),  # cf7 readme.txt
            MagicMock(status_code=200, text="Stable tag: 5.8.2"),  # cf7 readme.md
            MagicMock(status_code=404),  # cf7 php
            MagicMock(status_code=404),  # akismet readme.txt
            MagicMock(status_code=404),  # akismet readme.md
            MagicMock(status_code=404),  # akismet php
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        assert len(findings) == 1
        finding = findings[0]
        assert "cf7" in finding.evidence
        assert "5.8.2" in finding.evidence
        assert "akismet" in finding.evidence
        assert "unknown" in finding.evidence
        assert finding.raw["summary"]["known"] == 1
        assert finding.raw["summary"]["unknown"] == 1

    @pytest.mark.asyncio
    async def test_run_no_plugins_detected(self, plugin_step, mock_http):
        """Test run when no plugins are found."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>No plugins here</body></html>"
        mock_http.get.return_value = mock_response

        findings = await plugin_step.run()

        assert findings == []

    @pytest.mark.asyncio
    async def test_run_http_error_on_homepage(self, plugin_step, mock_http):
        """Test run when homepage returns error."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_http.get.return_value = mock_response

        findings = await plugin_step.run()

        assert findings == []


class TestFindingStructure:
    """Tests for Finding structure and content."""

    @pytest.mark.asyncio
    async def test_finding_has_correct_module(self, plugin_step, mock_http):
        """Test that finding has correct module."""
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/"></a></html>',
            ),
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),
            MagicMock(status_code=404),
            MagicMock(status_code=200, text="Version: 1.0.0"),
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        assert findings[0].module == "fingerprint"

    @pytest.mark.asyncio
    async def test_finding_has_correct_step(self, plugin_step, mock_http):
        """Test that finding has correct step name."""
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/"></a></html>',
            ),
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),
            MagicMock(status_code=404),
            MagicMock(status_code=200, text="Version: 1.0.0"),
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        assert findings[0].step == "plugin_version"

    @pytest.mark.asyncio
    async def test_finding_has_correct_severity(self, plugin_step, mock_http):
        """Test that finding has info severity."""
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/"></a></html>',
            ),
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),
            MagicMock(status_code=404),
            MagicMock(status_code=200, text="Version: 1.0.0"),
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        assert findings[0].severity == "info"

    @pytest.mark.asyncio
    async def test_finding_raw_data_structure(self, plugin_step, mock_http):
        """Test that raw data contains expected structure."""
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/"></a></html>',
            ),
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),
            MagicMock(status_code=404),
            MagicMock(status_code=200, text="Version: 1.0.0"),
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        raw = findings[0].raw
        assert "plugins" in raw
        assert "summary" in raw
        assert "cf7" in raw["plugins"]

    @pytest.mark.asyncio
    async def test_finding_raw_summary_counts(self, plugin_step, mock_http):
        """Test that summary counts are accurate."""
        mock_http.get.reset_mock()
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/"></a><a href="/wp-content/plugins/akismet/"></a></html>',
            ),
            MagicMock(status_code=404),  # cf7 readme.txt
            MagicMock(status_code=404),  # cf7 readme.md
            MagicMock(status_code=200, text="Version: 1.0.0"),  # cf7 php
            MagicMock(status_code=404),  # akismet readme.txt
            MagicMock(status_code=404),  # akismet readme.md
            MagicMock(status_code=404),  # akismet php
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        summary = findings[0].raw["summary"]
        assert summary["total"] == 2
        assert summary["known"] == 1
        assert summary["unknown"] == 1

    @pytest.mark.asyncio
    async def test_finding_recommendation_present(self, plugin_step, mock_http):
        """Test that finding includes recommendation."""
        responses = [
            MagicMock(
                status_code=200,
                text='<html><a href="/wp-content/plugins/cf7/"></a></html>',
            ),
            MagicMock(status_code=200, text="Stable tag: 1.0.0"),
            MagicMock(status_code=404),
            MagicMock(status_code=200, text="Version: 1.0.0"),
        ]
        mock_http.get.side_effect = responses

        findings = await plugin_step.run()

        assert "update" in findings[0].recommendation.lower()
