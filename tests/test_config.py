# tests/test_config.py
"""Unit tests for config.py — ScanConfig."""

from pathlib import Path

import pytest

from config import ScanConfig


class TestScanConfig:
    def test_default_threads(self):
        config = ScanConfig()
        assert config.threads == 2

    def test_default_timeout(self):
        config = ScanConfig()
        assert config.timeout == 10

    def test_default_insecure(self):
        config = ScanConfig()
        assert config.insecure is False

    def test_default_log_level(self):
        config = ScanConfig()
        assert config.log_level == "INFO"

    def test_default_output_dir(self):
        config = ScanConfig()
        assert config.output_dir == Path("./reports")

    def test_default_output_format(self):
        config = ScanConfig()
        assert config.output_format == "markdown"

    def test_default_quiet(self):
        config = ScanConfig()
        assert config.quiet is False

    def test_threads_ge_1(self):
        with pytest.raises(ValueError, match="Input should be greater than or equal to 1"):
            ScanConfig(threads=0)

    def test_threads_le_20(self):
        with pytest.raises(ValueError, match="Input should be less than or equal to 20"):
            ScanConfig(threads=21)

    def test_timeout_ge_1(self):
        with pytest.raises(ValueError, match="Input should be greater than or equal to 1"):
            ScanConfig(timeout=0)

    def test_wpscan_timeout_ge_60(self):
        with pytest.raises(ValueError, match="Input should be greater than or equal to 60"):
            ScanConfig(wpscan_timeout=30)

    def test_nuclei_threads_ge_1(self):
        with pytest.raises(ValueError, match="Input should be greater than or equal to 1"):
            ScanConfig(nuclei_threads=0)

    def test_log_level_validation(self):
        with pytest.raises(ValueError):
            ScanConfig(log_level="INVALID")

    def test_output_format_validation(self):
        with pytest.raises(ValueError):
            ScanConfig(output_format="csv")

    def test_wp_auth_method_validation(self):
        with pytest.raises(ValueError):
            ScanConfig(wp_auth_method="token")

    def test_env_prefix_wp(self, monkeypatch):
        monkeypatch.setenv("WP_THREADS", "10")
        config = ScanConfig()
        assert config.threads == 10

    def test_env_prefix_wp_log_level(self, monkeypatch):
        monkeypatch.setenv("WP_LOG_LEVEL", "DEBUG")
        config = ScanConfig()
        assert config.log_level == "DEBUG"

    def test_env_prefix_wp_shodan(self, monkeypatch):
        monkeypatch.setenv("WP_SHODAN_API_KEY", "test-key-123")
        config = ScanConfig()
        assert config.shodan_api_key == "test-key-123"

    def test_mkdir_output_creates_directory(self, tmp_path):
        output = tmp_path / "reports"
        config = ScanConfig(output_dir=output)
        config.mkdir_output()
        assert output.exists()

    def test_mkdir_output_idempotent(self, tmp_path):
        output = tmp_path / "reports"
        output.mkdir(parents=True)
        config = ScanConfig(output_dir=output)
        config.mkdir_output()  # should not raise

    def test_vulndb_cache_ttl_default(self):
        config = ScanConfig()
        assert config.vulndb_cache_ttl == 300

    def test_spider_max_depth_default(self):
        config = ScanConfig()
        assert config.spider_max_depth == 2

    def test_spider_max_pages_default(self):
        config = ScanConfig()
        assert config.spider_max_pages == 50

    def test_ffuf_rate_limit_default_zero(self):
        config = ScanConfig()
        assert config.ffuf_rate_limit == 0
