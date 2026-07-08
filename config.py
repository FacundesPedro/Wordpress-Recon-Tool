"""Configuration for the WordPress reconnaissance tool using pydantic-settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanConfig(BaseSettings):
    """Application configuration with pydantic-settings.

    Supports:
    - Environment variables (prefix: WP_)
    - .env file loading
    - CLI argument override via annotation
    - Validation with Field constraints

    Environment variables:
        WP_THREADS - number of concurrent threads
        WP_TIMEOUT - request timeout in seconds
        WP_LOG_LEVEL - logging level
        WP_WPSCAN_API_TOKEN - WPScan API token
        WP_SHODAN_API_KEY - Shodan API key
        WP_NUCLEI_SEVERITY - nuclei severity filter
        WP_USER - WordPress username for authenticated REST API
        WP_APPLICATION_PASSWORD - WordPress Application Password
    """

    model_config = SettingsConfigDict(
        env_prefix="WP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    threads: int = Field(
        default=2, ge=1, le=20, description="Number of concurrent threads"
    )
    timeout: int = Field(default=10, ge=1, description="Request timeout in seconds")
    insecure: bool = Field(
        default=False, description="Skip TLS certificate verification"
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", description="Logging level"
    )
    output_dir: Path = Field(
        default=Path("./reports"), description="Output directory for reports"
    )
    output_format: Literal["json", "markdown", "sarif", "all"] = Field(
        default="markdown", description="Report output format"
    )
    quiet: bool = Field(default=False, description="Suppress console output")

    wpscan_api_token: str = Field(default="", description="WPScan API token")
    wpscan_timeout: int = Field(
        default=600, ge=60, description="WPScan timeout in seconds"
    )
    wpscan_enumerate: str = Field(
        default="vp,vt,tt,cb,u",
        description="WPScan enumeration options",
    )
    enable_wpscan: bool = Field(
        default=False, description="Enable WPScan vulnerability scanner"
    )

    enable_nuclei: bool = Field(
        default=False, description="Enable Nuclei vulnerability scanner"
    )
    nuclei_severity: str = Field(
        default="medium,high,critical",
        description="Nuclei severity filter (comma-separated)",
    )
    nuclei_threads: int = Field(default=100, ge=1, description="Nuclei concurrency")
    nuclei_timeout: int = Field(
        default=300, ge=60, description="Nuclei timeout in seconds"
    )

    shodan_api_key: str = Field(default="", description="Shodan API key")

    wp_user: str = Field(default="", description="WordPress username for authenticated REST API scan")
    wp_application_password: str = Field(default="", description="WordPress application password (WP >= 5.6)")
    wp_auth_method: Literal["app_password", "cookie"] = Field(
        default="app_password",
        description="Authentication method for admin-area steps (app_password or cookie)",
    )

    vulndb_cache_ttl: int = Field(
        default=300, ge=0,
        description="Vulnerability DB cache TTL in seconds (0 = no cache)",
    )

    skip_version_check: bool = Field(
        default=False, description="Skip version checking for external tools"
    )
    require_version: bool = Field(
        default=False, description="Fail if tool version is incompatible"
    )
    verbose_version_check: bool = Field(
        default=False, description="Show detailed version check information"
    )

    # FFUF settings
    enable_ffuf: bool = Field(
        default=False, description="Enable FFUF fuzzer"
    )
    ffuf_wordlist: str = Field(
        default="", description="FFUF wordlist path"
    )
    ffuf_timeout: int = Field(
        default=300, ge=60, description="FFUF timeout in seconds"
    )
    ffuf_rate_limit: int = Field(
        default=0, ge=0, description="FFUF rate limit (0 = unlimited)"
    )
    ffuf_filter_status: str = Field(
        default="404", description="FFUF filter status codes"
    )

    # OpenDoor settings
    enable_opendoor: bool = Field(
        default=False, description="Enable OpenDoor scanner"
    )
    opendoor_wordlist: str = Field(
        default="", description="OpenDoor wordlist path"
    )
    opendoor_timeout: int = Field(
        default=300, ge=60, description="OpenDoor timeout in seconds"
    )
    opendoor_rate_limit: int = Field(
        default=0, ge=0, description="OpenDoor rate limit (0 = unlimited)"
    )
    opendoor_mode: str = Field(
        default="wp_paths", description="OpenDoor mode (wp_paths, backup, config, sensitive)"
    )

    spider_max_depth: int = Field(
        default=2, ge=1, le=10, description="Maximum crawl depth for content spider"
    )
    spider_max_pages: int = Field(
        default=50, ge=1, le=500, description="Maximum pages to crawl"
    )

    def mkdir_output(self) -> None:
        """Ensure output directory exists."""
        self.output_dir.mkdir(parents=True, exist_ok=True)


Config = ScanConfig
