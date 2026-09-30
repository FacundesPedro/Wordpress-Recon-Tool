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
    parallel_steps: bool = Field(
        default=False,
        description=(
            "Run the steps within a risk tier as a dependency-aware parallel "
            "graph, sharing data through a per-target ScanContext "
            "(env WP_PARALLEL_STEPS)"
        ),
    )
    step_concurrency: int = Field(
        default=0,
        ge=0,
        le=200,
        description=(
            "Max concurrently running steps in parallel mode "
            "(0 = use the threads value)"
        ),
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
    output_format: str = Field(
        default="markdown",
        description=(
            "Report output format(s): a single value or comma-separated list of "
            "json, markdown, sarif, html, pdf, or 'all'"
        ),
    )
    organize_by_target: bool = Field(
        default=True,
        description=(
            "Write each target's reports and raw tool output into a "
            "<output>/<host>/ subfolder (set false for the legacy flat layout)"
        ),
    )
    quiet: bool = Field(default=False, description="Suppress console output")
    raw_list_cap: int = Field(
        default=200, ge=0, le=100000,
        description=(
            "Max entries stored in a finding's list raw field and evidence "
            "(0 = unlimited); prevents report-size explosions"
        ),
    )
    report_render_limit: int = Field(
        default=500, ge=0, le=100000,
        description=(
            "Max findings rendered per report format (markdown/html/pdf); "
            "0 = unlimited. Guards against the PDF renderer OOMing on huge scans"
        ),
    )
    report_render_timeout: int = Field(
        default=120, ge=0, le=3600,
        description="Wall-clock timeout (seconds) for PDF rendering (0 = no limit)",
    )

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
    nuclei_threads: int = Field(
        default=25,
        ge=1,
        le=500,
        description="Nuclei template concurrency (-concurrency, env WP_NUCLEI_THREADS)",
    )
    nuclei_rate_limit: int = Field(
        default=150,
        ge=1,
        description="Nuclei max requests per second (-rl)",
    )
    nuclei_timeout: int = Field(
        default=300, ge=60, description="Nuclei timeout in seconds"
    )

    shodan_api_key: str = Field(default="", description="Shodan API key")

    wp_user: str = Field(
        default="", description="WordPress username for authenticated REST API scan"
    )
    wp_application_password: str = Field(
        default="", description="WordPress application password (WP >= 5.6)"
    )
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
    ffuf_directory_wordlist: str = Field(
        default="", description="FFUF wordlist for directory discovery (directories step)"
    )
    ffuf_files_wordlist: str = Field(
        default="", description="FFUF wordlist for file discovery (files step)"
    )
    ffuf_wp_wordlist: str = Field(
        default="", description="FFUF wordlist for WordPress path discovery (ffuf_wp step)"
    )
    ffuf_timeout: int = Field(
        default=300, ge=60, description="FFUF execution timeout in seconds"
    )
    ffuf_threads: int = Field(
        default=40, ge=1, le=500, description="FFUF concurrent threads (-t)"
    )
    ffuf_rate_limit: int = Field(
        default=0, ge=0, description="FFUF request rate per second (-rate; 0 = unlimited)"
    )
    ffuf_http_timeout: int = Field(
        default=10, ge=1, description="FFUF per-request HTTP timeout in seconds"
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
        default=0, ge=0, description="OpenDoor thread count (0 = default)"
    )
    opendoor_delay: float = Field(
        default=0.5, ge=0.0, le=30.0, description="OpenDoor delay between requests in seconds"
    )
    opendoor_mode: str = Field(
        default="wp_paths", description="OpenDoor mode (wp_paths, backup, config, sensitive)"
    )

    # Wordlist overrides (env: WP_<NAME>). Empty = use built-in resolution chain.
    wordlist: str = Field(
        default="", description="Credential wordlist path (username:password per line)"
    )
    login_wordlist: str = Field(
        default="", description="Login brute-force credential wordlist path"
    )
    plugin_wordlist: str = Field(
        default="", description="Plugin brute-force wordlist path"
    )
    theme_wordlist: str = Field(
        default="", description="Theme brute-force wordlist path"
    )
    source_assets: str = Field(
        default="", description="Asset path wordlist for source discovery fuzzing"
    )
    api_paths: str = Field(
        default="", description="API/documentation path wordlist for api_surface"
    )
    admin_paths: str = Field(
        default="", description="Admin/management path wordlist for admin_surface"
    )
    wp_config_backups: str = Field(
        default="", description="WP config backup pattern wordlist"
    )
    env_files: str = Field(
        default="", description="Environment file path wordlist"
    )
    security_headers: str = Field(
        default="", description="Security header wordlist"
    )
    common_ports: str = Field(
        default="", description="Common port wordlist"
    )
    waf_signatures: str = Field(
        default="", description="WAF signature wordlist (JSON)"
    )
    xmlrpc_dangerous_methods: str = Field(
        default="", description="Dangerous XML-RPC method wordlist"
    )
    login_pages: str = Field(
        default="", description="Login page path wordlist"
    )

    passive_osint: bool = Field(
        default=True,
        description=(
            "Query public OSINT sources (crt.sh, wayback) for the target "
            "(set false to skip on filtered/internal engagements)"
        ),
    )
    spider_max_depth: int = Field(
        default=2, ge=1, le=10, description="Maximum crawl depth for content spider"
    )
    spider_max_pages: int = Field(
        default=50, ge=1, le=500, description="Maximum pages to crawl"
    )

    bruteforce_concurrency: int = Field(
        default=4, ge=1, le=20,
        description="Concurrent probes for plugin/theme brute-force steps",
    )
    bruteforce_max_probes: int = Field(
        default=0, ge=0,
        description="Maximum brute-force probes (0 = unlimited)",
    )

    stealth_enabled: bool = Field(
        default=False, description="Enable stealth mode (jitter, UA pool, referer spoofing, dedup)"
    )
    stealth_min_delay: float = Field(
        default=1.0, ge=0.0, description="Minimum delay between requests in seconds (stealth mode)"
    )
    stealth_max_delay: float = Field(
        default=3.0, ge=0.0, description="Maximum delay between requests in seconds (stealth mode)"
    )
    stealth_rotate_ua: bool = Field(
        default=True, description="Rotate User-Agent headers per request"
    )
    stealth_rotate_referer: bool = Field(
        default=True, description="Spoof random Referer headers per request"
    )
    stealth_dedup_requests: bool = Field(
        default=True, description="Skip duplicate HTTP requests"
    )
    stealth_rate_limit: float = Field(
        default=0.0, ge=0.0,
        description="Max requests per second (0 = unlimited, uses jitter only)"
    )

    # Nmap settings
    enable_nmap: bool = Field(
        default=False, description="Enable Nmap port scan step (tools module)"
    )
    enable_nmap_scripts: bool = Field(
        default=False, description="Enable Nmap default NSE script scan step (tools module)"
    )
    nmap_top_ports: int = Field(
        default=100, ge=1, le=65535, description="Number of top ports for Nmap scan"
    )
    nmap_ports: str = Field(
        default="", description="Custom Nmap port list (overrides top ports, e.g. '80,443,8080')"
    )
    nmap_timeout: int = Field(
        default=300, ge=60, description="Nmap timeout in seconds"
    )

    # Raw external-tool output persistence
    save_raw: bool = Field(
        default=True,
        description="Persist raw stdout/stderr/argv of external tool steps",
    )
    raw_output_dir: str = Field(
        default="",
        description="Directory for raw tool output (default: <output>/raw)",
    )
    raw_max_bytes: int = Field(
        default=5_000_000,
        ge=0,
        description="Max bytes written per raw artifact (0 = unlimited)",
    )
    raw_no_redact: bool = Field(
        default=False,
        description="Do not redact secrets from persisted raw output (debug only)",
    )
    raw_history: bool = Field(
        default=True,
        description=(
            "Before overwriting a raw artifact on re-run, move the previous "
            "version into <raw>/history/<run-id>/ (append-only evidence)"
        ),
    )

    # Webapp / source review settings
    source_scan_max_js: int = Field(
        default=20, ge=1, le=200,
        description="Max JS/asset files to fetch for source review",
    )
    source_scan_max_bytes: int = Field(
        default=1000000, ge=1024,
        description="Max bytes per asset file for source review",
    )
    source_scan_sourcemaps: bool = Field(
        default=True, description="Probe for JS sourcemaps during source review"
    )
    source_scan_fuzz: bool = Field(
        default=True, description="Fuzz common asset paths during source discovery"
    )
    webapp_max_pages: int = Field(
        default=10, ge=1, le=100,
        description="Max pages to analyze for the content leak step",
    )
    webapp_open_redirect: bool = Field(
        default=True,
        description="Probe for open redirects with canary URLs (open_redirect step)",
    )
    webapp_redirect_max_requests: int = Field(
        default=60, ge=10, le=500,
        description="Max canary requests for the open redirect step",
    )
    webapp_host_probe: bool = Field(
        default=True,
        description="Probe Host/X-Forwarded-Host headers with canary values (host_header step)",
    )
    webapp_max_api_paths: int = Field(
        default=30, ge=5, le=200,
        description="Max API/documentation paths to probe (api_surface step)",
    )
    webapp_max_admin_paths: int = Field(
        default=40, ge=5, le=300,
        description="Max admin/management paths to probe (admin_surface step)",
    )
    webapp_jwt_audit: bool = Field(
        default=True,
        description="Audit JWTs found in cookies/HTML/JS (jwt_audit step)",
    )
    webapp_websocket_probe: bool = Field(
        default=True,
        description="Probe WebSocket endpoints for cross-origin handshakes (websocket step)",
    )
    webapp_mgmt_console_probe: bool = Field(
        default=True,
        description=(
            "Probe for exposed management consoles and match versions to "
            "advisories (management_console step)"
        ),
    )
    takeover_max_subdomains: int = Field(
        default=25, ge=1, le=200,
        description="Max subdomains to check for takeover (subdomain_takeover step)",
    )

    # Active / intrusive testing settings (tier 5, explicit opt-in only)
    active_enabled: bool = Field(
        default=False,
        description="Master switch for active/intrusive testing steps (active module)",
    )
    active_max_params: int = Field(
        default=20, ge=1, le=200,
        description="Max query parameters tested per active injection step",
    )
    active_max_requests: int = Field(
        default=100, ge=1, le=2000,
        description="Hard cap on probe requests per active step",
    )
    active_delay: float = Field(
        default=0.5, ge=0.0, le=30.0,
        description="Delay in seconds between active probe requests",
    )
    active_time_based: bool = Field(
        default=False,
        description="Enable time-based blind SQLi probes (SLEEP canaries; slow)",
    )
    active_file_upload: bool = Field(
        default=False,
        description="Enable file upload probing (uploads a safe marker file; leaves an artifact)",
    )
    active_smuggling: bool = Field(
        default=False,
        description="Enable HTTP request smuggling timing probes (raw sockets; noisy)",
    )
    active_race_endpoint: str = Field(
        default="",
        description=(
            "Absolute path for race-condition probing "
            "(e.g. /api/coupon/apply); empty = skip"
        ),
    )
    active_mass_assign_endpoint: str = Field(
        default="",
        description="Absolute path for mass-assignment probing (e.g. /api/register); empty = skip",
    )
    active_params: str = Field(
        default="",
        description=(
            "Operator-supplied injection targets for the active family, as "
            "comma-separated path:param pairs (e.g. '/api/items:id,/api/search:q')"
        ),
    )
    active_js_max: int = Field(
        default=5,
        ge=0,
        le=50,
        description=(
            "Max same-origin JS bundles to parse for API endpoints/params when "
            "the homepage exposes no query parameters (SPA support)"
        ),
    )

    skip_reachability_check: bool = Field(
        default=False, description="Skip pre-flight DNS/TCP/TLS reachability probe"
    )
    retries: int = Field(
        default=2,
        ge=0,
        le=10,
        description=(
            "Extra attempts for the pre-flight reachability probe on transient "
            "failures (timeout/reset/refused); 0 = single-shot"
        ),
    )
    retry_delay: float = Field(
        default=1.0,
        ge=0.0,
        le=30.0,
        description="Base delay between reachability retries (exponential backoff)",
    )
    target_ip: str = Field(
        default="",
        description=(
            "Override the target's resolved IP (split-horizon/internal targets); "
            "HTTP keeps the hostname for Host/SNI. Applies to a single target."
        ),
    )
    dns_resolve: str = Field(
        default="",
        description=(
            "Comma-separated host:ip overrides (e.g. "
            "'app.example:10.0.0.5,api.example:10.0.0.6')"
        ),
    )
    unreachable_threshold: int = Field(
        default=5, ge=1,
        description="Consecutive network errors before marking target unreachable and aborting",
    )

    def mkdir_output(self) -> None:
        """Ensure output directory exists."""
        self.output_dir.mkdir(parents=True, exist_ok=True)


Config = ScanConfig
