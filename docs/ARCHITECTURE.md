# WordPress Recon Tool — v2 Architecture Plan
**Paradigm:** SOLID principles + Atomic Design  
**Stack:** Python 3, Typer CLI, httpx async  

---

## 1. Design Philosophy

### SOLID mapping

| Principle | How it applies |
|-----------|---------------|
| **S** — Single Responsibility | Each step does exactly one thing. `WpscanStep` runs WPScan. `UserApiStep` enumerates users via REST. Never both. |
| **O** — Open/Closed | New checks extend `BaseStep` or `BaseToolStep`. The `Runner` and `Aggregator` never change when new steps are added. |
| **L** — Liskov Substitution | `BaseToolStep` is a valid `BaseStep`. The `Runner` treats every step identically through the base interface. |
| **I** — Interface Segregation | `BaseToolStep` only adds what tool steps need (`binary`, `build_command`, `parse_output`). HTTP steps don't inherit tool concerns. |
| **D** — Dependency Inversion | `Runner` depends on `BaseStep` (abstraction), not on `WpscanStep` or `NucleiStep` (concretions). |

### Atomic Design mapping

| Layer | What lives here |
|-------|----------------|
| **Atoms** | Smallest indivisible primitives: `HttpClient`, `ToolRunner`, `Target`, `Finding`, `Logger` |
| **Molecules** | First composed units: `BaseStep` (uses HttpClient + Finding + Logger), `BaseToolStep` (uses ToolRunner), `Config` |
| **Organisms** | Concrete steps grouped by concern: HTTP steps, Tool steps, each Module (a named group of steps) |
| **Pipeline** | The runtime: `Validator → ToolChecker → Runner → Aggregator` |
| **Output** | `ReportGenerator` consuming aggregated findings → JSON, Markdown, HTML |

---

## 2. Project Structure

```
wordpress_testing_tool/
│
├── main.py                         # CLI entrypoint (Typer)
│
├── config.py                       # ScanConfig (pydantic-settings, WP_* env prefix)
│
├── core/                           # ── ATOMS ──
│   ├── http_client.py              # Shared async httpx session (UA rotation)
│   ├── target.py                   # Target(url, domain, scope)
│   ├── finding.py                  # Finding dataclass + SARIF export
│   ├── logger.py                   # Rich-powered timestamped logger
│   ├── ssrf_protection.py          # IP blocklist (RFC 1918, cloud metadata)
│   ├── auth.py                     # Application Password + AdminSession (cookie)
│   ├── vulndb.py                   # WPVulnerability.net + WPScan API facade
│   └── exceptions.py               # ReconError, ToolNotFoundError, etc.
│
├── base/                           # ── MOLECULES ──
│   ├── step.py                     # BaseStep ABC, BaseHttpStep, BaseToolStep
│   ├── tool.py                     # ToolRunner, AsyncToolRunner, ToolResult
│   ├── dependencies.py             # WordlistDependencyMixin, BinaryDependencyMixin
│   ├── runner.py                   # Async orchestrator (risk-tier parallel execution)
│   └── aggregator.py               # Collects + deduplicates all findings
│
├── steps/                          # ── ORGANISMS (70 steps across 13 modules) ──
│   │
│   ├── access/                     # Authenticated REST API + login + hardening (7)
│   │   ├── plugins_step.py         # WpJsonPluginsStep
│   │   ├── themes_step.py          # WpJsonThemesStep
│   │   ├── users_step.py           # WpJsonUsersStep
│   │   ├── inactive_plugin_check_step.py
│   │   ├── login_bruteforce_step.py
│   │   ├── site_health_step.py     # Cookie-based admin session
│   │   └── rest_hardening_step.py  # CORS, route leakage, user endpoint
│   │
│   ├── passive/                    # External intelligence (5)
│   │   ├── whois_step.py
│   │   ├── dns_step.py
│   │   ├── crt_sh_step.py
│   │   ├── wayback_step.py
│   │   └── shodan_step.py
│   │
│   ├── infrastructure/             # Server configuration (5)
│   │   ├── headers_step.py
│   │   ├── tls_step.py
│   │   ├── waf_step.py
│   │   ├── ports_step.py
│   │   └── hosting_step.py         # 12 hosting providers + Bedrock
│   │
│   ├── discovery/                  # File enumeration + brute-force (9)
│   │   ├── readme_step.py
│   │   ├── license_step.py
│   │   ├── sitemap_step.py
│   │   ├── login_page_step.py
│   │   ├── wp_cron_step.py
│   │   ├── uploads_listing_step.py
│   │   ├── plugin_bruteforce_step.py
│   │   ├── theme_bruteforce_step.py
│   │   └── spider_step.py
│   │
│   ├── fingerprint/                # Version detection (6)
│   │   ├── wp_version_step.py
│   │   ├── theme_step.py
│   │   ├── plugin_step.py
│   │   ├── plugin_version_step.py
│   │   ├── versioned_assets_step.py
│   │   └── scripts_step.py
│   │
│   ├── vuln/                       # CVE correlation (3)
│   │   ├── core_vuln_step.py
│   │   ├── plugin_vuln_step.py
│   │   └── theme_vuln_step.py
│   │
│   ├── users/                      # User enumeration (4)
│   │   ├── rest_api_users_step.py
│   │   ├── oembed_users_step.py
│   │   ├── author_id_step.py
│   │   └── login_verbosity_step.py
│   │
│   ├── api/                        # REST API surface (3)
│   │   ├── rest_surface_step.py
│   │   ├── pages_ip_leak_step.py
│   │   └── app_passwords_step.py
│   │
│   ├── xmlrpc/                     # XML-RPC testing (5)
│   │   ├── xmlrpc_detect_step.py
│   │   ├── xmlrpc_methods_step.py
│   │   ├── xmlrpc_creds_step.py
│   │   ├── xmlrpc_multicall_step.py
│   │   └── xmlrpc_ssrf_step.py
│   │
│   ├── secrets/                    # Sensitive file exposure (5)
│   │   ├── wp_config_backup_step.py
│   │   ├── env_file_step.py
│   │   ├── git_exposure_step.py
│   │   ├── debug_log_step.py
│   │   └── phpinfo_step.py
│   │
 │   ├── ssrf/                       # SSRF vulnerability testing (2)
 │   │   ├── oembed_proxy_step.py
 │   │   └── pingback_ssrf_step.py
 │   │
 │   ├── webapp/                     # Generic web app checks, non-WP targets (8)
 │   │   ├── source_review_step.py
 │   │   ├── sourcemap_step.py
 │   │   ├── http_methods_step.py
 │   │   ├── cookie_flags_step.py
 │   │   ├── cors_step.py
 │   │   ├── stack_trace_step.py
 │   │   ├── content_leak_step.py
 │   │   └── header_quality_step.py
 │   │
 │   └── tools/                      # External tool integrations (8)
 │       ├── wpscan_step.py
 │       ├── nuclei_step.py
 │       ├── ffuf_directory_step.py
 │       ├── ffuf_files_step.py
 │       ├── ffuf_wp_step.py
 │       ├── opendoor_step.py
 │       └── nmap_step.py
│
├── modules/                        # ── MODULES (grouped steps) ──
│   ├── module.py                   # Module(name, steps[]) container
│   ├── __init__.py                 # MODULE_REGISTRY, PROFILES
│   ├── access_module.py
│   ├── passive_module.py
│   ├── infrastructure_module.py
│   ├── discovery_module.py
│   ├── fingerprint_module.py
│   ├── vuln_module.py
│   ├── users_module.py
│   ├── api_module.py
│   ├── xmlrpc_module.py
│   ├── secrets_module.py
 │   ├── ssrf_module.py
 │   ├── webapp_module.py
 │   └── tools_module.py
│
├── utils/                          # ── UTILITIES ──
│   ├── report.py                   # JsonFormatter, MarkdownFormatter, SarifFormatter
│   ├── rate_limiter.py             # RateLimiter, RetryLimiter (token bucket + backoff)
│   ├── xml_parser.py               # Safe XML parsing (XXE protection)
│   ├── wordlist_loader.py          # External wordlist management
│   ├── whois_parser.py             # TLD-aware WHOIS parsing
│   └── tool_version_checker.py     # External tool version checking
│
└── wordlists/                      # ── BUILT-IN WORDLISTS ──
    ├── ffuf/                       # directories, files, wp_paths, plugins, themes
    ├── opendoor/                   # wp_paths, backups, configs, sensitive
     ├── credentials/                # Common WP credential pairs
     ├── whois/                      # TLD-specific WHOIS patterns
     └── webapp/                     # Common asset paths for source discovery fuzzing
```

---

## 3. Core Abstractions

### Atom — `Finding`
```python
@dataclass
class Finding:
    module:         str
    step:           str
    severity:       Literal["info", "low", "medium", "high", "critical"]
    title:          str
    description:    str
    evidence:       str
    recommendation: str
    timestamp:      datetime = field(default_factory=datetime.utcnow)
    raw:            dict = field(default_factory=dict)
```

### Atom — `ToolRunner`
```python
class ToolRunner:
    """Single responsibility: run an external binary safely."""

    def run(
        self,
        cmd: list[str],
        timeout: int = 120,
        cwd: str | None = None,
    ) -> ToolResult:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, cwd=cwd
            )
            return ToolResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                success=result.returncode == 0,
            )
        except FileNotFoundError:
            raise ToolNotFoundError(cmd[0])
        except subprocess.TimeoutExpired:
            raise ToolTimeoutError(cmd[0], timeout)
```

### Molecule — `BaseStep` (ABC)
```python
class BaseStep(ABC):
    """
    Single Responsibility: defines the contract every step must fulfill.
    Open/Closed: new steps extend this, Runner never changes.
    """
    name:        str
    description: str
    severity:    str = "info"

    def __init__(self, target: Target, config: Config, http: HttpClient):
        self.target   = target
        self.config   = config
        self.http     = http
        self.findings: list[Finding] = []
        self.logger   = Logger(self.name)

    @abstractmethod
    async def run(self) -> list[Finding]: ...

    def add_finding(self, **kwargs) -> None:
        self.findings.append(Finding(step=self.name, **kwargs))
```

### Molecule — `BaseToolStep` (extends `BaseStep`)
```python
class BaseToolStep(BaseStep, ABC):
    """
    Interface Segregation: only tool steps know about binaries.
    Liskov: valid BaseStep — Runner uses it through the base interface.
    """

    @property
    @abstractmethod
    def binary(self) -> str: ...
    # e.g. "wpscan", "nuclei", "ffuf"

    @abstractmethod
    def build_command(self) -> list[str]: ...

    @abstractmethod
    def parse_output(self, result: ToolResult) -> list[Finding]: ...

    async def run(self) -> list[Finding]:
        self.logger.info(f"Running {self.binary}...")
        result = self.tool_runner.run(self.build_command())
        self.findings = self.parse_output(result)
        return self.findings
```

### Concrete Tool Step example — `WpscanStep`
```python
class WpscanStep(BaseToolStep):
    name        = "wpscan"
    description = "Automated WordPress vulnerability scanner"

    @property
    def binary(self) -> str:
        return "wpscan"

    def build_command(self) -> list[str]:
        return [
            "wpscan",
            "--url",    str(self.target.url),
            "--format", "json",
            "--api-token", self.config.wpscan_token,
            "--rua",
            "-e", "vp,vt,tt,cb,dbe,u",
            *(["--disable-tls-checks"] if self.config.insecure else []),
        ]

    def parse_output(self, result: ToolResult) -> list[Finding]:
        # Parse JSON output → Finding objects
        ...
```

---

## 4. Pipeline Flow

```
CLI input
   │
   ▼
Validator          ← scope check, URL normalization
   │
   ▼
ToolChecker        ← shutil.which() for each enabled tool binary
   │
   ▼
Runner             ← async, iterates modules → steps
   │  for each module:
   │    for each step:
   │      await step.run()
   │      yield findings
   ▼
Aggregator         ← collect + deduplicate all findings
    │
    ▼
ReportGenerator    ← findings.json + report.md + report.html
```

### Risk Tier Parallel Execution

Modules execute in sequential risk tiers, with parallel execution within each tier:

```
Tier 1 (parallel): passive
Tier 2 (parallel): infrastructure, discovery, fingerprint  
Tier 3 (parallel): users, api, xmlrpc, secrets, ssrf
Tier 4 (parallel): tools (wpscan, nuclei)
```

**Implementation:**
```python
async def run_all(self) -> Report:
    RISK_TIERS = {
        1: ["passive"],
        2: ["infrastructure", "discovery", "fingerprint"],
        3: ["users", "api", "xmlrpc", "secrets", "ssrf"],
        4: ["tools"],
    }
    
    semaphore = asyncio.Semaphore(self.config.threads)
    
    for tier in sorted(RISK_TIERS.keys()):
        modules_in_tier = [m for m in self.modules if m.name in RISK_TIERS[tier]]
        
        async with asyncio.TaskGroup() as tg:
            for module in modules_in_tier:
                tg.create_task(self.run_module(module, semaphore))
```

- **Sequential tiers**: Each tier waits for the previous to complete
- **Parallel within tier**: `asyncio.TaskGroup` runs modules concurrently
- **Concurrency control**: `Semaphore(config.threads)` limits simultaneous operations

### `Runner` depends on abstraction, not concretions
```python
class Runner:
    """
    Dependency Inversion: Runner only knows about BaseStep.
    It never imports WpscanStep, NucleiStep, etc. directly.
    """
    def __init__(self, modules: list[Module], config: Config):
        self.modules = modules
        self.config  = config

    async def run_all(self) -> list[Finding]:
        all_findings = []
        for module in self.modules:
            for step in module.steps:
                findings = await step.run()  # BaseStep interface only
                all_findings.extend(findings)
        return all_findings
```

---

## 5. Module Registry

Each module is just a named list of steps. The CLI resolves profiles to modules.

```python
MODULE_REGISTRY = {
    "access":          AccessModule,        # 7 steps — authenticated REST API, login brute-force, REST hardening
    "passive":         PassiveModule,       # 5 steps — WHOIS, DNS, crt.sh, Wayback, Shodan
    "infrastructure":  InfrastructureModule, # 5 steps — headers, TLS, WAF, ports, hosting
    "discovery":       DiscoveryModule,      # 9 steps — files, brute-force plugin/theme, spider
    "fingerprint":     FingerprintModule,    # 6 steps — WP version, themes, plugins, assets
    "vuln":            VulnModule,           # 3 steps — CVE correlation (core, plugin, theme)
    "users":           UsersModule,          # 4 steps — REST, oEmbed, author ID, login verbosity
    "api":             ApiModule,            # 3 steps — REST surface, IP leak, app passwords
    "xmlrpc":          XmlrpcModule,         # 5 steps — detect, methods, creds, multicall, SSRF
    "secrets":         SecretsModule,        # 5 steps — config backup, .env, .git, debug log, phpinfo
    "ssrf":            SsrfModule,           # 2 steps — oEmbed proxy, pingback SSRF
    "webapp":          WebappModule,         # 8 steps — source review, CORS, cookies, methods, headers, ...
    "tools":           ToolsModule,          # 8 steps — WPScan, Nuclei, FFUF (3), OpenDoor, Nmap (2)
}

PROFILES = {
    "passive":    ["passive"],
    "light":      ["passive", "infrastructure", "discovery", "fingerprint"],
    "standard":   ["passive", "infrastructure", "discovery", "fingerprint",
                   "users", "api", "xmlrpc", "secrets", "ssrf"],
    "web":        ["passive", "infrastructure", "webapp", "secrets", "tools"],
    "full":       list(MODULE_REGISTRY.keys()),
    "aggressive": ["users", "xmlrpc", "secrets", "tools"],
}
```

---

## 6. Config & Secrets

```
# .env  (never committed)
WPSCAN_API_TOKEN=xxx
SHODAN_API_KEY=xxx

# config.yaml
threads:    4
timeout:    10
insecure:   false
output_dir: ./results

tools:
  wpscan:   ""    # resolved via shutil.which() if empty
  nuclei:   ""
  ffuf:     ""

wordlists:
  plugins:  ./wordlists/wp-plugins.txt
  themes:   ./wordlists/wp-themes.txt
  paths:    ./wordlists/wp-paths.txt
```

```python
class Config(BaseSettings):          # pydantic BaseSettings reads .env
    wpscan_api_token:  str = ""      # WPScan API token for CVE data
    wpscan_timeout:     int = 600    # WPScan execution timeout
    wpscan_enumerate:   str = "vp,vt,tt,cb,u"  # WPScan enumeration modes
    enable_wpscan:      bool = False  # Enable WPScan via CLI flag
    shodan_key:    str = ""
    threads:       int = 4
    timeout:       int = 10
    insecure:      bool = False
    output_dir:    Path = Path("./results")

    model_config = SettingsConfigDict(env_file=".env")
```

---

## 7. CLI Interface

```bash
# Full scan
recon-wp --target https://example.com --output ./results --profile full

# Passive only
recon-wp --target https://example.com --profile passive

# Pick specific modules
recon-wp --target https://example.com --modules users,xmlrpc,secrets

# Enable WPScan with API token (recommended for vulnerability data)
recon-wp --target https://example.com --wpscan --wpscan-api-token YOUR_TOKEN

# WPScan with custom enumeration
recon-wp --target https://example.com --wpscan --wpscan-enumerate "vp,vt,u"

# WPScan with extended timeout
 recon-wp --target https://example.com --wpscan --wpscan-timeout 900
 
 # FFUF with custom wordlist
 recon-wp --target https://example.com --ffuf --ffuf-wordlist path/to/wordlist.txt
 
 # FFUF with rate limiting
 recon-wp --target https://example.com --ffuf --ffuf-rate-limit 50
 
 # OpenDoor with custom mode
 recon-wp --target https://example.com --opendoor --opendoor-mode wp_paths
 
 # OpenDoor with custom wordlist
 recon-wp --target https://example.com --opendoor --opendoor-wordlist path/to/wordlist.txt
 
 # Ignore TLS errors
 recon-wp --target https://example.com --insecure
```

---

## 8. Steps per Module (full list)

### Module: access (7 steps)
`WpJsonPluginsStep` · `WpJsonThemesStep` · `WpJsonUsersStep` · `InactivePluginCheckStep` · `LoginBruteforceStep` · `SiteHealthStep` · `RestHardeningStep`

### Module: passive (5 steps)
`WhoisStep` · `DnsStep` · `CrtShStep` · `WaybackStep` · `ShodanStep`

### Module: infrastructure (5 steps)
`HeadersStep` · `TlsStep` · `WafStep` · `PortsStep` · `HostingStep`

### Module: discovery (9 steps)
`ReadmeStep` · `LicenseStep` · `SitemapStep` · `LoginPageStep` · `WpCronStep` · `UploadsListingStep` · `PluginBruteforceStep` · `ThemeBruteforceStep` · `SpiderStep`

### Module: fingerprint (6 steps)
`WpVersionStep` · `ThemeStep` · `PluginStep` · `PluginVersionStep` · `VersionedAssetsStep` · `ScriptsStep`

### Module: vuln (3 steps)
`CoreVulnStep` · `PluginVulnStep` · `ThemeVulnStep`

### Module: users (4 steps)
`RestApiUsersStep` · `OembedUsersStep` · `AuthorIdStep` · `LoginVerbosityStep`

### Module: api (3 steps)
`RestSurfaceStep` · `PagesIpLeakStep` · `AppPasswordsStep`

### Module: xmlrpc (5 steps)
`XmlrpcDetectStep` · `XmlrpcMethodsStep` · `XmlrpcCredsStep` · `XmlrpcMulticallStep` · `XmlrpcSsrfStep`

### Module: secrets (5 steps)
`WpConfigBackupStep` · `EnvFileStep` · `GitExposureStep` · `DebugLogStep` · `PhpinfoStep`

### Module: ssrf (2 steps)
`OembedProxyStep` · `PingbackSsrfStep`

### Module: tools (6 steps)
`WpscanStep` · `NucleiStep` · `FfufDirectoryStep` · `FfufFilesStep` · `FfufWpStep` · `OpenDoorStep`

---

## 9. Key Improvements Over Previous Plan

| Previous plan | This plan |
|---------------|-----------|
| Flat module files (`01_passive.py`) | Atomic layers: atoms → molecules → organisms |
| No base class for HTTP steps | `BaseStep` ABC enforces contract on all steps |
| No base class for tool steps | `BaseToolStep` isolates subprocess concern (ISP) |
| Runner coupled to concrete steps | Runner depends only on `BaseStep` interface (DIP) |
| Adding a step required touching runner | New step = new file, extend base, register in module (OCP) |
| Tool logic mixed with recon logic | `ToolRunner` atom handles subprocess, step handles parsing |
| Config passed ad-hoc | `Config` molecule injected once, shared everywhere |

---

## 10. Dependency Graph

```
Finding ──────────────────────────────────┐
HttpClient ──────────────────────────────┐│
ToolRunner ─────────────────────────────┐││
Target ─────────────────────────────────│││
Logger ─────────────────────────────────│││
                                         ↓↓↓
                               BaseStep (molecule)
                                    │        │
                    ┌───────────────┘        └──────────────┐
                    ↓                                        ↓
             ConcreteHttpStep                       BaseToolStep (molecule)
         (e.g. RestApiUsersStep)                            │
                    │                                        ↓
                    │                             ConcreteToolStep
                    │                           (e.g. WpscanStep)
                    └────────────────┬───────────────────────┘
                                     ↓
                                  Module
                                     │
                                     ↓
                     Validator → ToolChecker → Runner → Aggregator
                                                              │
                                                              ↓
                                                     ReportGenerator
```

---

## 11. Roadmap (Phased)

| Phase | Scope | Status |
|-------|-------|--------|
| **1** | Atoms + Molecules + passive/discovery/fingerprint steps | ✅ Complete |
| **2** | Users + API + XMLRPC steps | ✅ Complete |
| **3** | Secrets + SSRF steps | ✅ Complete |
| **4.0** | Tool Version Checker | ✅ Complete (2026-05-07) |
| **4.1** | FFUF Integration | ✅ Complete (2026-05-07) |
| **4.2** | OpenDoor Integration | ✅ Complete (2026-05-07) |
| **4.3** | Nuclei Integration | ✅ Complete |
| **5** | Pipeline polish + full report generation | ✅ Complete |
| **6** | Authenticated scan mode (login-aware steps) | ✅ Complete |
| **7** | CVE correlation (WPVulnerability.net + WPScan API) | ✅ Complete (2026-07-08) |
| **8** | Plugin/Theme brute-force (response-code oracle) | ✅ Complete (2026-07-08) |
| **9** | Login brute-force + Cookie admin + REST hardening | ✅ Complete (2026-07-08) |
| **10** | Hosting fingerprint, SARIF output, Content spider | ✅ Complete (2026-07-08) |

### Completed Features (2026-05-07)

#### Tool Version Checker
 - Version pinning for external tools
 - Compatibility checking before execution
 - Multiple version requirement types (exact, min, range, list)
 - CLI options for version check control
 - Automatic version parsing per tool type

#### FFUF Integration (2026-05-07)
 - `FfufDirectoryStep` - Directory discovery
 - `FfufFilesStep` - File discovery
 - `FfufWpStep` - WordPress-specific path discovery
 - Local wordlists: directories, files, plugins, themes, WP paths
 - External wordlist support (SecLists, custom paths)
 - CLI flags: `--ffuf`, `--ffuf-wordlist`, `--ffuf-timeout`, `--ffuf-rate-limit`, `--ffuf-filter-status`

#### OpenDoor Integration (2026-05-07)
 - `OpenDoorStep` - WordPress path discovery
 - Local wordlists: backup files, config files, sensitive paths, WP paths
 - External wordlist support (SecLists, custom paths)
 - CLI flags: `--opendoor`, `--opendoor-wordlist`, `--opendoor-timeout`, `--opendoor-rate-limit`, `--opendoor-mode`

### Completed Features (2026-04-07)

#### Passive Reconnaissance
- `WhoisStep` - WHOIS enumeration with TLD-aware parsing
- `DnsStep` - DNS enumeration with SPF analysis, hosting detection
- `CrtShStep` - Certificate transparency for subdomain discovery
- `WaymachineStep` - Wayback Machine archive enumeration

#### WPScan Integration (2026-04-07)
- `WpscanStep` - Full WordPress vulnerability scanner integration
- CLI flags: `--wpscan`, `--wpscan-api-token`, `--wpscan-enumerate`, `--wpscan-timeout`
- Config support: `WPSCAN_API_TOKEN` environment variable
- Capabilities:
  - WordPress version detection + CVE mapping
  - Plugin enumeration + vulnerability detection  
  - Theme enumeration + vulnerability detection
  - User enumeration
  - Config backup discovery
  - Timthumb vulnerability detection

#### Report Generation
- JSON format output
- Markdown format output
- Custom filename support via `--report-file`
- Quiet mode with `--quiet` flag

---

## 12. Security Features

### SSRF Protection (`core/ssrf_protection.py`)
Prevents Server-Side Request Forgery attacks by blocking internal IP ranges:
- RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x)
- Loopback addresses (127.x, localhost)
- Cloud metadata endpoints (169.254.169.254, etc.)
- Link-local and multicast ranges

### Rate Limiting (`utils/rate_limiter.py`)
Async rate limiter with exponential backoff for brute-force operations:
- 5 requests/second default
- Exponential backoff (1s, 2s, 4s...)
- Lockout detection (skips after 3 consecutive failures)

### Safe XML Parsing (`utils/xml_parser.py`)
XXE-protected XML parsing for XML-RPC responses:
- Uses `xml.etree.ElementTree` (no external entities)
- Safe fault code extraction
- No DTD processing

### Subprocess Security (`base/tool.py`)
Safe external tool execution:
- `shell=False` enforced
- Argument sanitization
- Sensitive data redaction from logs
- Binary verification before execution

### User-Agent Rotation (`core/http_client.py`)
Avoids simple bot detection:
- 5 common browser User-Agents
- Rotation on each request

See `SECURITY.md` for full documentation.

---

## 13. Utility Modules

```
utils/
├── report.py                # Report generation (JSON, Markdown formatters)
├── rate_limiter.py         # Async rate limiting with retry logic
├── xml_parser.py           # Safe XML parsing utilities
├── wordlist_loader.py      # External wordlist management
├── whois_parser.py         # TLD-aware WHOIS parsing
├── tool_version_checker.py # External tool version checking
└── __init__.py
```

### Report Generation Usage
```python
from utils.report import Report, JsonFormatter, MarkdownFormatter

report = Report(
    target=target,
    findings=findings,
    modules_run=["passive", "xmlrpc"],
    errors=[],
)
JsonFormatter().write(report, "output.json")
MarkdownFormatter().write(report, "output.md")
```

### Rate Limiter Usage
```python
from utils.rate_limiter import RetryLimiter

limiter = RetryLimiter(
    max_requests=5,
    per_seconds=1.0,
    backoff_factor=2.0,
    max_retries=3,
    max_consecutive_failures=3,
)

result = await limiter.execute_with_retry(coro_func)
```

### XML Parser Usage
```python
from utils.xml_parser import parse_xmlrpc_response, extract_fault_code

response = parse_xmlrpc_response(xml_content)
if response.is_success:
    # Handle success
    pass

fault_code = extract_fault_code(xml_content)
```

### Wordlist Loader Usage
```python
from utils.wordlist_loader import load_wordlist, get_wordlist_path

wordlist = load_wordlist("whois/fields.txt")
path = get_wordlist_path("whois")
# Returns: ~/.config/recon-wp/wordlists/whois/
```

### Tool Version Checker Usage
```python
from utils.tool_version_checker import VersionChecker, VersionRequirement

# Create version requirement
requirement = VersionRequirement(
    tool="wpscan",
    required_version="3.8.23",  # Exact version
    # OR: min_version="3.8.0",  # Minimum version
    # OR: supported_versions=["3.8.23", "3.8.24"],  # List of versions
)

# Check compatibility
checker = VersionChecker()
result = checker.check_compatibility("wpscan", requirement)

if not result.is_compatible:
    print(f"Version incompatible: {result.message}")
```

In step implementation:
```python
class WpscanStep(BaseToolStep):
    _tool_binary = "wpscan"
    required_version = "3.8.23"  # Pin to specific version
    
    # Version check runs automatically before execution
    # Configurable via --skip-version-check, --require-version, --verbose-version-check
```