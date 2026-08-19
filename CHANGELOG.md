# Session Notes & Changelog

## Last Updated: 2026-07-23

---

## Recent Changes

### S14 - Config/CLI/Edge Case Unit Tests (2026-07-23)
| File | Change | Notes |
|------|--------|-------|
| `tests/test_config.py` | **NEW** | 24 tests — ScanConfig defaults, env prefix, field validation, mkdir_output |
| `tests/test_exceptions.py` | **NEW** | 9 tests — ReconError hierarchy, ToolNotFoundError, ToolTimeoutError |
| `tests/test_logger.py` | **NEW** | 16 tests — LEVEL_MAP, Logger init, method delegation |
| `tests/test_whois_parser.py` | **NEW** | 25 tests — tld detection, parse output, to_finding_dict |
| `tests/test_main_cli.py` | **NEW** | 15 tests — resolve_domain, get_module_names, build_modules, _save_report |
| `AGENTS.md` | **UPDATED** | Commit #28; test count 1038→1138 |
| `docs/NEXT_STEPS.md` | **UPDATED** | HEAD, current state, session history |

### S13 - Base Infrastructure Unit Tests (2026-07-23)
| File | Change | Notes |
|------|--------|-------|
| `tests/test_tool_runner.py` | **NEW** | 69 tests — ToolRunner, AsyncToolRunner, sanitize/redact |
| `tests/test_step.py` | **NEW** | 48 tests — BaseStep, BaseToolStep (init, run, verify) |
| `tests/test_http_step.py` | **NEW** | 12 tests — BaseHttpStep fetch, get/post/head, urljoin |
| `tests/test_dependencies.py` | **NEW** | 26 tests — WordlistDependencyMixin 6 paths, BinaryDependencyMixin |
| `tests/test_runner.py` | **NEW** | 14 tests — Runner init, tier grouping, run_all, summary |

### S12 - Core Layer Unit Tests (2026-07-23)
| File | Change | Notes |
|------|--------|-------|
| `tests/test_target.py` | **NEW** | 42 tests — URL parsing, validation, normalization |
| `tests/test_http_client.py` | **NEW** | 30 tests — httpx wrapper, user agents, timeout, close |
| `tests/test_auth.py` | **NEW** | 35 tests — get_wp_auth_header, string/bytes handling |
| `tests/test_vulndb.py` | **NEW** | 56 tests — VulnDB, WPVulnerabilityClient, WPScanClient |

### S11 - Security + Polish (2026-07-16)
| File | Change | Notes |
|------|--------|-------|
| `utils/report.py` | **FIXED** | XSS escape in HtmlFormatter, canonical SARIF schema URL |
| `core/ssrf_protection.py` | **FIXED** | Port restriction removed for DNS resolution |
| `core/target.py` | **FIXED** | IPv6 + port URL validation support |
| `core/logger.py` | **FIXED** | Replaced print() with stdlib logging |
| `core/vulndb.py` | **FIXED** | Deduplication in VulnDB facade |
| `modules/__init__.py` | **FIXED** | Profile composition validated against risk tiers |
| `base/runner.py` | **FIXED** | Warning for modules not matching risk tiers |

### S10 - Architecture Cleanup (2026-07-16)
| File | Change | Notes |
|------|--------|-------|
| `base/step.py` | **REMOVED** | Dead StepResult dataclass and getBinary property |
| `core/finding.py` | **FIXED** | Finding frozen=True for immutability |
| `base/__init__.py`, `base/http_step.py` | **FIXED** | http init chain cleaned up |
| `core/http_client.py` | **FIXED** | Removed unused random import, updated user agents |
| `base/dependencies.py` | **REMOVED** | Dead WORDLIST_FALLBACK_WARNING / WORDLIST_DISABLED_WARNING |
| `utils/whois_parser.py` | **REMOVED** | Dead use_wordlist parameter

### P0 - Tiers 2-3: Login Brute-Force, Cookie Session, REST Hardening, Hosting, SARIF, Spider (2026-07-08)
| File | Change | Notes |
|------|--------|-------|
| `steps/access/login_bruteforce_step.py` | **NEW** | POST wp-login.php with credential pairs |
| `core/auth.py` | **MODIFIED** | Added `AdminSession` class for cookie-based login |
| `steps/access/site_health_step.py` | **NEW** | Extract debug info via cookie admin session |
| `steps/access/rest_hardening_step.py` | **NEW** | CORS, user endpoint, route leakage, plugin endpoint checks |
| `steps/infrastructure/hosting_step.py` | **NEW** | 12 hosting provider signatures + Bedrock detection |
| `utils/report.py` | **MODIFIED** | Added `SarifFormatter` class |
| `steps/discovery/spider_step.py` | **NEW** | Same-origin crawler with robots.txt respect |
| `config.py` | **MODIFIED** | Added `wp_auth_method`, `spider_max_depth`, `spider_max_pages`, sarif in `output_format` |

### P0 - Inactive Plugin File Accessibility Check (2026-07-08)
| File | Change | Notes |
|------|--------|-------|
| `steps/access/inactive_plugin_check_step.py` | **NEW** | Probes readme.txt for deactivated plugins — medium severity if accessible |
| `modules/access_module.py` | **MODIFIED** | Registered InactivePluginCheckStep (55 total steps) |
| `steps/access/__init__.py` | **MODIFIED** | Export InactivePluginCheckStep |

### P0 - CVE Correlation Module (2026-07-08)
| File | Change | Notes |
|------|--------|-------|
| `core/vulndb.py` | **NEW** | WPVulnerability.net primary client + WPScan secondary + VulnDB facade with TTL cache, CVSS→severity, deduplication |
| `steps/vuln/core_vuln_step.py` | **NEW** | Detects WP version, queries VulnDB, emits findings grouped by severity |
| `steps/vuln/plugin_vuln_step.py` | **NEW** | Two-mode plugin detection (auth API → HTML fallback), CVE lookup per slug |
| `steps/vuln/theme_vuln_step.py` | **NEW** | Same pattern for themes |
| `steps/vuln/__init__.py` | **NEW** | Step exports |
| `modules/vuln_module.py` | **NEW** | VulnModule with 3 registered steps (54 total steps) |
| `modules/__init__.py` | **MODIFIED** | Added VulnModule to MODULE_REGISTRY and `full` profile |
| `base/runner.py` | **MODIFIED** | Added vuln to risk tier 2 |
| `config.py` | **MODIFIED** | Added vulndb_cache_ttl field (default 300s) |

### P0 - Plugin/Theme Brute-Force (2026-07-08)
| File | Change | Notes |
|------|--------|-------|
| `steps/discovery/plugin_bruteforce_step.py` | **NEW** | Response-code oracle for `/wp-content/plugins/{slug}/` — probes wordlist, extracts version from `readme.txt`/`readme.md` |
| `steps/discovery/theme_bruteforce_step.py` | **NEW** | Same oracle for `/wp-content/themes/{slug}/` — extracts version from `style.css` |
| `steps/discovery/__init__.py` | **MODIFIED** | Export `PluginBruteforceStep`, `ThemeBruteforceStep` |
| `modules/discovery_module.py` | **MODIFIED** | Registered both brute-force steps (51 total steps) |
| `wordlists/plugins/plugin_fallback.txt` | **NEW** | 30-entry default plugin wordlist (warns to use SecLists for production) |
| `wordlists/plugins/theme_fallback.txt` | **NEW** | 15-entry default theme wordlist |
| `AGENTS.md` | **NEW** | Session anchor file for AI agents |
| `docs/NEXT_STEPS.md` | **UPDATED** | Tier 1 item 2 marked done; HEAD updated |
| `docs/REFERENCES.md` | **UPDATED** | Added SecLists raw download URL |

### P0 - Authenticated REST API Enumeration (2026-06-17)
| File | Change | Notes |
|------|--------|-------|
| `core/auth.py` | **NEW** | Application Password auth header helper |
| `steps/access/plugins_step.py` | **NEW** | Authenticated plugin inventory via /wp-json/wp/v2/plugins |
| `steps/access/themes_step.py` | **NEW** | Authenticated theme inventory via /wp-json/wp/v2/themes |
| `steps/access/users_step.py` | **NEW** | Authenticated user enumeration with emails/roles |
| `modules/access_module.py` | **NEW** | AccessModule with 3 registered steps |
| `steps/passive/shodan_step.py` | **NEW** | Shodan intelligence gathering (open ports, services, WordPress fingerprints) |
| `config.py` | **MODIFIED** | Added wp_user, wp_application_password fields |
| `main.py` | **MODIFIED** | Added --wp-user, --wp-app-password CLI flags |
| `modules/__init__.py` | **MODIFIED** | Registered access module, added to full profile |
| `base/runner.py` | **MODIFIED** | Added access to risk tier 2 |
| `docs/MODULES.md` | **UPDATED** | Added access module section; step count 46→49 |
| `core/logger.py` | **FIXED** | datetime.utcnow() → datetime.now(timezone.utc) |
| `base/runner.py` | **FIXED** | datetime.utcnow() → datetime.now(timezone.utc) |
| `core/finding.py` | **FIXED** | datetime.utcnow() → datetime.now(timezone.utc) |

### P0 - Wordlist Pipeline Fix (2026-06-17)
| File | Change | Notes |
|------|--------|-------|
| `base/dependencies.py` | **FIXED** | Added wordlist_file parameter so local wordlists are actually consumed |
| 7 step callers | **FIXED** | Wired wordlist_file parameter to respective wordlist files |
| `wordlists/` | **ADDED** | WHOIS TLD files (tld_com, tld_br, tld_eu) |
| `wordlists/README.md` | **REWRITTEN** | Production wordlist guide with source URLs and examples |

### P0 - Documentation Reorganization (2026-06-17)
| File | Change | Notes |
|------|--------|-------|
| `MODULES.md`, `SECURITY.md`, etc. | **MOVED** | Root docs moved to docs/ directory |
| `docs/CODE.md` | **NEW** | Code abstraction documentation |

### P0 - API Module Implementation (2026-05-12)
| File | Change | Notes |
|------|--------|-------|
| `steps/api/rest_surface_step.py` | **NEW** | REST API surface discovery (19 routes) |
| `steps/api/pages_ip_leak_step.py` | **NEW** | Internal IP leak detection via REST API |
| `steps/api/app_passwords_step.py` | **NEW** | Application Passwords API endpoint check |
| `modules/api_module.py` | **NEW** | ApiModule with 3 registered steps |
| `modules/__init__.py` | **MODIFIED** | Registered ApiModule in MODULE_REGISTRY |
| `steps/tools/__init__.py` | **FIXED** | Added missing FFUF/OpenDoor step exports |

### P0 - Infrastructure & Environment (2026-05-12)
| File | Change | Notes |
|------|--------|-------|
| `venv/` | **REBUILT** | Migrated from Python 3.9 to Python 3.12 |
| `.gitignore` | **MODIFIED** | Removed `wordlists/` exclusion — default wordlists now tracked |
| `pyproject.toml` | **NEW** | Project metadata, ruff config, pytest config |

### P1 - Bug Fix (2026-05-12)
| File | Change | Notes |
|------|--------|-------|
| `main.py` | **FIXED** | Report files had double extensions (.json.json) — fixed `_save_report` |
| `utils/report.py` | **FIXED** | `generate_report_filename` no longer appends extension |

### P1 - Documentation (2026-05-12)
| File | Change | Notes |
|------|--------|-------|
| `docs/MODULES.md` | **UPDATED** | API module from "Planned" → "Implemented" with full docs; counts bumped from 37→45 steps |
| `docs/missing_wordlists.md` | **UPDATED** | Wordlist directory setup marked complete |
| `CHANGELOG.md` | **UPDATED** | This session |

### P0 - External Tool Version Checker (2026-05-07)

#### Overview
External tool version pinning system to ensure consistent executability across different setups and control which tool versions parsers work with.

| File | Change | Notes |
|------|--------|-------|
| `utils/tool_version_checker.py` | **NEW** | Complete version checker implementation |
| `base/step.py` | **MODIFIED** | Integrated version checking into BaseToolStep |
| `config.py` | **MODIFIED** | Added version check configuration options |
| `main.py` | **MODIFIED** | Added version check CLI flags |
| `tests/test_tool_version_checker.py` | **NEW** | 24 tests for version checker |
| `requirements.txt` | **MODIFIED** | Added packaging>=21.0 dependency |

#### Version Pinning Features

**Version Requirements in Steps:**
```python
class WpscanStep(BaseToolStep):
    # Option 1: Exact version required
    required_version = "3.8.23"
    
    # Option 2: Minimum version
    min_version = "3.8.0"
    
    # Option 3: Version range
    min_version = "3.8.0"
    max_version = "3.9.9"
    
    # Option 4: Specific compatible versions
    supported_versions = ["3.8.23", "3.8.24", "3.9.0"]
```

**CLI Options:**
```bash
# Skip version checking
python main.py main --target https://example.com --skip-version-check

# Require compatible version (fail if incompatible)
python main.py main --target https://example.com --require-version

# Show detailed version information
python main.py main --target https://example.com --verbose-version-check
```

**Configuration:**
- `skip_version_check`: Skip version checking (default: False)
- `require_version`: Fail if tool version is incompatible (default: False)
- `verbose_version_check`: Show detailed version information (default: False)

#### Implementation Details

**Files Created:**
- `utils/tool_version_checker.py`:
  - `VersionRequirement` - Version requirement specification
  - `VersionChecker` - Version checking functionality
  - `VersionMismatchError` - Exception for incompatible versions
  - `ToolVersionMixin` - Mixin for integration with BaseToolStep

**Modified Files:**
- `base/step.py`:
  - Added version requirement attributes to BaseToolStep
  - Added `get_version_requirement()` method
  - Added `check_version_compatibility()` method
  - Integrated version checking in default run() method

- `config.py`:
  - Added `skip_version_check` field
  - Added `require_version` field
  - Added `verbose_version_check` field

- `main.py`:
  - Added `--skip-version-check` option
  - Added `--require-version` option
  - Added `--verbose-version-check` option

#### Testing
- 24 tests covering:
  - Version requirement compatibility checks
  - Version parsing for multiple tools
  - Version formatting
  - Error handling
  - Integration with BaseToolStep

---

## Last Updated: 2026-04-10

---

## Previous Changes

### Architectural Refactoring (2026-04-10)

#### P0 - Pydantic-Settings Migration
| File | Change | Notes |
|------|--------|-------|
| `config.py` | **REFACTORED** | Replaced dataclass Config with pydantic-settings ScanConfig |
| `requirements.txt` | **MODIFIED** | Added pydantic>=2.0, pydantic-settings>=2.0, typer[all]>=0.12.0 |

**ScanConfig Features:**
- Type validation with Field constraints (e.g., `threads: int = Field(ge=1, le=20)`)
- Environment variable support with `WP_` prefix
- .env file loading support
- Single source of truth for all config

**Environment Variables:**
```bash
export WP_THREADS=4
export WP_WPSCAN_API_TOKEN=xxx
export WP_NUCLEI_SEVERITY=medium,high,critical
```

#### P0 - Typer CLI Migration
| File | Change | Notes |
|------|--------|-------|
| `main.py` | **REFACTORED** | Replaced argparse with Typer CLI with rich tables |

**CLI Improvements:**
- Rich table output for `--list-profiles` and `--list-modules`
- Better help text with rich formatting
- Same UX preserved: `--target`, `--profile`, `--wpscan`, `--nuclei`

**CLI Usage:**
```bash
python main.py main --target https://example.com --profile full --wpscan --nuclei
python main.py list-profiles
python main.py list-modules
```

#### P0 - Risk Tier Parallel Execution
| File | Change | Notes |
|------|--------|-------|
| `base/runner.py` | **REFACTORED** | Added asyncio.TaskGroup with risk tier grouping |

**Concurrency Model:**
```
Tier 1 (parallel): passive
Tier 2 (parallel): infrastructure, discovery, fingerprint  
Tier 3 (parallel): users, api, xmlrpc, secrets, ssrf
Tier 4 (parallel): tools (wpscan, nuclei)

- Tiers execute sequentially
- Modules within each tier run in parallel via TaskGroup
- Semaphore limits concurrent operations (config.threads)
```

#### P0 - AsyncToolRunner Integration
| File | Change | Notes |
|------|--------|-------|
| `steps/tools/wpscan_step.py` | **MODIFIED** | Uses AsyncToolRunner instead of synchronous ToolRunner |
| `base/tool.py` | **MODIFIED** | AsyncToolRunner implemented (non-blocking subprocess) |

#### P0 - NucleiStep Implementation
| File | Change | Notes |
|------|--------|-------|
| `steps/tools/nuclei_step.py` | **NEW** | Full Nuclei integration with JSON output parsing |
| `steps/tools/__init__.py` | **NEW** | Module exports |
| `modules/tools_module.py` | **MODIFIED** | Registers NucleiStep conditionally based on config |

**NucleiStep Features:**
- Template-based vulnerability scanning
- Configurable severity filtering (`--nuclei-severity`)
- JSON output parsing
- Async execution via AsyncToolRunner

**CLI Usage:**
```bash
python main.py main --target https://example.com --nuclei
python main.py main --target https://example.com --nuclei --nuclei-severity critical,high
```

#### P0 - Finding Serialization Fix
| File | Change | Notes |
|------|--------|-------|
| `core/finding.py` | **FIXED** | `severity` and `recommendation` now serialize in `to_dict()` |

---

#### P0 - New Step: PluginVersionStep
| File | Change | Notes |
|------|--------|-------|
| `steps/fingerprint/plugin_version_step.py` | **NEW** | Extracts version info for detected plugins |
| `steps/fingerprint/__init__.py` | **MODIFIED** | Export PluginVersionStep |
| `modules/fingerprint_module.py` | **MODIFIED** | Register PluginVersionStep after PluginStep |
| `docs/MODULES.md` | **MODIFIED** | Documented new step |
| `CHANGELOG.md` | **MODIFIED** | Added change log entry |

**PluginVersionStep Features:**
- Detects plugins from homepage HTML (same as PluginStep)
- Fetches version information from multiple sources:
  1. readme.txt (Stable tag:)
  2. readme.md (**Stable tag:** markdown)
  3. {plugin}.php (Version:)
- Reports "unknown" for plugins without version info
- Aggregates all plugins into single finding with raw data

#### P1 - Tests for PluginVersionStep
| File | Change | Notes |
|------|--------|-------|
| `tests/test_plugin_version_step.py` | **NEW** | 27 tests covering all functionality |
| `tests/conftest.py` | **MODIFIED** | Added mock_http, mock_target, mock_config, plugin_step fixtures |

**PluginVersionStep Features:**
- Detects plugins from homepage HTML (same as PluginStep)
- Fetches version information from multiple sources:
  1. readme.txt (Stable tag:)
  2. readme.md (Stable tag:)
  3. {plugin}.php (Version:)
- Reports "unknown" for plugins without version info
- Aggregates all plugins into single finding with raw data

---

### Documentation (2026-04-07)

#### P1 - Module Reference Documentation
| File | Change | Notes |
|------|--------|-------|
| `docs/MODULES.md` | **NEW** | Comprehensive documentation of all 37 steps across 10 modules |
| `README.md` | **MODIFIED** | Added link to docs/MODULES.md in documentation section |

**MODULES.md Contents:**
- Overview table of all modules and steps
- Detailed documentation per module:
  - Step descriptions
  - What each step does
  - Dependencies and fallbacks
  - Finding output examples
  - Security controls
- Dependency matrix (binaries, services, wordlists)
- Severity level reference
- Common code patterns
- Finding schema
- Profile reference

---

### Dependency Standardization (2026-04-07)

#### P0 - New Base Classes for Dependency Handling
| File | Change | Notes |
|------|--------|-------|
| `base/dependencies.py` | **NEW** | WordlistDependencyMixin and BinaryDependencyMixin |
| `base/__init__.py` | **NEW** | Export new mixins alongside BaseStep classes |

**WordlistDependencyMixin Features:**
- Standardized wordlist resolution with fallback support
- Built-in default credentials (20 common WordPress credentials)
- Consistent WARNING logs for missing dependencies
- Automatic finding generation when step is disabled

**BinaryDependencyMixin Features:**
- External binary checking with installation hints
- Consistent WARNING logs for missing binaries
- Automatic finding generation for skipped steps

**Default Credential Fallback:**
```python
DEFAULT_WORDLIST_CREDENTIALS = [
    ("admin", "password"), ("admin", "admin"), ("admin", "123456"),
    ("admin", "admin123"), ("administrator", "password"), ...
    # 20 total combinations
]
```

#### P0 - XMLRPC Steps Enhanced
| File | Change | Notes |
|------|--------|-------|
| `steps/xmlrpc/xmlrpc_creds_step.py` | **REFACTORED** | Uses WordlistDependencyMixin with fallback |
| `steps/xmlrpc/xmlrpc_multicall_step.py` | **REFACTORED** | Uses WordlistDependencyMixin with fallback |

**Changes:**
- Both steps now use 20 built-in fallback credentials if no wordlist configured
- Consistent WARNING log when using fallback mode
- "mode" field in findings shows "wordlist" or "fallback (limited)"

#### P1 - Bug Fixes
| File | Change | Notes |
|------|--------|-------|
| `steps/users/login_verbosity_step.py` | **FIXED** | Fixed URL bug - was using relative path instead of urljoin |

---

### WPScan Integration (2026-04-07)

#### P0 - Critical Feature
| File | Change | Notes |
|------|--------|-------|
| `steps/tools/wpscan_step.py` | **NEW** | Full WPScan integration with JSON output parsing |
| `config.py` | **MODIFIED** | Added `wpscan_api_token`, `wpscan_timeout`, `wpscan_enumerate`, `enable_wpscan` |
| `main.py` | **MODIFIED** | Added `--wpscan`, `--wpscan-api-token`, `--wpscan-enumerate`, `--wpscan-timeout` flags |
| `modules/tools_module.py` | **MODIFIED** | Registered WpscanStep, conditional on `--wpscan` flag |

**WPScanStep Capabilities:**
- WordPress version detection + CVE mapping
- Plugin enumeration + vulnerability detection
- Theme enumeration + vulnerability detection
- User enumeration
- Config backup discovery
- Timthumb vulnerability detection

**CLI Usage:**
```bash
# Basic WPScan
python main.py --target https://example.com --wpscan

# With API token (recommended)
python main.py --target https://example.com --wpscan --wpscan-api-token YOUR_TOKEN

# Custom enumeration
python main.py --target https://example.com --wpscan --wpscan-enumerate "vp,vt,u"

# Extended timeout
python main.py --target https://example.com --wpscan --wpscan-timeout 900
```

**Environment Variable:**
```bash
export WPSCAN_API_TOKEN=your_token_here
python main.py --target https://example.com --wpscan
```

---

### Security Tests (2026-04-06)

#### P1 - Test Suite Implementation
| File | Change | Notes |
|------|--------|-------|
| `tests/__init__.py` | **NEW** | Test package initialization |
| `tests/conftest.py` | **NEW** | Shared pytest fixtures |
| `tests/test_ssrf_protection.py` | **NEW** | SSRF protection unit tests (50 tests) |
| `tests/test_rate_limiter.py` | **NEW** | Rate limiter unit tests (16 tests) |
| `tests/test_xml_parser.py` | **NEW** | XML parser unit tests (30 tests) |

**Test Coverage:**
- SSRF Protection: Private IP detection, localhost detection, cloud metadata detection, URL validation, log sanitization
- Rate Limiter: Token bucket algorithm, exponential backoff, retry logic, concurrent access
- XML Parser: Safe parsing, XXE protection, billion laughs protection, malformed XML handling

**Run Tests:**
```bash
pytest tests/ -v
```

**Results:** 76 passed

---

### Passive Steps Enhancements (2026-04-06)

#### P0 - DnsStep Intelligence Analysis
| File | Change | Notes |
|------|--------|-------|
| `steps/passive/dns_step.py` | **ENHANCED** | Added SPF analysis, hosting provider detection, Google verification |

**New Intelligence Features:**
- SPF record analysis with severity escalation
- Hosting provider detection (Locaweb, AWS, Azure, GCP, etc.)
- Email provider detection from MX records
- Google Site Verification detection

#### P0 - CrtShStep Retry Logic
| File | Change | Notes |
|------|--------|-------|
| `steps/passive/crt_sh_step.py` | **ENHANCED** | Increased timeout, retry logic, multiple query patterns |

**Improvements:**
- Timeout increased to 60s (from 30s)
- Retry logic with 2 attempts and 5s delay
- Multiple query patterns (%.domain, domain, _domainkey)
- Better HTML fallback parsing
- Wildcard certificate detection

#### P0 - Wayback Machine Integration
| File | Change | Notes |
|------|--------|-------|
| `steps/passive/wayback_step.py` | **NEW** | Historical URL discovery via Wayback Machine CDX API |
| `steps/passive/__init__.py` | **MODIFIED** | Export WaymachineStep |
| `modules/passive_module.py` | **MODIFIED** | Register WaymachineStep |

**Features:**
- Queries Wayback CDX API for archived URLs
- URL categorization (Admin, API, Backup, Config, Login, etc.)
- Sensitive endpoint detection (wp-admin, .env, backups, etc.)
- Historical endpoint enumeration

---

### Passive Steps (2026-04-06)

#### P0 - DNS Enumeration
| File | Change | Notes |
|------|--------|-------|
| `steps/passive/dns_step.py` | **NEW** | DNS record enumeration using system `dig` binary |
| `steps/passive/__init__.py` | **MODIFIED** | Export DnsStep |
| `modules/passive_module.py` | **MODIFIED** | Register DnsStep |

**Features:**
- Queries A, AAAA, MX, TXT, NS, CNAME records
- Uses `dig` binary via BaseToolStep
- Validates and filters responses

#### P0 - Certificate Transparency
| File | Change | Notes |
|------|--------|-------|
| `steps/passive/crt_sh_step.py` | **NEW** | Subdomain discovery via crt.sh API |
| `steps/passive/__init__.py` | **MODIFIED** | Export CrtShStep |
| `modules/passive_module.py` | **MODIFIED** | Register CrtShStep |

**Features:**
- Queries crt.sh API for SSL/TLS certificates
- Parses JSON response for subdomains
- HTML fallback parsing
- Graceful timeout handling (30s)

#### Usage
```bash
python main.py --target https://example.com --modules passive --debug
```

---

### Type Fixes (2026-04-06)

#### P1 - LSP/IDE Improvements
| File | Change | Notes |
|------|--------|-------|
| `base/step.py` | **MODIFIED** | `severity` class attribute now typed as `Literal["info", "low", "medium", "high", "critical"]` |
| `base/step.py` | **MODIFIED** | `_add_finding()` method signature updated with proper types |
| `base/step.py` | **MODIFIED** | Added `Literal` and `Optional` imports |

---

### Report Generation (2026-04-06)

#### P0 - Core Implementation
| File | Change | Notes |
|------|--------|-------|
| `utils/report.py` | **NEW** | Report, JsonFormatter, MarkdownFormatter classes |
| `config.py` | **MODIFIED** | Added `output_format`, `quiet` fields |
| `base/runner.py` | **MODIFIED** | Returns `Report` object, tracks errors/modules_run |
| `main.py` | **MODIFIED** | Added `--format`, `--report-file`, `--quiet` flags |

#### CLI Usage
```bash
# Markdown output (default)
python main.py --target https://example.com --modules passive

# JSON output
python main.py --target https://example.com --format json

# Both formats
python main.py --target https://example.com --format both

# Custom filename
python main.py --target https://example.com --report-file my_report

# Quiet mode (report only)
python main.py --target https://example.com --quiet
```

#### Output Files
```
reports/
├── recon_example_com_20260406_193833.md
└── recon_example_com_20260406_193833.json
```

---

### WHOIS Wordlist Support (2026-04-06)

#### P0 - Wordlist Infrastructure
| File | Change | Notes |
|------|--------|-------|
| `utils/wordlist_loader.py` | **NEW** | Reusable wordlist utilities with path resolution |
| `utils/whois_parser.py` | **NEW** | TLD-aware WHOIS parsing with wordlist support |
| `steps/passive/whois_step.py` | **MODIFIED** | Uses WhoisParser for flexible field extraction |
| `utils/__init__.py` | **MODIFIED** | Export new utilities |

#### P0 - Bug Fixes & Error Handling
| File | Change | Notes |
|------|--------|-------|
| `utils/whois_parser.py` | **FIXED** | Removed duplicate pattern loading bug |
| `steps/passive/whois_step.py` | **FIXED** | Reduced WHOIS timeout to 30s |
| `steps/passive/whois_step.py` | **FIXED** | Added graceful error handling with try/except |
| `steps/passive/whois_step.py` | **FIXED** | Added null checks for target/domain |

#### External Wordlist Files (NOT in repo)
| Location | Files | Purpose |
|----------|-------|---------|
| `~/.config/recon-wp/wordlists/whois/` | `fields.txt`, `tld_br.txt`, `tld_eu.txt`, `tld_com.txt`, `tld_default.txt` | WHOIS field patterns |

#### P1 - Documentation
| File | Change | Notes |
|------|--------|-------|
| `docs/WHOIS_WORDLIST.md` | **NEW** | Wordlist configuration guide |
| `docs/missing_wordlists.md` | **MODIFIED** | Updated status, WHOIS section marked complete |

#### Usage
```bash
# Wordlists are auto-loaded from ~/.config/recon-wp/wordlists/whois/
python main.py --modules passive --target https://website.cfo.org.br/ --debug
```

#### Log Output (with wordlist)
```
[INFO] [WhoisStep] WHOIS patterns loaded from wordlist (TLD: .br)
```

#### Log Output (without wordlist)
```
[INFO] [WhoisStep] Wordlist not found, using fallback patterns. Set via: ~/.config/recon-wp/wordlists/whois/
```

---

### WhoisStep & Debug Logging (2026-04-06)

#### P0 - Critical Features
| File | Change | Notes |
|------|--------|-------|
| `steps/passive/whois_step.py` | **NEW** | WHOIS step using system `whois` binary via BaseToolStep |
| `steps/passive/__init__.py` | **NEW** | Passive steps module exports |
| `modules/passive_module.py` | **MODIFIED** | Registered WhoisStep |

#### P1 - Quality of Life
| File | Change | Notes |
|------|--------|-------|
| `core/logger.py` | **MODIFIED** | Added `level` parameter for DEBUG/INFO/WARN/ERROR control |
| `config.py` | **MODIFIED** | Added `log_level` field |
| `main.py` | **MODIFIED** | Added `--debug` / `-d` CLI flag |
| `modules/module.py` | **MODIFIED** | Added `validate()` method for empty module detection |
| `base/runner.py` | **MODIFIED** | Checks for empty modules, passes log_level to Logger |
| `base/step.py` | **MODIFIED** | Updated BaseStep/BaseToolStep for keyword args, added http support |
| `base/tool.py` | **MODIFIED** | Added `_decode_output()` for encoding fallback |

#### Usage
```bash
python main.py --modules passive --target https://example.com --debug
python main.py --modules passive --target https://website.cfo.org.br/ --debug
```

#### Empty Module Warning
```
[WARN] Module 'tools' has no steps registered - module is empty
```

---

### Security Hardening (2026-04-06)

#### P0 - Critical Fixes Applied
| File | Change | Notes |
|------|--------|-------|
| `core/ssrf_protection.py` | **NEW** | SSRF validation with comprehensive IP blocklist |
| `base/tool.py` | **MODIFIED** | Removed sensitive data from stdout, added shell=False, argument sanitization |
| `config.py` | **MODIFIED** | Added `insecure` flag field |
| `main.py` | **MODIFIED** | Propagate `--insecure` CLI flag to config |
| `base/runner.py` | **MODIFIED** | Pass `insecure` to HttpClient |
| `steps/infrastructure/ports_step.py` | **MODIFIED** | Added SSRF validation before port scanning |

#### P1 - High Priority Fixes Applied
| File | Change | Notes |
|------|--------|-------|
| `utils/rate_limiter.py` | **NEW** | Async rate limiter with exponential backoff (5 req/sec) |
| `utils/__init__.py` | **NEW** | Module exports |
| `steps/xmlrpc/xmlrpc_creds_step.py` | **MODIFIED** | Implemented rate limiting |
| `steps/xmlrpc/xmlrpc_multicall_step.py` | **MODIFIED** | Implemented rate limiting |

#### P2 - Medium Priority Fixes Applied
| File | Change | Notes |
|------|--------|-------|
| `utils/xml_parser.py` | **NEW** | Safe XML parsing (no XXE), `XmlrpcResponse` dataclass |
| `core/http_client.py` | **MODIFIED** | User-Agent rotation, `insecure` support |
| `core/target.py` | **MODIFIED** | URL validation with domain regex |
| `steps/xmlrpc/xmlrpc_detect_step.py` | **MODIFIED** | Uses safe XML parsing |
| `steps/xmlrpc/xmlrpc_ssrf_step.py` | **MODIFIED** | Uses safe XML parsing + SSRF check |

#### Documentation
| File | Change | Notes |
|------|--------|-------|
| `docs/SECURITY.md` | **NEW** | Comprehensive security documentation with architecture, risks, dependencies |

---

## Architecture Status — All Complete

All 6 phases from `docs/architecture_plan.md` implemented. 12 modules, 60 steps, 1138 tests.

| Module | Steps | Status |
|--------|-------|--------|
| `passive` | 5 | Complete — Whois, DNS, crt.sh, Wayback, Shodan |
| `infrastructure` | 5 | Complete — Headers, TLS, WAF, Ports, Hosting |
| `discovery` | 9 | Complete — Readme, License, Sitemap, Login, wp-cron, Uploads, Plugin/Theme brute-force, Spider |
| `fingerprint` | 6 | Complete — WP version, Themes, Plugins, Plugin version, Assets, Scripts |
| `access` | 7 | Complete — Auth REST API, Inactive plugin check, Login brute-force, Site health, REST hardening |
| `vuln` | 3 | Complete — Core/Plugin/Theme CVE correlation |
| `users` | 4 | Complete — REST API, oEmbed, Author ID, Login verbosity |
| `api` | 3 | Complete — REST surface, IP leak, App passwords |
| `xmlrpc` | 5 | Complete — Detection, Methods, Creds, Multicall, SSRF |
| `secrets` | 5 | Complete — Config backups, .env, Git, Debug log, phpinfo |
| `ssrf` | 2 | Complete — oEmbed proxy, Pingback SSRF |
| `tools` | 6 | Complete — WPScan, Nuclei, FFUF (dir/files/WP), OpenDoor |

---

## Dependencies

### Runtime Dependencies
```
httpx>=0.27.0
pydantic>=2.0
pydantic-settings>=2.0
typer[all]>=0.12.0
```

### Development Dependencies (Recommended)
```
pytest>=8.0.0
pytest-asyncio>=0.23.0
ruff>=0.3.0
mypy>=1.9.0
```

### External Tools (Optional)
- `wpscan` - WordPress vulnerability scanner
- `nuclei` - Vulnerability scanner templates
- `ffuf` - Web fuzzer
- `opendoor` - WordPress scanner

---

## Configuration Reference

### CLI Flags
```bash
python main.py --target https://example.com --profile light
python main.py --target https://example.com --modules xmlrpc,secrets
python main.py --target https://example.com --insecure  # Disable TLS verification
python main.py --list-profiles
python main.py --list-modules
```

### Environment Variables (Future)
```bash
# Planned for .env support
WPSCAN_API_TOKEN=xxx
SHODAN_API_KEY=xxx
```

### Wordlist Configuration (Future)
```python
# In config, planned:
config.keys["wordlist"] = "/path/to/wordlist.txt"
```

---

## Known Issues

1. **LSP Type Errors**: Type checkers show errors in tests that mock httpx responses (accessing attributes on `None`) — expected false positives, don't affect runtime.
2. **`pyproject.toml` requires `>=3.9` but Dockerfile uses `python:3.11-slim`** — consistent (3.11 satisfies >=3.9).
3. **Wordlists**: Built-in fallback lists are small (30 plugins / 15 themes). See `wordlists/README.md` for SecLists production setup.
