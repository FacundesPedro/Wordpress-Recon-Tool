# Code Abstractions & Execution Flow

**Tool:** WordPress Reconnaissance Tool  
**Version:** 2.1.0  
**Updated:** 2026-05-12

---

## 1. Architecture Paradigm

SOLID principles + Atomic Design layered on Python async (httpx, asyncio).

### Layer Mapping

| Layer | Package | What lives here |
|-------|---------|-----------------|
| **Atoms** | `core/` | `Finding`, `HttpClient`, `Target`, `Logger`, `SsrfProtection`, exceptions |
| **Molecules** | `base/` | `BaseStep`, `BaseHttpStep`, `BaseToolStep`, `Runner`, `ToolRunner`/`AsyncToolRunner`, dependency mixins |
| **Organisms** | `steps/` | 45 concrete step implementations across 10 modules |
| **Modules** | `modules/` | `Module` container, `MODULE_REGISTRY`, `PROFILES` |
| **Pipeline** | `main.py` | `Validator → Runner → Aggregator → Report` |
| **Output** | `utils/report.py` | `JsonFormatter`, `MarkdownFormatter` |

---

## 2. Dependency Graph

```
Finding ──────────────────────────────────────┐
HttpClient ──────────────────────────────────┐│
Target ─────────────────────────────────────┐││
Logger ────────────────────────────────────┐││
SsrfProtection ─────────────┐              │││
RateLimiter ───────────────┐│              │││
XmlParser ────────────────┐││              │││
                           ↓↓↓              ↓↓↓
                    BaseStep (ABC) ──► Finding[]
                    │              │
        ┌───────────┘     ┌───────┘
        ↓                 ↓
  BaseHttpStep      BaseToolStep
  (HttpClient)      (AsyncToolRunner + VersionChecker)
        │                 │
        ↓                 ↓
  45 Concrete Steps     WpscanStep, NucleiStep,
  (HTTP-based)          Ffuf*, OpenDoorStep
        │                 │
        └────────┬────────┘
                 ↓
            Module[]
                 │
                 ↓
    CLI → Config → Runner (risk-tier async) → Aggregator → Report
```

---

## 3. Atoms (`core/`)

### `core/finding.py` — `Finding` dataclass

```python
@dataclass
class Finding:
    module: str
    step: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    evidence: str
    recommendation: str
    timestamp: datetime
    raw: dict[str, Any]

    def to_dict(self) -> dict: ...       # JSON-serializable dict
    def to_sarif(self) -> dict: ...       # SARIF-compliant format
```

**Role:** Single immutable record of a discovered issue. Every step produces a list of these. Used everywhere — serialized to JSON/MD reports and convertible to SARIF.

### `core/http_client.py` — `HttpClient`

```python
class HttpClient:
    def __init__(self, timeout=10, insecure=False): ...
    async def __aenter__(self) -> HttpClient: ...    # Creates httpx.AsyncClient
    async def __aexit__(self, ...): ...               # Closes client
    async def get(self, url, **kwargs) -> Response: ...
    async def post(self, url, **kwargs) -> Response: ...
    async def head(self, url, **kwargs) -> Response: ...
    async def request(self, method, url, **kwargs) -> Response: ...
```

**Role:** Shared async HTTP session manager. Features User-Agent rotation (cycle of 5 common browsers), configurable TLS verification via `insecure` flag, and redirect following. Used as async context manager — created once by `Runner` and injected into every step.

### `core/target.py` — `Target`

```python
@dataclass
class Target:
    url: str
    domain: str = ""
    scope: list[str] | None = None
```

**Role:** Validated target representation. Auto-prepends `https://`, validates domain format, extracts domain via regex. Used as the base URL for all HTTP steps.

### `core/logger.py` — `Logger`

```python
class Logger:
    def __init__(self, name, level="INFO"): ...
    def debug(self, message): ...
    def info(self, message): ...
    def warning(self, message): ...
    def warn(self, message): ...
    def error(self, message): ...
```

**Role:** Simple level-gated console logger with ISO timestamp format: `[timestamp] [LEVEL] [name] message`. Supports DEBUG/INFO/WARN/ERROR levels. Used everywhere — each step gets `self.logger`.

### `core/ssrf_protection.py` — SSRF Protection

```python
def is_safe_target(host, port) -> bool: ...           # True = UNSAFE (blocked)
def validate_safe_url(url, allow_private=False) -> str: ...
def is_safe_url(url, allow_private=False) -> bool: ...
def sanitize_target_for_logging(target) -> str: ...
```

**Role:** Blocks requests to private/internal IPs. Blocks RFC 1918, loopback, link-local, cloud metadata (AWS/GCP/Azure/Alibaba), and resolves hostnames to check resolved IPs. Used by `PortsStep`, `XmlrpcSsrfStep`, and SSRF steps.

### `core/exceptions.py` — Custom Exceptions

```
ReconError (base)
├── ToolNotFoundError(binary)    # shutil.which() failed
├── ToolTimeoutError(binary, sec) # subprocess timeout
└── ValidationError              # Target validation failed
```

---

## 4. Molecules (`base/`)

### `base/step.py` — `BaseStep` (ABC)

```python
class BaseStep(ABC):
    name: str = "base_step"
    description: str = ""
    severity: Literal[...] = "info"

    def __init__(self, target, config, http, name=None, description=None): ...
    @abstractmethod
    async def run(self) -> list[Finding]: ...
    def _add_finding(self, module, severity, title, description="",
                     evidence="", recommendation="", raw=None): ...
    def clear_findings(self): ...
```

**Role:** The contract every step fulfills. Stores shared state (target, config, http, logger). The `_add_finding` method wraps `Finding` creation with `step=self.name` and appends to `self.findings` list.

### `base/step.py` — `BaseToolStep` (extends BaseStep)

```python
class BaseToolStep(BaseStep, ABC):
    _tool_binary: str = ""
    required_version: str | None = None
    min_version: str | None = None

    def __init__(self, ...): ...
    @property
    @abstractmethod
    def getBinary(self) -> str: ...
    @abstractmethod
    def build_command(self) -> list[str]: ...
    @abstractmethod
    def parse_output(self, result: ToolResult) -> list[Finding]: ...
    def check_version_compatibility(self) -> bool: ...
    def verify_binary(self) -> bool: ...

    async def run(self) -> list[Finding]:   # Default impl:
        # 1. check_binary() → add finding if missing
        # 2. check_version_compatibility()
        # 3. build_command()
        # 4. AsyncToolRunner.run(cmd)
        # 5. parse_output(result)
```

**Role:** Interface Segregation — only tool steps know about binaries. Liskov-compatible with BaseStep. The default `run()` handles binary verification, version checking, async execution, and error handling uniformly. WpscanStep overrides `run()` for custom error detection.

### `base/http_step.py` — `BaseHttpStep` (extends BaseStep)

```python
class BaseHttpStep(BaseStep):
    MODULE = "base"
    def __init__(self, target, config, http): ...
    async def fetch(self, path, method="GET", **kwargs) -> Response: ...
    async def get(self, path, **kwargs) -> Response: ...
    async def post(self, path, **kwargs) -> Response: ...
    async def head(self, path, **kwargs) -> Response: ...
    def urljoin(self, path) -> str: ...
```

**Role:** Provides HTTP helper methods for all HTTP-based steps. `fetch()` joins path with `target.url`. Most steps (40 of 45) inherit from this.

### `base/tool.py` — Tool Runners

```python
@dataclass
class ToolResult:
    stdout: str
    stderr: str
    returncode: int
    success: bool
    @property
    def output(self) -> str: ...

class ToolRunner:                          # Synchronous (blocking)
    def __init__(self, binary_path): ...
    def run(self, args, timeout=600, cwd=None, env=None) -> ToolResult: ...

class AsyncToolRunner:                     # Asynchronous (non-blocking)
    def __init__(self, binary_path): ...
    async def run(self, args, timeout=600, cwd=None, env=None) -> ToolResult: ...
```

**Security features:**
- `shell=False` enforced (subprocess.run / create_subprocess_exec)
- `_sanitize_arg()` — removes `;`, `&&`, `` ` ``, `$()`, etc.
- `_redact_sensitive_from_output()` — redacts API keys, tokens, passwords
- `_decode_output()` — encoding fallback chain (utf-8 → latin-1 → cp1252 → iso-8859-1)

**Role:** `ToolRunner` used by `WhoisStep` (sync tool). `AsyncToolRunner` used in `BaseToolStep.run()` for all modern tools. Both share the same `ToolResult` interface.

### `base/runner.py` — `Runner`

```python
RISK_TIERS = {
    1: ["passive"],
    2: ["infrastructure", "discovery", "fingerprint"],
    3: ["users", "api", "xmlrpc", "secrets", "ssrf"],
    4: ["tools"],
}

class Runner:
    def __init__(self, modules, config, target): ...
    async def run_all(self) -> Report:
        # 1. Create HttpClient (async context manager)
        # 2. For each tier (sorted):
        #      asyncio.TaskGroup → run modules in parallel
        #      Semaphore(config.threads) per module
        # 3. Collect all findings → Report
    async def run_module(self, module, semaphore) -> list[Finding]: ...
```

**Role:** The orchestrator. Depends on `BaseStep` abstraction only (DIP). Creates HttpClient once, shares across all steps. Handles tier ordering, parallel execution, error isolation (one step failure doesn't crash others).

### `base/dependencies.py` — Mixins

```python
class WordlistDependencyMixin:
    def resolve_wordlist_or_fallback(self, config_key, defaults, name, ...): ...
    def resolve_credentials_with_fallback(self, config_key="wordlist"): ...
    def load_credentials_from_wordlist(self, path): ...

class BinaryDependencyMixin:
    async def check_binary_with_warning(self, binary, install_hint, ...): ...
```

**Role:** Standardized dependency handling with graceful fallbacks. Used by XmlrpcCredsStep, XmlrpcMulticallStep (20 fallback credentials). Consistent WARNING logs and automatic disabled-finding generation.

---

## 5. Pipeline Flow

```
┌─────────┐     ┌─────────┐     ┌─────────────┐     ┌──────────┐
│  CLI    │────▶│ Config  │────▶│   Target    │────▶│  Runner  │
│ (Typer) │     │ (pydantic│     │ (validation)│     │ (async)  │
└─────────┘     │ -settings│    └─────────────┘     └────┬─────┘
                └─────────┘                              │
                                                         ▼
                                              ┌──────────────────┐
                                              │  Module Registry │
                                              │  + Profiles      │
                                              └────────┬─────────┘
                                                       │
                                                       ▼
                                          ┌────────────────────┐
                                          │  Risk Tier Loop    │
                                          │  Tier 1 → 2 → 3 → 4│
                                          │  Parallel per tier │
                                          └────────┬───────────┘
                                                   │
                                                   ▼
                                   ┌───────────────────────────┐
                                   │  Step.run() per step      │
                                   │  ↓ Findings               │
                                   └───────────────────────────┘
                                                   │
                                                   ▼
                                   ┌───────────────────────────┐
                                   │  Report (aggregated)      │
                                   │  JsonFormatter / MD       │
                                   └───────────────────────────┘
```

### Step Execution Detail

```
HttpClient (shared, async context manager)
    │
    ▼
BaseHttpStep.fetch("wp-json/wp/v2/users")
    │  GET https://target/wp-json/wp/v2/users
    │  with rotated User-Agent
    ▼
response = httpx.Response (status=200)
    │
    ├── parse HTML/image/JSON
    ├── check patterns
    ├── extract evidence
    │
    ▼
self._add_finding(module="users", severity="info",
    title="Users enumerated via REST API",
    evidence="john.doe (johndoe), jane.smith (janesmith)",
    recommendation="Disable user enumeration...")
    │
    ▼
return self.findings  →  collected by Runner
```

---

## 6. Module System

### Registry (`modules/__init__.py`)

```python
MODULE_REGISTRY = {
    "passive": PassiveModule,     # WhoisStep, DnsStep, CrtShStep, WaymachineStep
    "infrastructure": ...         # HeadersStep, TlsStep, WafStep, PortsStep
    "discovery": ...              # ReadmeStep, LicenseStep, SitemapStep, LoginPageStep, WpCronStep, UploadsListingStep
    "fingerprint": ...            # WpVersionStep, ThemeStep, PluginStep, PluginVersionStep, VersionedAssetsStep, ScriptsStep
    "users": ...                  # RestApiUsersStep, OembedUsersStep, AuthorIdStep, LoginVerbosityStep
    "api": ...                    # RestSurfaceStep, PagesIpLeakStep, AppPasswordsStep
    "xmlrpc": ...                 # XmlrpcDetectStep, XmlrpcMethodsStep, XmlrpcCredsStep, XmlrpcMulticallStep, XmlrpcSsrfStep
    "secrets": ...                # WpConfigBackupStep, EnvFileStep, GitExposureStep, DebugLogStep, PhpinfoStep
    "ssrf": ...                   # OembedProxyStep, PingbackSsrfStep
    "tools": ...,                 # WpscanStep, NucleiStep, FfufDirectoryStep, FfufFilesStep, FfufWpStep, OpenDoorStep
}
PROFILES = {
    "passive": ["passive"],
    "light": ["passive", "infrastructure", "discovery", "fingerprint"],
    "standard": ["passive", "infrastructure", "discovery", "fingerprint",
                 "users", "api", "xmlrpc", "secrets", "ssrf"],
    "full": list(MODULE_REGISTRY.keys()),
    "aggressive": ["users", "xmlrpc", "secrets", "tools"],
}
```

### Module Container (`modules/module.py`)

```python
class Module:
    def __init__(self, name, description=""): ...
    def add_step(self, step_class): ...
    def validate(self) -> list[str]: ...   # Warns if empty
    @property
    def steps(self) -> list[Type]: ...
```

**Role:** Pure container. No execution logic — that's the Runner's job. Tools module is special — it conditionally registers steps based on CLI flags (--wpscan, --nuclei, --ffuf, --opendoor).

---

## 7. Step Inventory

### Passive (4 steps, Tier 1)
| Step | Base | Binary/API | Severity |
|------|------|-----------|----------|
| `WhoisStep` | BaseToolStep | `whois` | Info |
| `DnsStep` | BaseToolStep | `dig` | Info |
| `CrtShStep` | BaseHttpStep | crt.sh API | Info |
| `WaymachineStep` | BaseHttpStep | Wayback CDX | Info |

### Infrastructure (4 steps, Tier 2)
| Step | Base | Severity |
|------|------|----------|
| `HeadersStep` | BaseHttpStep | Info |
| `TlsStep` | BaseHttpStep | Info |
| `WafStep` | BaseHttpStep | Info |
| `PortsStep` | BaseHttpStep | Medium |

### Discovery (6 steps, Tier 2)
| Step | Severity |
|------|----------|
| `ReadmeStep` | Low |
| `LicenseStep` | Low |
| `SitemapStep` | Info |
| `LoginPageStep` | Info |
| `WpCronStep` | Medium |
| `UploadsListingStep` | Medium |

### Fingerprint (6 steps, Tier 2)
| Step | Method | Severity |
|------|--------|----------|
| `WpVersionStep` | meta tag, theme CSS, core JS | Info |
| `ThemeStep` | HTML path regex | Info |
| `PluginStep` | HTML path regex | Info |
| `PluginVersionStep` | readme.txt/md + PHP header | Info |
| `VersionedAssetsStep` | `?ver=` in URLs | Info |
| `ScriptsStep` | Core WP scripts | Info |

### Users (4 steps, Tier 3)
| Step | Endpoint | Severity |
|------|----------|----------|
| `RestApiUsersStep` | `/wp-json/wp/v2/users` | Info |
| `OembedUsersStep` | `/wp-json/oembed/1.0/embed` | Info |
| `AuthorIdStep` | `/?author={id}` | Info |
| `LoginVerbosityStep` | `/wp-login.php` | Info |

### API (3 steps, Tier 3)
| Step | Endpoint | Severity |
|------|----------|----------|
| `RestSurfaceStep` | 19 REST routes | Info |
| `PagesIpLeakStep` | `/wp-json/wp/v2/pages` | Medium |
| `AppPasswordsStep` | Application passwords API | Info |

### XML-RPC (5 steps, Tier 3)
| Step | Method | Severity |
|------|--------|----------|
| `XmlrpcDetectStep` | `system.listMethods` | Info |
| `XmlrpcMethodsStep` | `system.listMethods` | Info |
| `XmlrpcCredsStep` | `wp.getUsersBlogs` + rate limiter | High |
| `XmlrpcMulticallStep` | `system.multicall` (10/batch) | High |
| `XmlrpcSsrfStep` | `pingback.ping` | Medium |

### Secrets (5 steps, Tier 3)
| Step | Files checked | Severity |
|------|--------------|----------|
| `WpConfigBackupStep` | `wp-config.php.bak`, `~`, `.old`, `.save`, `.swp`, etc. | Critical |
| `EnvFileStep` | `.env`, `.env.local`, etc. | Critical |
| `GitExposureStep` | `/.git/config`, `/.git/HEAD` | High |
| `DebugLogStep` | `wp-content/debug.log` | Medium |
| `PhpinfoStep` | `phpinfo.php`, `info.php` | Medium |

### SSRF (2 steps, Tier 3)
| Step | Endpoint | Severity |
|------|----------|----------|
| `OembedProxyStep` | `/wp-json/oembed/1.0/proxy` | Medium |
| `PingbackSsrfStep` | `/xmlrpc.php` (pingback.ping) | Medium |

### Tools (6 steps, Tier 4)
| Step | Binary | Enable flag |
|------|--------|-------------|
| `WpscanStep` | `wpscan` | `--wpscan` |
| `NucleiStep` | `nuclei` | `--nuclei` |
| `FfufDirectoryStep` | `ffuf` | `--ffuf` |
| `FfufFilesStep` | `ffuf` | `--ffuf` |
| `FfufWpStep` | `ffuf` | `--ffuf` |
| `OpenDoorStep` | `opendoor` | `--opendoor` |

---

## 8. Utilities (`utils/`)

### `utils/report.py`
- `Report` — Aggregated scan container (target, domain, timestamps, findings, modules_run, errors)
- `JsonFormatter.format/save` — Pretty-printed JSON output
- `MarkdownFormatter.format/save` — Markdown report with badges, severity buckets, evidence blocks
- `generate_report_filename()` — `recon_{domain}_{timestamp}`

### `utils/rate_limiter.py`
- `RateLimiter` — Token bucket algorithm (5 req/sec, async safe)
- `RetryLimiter` — Rate limiter + exponential backoff (1s, 2s, 4s) + lockout detection (skips after 3 consecutive failures)

### `utils/xml_parser.py`
- `safe_parse_xml()` — ET.fromstring (no DTD, no entities, no XXE)
- `parse_xmlrpc_response()` → `XmlrpcResponse(is_success, fault_code, fault_string)`
- `extract_fault_code()`, `is_xmlrpc_success()`, `check_xmlrpc_available()`

### `utils/wordlist_loader.py`
- `get_wordlist_path()` — Resolves path: custom → `~/.config/recon-wp/wordlists/` → `./wordlists/`
- `load_lines()` — Line iterator with comment skipping
- `load_key_value_lines()` — `key:value` parser

### `utils/whois_parser.py`
- `WhoisParser` — TLD-aware WHOIS output parser with wordlist patterns + hardcoded fallbacks
- `WhoisPattern(name, pattern, tld_specific)`
- Maps 23 field types (registrar, nameservers, dates, contacts, status, DNSSEC)

### `utils/tool_version_checker.py`
- `VersionRequirement` — `required_version`, `min_version`, `max_version`, `supported_versions`
- `VersionChecker` — Gets installed version via `tool --version`, parses per-tool patterns, compares with `packaging.version`
- `VersionMismatchError` — Raised when strict mode enabled
- `ToolVersionMixin` — Integrates with `BaseToolStep`

---

## 9. Config System

### `config.py` — `ScanConfig(BaseSettings)`

```python
class ScanConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WP_", env_file=".env")

    threads: int = Field(default=2, ge=1, le=20)
    timeout: int = Field(default=10, ge=1)
    insecure: bool = False
    log_level: Literal["DEBUG","INFO","WARNING","ERROR"] = "INFO"
    output_dir: Path = Path("./reports")
    output_format: Literal["json","markdown","both"] = "markdown"
    quiet: bool = False

    # WPScan
    wpscan_api_token: str = ""
    wpscan_timeout: int = 600
    wpscan_enumerate: str = "vp,vt,tt,cb,u"
    enable_wpscan: bool = False

    # Nuclei
    enable_nuclei: bool = False
    nuclei_severity: str = "medium,high,critical"
    nuclei_threads: int = 100

    # FFUF
    enable_ffuf: bool = False
    ffuf_wordlist: str = ""
    ffuf_rate_limit: int = 0

    # OpenDoor
    enable_opendoor: bool = False
    opendoor_mode: str = "wp_paths"

    # Version checking
    skip_version_check: bool = False
    require_version: bool = False
    verbose_version_check: bool = False

    # External APIs
    shodan_api_key: str = ""
```

**Config sources (priority):** CLI args > `.env` file > environment variables (`WP_*`) > defaults

---

## 10. CLI Interface (`main.py`)

Typer app with two commands:

```bash
python main.py main --target https://example.com --profile full --wpscan --nuclei
python main.py list-profiles      # Rich table of profiles
python main.py list-modules       # Rich table of modules
```

**Key CLI flags:**

| Flag | Default | Purpose |
|------|---------|---------|
| `--target` / `-t` | (required) | Target URL |
| `--profile` / `-p` | `light` | Scan profile |
| `--modules` / `-m` | None | Comma-separated modules |
| `--wpscan` | False | Enable WPScan |
| `--nuclei` | False | Enable Nuclei |
| `--ffuf` | False | Enable FFUF |
| `--opendoor` | False | Enable OpenDoor |
| `--insecure` | False | Skip TLS verification |
| `--debug` / `-d` | False | Debug logging |

**Module resolution logic:** If `--modules` given, use that. Otherwise resolve from profile name. Tools module is only included if at least one `--wpscan/--nuclei/--ffuf/--opendoor` flag is set.

---

## 11. Security Features

| Feature | Location | Mechanism |
|---------|----------|-----------|
| SSRF protection | `core/ssrf_protection.py` | IP blocklist (RFC 1918, loopback, cloud metadata) + hostname resolution checking |
| Rate limiting | `utils/rate_limiter.py` | Token bucket (5 req/s) + exponential backoff + lockout detection |
| Safe XML parsing | `utils/xml_parser.py` | ET.fromstring (no DTD, no entities, no XXE) |
| Subprocess security | `base/tool.py` | `shell=False`, arg sanitization, output credential redaction |
| TLS verification | `core/http_client.py` | `verify=` parameter, controlled by `--insecure` flag |
| User-Agent rotation | `core/http_client.py` | Cycle of 5 common browser UAs |
| Target validation | `core/target.py` | Domain regex, scheme whitelist (http/https only) |

---

## 12. Testing

```
tests/
├── conftest.py              # Shared fixtures (mock_http, mock_target, mock_config, IP ranges)
├── test_ssrf_protection.py  # 50 tests (private IP, localhost, cloud metadata, URL validation)
├── test_rate_limiter.py     # 16 tests (token bucket, backoff, retry, concurrent access)
├── test_xml_parser.py       # 30 tests (safe parsing, XXE, billion laughs, malformed XML)
├── test_plugin_version_step.py  # 27 tests (version detection from readme.txt/md/PHP)
├── test_tool_version_checker.py # 24 tests (version parsing, compatibility, error handling)
└── test_ffuf_opendoor.py    # Tests for FFUF/OpenDoor step integration
```

Run: `pytest tests/ -v` | Coverage: `pytest tests/ --cov=. --cov-report=term-missing`
