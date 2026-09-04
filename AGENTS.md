# AGENTS.md — Session Anchor for AI Agents

## Project

WordPress reconnaissance tool. Python 3.11+, httpx, Typer, pydantic-settings, Rich.

Core architecture: `modules/` → `steps/` with risk tiers (1-4), config via environment variables (`WP_*`), wordlist resolution chain, findings emitted via `core/finding.py`.

**Current state:** 13 modules, 70 steps, 1339 tests passing (70/70 steps covered, 100%). All infrastructure, core, config, CLI, and edge cases covered at unit level. Wordlists set up with SecLists (13,370 plugins / 3,646 themes) at `~/.config/recon-wp/wordlists/`. Note: 4 PDF tests fail in environments where weasyprint's native libs (pango/cairo) are missing — pre-existing environment issue, not a code bug.

**Latest feature: Generic web security (`webapp` module + `web` profile + Nmap)** — New `webapp` module (tier 2, 8 steps) for non-WordPress web app checks: `SourceReviewStep` (credentials/info leaks in HTML/JS/sourcemaps, gitleaks-derived rules), `SourcemapStep`, `HttpMethodsStep`, `CookieFlagsStep`, `CorsStep`, `StackTraceStep`, `ContentLeakStep`, `HeaderQualityStep`. Shared discovery helper `utils/source_discovery.py` (static asset extraction + wordlist fuzzing via `wordlists/webapp/assets.txt` + bounded same-origin fetch). Nmap integration in `tools` module: `NmapPortScanStep` (`-sT -sV --top-ports`) and `NmapScriptScanStep` (`-sC`), both `-oJ` JSON, min version 7.92. New `-p web` profile for generic (non-WP) client assessments: `passive, infrastructure, webapp, secrets, tools`.

**Previous feature: Brute-force concurrency + progress** — `PluginBruteforceStep` and `ThemeBruteforceStep` now use bounded concurrency (`asyncio.Semaphore` + batched `gather`), progress logging every 500 probes, early abort on `http.unreachable`, and `WP_BRUTEFORCE_MAX_PROBES` cap. `LoginBruteforceStep` has progress logging. `HttpClient._execute` closes un-awaited coroutines when unreachable (fixes RuntimeWarning).

## Agent Working Protocol

**Always research before coding.** When implementing changes (especially new features, API integrations, or external library usage), use `websearch` and `webfetch` to verify current API schemas, library versions, and best practices. Do not rely on training data alone — external APIs and libraries change. Validate code against live documentation before writing it.

**Research-first workflow:**
1. `websearch` for current API/library docs and recent changes
2. `webfetch` official docs for exact schemas, parameters, and deprecations
3. Implement based on verified information
4. Run tests/lint to confirm correctness

This applies especially to: REST API endpoints, Python library APIs, CVE data sources (WPVulnerability, WPScan), Shodan API, SARIF schema, and httpx/typer/pydantic-settings usage patterns.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Wordlist resolution | CLI → config → `wordlists/` → `~/.config/recon-wp/` → hardcoded | Graceful degradation, no file required |
| Auth mechanism | Application Passwords (HTTP Basic) | WP >= 5.6, no 2FA bypass, cookie-free |
| Shodan integration | Raw REST API via httpx | No extra `shodan` package dependency |
| CVE source | WPVulnerability.net primary, WPScan secondary | Free, no API key, 47k+ plugin vulns |
| Plugin brute-force | Response-code oracle (200/301/403 = exists) | Standard approach, SecLists wordlists |

## Commit History (45 on main)

| # | Commit | Description |
|---|--------|-------------|
| 1 | `c1ba72b` | Fix wordlist loading: `wordlist_file` param, `get_wordlist_path()` fallback |
| 2 | `48c6cf8` | Wire `wordlist_file` in all 7 `WordlistDependencyMixin` callers |
| 3 | `1e72cba` | Add WHOIS TLD wordlist files (`.com`, `.br`, `.eu`) |
| 4 | `8abb857` | Rewrite `wordlists/README.md` as production guide |
| 5 | `8c24a92` | Reorganize docs into `docs/` directory |
| 6 | `b7491fd` | Fix `utcnow()` deprecation (3 files, 13 pytest warnings) |
| 7 | `836b50e` | Add Shodan intelligence gathering step |
| 8 | `4571726` | Add authenticated REST API module (plugins, themes, users via App Passwords) |
| 9 | — | Add `docs/NEXT_STEPS.md` — prioritized roadmap |
| 10 | — | Add `docs/REFERENCES.md` — indexed external URLs |
| 11 | `c646dd3` | **Plugin/Theme brute-force** — response-code oracle with fallback wordlists |
| 12 | `f1520dd` | **CVE correlation** — VulnDB client + 3 vuln lookup steps (core, plugin, theme) |
| 13 | `f5c4d85` | **Inactive plugin file accessibility** — probe readme.txt for deactivated plugins |
| 14 | `f8c044d` | **Tiers 2-3: Login brute-force, cookie admin session, REST API hardening, hosting fingerprint, SARIF, content spider** |
| 15 | `e6c6efa` | **Doc cleanup: remove redundant .md files, update outdated references** |
| 16 | `c3e5b10` | **Phase 1 bug fixes: 8 correctness bugs (findings discard, error double-format, silent validation failure, SSRF rename, urljoin inconsistency, auth improvements, sanitize chars, output redaction)** |
| 17 | `bcf93fb` | **Phase 3 tests: passive module (75 new tests, 432 total)** |
| 18 | `90299c6` | **Phase 4 tests: discovery + fingerprint modules (68 new tests, 500 total)** |
| 19 | `ae098c2` | **Phase 5 tests: xmlrpc + secrets + api modules (75 new tests, 575 total)** |
| 20 | `8a95798` | **Session 6 tests: infrastructure module (20 tests, 595 total)** |
| 21 | `981f01d` | **Session 7 tests: ssrf + users modules (31 tests, 626 total)** |
| 22 | `323f1a9` | **Session 8 tests: tools + utils modules (96 tests, 722 total)** |
| 23 | `fdcd75c` | **Sessions 8-9: tools/utils tests + code quality docstrings** |
| 24 | `fdcd75c` | **Session 10: architecture cleanup — dead code removal, Finding frozen=True, http init chain, user agents, wordlist resolution** |
| 25 | `8c24a7f` | **Session 11: Security + Polish — XSS escape, SARIF URL, SSRF port fix, IPv6 target, stdlib logger, VulnDB dedup, profile/tier validation** |
| 26 | `f54c316` | **Session 12: Core layer unit tests — target, http_client, auth, vulndb (163 new tests, 885 total)** |
| 27 | `01cea35` | **Session 13: Base infrastructure unit tests — tool_runner, step, http_step, dependencies, runner (153 new tests, 1038 total)** |
| 28 | `5952286` | **Session 14: Config, CLI, edge case unit tests — config, exceptions, logger, whois_parser, main_cli (100 new tests, 1138 total)** |
| 29 | `18730f5` | **HTML Dashboard Report** — dark theme, health score, SVG donut chart, metric cards, collapsible findings, responsive layout |
| 30 | `2dad206` | **Stealth Mode** — timing jitter, 50+ UA pool, referer spoofing, request dedup, rate limit integration (24 new tests, 1162 total) |
| 31 | `71776d3` | Rename `docs/architecture_plan.md` → `docs/ARCHITECTURE.md` |
| 32 | `f2f856f` | **Convert noise findings to warnings** — config/absence issues no longer report (10 findings removed) |
| 33 | `457de8e` | **Pre-flight reachability check** — async DNS/TCP/TLS probe before scan |
| 34 | `be7f651` | **Graceful report degradation** — formatters wrapped in try/except, PDF ImportError handler |
| 35 | `3b4385a` | **Circuit breaker** — consecutive transport errors trip `unreachable`, steps/tiers skip |
| 36 | `d9e03c9` | **Friendly network errors** — `friendly_network_error()` + debug logging in `fetch()` |
| 37 | `1465323` | Add `weasyprint>=60.0` dependency for PDF report output |
| 38 | `af8589e` | Update docs: unreachable-target resilience feature and 1189 test count |
| 39 | `b257fe7` | Rename docs files to uppercase (`code.md`→`CODE.md`, etc.) + update references |
| 40 | `a432066` | **Fix event-loop ordering in AsyncToolRunner tests** — `asyncio.run()` instead of deprecated `get_event_loop()` (1191 tests passing) |
| 41 | `a6ccdd9` | Add `bruteforce_concurrency` and `bruteforce_max_probes` config fields |
| 42 | `5d2e8ec` | Fix un-awaited coroutine in HttpClient when target unreachable |
| 43 | `b82436a` | Add concurrency, progress logging, early abort and probe cap to plugin/theme brute-force |
| 44 | `be43873` | Add progress logging to login brute-force step |
| 45 | `443702e` | Update brute-force and http_client tests for concurrency and progress features |

## Roadmap Status — ✅ All 9 items implemented (plus 1 enhancement)

| Tier | # | Feature | Key Files |
|------|---|---------|-----------|
| T1 | 1-3 | CVE correlation, Plugin/Theme brute-force, Inactive plugin check | Done in commits `f1520dd`, `c646dd3`, `f5c4d85` |
| T2 | 4 | **Login Brute-Force** | `steps/access/login_bruteforce_step.py` |
| T2 | 5 | **Cookie-Based Admin Session** | `core/auth.py`, `steps/access/site_health_step.py` |
| T2 | 6 | **REST API Hardening** | `steps/access/rest_hardening_step.py` |
| T3 | 7 | **Host Platform Fingerprinting** | `steps/infrastructure/hosting_step.py` |
| T3 | 8 | **SARIF Output Format** | `utils/report.py` |
| T3 | 8b | **HTML Dashboard Report** | `utils/report.py` — dark theme, health score, donut chart, metric cards, collapsible sections |
| T3 | 9 | **Content Crawling / Spider** | `steps/discovery/spider_step.py` |

## Remaining Work

### Priority 1 — Tests (complete)

**Coverage:** 70/70 steps tested (100%), 1339 tests passing across all layers. All infrastructure, core, config, CLI, and edge cases covered at unit level.

Test patterns: pytest + `conftest.py` fixtures (`mock_http`, `mock_target`, `mock_config`). For HTTP steps, mock `mock_http.request` (not `mock_http.get` — steps delegate through `BaseHttpStep.get()` → `self.http.request()`). For VulnDB-dependent steps, use `@patch("steps.vuln.*.VulnDB")`.

### Priority 2 — Wordlists (production scan effectiveness)

Brute-force steps use small fallback lists (30 plugins / 15 themes). Production scans need SecLists.

```bash
# Download to project
mkdir -p wordlists/external
curl -o wordlists/external/wp-plugins.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt
curl -o wordlists/external/wp-themes.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-themes.fuzz.txt

# Or to user config
mkdir -p ~/.config/recon-wp/wordlists/plugins
cp wordlists/external/wp-plugins.txt ~/.config/recon-wp/wordlists/plugins/plugin_fallback.txt
cp wordlists/external/wp-themes.txt ~/.config/recon-wp/wordlists/plugins/theme_fallback.txt
```

See `wordlists/README.md` for full resolution chain.

### Priority 3 — Beyond roadmap (future features)

| Feature | Effort | Impact | Notes |
|---------|--------|--------|-------|
| **Stealth** | High | High | ✅ Implemented — timing jitter, 50+ UA pool, referer spoofing, request dedup, rate limit integration |
| **VulnDB alignment** | Low | Medium | Share `HttpClient` with `WPVulnerabilityClient`/`WPScanClient` for stealth consistency |
| **PyPI package** | Medium | Low | `pyproject.toml`, entry point, versioning — config exists, needs publish workflow |
| **Plugin architecture** | High | High | Dynamic step loading from external packages, CLI `--plugin` flag |

### Config Reference — Stealth Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `WP_STEALTH_ENABLED` | `false` | Enable stealth mode |
| `WP_STEALTH_MIN_DELAY` | `1.0` | Minimum delay between requests (seconds) |
| `WP_STEALTH_MAX_DELAY` | `3.0` | Maximum delay between requests (seconds) |
| `WP_STEALTH_ROTATE_UA` | `true` | Rotate User-Agent per request |
| `WP_STEALTH_ROTATE_REFERER` | `true` | Spoof random Referer headers |
| `WP_STEALTH_DEDUP_REQUESTS` | `true` | Skip duplicate HTTP requests |
| `WP_STEALTH_RATE_LIMIT` | `0.0` | Max requests/second (0 = unlimited) |

Key files: `core/http_client.py` (UA pool, jitter, referer, dedup), `config.py` (stealth fields), `utils/rate_limiter.py` (rate limiter wired into client).

### Config Reference — Brute-Force

| Variable | Default | Description |
|----------|---------|-------------|
| `WP_BRUTEFORCE_CONCURRENCY` | `4` | Max parallel probes per brute-force step (1-20) |
| `WP_BRUTEFORCE_MAX_PROBES` | `0` | Hard cap on total probes (0 = unlimited) |

Key files: `steps/discovery/plugin_bruteforce_step.py`, `steps/discovery/theme_bruteforce_step.py`, `steps/access/login_bruteforce_step.py`.

### Config Reference — Nmap

| Variable | Default | Description |
|----------|---------|-------------|
| `WP_ENABLE_NMAP` | `false` | Enable `NmapPortScanStep` (top-ports + `-sV` version detection) |
| `WP_ENABLE_NMAP_SCRIPTS` | `false` | Enable `NmapScriptScanStep` (default NSE scripts, `-sC`) |
| `WP_NMAP_TOP_PORTS` | `100` | Top-N ports to scan (1-65535) |
| `WP_NMAP_PORTS` | `""` | Custom port list, overrides top ports (e.g. `80,443,8080`) |
| `WP_NMAP_TIMEOUT` | `300` | Nmap execution timeout (seconds) |

CLI: `--nmap`, `--nmap-scripts`, `--nmap-top-ports`, `--nmap-ports`, `--nmap-timeout`. Key files: `steps/tools/nmap_step.py`, `modules/tools_module.py`. Direct host scan (connect scan, no root, no SSRF blocklist) — authorized targets only.

### Config Reference — Webapp / Source Scan

| Variable | Default | Description |
|----------|---------|-------------|
| `WP_SOURCE_SCAN_MAX_JS` | `20` | Max JS/asset files to fetch for source review |
| `WP_SOURCE_SCAN_MAX_BYTES` | `1000000` | Max bytes kept per asset file |
| `WP_SOURCE_SCAN_SOURCEMAPS` | `true` | Probe for `.js.map` sourcemaps |
| `WP_SOURCE_SCAN_FUZZ` | `true` | Fuzz common asset paths (`wordlists/webapp/assets.txt`, config key `source_assets`) |
| `WP_WEBAPP_MAX_PAGES` | `10` | Max pages analyzed by `ContentLeakStep` |

Key files: `steps/webapp/*`, `utils/source_discovery.py`, `modules/webapp_module.py`, `wordlists/webapp/assets.txt`.

### Scan Profiles

`-p web` → `passive, infrastructure, webapp, secrets, tools` — generic (non-WP) web security profile. `tools` is a no-op unless a tool flag is passed. Usage: `python main.py -t https://site.com -p web --nmap --nmap-scripts -f all`.

See `docs/NEXT_STEPS.md` for implementation details and `docs/REFERENCES.md` for external API/tool URLs (nmap, OWASP WSTG test mappings, gitleaks rules source).
