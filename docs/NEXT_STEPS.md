# Next Steps — WordPress Reconnaissance Tool

**Last Updated:** 2026-09-11  
**Current Branch:** `main`  
**HEAD:** `443702e` — Update brute-force and http_client tests for concurrency and progress features (1200 tests passing)

---

## Web Pentest + Intrusive Expansion (implemented 2026-09-11, status: ✅ complete)

Research-driven expansion in 7 phases — all implemented and tested (96 steps, 1605 tests passing). Full reference list in `docs/REFERENCES.md`
(sections "Web Pentest Expansion References" and "Active testing").

### Phase 0 — Foundation: `active` module + `intrusive` profile ✅
- `modules/active_module.py` (new, tier 5, 15 steps), `RISK_TIERS[5]`, `PROFILES["intrusive"]` / `PROFILES["web-intrusive"]`
- `base/runner.py`: dynamic tier grouping (supports any tier in RISK_TIERS)
- `config.py`: `active_enabled` master switch (default false) + caps (`active_max_params` 20, `active_max_requests` 100, `active_delay` 0.5s, `active_time_based`, `active_file_upload`, `active_smuggling`, `active_race_endpoint`, `active_mass_assign_endpoint`)
- `main.py`: `-p intrusive` / `web-intrusive` + `--active` flag + `--authorized` ack (scan exits without it)
- Safety model: default off, hard request caps, delay between probes, detection-only (no data extraction), respects circuit breaker

### Phase 1 — Tier A web recon (webapp/passive) ✅
| Step | WSTG | Approach |
|------|------|----------|
| `JwtAuditStep` | 4.6.10 | Extract JWTs from cookies/HTML/JS; offline decode: alg:none, missing/expired exp, weak HS256 secret (stdlib dict), sensitive claims, kid/jku |
| `ClientSideAuditStep` | 4.11.1/11/12/14 | Static HTML/JS: postMessage `*`, DOM sinks fed by location, localStorage secrets, target=_blank w/o noopener |
| `SubdomainTakeoverStep` | 4.2.10 | crt.sh candidates + dig CNAME + can-i-take-over-xyz fingerprints (`wordlists/takeover/fingerprints.json`) |
| `WebSocketStep` | 4.11.10 | ws/wss discovery in HTML/JS + raw asyncio handshake with canary Origin (101 = CSWSH signal) |
| `JsLibraryStep` | 4.11.6 | JS lib/version detection + vendored retire.js subset (`wordlists/webapp/js_libraries.json`) + missing SRI |

### Phase 2 — Tier B config surface ✅
| Step | WSTG | Approach |
|------|------|----------|
| `SensitiveFilesStep` | 4.2.3/4.2.4 | Generic backup/config wordlist (`wordlists/webapp/sensitive_files.txt`) |
| `CacheAnalysisStep` | cache | Cache-layer detection (Age/X-Cache/CF-Cache-Status) + capped path-suffix WCD canary |
| `FormSecurityStep` | 4.4.1/4.4.6/4.6.5 | Password form over http://, CSRF-token heuristic, autocomplete, cacheable auth pages |
| `TechFingerprintStep` | 4.1.8/4.1.9 | Framework fingerprint from headers/cookies/HTML |
| `EmailSecurityStep` | passive | DMARC/DKIM/CAA/DNSSEC via dig |

### Phase 3 — Tier C WordPress ✅
| Step | Approach |
|------|----------|
| `PluginAbandonmentStep` | wp.org API `last_updated`/`closed`/`tested` risk scoring |
| `WooCommerceStep` | `/wp-json/wc/store/v1/` + `/?wc-ajax=` + version from readme |
| `PhpVersionStep` | PHP version from headers/cookies → EOL mapping |
| `RegistrationStep` | `wp-login.php?action=register` + `wp-signup.php` open registration |

### Phase 4 — Active injection family (tier 5, detection-only) ✅
`SqlInjectionStep` (4.7.5, error-signatures + optional time-based), `ReflectedXssStep` (4.7.1, canary reflection), `SstiStep` (4.7.18), `PathTraversalStep` (4.5.1), `CrlfInjectionStep` (4.7.15), `HttpParameterPollutionStep` (4.7.4).

### Phase 5 — Active auth family ✅
`AuthBypassStep` (4.4.4/4.5.2), `RateLimitStep` (4.4.3), `PasswordResetStep` (4.4.9), `CsrfStep` (4.6.5), `DefaultCredentialsStep` (4.4.2, capped, stops on success).

### Phase 6 — Active high-risk (double-gated) ✅
`RequestSmugglingStep` (4.7.16, raw sockets, off even in intrusive), `MassAssignmentStep` (4.7.20, operator-supplied endpoint), `RaceConditionStep` (4.10.x, operator-supplied endpoint), `FileUploadStep` (4.10.8/9, safe marker file, requires `active_file_upload=true`).

### New wordlists ✅
`webapp/sensitive_files.txt`, `webapp/js_libraries.json`, `takeover/fingerprints.json`, `active/` payload lists (built-in fallbacks in steps).

---

## Session History (Commit Reference)

| # | Commit | Description |
|---|--------|-------------|
| 1 | `c1ba72b` | Fix wordlist loading: add `wordlist_file` param to `resolve_wordlist_or_fallback()` |
| 2 | `48c6cf8` | Wire `wordlist_file` in all 7 `WordlistDependencyMixin` callers |
| 3 | `1e72cba` | Add WHOIS TLD wordlist files for `.com`, `.br`, `.eu` domains |
| 4 | `8abb857` | Rewrite `wordlists/README.md` as production wordlist guide |
| 5 | `8c24a92` | Reorganize documentation into `docs/` directory |
| 6 | `b7491fd` | Fix `datetime.utcnow()` deprecation warnings (4 occurrences) |
| 7 | `836b50e` | Add Shodan intelligence gathering step |
| 8 | `4571726` | Add authenticated REST API enumeration (plugins, themes, users via App Passwords) |
| 9 | `c646dd3` | Add plugin/theme brute-force — response-code oracle with SecLists fallback wordlists |
| 10 | `f1520dd` | Add CVE correlation — VulnDB client + 3 vuln lookup steps (core, plugin, theme) |
| 11 | `f5c4d85` | Add inactive plugin file accessibility check — probe readme.txt for deactivated plugins |
| 12 | `f8c044d` | Tiers 2-3: Login brute-force, cookie admin, REST hardening, hosting fingerprint, SARIF, spider |
| 13 | `e6c6efa` | Doc cleanup: remove redundant .md files, update outdated references |
| 14 | `c3e5b10` | Phase 1 bug fixes: 8 correctness bugs |
| 15 | `bcf93fb` | Phase 3 tests: passive module (75 tests, 432 total) |
| 16 | `90299c6` | Phase 4 tests: discovery + fingerprint (68 tests, 500 total) |
| 17 | `ae098c2` | Phase 5 tests: xmlrpc + secrets + api (75 tests, 575 total) |
| 18 | `8a95798` | Session 6 tests: infrastructure module (20 tests, 595 total) |
| 19 | `981f01d` | Session 7 tests: ssrf + users (31 tests, 626 total) |
| 20 | `323f1a9` | Session 8 tests: tools + utils (96 tests, 722 total) |
| 21 | `fdcd75c` | Sessions 8-9: tools/utils tests + code quality docstrings |
| 22 | `fdcd75c` | Session 10: architecture cleanup |
| 23 | `8c24a7f` | Session 11: Security + Polish |
| 24 | `f54c316` | Session 12: Core layer unit tests (163 tests, 885 total) |
| 25 | `01cea35` | Session 13: Base infrastructure tests (153 tests, 1038 total) |
| 26 | `5952286` | Session 14: Config/CLI/edge case tests (100 tests, 1138 total) |
| 27 | `2dad206` | **Stealth Mode** — timing jitter, 50+ UA pool, referer spoofing, request dedup, rate limit (24 tests, 1162 total) |
| 28 | `71776d3` | Rename `docs/architecture_plan.md` → `docs/ARCHITECTURE.md` |
| 29 | `f2f856f` | **Convert noise findings to warnings** — config/absence issues no longer report (10 findings removed) |
| 30 | `457de8e` | **Pre-flight reachability check** — async DNS/TCP/TLS probe before scan |
| 31 | `be7f651` | **Graceful report degradation** — formatters wrapped in try/except, PDF ImportError handler |
| 32 | `3b4385a` | **Circuit breaker** — consecutive transport errors trip `unreachable`, steps/tiers skip |
| 33 | `d9e03c9` | **Friendly network errors** — `friendly_network_error()` + debug logging in `fetch()` |
| 34 | `1465323` | Add `weasyprint>=60.0` dependency for PDF report output |
| 35 | `af8589e` | Update docs: unreachable-target resilience feature and 1189 test count |
| 36 | `b257fe7` | Rename docs files to uppercase (`code.md`→`CODE.md`, etc.) + update references |
| 37 | `a432066` | **Fix event-loop ordering in AsyncToolRunner tests** — `asyncio.run()` instead of deprecated `get_event_loop()` (1191 tests passing) |
| 38 | `a6ccdd9` | Add `bruteforce_concurrency` and `bruteforce_max_probes` config fields |
| 39 | `5d2e8ec` | Fix un-awaited coroutine in HttpClient when target unreachable |
| 40 | `b82436a` | Add concurrency, progress logging, early abort and probe cap to plugin/theme brute-force |
| 41 | `be43873` | Add progress logging to login brute-force step |
| 42 | `443702e` | Update brute-force and http_client tests for concurrency and progress features |
| 43 | — | **Generic web security: `webapp` module + `web` profile + Nmap integration** — 10 new steps, 139 new tests (see "Generic Web App Security ✅" below) |
| 44 | — | **Webapp module expansion: 5 new research steps + 6 refinements** — CSP audit, API surface, admin surface, open redirect, host header; 80 new tests, 1419 total (see "Webapp Research Expansion ✅" below) |

**Current state:** 14 modules, 96 steps, 1605 tests passing (4 pre-existing weasyprint environment failures unrelated to code). Web pentest expansion + active module (`active` tier 5, 15 gated steps), `intrusive`/`web-intrusive` profiles for authorized client assessments — see AGENTS.md for config reference.

---

## Tier 1 — High Impact

### 1. CVE Correlation ✅ (commit `f1520dd`)

**Why:** The tool enumerates plugin/theme/core versions but does not map them to known CVEs. Every major scanner (WPScan, WPSecScan, WPProbe, WPHunter) does this — without it, version numbers are data without findings.

**Status:** Implemented. `VulnDB` facade queries WPVulnerability.net (primary, free, no key) and optionally WPScan API (when `wpscan_api_token` configured). Three steps — `CoreVulnStep`, `PluginVulnStep`, `ThemeVulnStep` — each detect their components (auth API → HTML fallback) and emit per-CVE findings with CVSS-based severity.

#### Vulnerability Data Sources

| Source | Cost | Key Required | Coverage | Rate Limit |
|--------|------|-------------|----------|------------|
| **WPVulnerability.net** | Free | No | 47,341 plugin vulns (16k plugins), 4,030 theme vulns, core vulns | Reasonable use |
| **WPScan API** | Free tier | Yes (API token) | Curated DB | 25 req/day |
| **Wordfence** | Free | Yes (API key) | ~7,000 plugin CVEs | 117MB feed dump |

**Recommendation:** Use **WPVulnerability.net as the primary source** (free, no key, most comprehensive). Add WPScan API as an optional secondary source for users who already have a token. This matches the approach used by wphunter, wordpress-vulnerable-scanner, and wpsecscan.

#### API Reference

**WPVulnerability.net** (no auth required):
```
GET https://www.wpvulnerability.net/plugin/{slug}/
GET https://www.wpvulnerability.net/theme/{slug}/
GET https://www.wpvulnerability.net/core/{version_with_dots}/
```
Response envelope: `{ error: 0, message: null, data: { vulnerabilities: [...] }, updated: <unix_ts> }`
Version matching uses PHP `version_compare()` operators.

**WPScan API v3** (requires `Authorization: Token token=<API_TOKEN>`):
```
GET https://wpscan.com/api/v3/plugins/{slug}/
GET https://wpscan.com/api/v3/themes/{slug}/
GET https://wpscan.com/api/v3/wordpresses/{version_no_dots}/
```

#### Implementation Plan

| File | Action | Notes |
|------|--------|-------|
| `core/vulndb.py` | **NEW** | Vulnerability lookup client with dual-source support |
| `steps/vuln/core_vuln_step.py` | **NEW** | Match WP core version against vuln DB |
| `steps/vuln/plugin_vuln_step.py` | **NEW** | Match detected plugin slugs+versions against vuln DB |
| `steps/vuln/theme_vuln_step.py` | **NEW** | Match detected theme slugs+versions against vuln DB |
| `modules/vuln_module.py` | **NEW** | VulnerabilityModule with 3 steps |
| `modules/__init__.py` | **MODIFY** | Register vuln module |
| `base/runner.py` | **MODIFY** | Add "vuln" to risk tier |
| `config.py` | **MODIFY** | Optional cache TTL, WPScan token reuse |

**Key design decisions:**
- WPVulnerability.net primary (free, no key)
- WPScan API as fallback/enrichment when `wpscan_api_token` is configured
- Cache per-slug responses to avoid redundant API calls
- CVSS score → severity mapping: 0.0-3.9=low, 4.0-6.9=medium, 7.0-8.9=high, 9.0-10.0=critical
- Version comparison: `version_compare(installed, fixed_in, "<")` — report if installed < fixed_in

**Comparison with other tools:**
- WPHunter uses WPVulnerability.net + WPScan API with deduplication. Reports ~120 vulns on a typical site vs 108 from WPVulnerability alone vs 74 from WPScan alone.
- WPSecScan uses 8-source nightly aggregator (NVD, GHSA, Mitre, OSV, Wordfence, WPVulnerability, CIRCL, Patchstack).

---

### 2. Plugin/Theme Brute-Force Detection ✅ (commit `c646dd3`)

**Why:** Current fingerprinting only detects plugins/themes that appear in HTML (CSS/JS references, meta tags). Inactive plugins and themes hidden from the page source are invisible. A 403/200 response-code oracle catches them.

**Status:** Implemented. `PluginBruteforceStep` and `ThemeBruteforceStep` probe `/wp-content/plugins/{slug}/` and `/wp-content/themes/{slug}/` with wordlist fallbacks (30 plugins / 15 themes). Steps log a WARNING when using the small fallback list and advise downloading SecLists for production use.

**Concurrency & Progress (commit `b82436a`):** Both steps now use bounded concurrency via `asyncio.Semaphore` + batched `asyncio.gather` (`WP_BRUTEFORCE_CONCURRENCY`, default 4). Progress logs every 500 probes. Steps abort early when `http.unreachable` trips the circuit breaker. A configurable probe cap (`WP_BRUTEFORCE_MAX_PROBES`, default 0 = unlimited) allows limiting scan scope on large wordlists.

#### Detection Methods

| Mode | Method | Requests | Coverage | Stealth |
|------|--------|----------|----------|---------|
| **Stealthy** (exist) | Parse HTML for `/wp-content/plugins/{name}/` | 0 (passive) | Limited to loaded assets | Maximum |
| **REST API** | Match `?rest_route=/` responses against plugin→endpoint DB | 1-5 | ~5,000 plugins | High |
| **Brute-force** | Probe `GET /wp-content/plugins/{slug}/` | 1 per slug | ~20,000+ plugins | Low |

#### Wordlists

| Source | Size | URL |
|--------|------|-----|
| SecLists `wordpress-plugins.fuzz.txt` | ~20k plugins | `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress-plugins.fuzz.txt` |
| SecLists `wp-plugins.fuzz.txt` | ~2k plugins | `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt` |
| WPScan built-in | ~28k plugins | Bundled with WPScan distribution |
| WPProbe stealthy DB | ~5k plugins | Plugin→REST-endpoint mapping DB |

#### Implementation Plan

| File | Action | Notes |
|------|--------|-------|
| `steps/discovery/plugin_bruteforce_step.py` | **NEW** | Probe `/wp-content/plugins/{slug}/` with response-code oracle |
| `steps/discovery/theme_bruteforce_step.py` | **NEW** | Same for themes |
| `modules/discovery_module.py` | **MODIFY** | Register new steps |
| `wordlists/` | **ADD** | Symlink or download reference to SecLists |

**Brute-force algorithm:**
1. For each slug in wordlist, probe `GET /wp-content/plugins/{slug}/`
2. 200 → exists; optionally validate `readme.txt` to confirm
3. 301/302 → exists (redirects to same dir with trailing slash)
4. 403 → exists (directory listing forbidden by Apache)
5. 404 → absent
6. For confirmed plugins, try version extraction from `readme.txt` (`curl -s <url>/readme.txt | grep -i "stable tag\|^version"`)

**Rate limiting:** Use existing `RetryLimiter` (from `utils/rate_limiter.py`). This step generates many requests — default throttle recommended.

**Integration note:** The brute-force step should skip slugs already confirmed by passive fingerprint steps (`PluginStep`, `ThemeStep`). Or feed brute-force results into the CVE correlation step for vuln lookup.

---

### 3. Inactive Plugin File Accessibility Check ✅ (commit `f5c4d85`)

**Why:** The authenticated `WpJsonPluginsStep` (commit `4571726`) already lists inactive plugins. This step checks whether their files are still accessible on disk — they often are, even when deactivated. Accessible inactive plugins can still be exploited.

**Status:** Implemented. `InactivePluginCheckStep` queries `/wp-json/wp/v2/plugins` with auth, filters to inactive plugins, probes `/wp-content/plugins/{slug}/readme.txt` for each, and emits a medium-severity finding if files are publicly readable.

**Implementation:**
| File | Action | Notes |
|------|--------|-------|
| `steps/access/inactive_plugin_check_step.py` | **NEW** | Probe inactive plugin files for accessibility |
| `modules/access_module.py` | **MODIFY** | Register new step |

**Algorithm:**
1. Accept list of inactive plugin slugs (from `WpJsonPluginsStep` output or re-query)
2. Probe `GET /wp-content/plugins/{slug}/readme.txt`
3. If 200 → files are accessible → finding severity: medium
4. Evidence: "Plugin {slug} is inactive but files are readable at /wp-content/plugins/{slug}/"

---

## Tier 2 — Moderate Impact ✅

### 4. Login Brute-Force Step ✅

**Status:** Implemented. `LoginBruteforceStep` probes `POST /wp-login.php` with credential pairs via `resolve_credentials_with_fallback()`, detects success via 302 redirect to `/wp-admin/`, and emits high-severity findings for valid credentials. Progress logging every 5 attempts (commit `be43873`).

Key files: `steps/access/login_bruteforce_step.py`, registered in `AccessModule`.

---

### 5. Cookie-Based Admin Session ✅

**Status:** Implemented. `AdminSession` class in `core/auth.py` handles cookie-based wp-login.php POST + session cookie management. `SiteHealthStep` uses it to extract debug info from `/wp-admin/site-health-info.php`. Config field `wp_auth_method` added (default: `app_password`).

Key files: `core/auth.py`, `steps/access/site_health_step.py`, `config.py`.

---

### 6. REST API Hardening Checks ✅

**Status:** Implemented. `RestHardeningStep` performs 4 checks: CORS wildcard detection, route leakage from `/wp-json/` response, public user endpoint exposure, and plugin endpoint accessibility audit.

Key files: `steps/access/rest_hardening_step.py`, registered in `AccessModule`.

---

## Tier 3 — Polish & Integration ✅

### 7. Host Platform Fingerprinting ✅

**Status:** Implemented. `HostingStep` detects 12 hosting providers from response headers (WP Engine, Kinsta, Pantheon, Cloudways, Flywheel, WordPress.com, wpX, Pressable, SiteGround, GoDaddy, Pressable, Cloudways) plus Bedrock path-structure detection.

Key files: `steps/infrastructure/hosting_step.py`, registered in `InfrastructureModule`.

### 8. SARIF Output Format ✅

**Status:** Implemented. `SarifFormatter` wraps findings in SARIF 2.1.0 run envelope with tool metadata, rules, results, and invocation info. Available via `output_format: "sarif"` or `"all"`. Uses existing `Finding.to_sarif()` method.

Key files: `utils/report.py`, `config.py` (output_format extended).

### 8b. HTML Dashboard Report ✅

**Status:** Enhanced. `HtmlFormatter` produces a self-contained HTML page with:
  - Dark theme dashboard using deep-space color palette (`#212f45` → `#272640` → `#312244`)
  - Health score badge (weighted: max(0, 100 - critical*25 - high*10 - medium*3 - low*1))
  - Five dashboard metric cards (Critical, High, Medium, Low, Info) with severity-colored top borders
  - SVG donut chart showing severity distribution with legend
  - Scan Overview panel (modules, duration, total findings, health score)
  - Collapsible findings sections: Critical+High expanded by default, Medium+Low and Informational collapsed
  - Finding cards with left-border accent, severity badge, evidence, and recommendation
  - Responsive grid layout, print styles, XSS-safe HTML escaping
  - Wraps to PDF via `PdfFormatter` (WeasyPrint)

Key files: `utils/report.py` (HtmlFormatter).

### 9. Content Crawling / Spider ✅

**Status:** Implemented. `SpiderStep` crawls same-origin links from homepage up to configurable depth (default 2) and page limit (default 50). Extracts form actions, upload directories, admin-like paths, and comment sections. Respects `robots.txt` disallow rules.

Key files: `steps/discovery/spider_step.py`, `config.py` (spider_max_depth, spider_max_pages).

---

## Unreachable-Target Resilience ✅

**Why:** Scanning an unreachable target (bad DNS, expired TLS cert, firewalled host) previously wasted 70s–10min on silently failing steps, produced noise findings, then crashed on PDF output when WeasyPrint was missing.

**Status:** Implemented. Four features:

### 1. Pre-flight Reachability Check
`core/reachability.py` probes DNS → TCP → TLS before the scan starts. On failure, aborts with `typer.Exit(1)` and a friendly message instead of running the full scan. Skip with `--skip-reachability-check`.

### 2. Circuit Breaker
`HttpClient._execute()` counts consecutive transport-level failures. After `unreachable_threshold` (default 5) consecutive errors, the target is marked unreachable and `Runner` skips remaining steps and tiers. Configurable via `WP_UNREACHABLE_THRESHOLD`.

### 3. Graceful Report Degradation
`_save_report` wraps every formatter in try/except. A missing WeasyPrint now prints a warning ("install weasyprint") instead of crashing the whole scan. `weasyprint>=60.0` added to `requirements.txt`.

### 4. Report Noise Cleanup
Config/tool/absence issues are now `logger.warning` only, not findings:
- Shodan: missing API key, no HTTP client, DNS resolution failure, no data
- Wayback: no HTTP client, no archives
- DNS: dig binary missing, no records
- Plugin/theme vuln: no items detected (skips "no CVEs" finding)

**Key files:** `core/reachability.py`, `core/http_client.py`, `base/runner.py`, `base/http_step.py`, `main.py`, `config.py`, `requirements.txt`.

---

## Brute-Force Concurrency & Progress ✅

**Why:** With SecLists wordlists (13k+ plugins), sequential brute-force takes 15-60+ minutes with zero progress output — scan appears frozen. Circuit breaker can't rescue because requests succeed (200/404) rather than fail.

**Status:** Implemented across 3 commits:

### 1. Config Fields (commit `a6ccdd9`)
- `WP_BRUTEFORCE_CONCURRENCY` — max parallel probes (default 4, range 1-20)
- `WP_BRUTEFORCE_MAX_PROBES` — hard cap on total probes (default 0 = unlimited)

### 2. Coroutine Cleanup (commit `5d2e8ec`)
`HttpClient._execute()` now closes un-awaited coroutines when raising `UnreachableError`, fixing RuntimeWarning on shutdown.

### 3. Plugin/Theme Concurrency (commit `b82436a`)
Both brute-force steps use `asyncio.Semaphore` + batched `asyncio.gather` for bounded concurrency. Features:
- Start log with wordlist size and scale ("probing 13370 plugins × 4 concurrent")
- Progress logging every 500 probes with elapsed time and hit count
- Early abort when `http.unreachable` (circuit breaker trip)
- Hard probe cap via `WP_BRUTEFORCE_MAX_PROBES`
- Graceful fallback to sequential if concurrency=1

### 4. Login Progress (commit `be43873`)
`LoginBruteforceStep` logs progress every 5 attempts (sequential + sleep preserved).

**Key files:** `config.py`, `core/http_client.py`, `steps/discovery/plugin_bruteforce_step.py`, `steps/discovery/theme_bruteforce_step.py`, `steps/access/login_bruteforce_step.py`.

---

## Generic Web App Security ✅

**Why:** Reuse this tool for web security analysis of internal clients that are not WordPress sites. Extends the tool from "WP recon" to "general web security assessment" with non-intrusive, reusable checks.

**Status:** Implemented. Two new areas: a `webapp` module (13 pure-HTTP steps) and Nmap integration (2 tool steps), plus a `web` scan profile.

### 1. `webapp` Module (tier 2, 13 steps)

| Step | WSTG ref | What it checks |
|------|----------|----------------|
| `SourceReviewStep` | 4.1.5 | Scans HTML/JS/sourcemaps for embedded credentials (AWS, GitHub, Slack, JWT, PEM keys, GCP, Stripe, Twilio, SendGrid, npm, HuggingFace, Mailgun, OpenAI, Anthropic, GitLab, Notion, Telegram, Discord, Heroku, Terraform, Azure, DB connection strings, basic-auth URLs, hardcoded passwords) + info leaks (internal IPs, cloud metadata, emails). Rules adapted from gitleaks (Go RE2 → Python `re`); AWS secret keys require `secret`-context to cut false positives; email/internal-IP rules are JS-only (HTML handled by `ContentLeakStep`). Secrets masked in evidence, full value in `raw`. |
| `SourcemapStep` | 4.1.5 | Detects sourcemaps via `sourceMappingURL=` comments in fetched JS (map URL resolved relative to the JS file), with a `.js.map` suffix fallback for unfetched sources. |
| `HttpMethodsStep` | 4.2.6 | TRACE/PUT/DELETE/PROPFIND enabled; missing `Allow` header. |
| `CookieFlagsStep` | 4.6.2 | Set-Cookie audit: `Secure`/`HttpOnly`/`SameSite` on common entry paths; flags `SameSite=None` without `Secure`. |
| `CorsStep` | 4.11.7 | Canary-Origin probes across 8 API paths: wildcard `ACAO`, origin reflection, reflection with credentials; records `Access-Control-Allow-Methods`. |
| `StackTraceStep` | 4.8 | Malformed-shape probes (recon only), incl. malformed-JSON POSTs to `/api` and `/graphql` + framework error signatures (Python, PHP, Django, Rails, .NET, Spring, SQL). |
| `ContentLeakStep` | 4.1.5 | BFS crawl (homepage + 2 link levels, capped at `webapp_max_pages`): internal IPs, internal hostnames, emails, meta generator, config-like HTML comments; plus `http://` mixed-content detection on HTTPS pages. |
| `HeaderQualityStep` | 4.2.7/4.2.12/4.2.14 | Present-but-weak headers: HSTS max-age/includeSubDomains, `X-Frame-Options: NONE`, CSP without `frame-ancestors`. Complements `infrastructure`'s missing-header check. |
| `CspAuditStep` | 4.2.12 | Audits a *present* CSP for weak directives (`unsafe-inline`/`unsafe-eval`/unsafe hashes) and missing hardening (`object-src 'none'`, `base-uri`, `form-action`, `script-src`, violation reporting). |
| `ApiSurfaceStep` | 4.12.1/4.12.99/4.1.4 | Maps API surface: robots.txt + sitemap discovery, OpenAPI/Swagger doc detection (endpoint + sensitive-path count), GraphQL introspection probe, API endpoint discovery over `wordlists/webapp/api_paths.txt` (cap `webapp_max_api_paths`). |
| `AdminSurfaceStep` | 4.2.5/4.2.13 | Probes `wordlists/webapp/admin_paths.txt` (46 console/monitoring/debug paths, cap `webapp_max_admin_paths`); per-path severity (heapdump/actuator = high, consoles = medium), aggregated "behind authentication" finding, security.txt detection. |
| `OpenRedirectStep` | 4.11.4 | Canary-URL probes: 16 redirect-capable paths × 15 params (cap `webapp_redirect_max_requests`, `follow_redirects=False`); 3xx `Location` to canary = open redirect (high on auth paths, medium otherwise). |
| `HostHeaderStep` | 4.7.17 | Canary `Host:` + `X-Forwarded-Host:` probes against a baseline: unknown-vhost response, canary reflected in body, XFH reflection (cookie-domain poisoning surface). |

**Source discovery** (`utils/source_discovery.py`): static asset extraction from HTML (`<script src>`, `<link>`, CSS `url()`, inline JS literals, `<a href>`) + a built-in fuzzing pass over `wordlists/webapp/assets.txt` (resolvable via `WP_SOURCE_ASSETS`), same-origin normalization, and bounded fetching (`WP_SOURCE_SCAN_MAX_JS` / `WP_SOURCE_SCAN_MAX_BYTES`).

### 2. Nmap Integration (`tools` module, tier 4)

| Step | Command | Output |
|------|---------|--------|
| `NmapPortScanStep` (`--nmap`) | `nmap -oX - -Pn -sT -T4 -sV --top-ports 100 <host>` | Open ports + service versions; `medium` severity when risky services exposed (SSH, RDP, VNC, DBs). |
| `NmapScriptScanStep` (`--nmap-scripts`) | `nmap -oX - -Pn -sT -T4 -sV -sC --top-ports 100 <host>` | Notable NSE script output (ftp-anon, http-headers, ssl-cert, …) + NSE `vulns` entries with CVE ids. |

Connect scan (`-sT`) works without root; direct host scan (no SSRF blocklist — intended for authorized targets). Requires nmap >= 7.92 (version-checked like other tools).

### 3. `web` Profile

`-p web` → `passive, infrastructure, webapp, secrets, tools` — a generic (non-WP) assessment profile. `tools` is a no-op unless a tool flag (`--nmap`, `--nuclei`, …) is passed. WP-specific probes in `secrets`/`infrastructure` 404 harmlessly on non-WP targets.

**Usage:** `python main.py -t https://client-site.com -p web --nmap --nmap-scripts -f all`

**Config:** `WP_ENABLE_NMAP`, `WP_ENABLE_NMAP_SCRIPTS`, `WP_NMAP_TOP_PORTS`, `WP_NMAP_PORTS`, `WP_NMAP_TIMEOUT`, `WP_SOURCE_SCAN_MAX_JS`, `WP_SOURCE_SCAN_MAX_BYTES`, `WP_SOURCE_SCAN_SOURCEMAPS`, `WP_SOURCE_SCAN_FUZZ`, `WP_WEBAPP_MAX_PAGES`, `WP_WEBAPP_OPEN_REDIRECT`, `WP_WEBAPP_REDIRECT_MAX_REQUESTS`, `WP_WEBAPP_HOST_PROBE`, `WP_WEBAPP_MAX_API_PATHS`, `WP_WEBAPP_MAX_ADMIN_PATHS`.

**Key files:** `steps/webapp/*`, `steps/tools/nmap_step.py`, `utils/source_discovery.py`, `modules/webapp_module.py`, `modules/__init__.py`, `modules/tools_module.py`, `main.py`, `config.py`, `wordlists/webapp/assets.txt`, `wordlists/webapp/api_paths.txt`, `wordlists/webapp/admin_paths.txt`, `utils/tool_version_checker.py` (nmap version pattern).

### 4. Webapp Research Expansion (5 new steps + 6 refinements)

**New steps** (see table above): `CspAuditStep` (4.2.12), `ApiSurfaceStep` (4.12.1/4.12.99/4.1.4), `AdminSurfaceStep` (4.2.5/4.2.13), `OpenRedirectStep` (4.11.4), `HostHeaderStep` (4.7.17). All are config-gated and request-capped, following the existing non-intrusive convention.

**Refinements to existing steps:**
- `SourceReviewStep` — 9 new gitleaks-verified rules (OpenAI, Anthropic, GitLab PAT, Notion, Telegram bot token, Discord webhook, Heroku, Terraform, Azure storage account key); AWS secret-key pattern tightened to require `secret` context; email/internal-IP rules skipped for HTML (owned by `ContentLeakStep`).
- `SourcemapStep` — parses `sourceMappingURL=` comments from fetched JS, resolves map URLs relative to the JS file; `.js.map` fallback for unfetched sources.
- `CookieFlagsStep` — captures SameSite value; `SameSite=None` without `Secure` → medium finding.
- `CorsStep` — probes 8 API paths (was 3); records `Access-Control-Allow-Methods`.
- `StackTraceStep` — adds malformed-JSON POST probes to `/api` and `/graphql`.
- `ContentLeakStep` — BFS crawl to 2 link levels (was homepage-only) with a `queued` set to avoid dequeue-skip; adds mixed-content (`http://` subresources on HTTPS pages) detection.

**New wordlists:** `wordlists/webapp/api_paths.txt` (27 API/doc paths), `wordlists/webapp/admin_paths.txt` (46 admin/console/debug paths). Both resolvable via the standard wordlist resolution chain.

**Tests:** 80 new tests across 5 new files (`test_csp_audit_step.py`, `test_api_surface_step.py`, `test_admin_surface_step.py`, `test_open_redirect_step.py`, `test_host_header_step.py`) + updates to the 7 existing webapp suites. Suite: 1419 passing.

---

## Tools Referenced

| Tool | Language | Approach | Key Feature |
|------|----------|----------|-------------|
| **WPScan** | Ruby | Passive + aggressive + CVE DB | Industry standard, `--wp-auth` (May 2026) |
| **WPSecScan** | Python | 268 checks, 8-source CVE aggregator | Most comprehensive open source scanner |
| **WPProbe** | Go | REST API stealth + brute-force hybrid | 5k+ stealth, 10k+ brute-force plugin detection |
| **WPHunter** | Python | WPVulnerability + WPScan CVE lookup | No-API-key vulnerability scanning |
| **WP-Hijack** | Python | 10-phase pipeline, AI exploit gen | Offline (Ollama) AI workflow |

## Key URLs

- WPVulnerability.net API: https://www.wpvulnerability.com/api/
- WPScan API v3 docs: https://wpscan.com/docs/api/v3/
- WPScan v4.0.0 release: https://github.com/wpscanteam/wpscan/releases/tag/v4.0.0
- SecLists WordPress wordlists: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/CMS
