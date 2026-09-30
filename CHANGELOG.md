# Session Notes & Changelog

## Last Updated: 2026-09-30

---

## Recent Changes

### S26 - Field-report update `mundosenaiba.senaibahia.com.br`: status-code FP class, tool fixes, management-console CVE, DNS rigor (2026-09-30)

Engagement over `reports/mundosenaiba.senaibahia.com.br/UPDATE.md` (49 findings,
0 critical/high, 5 medium; openresty + Wordfence returning a blanket 403 for
unknown paths). Implemented in four phases.

**Phase 0 — small real bugs**

| Item | Change |
|------|--------|
| B1 `ServiceInventoryStep` crash | `__init__` now accepts `http=None` (the Runner always passes it), fixing `unexpected keyword argument 'http'`. |
| A5 plugin slug junk | New `utils/slugs.py` (`is_valid_slug`); `plugin`/`theme` fingerprint steps drop HTML-parse tokens like `*","`. |
| A7 cache FP | Removed `x-served-by` (custom origin header) and `x-fastly-request-id` from `CACHE_INDICATOR_HEADERS`; added `via`/`x-fastcgi-cache`. |
| A8 lockout cookie | `cookie_flags` ignores WAF lockout/consent/analytics/CDN cookies (`wpdef_lockout_*`, `_ga`, `cookieyes`, `cf_clearance`, ...); only session/auth cookies are flagged. |
| B2 WPScan 403 abort | `WpscanStep` retries once with `--force` when the run aborts (`scan_aborted` / rc 4). |
| B10 silent vuln-DB failure | `VulnDB` tracks `unavailable`/`last_error` (network/5xx); the three `steps/vuln/*_vuln_step.py` emit an operational `info` finding instead of a false "No CVEs". New `steps/vuln/vuln_common.py`. |
| C2 duplicate SPF | `dns_step` no longer emits SPF findings (owned by `email_security`). |
| A6 REST route index | `rest_hardening` skips namespace route-index 200s (`/wp-json/<ns>/v1/`), which are not unauthenticated data. |

**Phase 1 — status-code false positives**

| Item | Change |
|------|--------|
| A1/A2 double prefix | `normalize_wp_slugs()` strips `wp-content/<dir>/`, `<dir>/`, query/fragment and trailing slashes from every wordlist entry (SecLists lists are already full paths) in both brute-force steps. |
| A3/A4/A10 catch-all | `Soft404Detector` gains `scope_prefix` (canaries inside e.g. `wp-content/plugins/`) and **status-level suppression**: when a scope canary returns 401/403, every 401/403 at that scope is treated as a blanket denial and never reported as "exists/protected" (Wordfence returns dynamic 403 bodies that defeat content matching). Wired into plugin/theme brute-force, `admin_surface`, `uploads_listing`; `ScanContext.soft404_detector(scope_prefix=...)`. |
| C3 report size | `utils/limits.py` (`cap_list`/`cap_lines`) + `WP_RAW_LIST_CAP` truncate list findings; Markdown/HTML/PDF gained a `max_findings` render cap (severity-prioritized, with an omission note); `PdfFormatter` runs `pisa.CreatePDF` on a daemon thread with a wall-clock timeout. CLI `--report-render-limit`/`--report-timeout`; JSON/SARIF stay complete. |

**Phase 2 — tool-execution gaps**

| Item | Change |
|------|--------|
| B4 ffuf SNI | `sni_hostname()` + `-sni <host>` when pinned (ffuf derives SNI from the URL host = the IP). A 0-result run with `Errors: N` now emits a loud "FFUF requests failed" finding. |
| B3 OpenDoor TTY | `AsyncToolRunner.run(..., use_pty=True)` allocates a PTY (local + async paths); `OpenDoorStep` uses it, fixing the `stty: Inappropriate ioctl` crash. |
| B7 spider 0 pages | `spider` records why the start URL was not retrievable (HTTP status / exception) and emits an operational finding instead of a silent "0 pages". |
| A9/C5 jQuery FP | `js_library` only scans the first 4 KB for a banner and only trusts it when the asset URL matches the library's file pattern (a bundled jQuery banner in an unrelated script no longer reports). |
| C1 internal-IP leak | `restore_public_host()` + `BaseHttpStep.public_url()` rewrite pinned IPs back to the public hostname across all `final_url` call sites (`wp_cron`, `readme`, `license`, secrets steps, sourcemap, author_id, rate_limit, default_credentials, spider). |

**Phase 3 — management-console discovery (B11)**

New `steps/webapp/management_console_step.py` + `wordlists/webapp/management_consoles.json` (Nginx Proxy Manager, Portainer, Grafana, Jenkins, Kibana, Jupyter). Probes signatures, extracts versions (body/header), and matches advisories via `utils.version.cve_applies` (e.g. NPM ≤ 2.15.1 → CVE-2026-40519 / CVE-2026-93964, `high`). Also probes HTTP ports discovered by nmap (`ctx["services"]`), so a console on port 81 is found. Registered in `WebappModule`; `WP_MGMT_CONSOLE_PROBE`.

**Phase 4 — DNS evidence rigor (C6)**

New `utils/dns_query.py` (`build_dig_command`, `parse_dig_output`, `organizational_domain`). `dig` is run without `+short` so the status/ANSWER header is parsed: "absent" (NOERROR + 0 answers, or NXDOMAIN) is distinguished from a lookup failure (SERVFAIL/REFUSED/timeout). `email_security` falls back to the zone's authoritative nameservers and only reports "No SPF/DMARC" for a proven absence; a failed lookup becomes an operational note. DMARC is evaluated at the organizational domain (subdomains inherit via `sp=`), while SPF is not inherited. `dns_step` records `dns_status`/`answer_count` in each record finding.

Tests: new `test_slugs.py`, `test_limits.py`, `test_dns_query.py`,
`test_management_console.py` plus cases across soft-404, brute-force, cookies,
cache, WPScan, VulnDB, REST, admin-surface, service-inventory, report/PDF, DNS,
email-security, spider, JS-library, target-net, FFUF and tool-runner. Suite
**1992 passing**; ruff clean on all new/changed lines.

### S25 - Field-report follow-up: dig in image, OSINT timeout, breaker resume, rate-limit FP, HTTP evidence, Keycloak, SPA param discovery (2026-09-29)

Second pass over `reports/verifai.senaicimatec.com.br/UPDATE.md` (new items
A8-A11, B4, C5 + a C1 update).

| Item | Change |
|------|--------|
| A8 `dig` missing | `Dockerfile` always installs `dnsutils` (provides `dig`) alongside `whois`, and echoes `dig -v` in the tool-version block, so the passive DNS/email-security steps actually run. |
| A9 crt.sh stalls | `CrtShStep` request timeout 60s → 10s, retry delay 5s → 1s, and a `MAX_FAILURES` cap that stops trying further patterns; when OSINT fails it now emits an `info` operational finding instead of silently returning nothing. New `WP_PASSIVE_OSINT` (default true) opts out of public OSINT (crt.sh + wayback). |
| A10 breaker aborts module | `HttpClient.reset_unreachable()`; the `Runner` now resets the circuit breaker once per module/tier to retry a transient blip, records the steps it still had to skip, and logs the module as **INCOMPLETE** (also appended to `Report.errors`) instead of "completed". |
| A11 rate-limit FP | `RateLimitStep` no longer follows redirects for the baseline/burst, skips 3xx and non-credential-processing responses (`_looks_like_login`: 401/403, JSON error, or a password field), and records `final_url`/`content_type`/`snippet`. A 301→SPA-shell can no longer produce "No rate limiting observed". |
| B4 no HTTP evidence | `RawArtifactWriter.persist_evidence()` writes `<step>.requests.jsonl` + `.meta.json` (`type: http-evidence`); `ActiveHttpStep` records every probe (method/url/status/length/content-type/snippet/redactable payload) and persists them on `run()` completion via an `__init_subclass__` wrapper. |
| C1 Keycloak | `tech_fingerprint` adds a Keycloak body signature **and** probes `/auth/realms/master` + `/realms/master` for realm-discovery JSON (`public_key`/`token-service`) so an unlinked IdP is surfaced. |
| C5 SPA params | `ActiveHttpStep.discover_params()` now also parses same-origin JS bundles for API paths + parameter names (`WP_ACTIVE_JS_MAX`, default 5) and honours operator-supplied `WP_ACTIVE_PARAMS` (`path:param` pairs), so the injection family can run on client-rendered SPAs. |

Tests: +15 (crt.sh OSINT gating/failure cap, breaker reset + resume, rate-limit
redirect/non-credential skips, HTTP evidence persistence, Keycloak detection,
SPA param discovery). Suite **1917 passing**; ruff clean on all new/changed
lines (pre-existing `E501` UA strings in `core/http_client.py` and a few
pre-existing `crt_sh`/`wayback` long lines remain).

### S24 - Field-report update: split-horizon pinning, pre-flight retries, combined raw output, WP-gated tool steps (2026-09-29)

Driven by the `verifai.senaicimatec.com.br` engagement (source notes were
`reports/verifai.senaicimatec.com.br/UPDATE.md`). Every item below is grounded
in that run's evidence.

**Defects (Section A)**

| Item | Change |
|------|--------|
| A1 split-horizon | New `--target-ip <ip>` / `--resolve host:ip` (config `WP_TARGET_IP` / `WP_DNS_RESOLVE`). `Target.connect_ip` + `core/pinned_transport.py` (httpx connects to the IP while keeping the real `Host` header and `sni_hostname`, and follows redirects through the transport). Tool steps pin too: nmap scans the IP; ffuf/nuclei add `-H "Host: ..."`; opendoor adds `--header "Host: ..."`. Reachability probes the pinned IP. Helpers in `utils/target_net.py`; `--target-ip` warns on a multi-target run. |
| A2 pre-flight abort | `core/reachability.py` retries transient failures with exponential backoff; permanent failures (NXDOMAIN, cert verification) are not retried. New `WP_RETRIES` (2), `WP_RETRY_DELAY` (1.0), CLI `--retries`/`--retry-delay`; result carries `attempts`/`permanent`. |
| A3 compose | `docker-compose.yml` `env_file` is now `{path: .env, required: false}` so `docker compose up` works without a `.env`. |
| A4 raw overwrite | `RawArtifactWriter` archives the previous `<step>.*` into `<raw>/history/<original-run-id>/` before overwriting (`WP_RAW_HISTORY`, default on). |
| A5 opendoor `--host` | **Investigated, no change** — verified against the pinned OpenDoor 5.18.0 `--help` and its source: `--host` accepts a full URL and parses the scheme from it; `--scheme` only applies to `--raw-request`. The proposed bare-host + `--scheme` change would default to `http://` and regress. Documented + regression test. |
| A6 WP-only tool steps | `FfufWpStep` (`wp_only=True`, `requires=("wordpress",)`) and OpenDoor `wp_paths` are skipped on non-WordPress targets via the existing `utils.wordpress_detect.is_wordpress` gate. |
| A7 ffuf wordlists | Per-step overrides `WP_FFUF_DIRECTORY_WORDLIST` / `WP_FFUF_FILES_WORDLIST` / `WP_FFUF_WP_WORDLIST`; the Dockerfile bakes SecLists `raft-medium-directories.txt` / `raft-medium-files.txt` into `wordlists/external/ffuf/`. Wordlist name/path/entry-count are logged and recorded in the finding `raw` and `.meta.json`. |

**Observability (Section B)** — `RawArtifactWriter.persist()` now always writes
`<step>.output`, one combined proof-of-execution record (header with tool
version/returncode/timings, `########## command/stdout/stderr` sections with
`(empty)` markers, and a native section only when it differs from stdout). The
native file is written even when empty (`native_name is not None`), and
`.meta.json` gains `stdout_bytes`/`stderr_bytes`/`native`/`run_id` plus any
`extra` metadata. `base/step.py:_persist_raw` forwards `extra`.

**Detections / architecture (Section C/D)** — `tech_fingerprint` gains
Angular (`data-beasties-container`, `main-*.js`/`chunk-*.js`), Tailwind v4
(`@layer theme,base,components,utilities`, `--tw-*`) and server banners
(nginx/Apache/IIS/Caddy/LiteSpeed/Tomcat/gunicorn/Werkzeug), plus a
machine-readable `raw["technologies"]` inventory finding. `ScanContext` gains a
first-class soft-404 capability (`soft404_detector()` memoized per base URL +
`enumeration_unreliable`/`enumeration_is_unreliable`). A new
`ServiceInventoryStep` (tools module, `requires=("services",)`) consolidates
nmap banner data (published by both nmap steps) into one normalized inventory
finding — the basis for the report's service table and the future infra-CVE
step (C3, deferred).

Tests: +40 (reachability retries/permanent/pinning, pinned transport,
`target_net`, combined raw output + history archive, WP gating, pinned Host
headers, tech signatures, soft-404 capability, service inventory). Suite **1902
passing**; ruff clean on all new/changed files (pre-existing `E501` UA strings
in `core/http_client.py` remain).

### S23 - Severity audit + `Finding.confidence` (2026-09-29)

Full, code-grounded audit of the severity of every finding across all 96 steps.
Calibrated ratings to real-world impact (CVSS-style), fixed the detection bugs
that made several severities indefensible, and added a `confidence` dimension so
heuristics no longer share a band with confirmed exploitation.

**Correctness fixes**

| File | Change |
|------|--------|
| `steps/infrastructure/tls_step.py` | **Bug:** `check_hostname=True` then `verify_mode=CERT_NONE` raised `ValueError` (swallowed) so the step emitted **zero findings in production**; now validates the cert first (emits `high` for expired/hostname-mismatch, `medium` for untrusted) and retries unverified to still report version/cipher. |
| `steps/tools/nuclei_step.py` | `unknown`/missing severity → `low` (+`raw["severity_unknown"]`); new "Nuclei Output Unparseable" `medium` finding; network-error trigger no longer discards real findings; `matched-at`/`template-id` reads fixed. |
| `steps/xmlrpc/xmlrpc_creds_step.py` | Parses `<isAdmin>` (bare + struct forms); confirmed admin credentials → `critical`; admin logins recorded in `raw`. |
| `steps/vuln/{core,plugin,theme}_vuln_step.py`, `core/vulndb.py`, `utils/version.py` (new) | CVEs are now filtered by `fixed_in` vs the detected version; a real CVE is never `info`; applicability unknown → capped at `medium` with `confidence="low"`. |
| `steps/tools/wpscan_step.py` | Config-backup detection is shape-based (`wp-config-sample.php` no longer flagged) → `high`; core/plugin/theme vuln severity is **type-driven** (SQLi/RCE→critical, XSS→medium); users → `low`/`medium`; plugin confidence gates severity; `interesting_findings` (debug_log/environment/full_path_disclosure/directory_listing/upload_directory_listing) now parsed. |
| `steps/ssrf/pingback_ssrf_step.py` | Was a broken duplicate (inverted `faultCode`); now delegates to `XmlrpcSsrfStep` and is no longer registered in `SsrfModule` (no double-counting). |
| `steps/tools/nmap_step.py`, `opendoor_step.py` | No more silent parse failures; OpenDoor escalates sensitive-looking paths to `high`/`confidence="low"`. |

**Severity recalibration (highlights)** — downgrades: API docs/GraphQL introspection → `low`; admin login pages/consoles → `low`; CORS reflection without credentials → `low`; CSP `unsafe-inline`/`unsafe-eval` → `low`; XFO `NONE` → `low`; cookie flags session-gated (missing-SameSite on session cookies → `medium`, `SameSite=None` w/o Secure → `low`); postMessage-`*`/localStorage → `low`; open redirect → `medium`; JWT `alg:none`/empty sig → `high`; source_review AWS key-ID/GitHub tokens → `high`; request smuggling/race condition → `low`; wayback/spider/pages_ip_leak → `low`/`info`. Upgrades: SQLi/SSTI → `critical`; subdomain/user-enumeration family unified; sensitive DB dumps/service-accounts → `critical`; risky ports → `medium`; XML-RPC `isAdmin` → `critical`. Tool operational failures unified to `info` (+`raw["operational"]`), except ffuf "ran but produced nothing usable" → `low`.

**New model**

| File | Change |
|------|--------|
| `core/finding.py` | **ADDED** `confidence: Literal["low","medium","high"] = "high"` (excluded from dedup; included in `to_dict()`/`to_sarif()`). |
| `base/step.py`, `steps/active/base_active.py`, `steps/webapp/websocket_step.py` | `_add_finding`/`add_finding` accept a `confidence` kwarg. |
| `utils/report.py` | Markdown/HTML/PDF show the confidence; SARIF rules carry `properties.confidence`. |
| `tests/conftest.py` | `mock_http` now also exposes an async `post`. |

Raw `.cmd` artifacts are now rendered as a shell command wrapped at 100 columns
with line continuations (`utils/raw_output.py:format_command`), so they are
readable and pasteable without horizontal overflow (previously one argv per
line). Verified live against WordPress + Juice Shop in Docker (per-host report
folders + `raw/`); surfaced and fixed two live regressions along the way
(OpenDoor per-item severity leak, WPScan `scan_aborted` now reported).
Full suite **1846 passing** (was 1804 before this work), no new ruff violations.

### S22 - Step relations: shared ScanContext + dependency-aware parallel execution (2026-09-28)

Steps can now share data through a per-target context and run as a
dependency-aware graph inside each risk tier. The headline result: on a local
target the `webapp` profile's ~30 homepage readers collapse to **1 HTTP
request, 10 duplicates avoided** (both sequential and parallel modes).
Full suite **1804 passing**, ruff clean on new/changed core files.

| File | Change | Notes |
|------|--------|-------|
| `core/scan_context.py` | **NEW** | `ScanContext` (per-target blackboard: `set/get/has/wait/mark_missing`, `stats`) + `WebArtifacts` (lazy, memoized, **single-flight** `homepage()` / `wp_json()` / `robots()` / `get()` / `wordpress()`). Only anonymous GET/HEAD is cached; `Authorization`/`Cookie` callers bypass it; `invalidate()` clears after a login. `LAZY_ARTIFACTS` lists self-resolving keys. |
| `base/step.py` | **ADDED** | `requires` / `provides` / `depends_on` class attributes (default empty) and a `ctx` property: uses the Runner-injected shared context, else a `http.scan_context` attached by the Runner, else a lazily-created private context so standalone/test usage keeps working unchanged. |
| `base/scheduler.py` | **NEW** | `build_graph(entries)` resolves `provides`→`requires` and explicit `depends_on` edges, warns on unknown/duplicate producers and missing keys, and breaks cycles (Kahn). `run_graph()` launches ready nodes concurrently and releases dependents only after a producer **completes**; failures are swallowed so the graph cannot deadlock. |
| `base/runner.py` | **WIRED** | Creates one `ScanContext` per target (reused across tiers) and attaches it to the `HttpClient`. New `_run_tier_parallel()` builds a tier-wide DAG; `_run_step_node()` instantiates steps with the shared context and isolates errors. `SERIAL_MODULES = {"active"}` keeps active steps on a `Semaphore(1)`. `_parallel_enabled()` uses an identity check so MagicMock configs don't enable it. Logs "N request(s) made, M duplicate request(s) avoided" at scan end. `run_module()` (sequential path) is unchanged. |
| `config.py`, `main.py` | **ADDED** | `parallel_steps` (`WP_PARALLEL_STEPS`, default `false`) and `step_concurrency` (`WP_STEP_CONCURRENCY`, `0` = use `--threads`); CLI `--parallel-steps/--no-parallel-steps` and `--step-concurrency`. |
| `utils/wordpress_detect.py` | **WIRED** | `is_wordpress()` prefers `http.scan_context.web.wordpress()` (shared `/wp-json/` + homepage responses) via an `isinstance(ScanContext)` guard, falling back to the legacy per-process cache when no context is attached. |
| 30 steps (infrastructure/fingerprint/webapp/discovery) | **MIGRATED** | Homepage reads now go through `ctx.web.homepage()`: `headers`, `hosting`, `waf`, `php_version`, `wp_version`, `plugin`, `theme`, `scripts`, `versioned_assets`, `plugin_version` (incl. `_fetch_version`), `tech_fingerprint`, `header_quality`, `cookie_flags`, `csp_audit`, `js_library`, `sourcemap`, `cache`, `client_side_audit`, `jwt_audit`, `websocket`, `form_security`, `source_review`, `woocommerce`. |
| 12 WP-gated steps | **ANNOTATED** | `requires = ("wordpress",)` on `login_bruteforce`, `rest_hardening`, `rest_surface`, `app_passwords`, `xmlrpc_detect`, `wp_cron`, `sitemap`, `plugin_bruteforce`, `theme_bruteforce`, `woocommerce`, `oembed_proxy`, `author_id` (self-resolving lazy artifact). |
| `tests/test_scan_context.py`, `tests/test_scheduler.py` | **NEW** | 25 tests: memoization, single-flight under concurrency, auth bypass, invalidate, WordPress detection, `wait`/`mark_missing`/timeout; graph wiring, lazy artifacts, warnings, cycle breaking, dependency ordering, concurrent independent nodes, skip, failure isolation. `tests/test_runner.py` gained a parallel-mode ordering test. |
| `tests/conftest.py` | **CHANGED** | `mock_http` now also exposes an async `request`; tests for migrated steps were updated from `mock_http.get` to `mock_http.request`. Homepage canonical URL is `<target>/` so existing `"/"` responders keep matching. |

### S21 - Multi-target runs + per-target output folders (2026-09-25)

| File | Change | Notes |
|------|--------|-------|
| `main.py` | **ADDED** | `-t/--target` is now repeatable and comma-separated; new `--targets-file` (one target per line, `#` comments ignored); `_parse_targets` de-dupes while preserving order and fails fast when no target is supplied. |
| `main.py` | **ADDED** | Each target is scanned in its own `reports/<host>/` folder (host only, ports dropped) containing all report formats and that target's `raw/` tool output. `safe_target_dir` sanitizes the folder name. Target loop rebuilds modules per target, skips invalid/unreachable targets without aborting the batch, and prints a batch summary table (hidden with `-q`). Exit 1 only when no target succeeded. |
| `main.py` | **CHANGED** | `_save_report(report, config, report_file)` now derives its destination from `config.output_dir` (the per-target folder) instead of a passed-in path. |
| `config.py` | **ADDED** | `organize_by_target` (`WP_ORGANIZE_BY_TARGET`, default `true`); `--flat-output` sets it false for the legacy flat layout. `--raw-output`, when set, is treated as a base dir and gets the per-target subfolder appended. |
| `tests/test_main_cli.py` | **ADDED** | `_parse_targets` / `safe_target_dir` unit tests + multi-target and `--flat-output` folder-layout integration tests. Full suite **1777 passing**, ruff clean on changed files; smoke-tested two local targets (`127.0.0.1`, `localhost`) → one folder each with a JSON report. |

### S20 - Field-report defect sweep: FFUF/TLS/formats/Nuclei + raw tool output (2026-09-25)

Source: authorized engagement against an intranet WordPress/PHP target (see the
now-removed `UPDATE.md`). Fixes span three phases; full suite **1762 passing**,
ruff clean on changed code, verified with a rebuilt `INSTALL_TOOLS=true` image.

| File | Change | Notes |
|------|--------|-------|
| `steps/tools/ffuf_base.py` | **NEW** | Shared `FfufBaseStep`: drops the non-existent `-ik` flag, adds `-ic`, separates `-t` (threads) from `-rate` (req/s) and the per-request `-timeout`, adds `min_version = "2.0.0"`, and **fails loudly** — non-zero exit or non-JSON output emits a `high` finding instead of "0 results". |
| `steps/tools/ffuf_directory_step.py`, `ffuf_files_step.py`, `ffuf_wp_step.py` | **SIMPLIFIED** | Now thin subclasses of `FfufBaseStep` (wordlist URL suffix + finding wording only). |
| `Dockerfile` | **FIXED** | Always installs/refreshes `ca-certificates openssl whois` + `update-ca-certificates`, upgrades `certifi`, and adds a build-time TLS smoke test against a known-good public chain. Creates a writable `/app/reports` owned by `recon`, sets `ENV HOME=/home/recon`, makes the nuclei template dir explicit (`-ud /home/recon/nuclei-templates`), and logs installed tool versions. |
| `config.py`, `main.py` | **FIXED** | Report `output_format` accepts a **comma-separated list** (`-f json,markdown,html` / `all`); `_parse_formats` validates and fails fast on unknown names instead of silently writing nothing. Added `ffuf_threads`, `ffuf_http_timeout`, `nuclei_rate_limit`, and raw-output fields. |
| `steps/tools/nuclei_step.py` | **FIXED** | Honors `WP_NUCLEI_THREADS` (previously shadowed by a `threads=100` default), adds `-rl`, polite defaults 25/150, and new `--nuclei-concurrency` / `--nuclei-rate-limit` flags. Removed the incorrect "--insecure unsupported" warning (nuclei skips cert validation by default; there is no such flag). |
| `steps/infrastructure/ports_step.py` | **FIXED** | The SSRF blocklist no longer rejects the authorized target's own host (it blocked all 21 ports, scanning 0). Emits an `info` finding when the scan cannot run. |
| `steps/webapp/header_quality_step.py` | **FIXED** | `parse_hsts` splits on both `,` and `;`, handles quoted values and duplicated headers, and takes the effective (max) `max-age` so `max-age=31536000` is no longer mis-parsed as 0. |
| `steps/webapp/source_review_step.py`, `client_side_audit_step.py` | **HARDENED** | Minified/vendor bundles downgrade hardcoded-password matches to `low` confidence (recorded in `raw`); placeholder email deny-list; DOM-XSS co-occurrence downgraded to a `low` heuristic that additionally requires source/sink proximity and is skipped for minified code. |
| `utils/raw_output.py` | **NEW** | `RawArtifactWriter` + `--save-raw/--no-save-raw`, `--raw-output`, `--raw-max-bytes`, `--raw-no-redact`. Persists `<step>.stdout/.stderr/.cmd/.meta.json` plus native formats (nmap XML, nuclei jsonl, ffuf/wpscan JSON, `opendoor/` reports dir). Redacted by default, size-capped, best-effort (never aborts a scan). |
| `base/step.py`, `steps/tools/{nuclei,wpscan,opendoor}_step.py` | **WIRED** | `BaseToolStep._persist_raw()` is called from the base `run()` and every overriding `run()`; timeouts persist the exact command too. |
| `utils/tool_version_checker.py` | **FIXED** | Version regexes updated for current output (`ffuf version:`, `Nuclei Engine Version: v`, `Current Version:`, `Opendoor scanner:`), `-V` fallback for ffuf, and an unparseable version no longer disables a step. |
| `modules/__init__.py` | **ADDED** | `web-generic` profile alias (same modules as `web`). |
| `main.py` | **ADDED** | Pre-flight logs the DNS-resolved IP and hints at `--add-host` for split-horizon DNS. |

**Verification (rebuilt `wp-recon-tool:latest`, `INSTALL_TOOLS=true`)**: whois
5.6.3, ffuf 2.3.0, nuclei 3.11.1, nmap 7.95 present; `urllib` TLS check passes
without `--insecure`; end-to-end scan against a local HTTP target wrote
`recon_*.json` + `recon_*.md` (`-f json,markdown`) and `raw/` artifacts
(`ffuf_*.cmd` without `-ik`, `nmap-ports.xml`, `meta.json` with real tool
versions); ports step logged `Scanned 21 ports, blocked 0`.

### S19 - Cross-platform PDF (xhtml2pdf) + HTML/PDF report redesign (2026-09-22)
| File | Change | Notes |
|------|--------|-------|
| `utils/report.py` | **REWRITTEN** | `PdfFormatter` now uses pure-Python **xhtml2pdf** (`pisa.CreatePDF` into `BytesIO`, `result.err` check, friendly `ImportError`) instead of WeasyPrint, whose native Pango/Cairo imports raise `OSError` on every OS unless system libraries are installed. Renders a dedicated print template (`@page` + static footer frame with `<pdf:pagenumber>`/`<pdf:pagecount>`, severity ledger bar, Scope & Execution facts table, numbered findings, no side-stripe borders). |
| `utils/report.py` | **REDESIGNED** | `HtmlFormatter` report rebuilt: removed the five hero-metric cards, the decorative donut SVG, the SaaS gradient masthead, and the 4px colored side-stripe borders on findings. Replaced with a flat masthead + health gauge, a proportional **Severity Ledger** bar with legend, a Scope & Execution facts grid, and globally numbered findings with hairline separators and severity tags. |
| `pyproject.toml`, `requirements.txt` | **CHANGED** | `weasyprint` → `xhtml2pdf>=0.2.17` (optional `[pdf]` extra and dev requirements). |
| `Dockerfile` | **SIMPLIFIED** | Removed the WeasyPrint native-library `apt` block (`libpango*`, `libcairo2`, `libgdk-pixbuf-2.0-0`, `libffi-dev`); PDF is pure-Python in-image. |
| `main.py` | **UPDATED** | PDF `ImportError` warning now names xhtml2pdf. |
| `tests/test_pdf_formatter.py` | **REWRITTEN** | Missing-dependency `ImportError`, mocked `xhtml2pdf.pisa` returns PDF bytes, UTF-8 encoding pass-through, render-error `RuntimeError`, `save` writes bytes. |
| `tests/test_report_utils.py` | **UPDATED** | `mock_weasyprint` fixture → `mock_xhtml2pdf`; PDF tests updated. |
| `tests/test_html_formatter.py` | **UPDATED** | Assertions moved to the new markup contract (`wrap`, Severity Ledger, numbered findings, `.evidence`, `.errors`, title-case severities). |
| Verification | — | Full suite **1727 passing** (the 4 pre-existing WeasyPrint/pango env failures are gone); ruff clean on changed files (two pre-existing `report.py` violations remain: `I001`, long `_esc` line). Generated real output: HTML before/after screenshots and a 4-page PDF (valid `%PDF` header, `Page 1 of 4` footer, no xhtml2pdf warnings). |

### S18 - Nmap output-format fix found by Docker end-to-end run (2026-09-12)
| File | Change | Notes |
|------|--------|-------|
| `steps/tools/nmap_step.py` | **FIXED** | Both steps invoked `nmap -oJ -`, which is not a valid nmap flag (nmap only supports `-oN`/`-oX`/`-oG`/`-oA`). Real nmap interpreted `-oJ` as normal output to a file named `J`, so direct port/script scans silently failed (`Failed to open normal output file J`). Switched to `-oX -` (XML to stdout) and replaced the fabricated JSON parser (`nmap-run.host[].ports[]`) with `parse_nmap_xml`, which parses real `<nmaprun>` XML (ports, `state`, `service` attributes, nested NSE `<script>`/`<table>`/`<elem>` nodes, and `vulns` tables) into the internal schema. `NmapScriptScanStep` now also passes `-sV` because default NSE scripts are selected from detected services (`-sC` alone produced no output on non-standard ports). |
| `tests/test_nmap_step.py` | **REWRITTEN** | Fixtures now use real nmap 7.95 `-oX` XML (including DOCTYPE/prologue and NSE script tables) instead of the fabricated JSON, and assert `-oX`/`-sV` in the built command. |
| `docs/MODULES.md`, `docs/NEXT_STEPS.md`, `docs/REFERENCES.md`, `AGENTS.md` | **UPDATED** | Document `-oX` XML output and `-sV -sC` for the script scan. |

**Verification (Docker, `INSTALL_TOOLS=true`)**: `NmapPortScanStep` reports real open ports/service versions (`3000/tcp ppp`, `8099/tcp http 2.4.68`); `NmapScriptScanStep` now emits NSE output (`http-title`). Full suite 1719 passing.

### S17 - Docker tool/wordlist build args + wordlist override plumbing + OpenDoor 5.x fix (2026-09-11)
| File | Change | Notes |
|------|--------|-------|
| `Dockerfile` | **REWRITTEN** | Base bumped to `python:3.13-slim-trixie` (Ruby 3.3 for WPScan, Python >=3.12 for OpenDoor); builder now copies the full source (previously only `pyproject.toml`, producing an empty wheel); fixed `pip install` (`--find-links` instead of an invalid `*.whl[pdf]` glob); trixie PDF packages (`libgdk-pixbuf-2.0-0`, `libpangoft2-1.0-0`, `libharfbuzz-subset0`); `PYTHONPATH=/app` so wordlist paths resolve in-image |
| `Dockerfile` | **ADDED** | `INSTALL_TOOLS=false` build arg — installs nmap, ruby+WPScan gem, ffuf v2.3.0, nuclei v3.11.1 (GitHub releases via `TARGETARCH`), opendoor 5.18.0 via pipx; bakes WPScan DB + nuclei templates |
| `Dockerfile` | **ADDED** | `INSTALL_RECOMMENDED_WORDLISTS=true` build arg — downloads SecLists plugin/theme lists to `wordlists/external/plugins/` (loader prefers them; `~/.config` overrides still win); `SECLISTS_*_URL` and tool version overrides |
| `docker-compose.yml` | **UPDATED** | `build.args` for `INSTALL_TOOLS`, `INSTALL_RECOMMENDED_WORDLISTS`, `FFUF_VERSION`, `NUCLEI_VERSION`, `WPSCAN_VERSION`, `OPENDOOR_VERSION` |
| `config.py` | **ADDED** | Wordlist override fields (`wordlist`, `login_wordlist`, `plugin_wordlist`, `theme_wordlist`, `source_assets`, `api_paths`, `admin_paths`, `wp_config_backups`, `env_files`, `security_headers`, `common_ports`, `waf_signatures`, `xmlrpc_dangerous_methods`, `login_pages`) and `opendoor_delay`; `opendoor_rate_limit` now documented as thread count |
| `base/dependencies.py` | **FIXED** | `resolve_wordlist_or_fallback` now reads `ScanConfig` attributes (previously only a nonexistent `config.keys` dict, so every `WP_*_WORDLIST` env override was dead); added `config_str` / `config_int` / `config_float` helpers with type guards |
| `steps/discovery/plugin_bruteforce_step.py`, `theme_bruteforce_step.py` | **FIXED** | `config_key` wired to `plugin_wordlist` / `theme_wordlist`; log hints now reference real env vars |
| `steps/tools/ffuf_directory_step.py`, `ffuf_files_step.py`, `ffuf_wp_step.py` | **FIXED** | Read `ffuf_wordlist` / `ffuf_timeout` / `ffuf_rate_limit` from config and resolve wordlists via `get_wordlist_path()` chain |
| `steps/tools/opendoor_step.py` | **REWRITTEN** | Modern OpenDoor 5.x CLI (`--host --scan directories --method GET --wordlist --threads --timeout --auto-calibrate --reports json --reports-dir`); reads the emitted JSON report (`report_items` + legacy `items`); mode→wordlist mapping; config/env wiring for wordlist, timeout, threads, delay; explicit target ports are split into `--port` (OpenDoor rejects `host:port` in `--host`) |
| `pyproject.toml`, `steps/__init__.py` | **FIXED** | Build backend was invalid (`setuptools.backends._legacy:_Backend`) → `setuptools.build_meta` with explicit `py-modules`/`packages.find`; added missing `steps/__init__.py` so the wheel includes the step tree |
| `tests/test_ffuf_opendoor.py`, `tests/test_dependencies.py` | **UPDATED** | 23 tests — OpenDoor CLI/report schema (new + legacy), config overrides, unknown-mode fallback, `--port` split, mocked `run()` report read; config attribute lookup + helper units |
| `README.md`, `wordlists/README.md`, `.env.example` | **UPDATED** | Docker build-arg table, wordlist override (env + mount) docs, per-step env var table, fixed broken SecLists URLs |
| Verification | — | Full suite 1718 passing (4 pre-existing weasyprint/pango env failures); ruff clean on changed files; Docker default + `INSTALL_TOOLS=true` builds verified (nmap 7.95, ffuf 2.3.0, nuclei v3.11.1 + baked templates, wpscan, opendoor 5.18.0); live `OpenDoorStep.run()` in-container test found 2/2 seeded paths |

### S16 - Webapp Research Expansion: 5 new steps + 6 refinements (2026-09-08)
| File | Change | Notes |
|------|--------|-------|
| `steps/webapp/csp_audit_step.py` | **NEW** | `CspAuditStep` (WSTG 4.2.12) — parses a present CSP; flags `unsafe-inline`/`unsafe-eval`/unsafe hashes and missing `object-src 'none'`/`base-uri`/`form-action`/`script-src`/violation reporting |
| `steps/webapp/api_surface_step.py` | **NEW** | `ApiSurfaceStep` (WSTG 4.12.1/4.12.99/4.1.4) — robots.txt + sitemap discovery, OpenAPI/Swagger detection with endpoint/sensitive-path counts, GraphQL introspection probe, API path fuzzing |
| `steps/webapp/admin_surface_step.py` | **NEW** | `AdminSurfaceStep` (WSTG 4.2.5/4.2.13) — 46 console/monitoring/debug paths; per-path severity (heapdump/actuator = high), aggregated "behind auth" finding, security.txt |
| `steps/webapp/open_redirect_step.py` | **NEW** | `OpenRedirectStep` (WSTG 4.11.4) — 16 paths × 15 redirect params with canary URLs, `follow_redirects=False`, request-capped; high on auth paths |
| `steps/webapp/host_header_step.py` | **NEW** | `HostHeaderStep` (WSTG 4.7.17) — canary `Host:`/`X-Forwarded-Host:` vs baseline: unknown vhost, body reflection, XFH reflection (cookie-domain poisoning) |
| `steps/webapp/source_review_step.py` | **UPDATED** | 9 new gitleaks-verified rules (OpenAI, Anthropic, GitLab, Notion, Telegram, Discord, Heroku, Terraform, Azure); AWS key pattern requires `secret` context; email/IP rules HTML-skipped (`_PAGE_ONLY_RULES`) |
| `steps/webapp/sourcemap_step.py` | **UPDATED** | Parses `sourceMappingURL=` comments, resolves map URLs relative to JS file; `.js.map` suffix fallback for unfetched sources |
| `steps/webapp/cookie_flags_step.py` | **UPDATED** | Captures SameSite value; `SameSite=None` without `Secure` → medium finding |
| `steps/webapp/cors_step.py` | **UPDATED** | 8 API probe paths (was 3); records `Access-Control-Allow-Methods` in raw |
| `steps/webapp/stack_trace_step.py` | **UPDATED** | Malformed-JSON POST probes to `/api` + `/graphql`; `_scan_response` refactor |
| `steps/webapp/content_leak_step.py` | **UPDATED** | BFS crawl to 2 link levels (capped `webapp_max_pages`); `http://` mixed-content detection on HTTPS pages |
| `wordlists/webapp/api_paths.txt` | **NEW** | 27 API/documentation paths for `ApiSurfaceStep` |
| `wordlists/webapp/admin_paths.txt` | **NEW** | 46 admin/console/debug paths for `AdminSurfaceStep` |
| `config.py` | **ADDED** | `webapp_open_redirect`, `webapp_redirect_max_requests`, `webapp_host_probe`, `webapp_max_api_paths`, `webapp_max_admin_paths` |
| `modules/webapp_module.py`, `steps/webapp/__init__.py` | **UPDATED** | 13 steps registered/exported |
| 5 test files | **NEW** | 57 tests (`test_csp_audit_step.py`, `test_api_surface_step.py`, `test_admin_surface_step.py`, `test_open_redirect_step.py`, `test_host_header_step.py`) |
| 7 test files | **UPDATED** | 23 new tests in existing webapp suites (source review, sourcemap, cookie flags, CORS, stack trace, content leak, module registry) |
| `README.md`, `docs/NEXT_STEPS.md`, `docs/REFERENCES.md`, `AGENTS.md`, `wordlists/README.md` | **UPDATED** | webapp expansion documentation: 13 steps, WSTG references, new config vars, new wordlists; suite 1419 passing (4 pre-existing weasyprint env failures) |

### S15 - Generic Web Security: webapp module + web profile + Nmap (2026-09-04)
| File | Change | Notes |
|------|--------|-------|
| `steps/webapp/` | **NEW** (8 steps) | Generic non-WP checks: source credential review (gitleaks-derived rules), sourcemaps, HTTP methods, cookie flags, CORS, stack traces, content leaks, header quality (OWASP WSTG-based) |
| `utils/source_discovery.py` | **NEW** | Static asset/link extraction + wordlist fuzzing + bounded same-origin fetch, shared by webapp steps |
| `modules/webapp_module.py` | **NEW** | `WebappModule` (tier 2); registered in `MODULE_REGISTRY` |
| `steps/tools/nmap_step.py` | **NEW** | `NmapPortScanStep` (`-sT -sV --top-ports`) + `NmapScriptScanStep` (`-sC`), `-oJ` JSON, min version 7.92 |
| `wordlists/webapp/assets.txt` | **NEW** | ~44 common asset paths for source discovery fuzzing |
| `config.py` | **ADDED** | Nmap (5) + source scan (5) config fields |
| `modules/__init__.py` | **UPDATED** | `webapp` in registry + tier 2; new `web` profile |
| `modules/tools_module.py` | **UPDATED** | Nmap steps registered on `--nmap` / `--nmap-scripts` |
| `main.py` | **UPDATED** | `--nmap`, `--nmap-scripts`, `--nmap-top-ports`, `--nmap-ports`, `--nmap-timeout` |
| `utils/tool_version_checker.py` | **UPDATED** | nmap version pattern |
| 11 test files | **NEW** | 139 tests; suite 1339 passing (4 pre-existing weasyprint env failures) |
| `README.md`, `docs/MODULES.md`, `docs/ARCHITECTURE.md`, `docs/CODE.md`, `docs/NEXT_STEPS.md`, `docs/REFERENCES.md`, `AGENTS.md`, `.env.example`, `wordlists/README.md` | **UPDATED** | webapp/nmap/web-profile documentation + external references |

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
