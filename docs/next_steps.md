# Next Steps — WordPress Reconnaissance Tool

**Last Updated:** 2026-07-08  
**Current Branch:** `main`  
**HEAD:** `c646dd3` — Plugin/Theme brute-force — response-code oracle with fallback wordlists

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

**Current state:** 11 modules, 51 steps, 143 tests passing (1 pre-existing warning).

---

## Tier 1 — High Impact

### 1. CVE Correlation (Vulnerability Lookup)

**Why:** The tool enumerates plugin/theme/core versions but does not map them to known CVEs. Every major scanner (WPScan, WPSecScan, WPProbe, WPHunter) does this — without it, version numbers are data without findings.

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

### 3. Inactive Plugin File Accessibility Check

**Why:** The authenticated `WpJsonPluginsStep` (commit `4571726`) already lists inactive plugins. The next step checks whether their files are still accessible on disk — they often are, even when deactivated. Accessible inactive plugins can still be exploited.

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

## Tier 2 — Moderate Impact

### 4. Login Brute-Force Step

**Why:** Standard WordPress attack vector. The tool already has credential wordlists and `XmlrpcCredsStep` for XML-RPC brute-force, but no dedicated `wp-login.php` form brute-force step.

| File | Action | Notes |
|------|--------|-------|
| `steps/access/login_bruteforce_step.py` | **NEW** | Bypass wp-login.php with credential pairs |
| `modules/access_module.py` | **MODIFY** | Register new step |

**Implementation:**
- Uses `resolve_credentials_with_fallback()` (already built in commit `c1ba72b`)
- Probes `POST /wp-login.php` with `log={user}&pwd={pass}&wp-submit=Log+In`
- Detects success vs failure: redirect to `/wp-admin/` = success, back to login page with error = failure
- Uses existing `RetryLimiter` for rate-limit awareness
- Built-in default credentials from `credentials/common_wp.txt` (commit `c1ba72b`)

---

### 5. Cookie-Based Admin Session

**Why:** Application Passwords (commit `4571726`) only work for REST API (`/wp-json/`). The WordPress admin area (`/wp-admin/`) requires cookie-based auth. This unlocks additional attack surface.

**Endpoints unlocked by cookie auth:**
- `/wp-admin/site-health-info.php` — server config, active PHP extensions, file paths
- `/wp-admin/options.php` — all WordPress options (some may leak sensitive info)
- `/wp-admin/update-core.php` — core version and update status
- `/wp-admin/export.php` — content export functionality

**Implementation:**

| File | Action | Notes |
|------|--------|-------|
| `core/auth.py` | **MODIFY** | Add cookie-based login support alongside Basic Auth |
| `core/auth.py` | **ADD** | `AdminSession` class wrapping HttpClient with cookie jar |
| `config.py` | **MODIFY** | Add `wp_auth_method: Literal["app_password", "cookie"]` |
| `main.py` | **MODIFY** | Add `--wp-auth-method` CLI flag |
| `steps/access/site_health_step.py` | **NEW** | Query `/wp-admin/site-health-info.php` |

**Cookie login flow:**
1. POST `wp-login.php` with `log=`, `pwd=`, `rememberme=forever`, `testcookie=1`
2. Store `Set-Cookie` in httpx.CookieJar
3. For each subsequent admin-page request, cookies are sent automatically
4. Verify session is alive by checking `/wp-admin/` redirects to dashboard (not login)

**Note:** Cookie-based auth is more invasive than Application Passwords and may trigger security plugins (Wordfence, etc.). Recommend it as opt-in via `--wp-auth-method cookie`.

---

### 6. REST API Hardening Checks

**Why:** The REST API is the #1 attack surface. The existing `RestSurfaceStep` discovers routes but does not test authorization. Multiple common misconfigurations exist.

**Checks to add:**

| Check | Method | What it detects |
|-------|--------|-----------------|
| **Permission callback audit** | Probe common endpoints without auth | Plugins/endpoints missing permission callbacks |
| **CORS misconfiguration** | Send `Origin: null`, `Origin: evil.com` | CORS policies that allow any origin |
| **User endpoint exposure** | Already partially covered by `RestApiUsersStep` | Verify `/wp-json/wp/v2/users` requires auth |
| **Route discovery** | Crawl registered routes from `/wp-json/` | Plugin-specific endpoints leaked |

---

## Tier 3 — Polish & Integration

### 7. Host Platform Fingerprinting

Detect hosting provider from response headers, IP ranges, and specific paths.

| Platform | Detection Signal |
|----------|-----------------|
| WP Engine | `X-WP-Engine` header, `wpengine.com` references in page source |
| Kinsta | `X-Kinsta` header, specific CDN path patterns |
| Bedrock | `web/app/` path structure in wp-content references |
| Pantheon | `X-Pantheon-Styx-Hostname` header |
| Cloudways | `X-Cloudways` header |
| WordPress.com | `x-hacker` header, specific cookies |
| Flywheel | `X-Flywheel` header |

**Implementation:** New step in `steps/infrastructure/` — single HTTP request + header inspection.

### 8. SARIF Output Format

WPScan v4.0.0 (May 2026) added SARIF output for CI/CD integration. The tool already has JSON and Markdown output via `JsonFormatter` and `MarkdownFormatter`.

**Implementation:** Add `SarifFormatter` in `utils/report.py` following the existing formatter pattern. SARIF standard: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

### 9. Content Crawling / Spider

**Why:** Spidering the target site can discover hidden forms, endpoints, and upload directories not found by wordlist-based enumeration.

**Implementation:** New step using `httpx` to crawl same-origin links from the homepage, following links up to a configurable depth. Extract:
- Form actions (potential XSS/CSRF surface)
- Upload directories
- Comment sections
- Plugin-specific admin pages

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
