# AGENTS.md — Session Anchor for AI Agents

## Project

WordPress reconnaissance tool. Python 3.11+, httpx, Typer, pydantic-settings, Rich.

Core architecture: `modules/` → `steps/` with risk tiers (1-4), config via environment variables (`WP_*`), wordlist resolution chain, findings emitted via `core/finding.py`.

**Current state:** 12 modules, 61 steps, 143 tests passing.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Wordlist resolution | CLI → config → `wordlists/` → `~/.config/recon-wp/` → hardcoded | Graceful degradation, no file required |
| Auth mechanism | Application Passwords (HTTP Basic) | WP >= 5.6, no 2FA bypass, cookie-free |
| Shodan integration | Raw REST API via httpx | No extra `shodan` package dependency |
| CVE source | WPVulnerability.net primary, WPScan secondary | Free, no API key, 47k+ plugin vulns |
| Plugin brute-force | Response-code oracle (200/301/403 = exists) | Standard approach, SecLists wordlists |

## Commit History (15 on main)

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
| 9 | — | Add `docs/next_steps.md` — prioritized roadmap |
| 10 | — | Add `docs/references.md` — indexed external URLs |
| 11 | `c646dd3` | **Plugin/Theme brute-force** — response-code oracle with fallback wordlists |
| 12 | `f1520dd` | **CVE correlation** — VulnDB client + 3 vuln lookup steps (core, plugin, theme) |
| 13 | `f5c4d85` | **Inactive plugin file accessibility** — probe readme.txt for deactivated plugins |
| 14 | (current) | **Tiers 2-3: Login brute-force, cookie admin session, REST API hardening, hosting fingerprint, SARIF, content spider** |
| 15 | `e6c6efa` | **Doc cleanup: remove redundant .md files, update outdated references** |

## Roadmap Status — ✅ All 9 items implemented

| Tier | # | Feature | Key Files |
|------|---|---------|-----------|
| T1 | 1-3 | CVE correlation, Plugin/Theme brute-force, Inactive plugin check | Done in commits `f1520dd`, `c646dd3`, `f5c4d85` |
| T2 | 4 | **Login Brute-Force** | `steps/access/login_bruteforce_step.py` |
| T2 | 5 | **Cookie-Based Admin Session** | `core/auth.py`, `steps/access/site_health_step.py` |
| T2 | 6 | **REST API Hardening** | `steps/access/rest_hardening_step.py` |
| T3 | 7 | **Host Platform Fingerprinting** | `steps/infrastructure/hosting_step.py` |
| T3 | 8 | **SARIF Output Format** | `utils/report.py` |
| T3 | 9 | **Content Crawling / Spider** | `steps/discovery/spider_step.py` |

## Remaining Work

### Priority 1 — Tests (high impact, untested production code)

6 steps and 1 formatter have zero test coverage. All other modules have tests.

| Step | File | What to test |
|------|------|-------------|
| `LoginBruteforceStep` | `steps/access/login_bruteforce_step.py` | POST wp-login.php with mock responses (302 success, 200 failure), credential wordlist fallback, rate limiting |
| `SiteHealthStep` | `steps/access/site_health_step.py` | Cookie-based login via `AdminSession`, debug info extraction from HTML, skip when `wp_auth_method != "cookie"` |
| `RestHardeningStep` | `steps/access/rest_hardening_step.py` | CORS wildcard detection, route leakage parsing, user endpoint exposure, plugin endpoint audit |
| `HostingStep` | `steps/infrastructure/hosting_step.py` | Header matching for 12 providers, Bedrock path detection, no-match fallback |
| `SarifFormatter` | `utils/report.py` | SARIF 2.1.0 envelope structure, rules/results/invocations, empty findings handling |
| `SpiderStep` | `steps/discovery/spider_step.py` | Same-origin link extraction, depth limiting, max page limiting, robots.txt respect, form/upload detection |

Test patterns: follow existing `tests/test_ssrf_protection.py` style — pytest + `conftest.py` fixtures (`mock_http`, `mock_target`, `mock_config`).

### Priority 2 — Wordlists (production scan effectiveness)

Brute-force steps use small fallback lists (30 plugins / 15 themes). Production scans need SecLists.

```bash
# Download to project
mkdir -p wordlists/external
curl -o wordlists/external/wp-plugins.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress-plugins.fuzz.txt
curl -o wordlists/external/wp-themes.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress-themes-fuzz.txt

# Or to user config
mkdir -p ~/.config/recon-wp/wordlists
cp wordlists/external/wp-plugins.txt ~/.config/recon-wp/wordlists/
```

See `wordlists/README.md` for full resolution chain.

### Priority 3 — Beyond roadmap (future features)

| Feature | Effort | Impact | Notes |
|---------|--------|--------|-------|
| **Stealth** | High | High | Timing jitter, user-agent pool, request deduplication, distributed scanning |
| **HTML reporting** | Medium | Medium | Visual report with severity badges, charts, executive summary |
| **Docker** | Low | Medium | `Dockerfile` + `docker-compose.yml` with all deps pre-installed |
| **PyPI package** | Medium | Low | `pyproject.toml`, entry point, versioning |
| **Plugin architecture** | High | High | Dynamic step loading from external packages, CLI `--plugin` flag |

See `docs/next_steps.md` for implementation details and `docs/references.md` for external API/tool URLs.
