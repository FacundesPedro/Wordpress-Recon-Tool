# AGENTS.md — Session Anchor for AI Agents

## Project

WordPress reconnaissance tool. Python 3.11+, httpx, Typer, pydantic-settings, Rich.

Core architecture: `modules/` → `steps/` with risk tiers (1-4), config via environment variables (`WP_*`), wordlist resolution chain, findings emitted via `core/finding.py`.

**Current state:** 12 modules, 60 steps, 575 tests passing (50/60 steps covered, 83%).

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
| 14 | `f8c044d` | **Tiers 2-3: Login brute-force, cookie admin session, REST API hardening, hosting fingerprint, SARIF, content spider** |
| 15 | `e6c6efa` | **Doc cleanup: remove redundant .md files, update outdated references** |
| 16 | (current) | **Phase 1 bug fixes: 8 correctness bugs (findings discard, error double-format, silent validation failure, SSRF rename, urljoin inconsistency, auth improvements, sanitize chars, output redaction)** |
| 17 | (current) | **Tests for access + vuln modules: 7 new test files, 74 tests, 357 total passing** |

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

**Coverage:** 50/60 steps tested (83%). 10 steps remain untested, concentrated in 3 modules.

| Module | Steps | Tested | Untested | Priority |
|--------|-------|--------|----------|----------|
| infrastructure | 5 | 1 | 4 | **next** |
| ssrf | 2 | 0 | 2 | high |
| users | 4 | 0 | 4 | high |
| tools | 6 | 4 | 2 | low |

Test patterns: pytest + `conftest.py` fixtures (`mock_http`, `mock_target`, `mock_config`). For HTTP steps, mock `mock_http.request` (not `mock_http.get` — steps delegate through `BaseHttpStep.get()` → `self.http.request()`). For VulnDB-dependent steps, use `@patch("steps.vuln.*.VulnDB")`.

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
