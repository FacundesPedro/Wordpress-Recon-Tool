# AGENTS.md — Session Anchor for AI Agents

## Project

WordPress reconnaissance tool. Python 3.11+, httpx, Typer, pydantic-settings, Rich.

Core architecture: `modules/` → `steps/` with risk tiers (1-4), config via environment variables (`WP_*`), wordlist resolution chain, findings emitted via `core/finding.py`.

**Current state:** 12 modules, 60 steps, 1138 tests passing (60/60 steps covered, 100%). All infrastructure, core, config, CLI, and edge cases covered at unit level. Wordlists set up with SecLists (13,370 plugins / 3,646 themes) at `~/.config/recon-wp/wordlists/`.

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

## Commit History (28 on main)

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
| 29 | — | **HTML Dashboard Report** — dark theme, health score, SVG donut chart, metric cards, collapsible findings, responsive layout |

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

**Coverage:** 60/60 steps tested (100%), 1138 tests passing across all layers. All infrastructure, core, config, CLI, and edge cases covered at unit level.

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
| **Stealth** | High | High | Timing jitter, user-agent pool, request deduplication, distributed scanning |
| **PyPI package** | Medium | Low | `pyproject.toml`, entry point, versioning |
| **Plugin architecture** | High | High | Dynamic step loading from external packages, CLI `--plugin` flag |

See `docs/next_steps.md` for implementation details and `docs/references.md` for external API/tool URLs.
