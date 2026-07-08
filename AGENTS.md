# AGENTS.md — Session Anchor for AI Agents

## Project

WordPress reconnaissance tool. Python 3.11+, httpx, Typer, pydantic-settings, Rich.

Core architecture: `modules/` → `steps/` with risk tiers (1-2), config via environment variables (`WP_*`), wordlist resolution chain, findings emitted via `core/finding.py`.

**Current state:** 12 modules, 55 steps, 143 tests passing.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Wordlist resolution | CLI → config → `wordlists/` → `~/.config/recon-wp/` → hardcoded | Graceful degradation, no file required |
| Auth mechanism | Application Passwords (HTTP Basic) | WP >= 5.6, no 2FA bypass, cookie-free |
| Shodan integration | Raw REST API via httpx | No extra `shodan` package dependency |
| CVE source | WPVulnerability.net primary, WPScan secondary | Free, no API key, 47k+ plugin vulns |
| Plugin brute-force | Response-code oracle (200/301/403 = exists) | Standard approach, SecLists wordlists |

## Commit History (13 on main)

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

## Next Steps by Tier

### Tier 1 — High Impact

| # | Feature | Key Files | Why Now |
|---|---------|-----------|---------|
| 1 | **CVE Correlation** | `core/vulndb.py`, `steps/vuln/` (3 steps), `modules/vuln_module.py` | ✅ Done — commit `f1520dd` |
| 2 | **Plugin/Theme Brute-Force** | `steps/discovery/plugin_bruteforce_step.py`, `theme_bruteforce_step.py` | ✅ Done — commit `c646dd3` |
| 3 | **Inactive Plugin File Accessibility** | `steps/access/inactive_plugin_check_step.py`, `modules/access_module.py` | ✅ Done — commit `f5c4d85` |

### Tier 2 — Moderate Impact

| # | Feature | Key Files |
|---|---------|-----------|
| 4 | **Login Brute-Force** | `steps/access/login_bruteforce_step.py` (uses existing `resolve_credentials_with_fallback()`) |
| 5 | **Cookie-Based Admin Session** | `core/auth.py` (extend), `steps/access/site_health_step.py` (new) |
| 6 | **REST API Hardening** | Permission audits, CORS checks on `/wp-json/` endpoints |

### Tier 3 — Polish

| # | Feature |
|---|---------|
| 7 | Host Platform Fingerprinting (WP Engine, Kinsta, Bedrock, etc.) |
| 8 | SARIF Output Format (CI/CD integration) |
| 9 | Content Crawling / Spider (discover hidden forms, upload dirs) |

See `docs/next_steps.md` for full implementation plans and `docs/references.md` for external API/tool URLs.
