# Module Refinement Plan

## Codebase Health Summary

| Metric | Value |
|--------|-------|
| Modules | 12 |
| Step files | 60 |
| Codebase lines | ~11,000 |
| Test count | 357 (all passing) |
| Steps with tests | 21/60 (35%) |
| utcnow() warnings | 50 |

---

## Phase 1 — Fix Bugs (critical path)

| # | Module | Issue | File(s) | Impact |
|---|--------|-------|---------|--------|
| 1 | **base** | `BaseToolStep.run()` replaces findings — discards pre-run version warnings | `base/step.py:315` | Loss of findings in tool steps |
| 2 | **base** | `verify_binary()` double-formats error message | `base/step.py:276` | Ugly error output |
| 3 | **core** | `Target._validate_and_normalize` silently returns `{}` on invalid URLs | `core/target.py` | Invisible scan failures |
| 4 | **core** | `is_safe_target` inverted semantics (returns `True` when target is **un**safe) | `core/ssrf_protection.py` | SSRF bypass risk |
| 5 | **base** | `urljoin()` vs `fetch()` path-joining inconsistency | `base/http_step.py` | Wrong URLs in requests |
| 6 | **core** | `AdminSession` no CSRF nonce handling; fragile 302-only login detection | `core/auth.py` | Auth failures on admin pages |
| 7 | **base** | `_sanitize_arg` doesn't handle `>`,`<`,`~`,`{}` shell chars | `base/tool.py` | Injection surface |
| 8 | **base** | `_redact_sensitive_from_output` defined but never called | `base/tool.py` | Secrets leak in logs |

---

## Phase 2 — Tests (highest coverage gap)

| # | Module | Steps to test | Existing test effort |
|---|--------|--------------|---------------------|
| 9 | **access** | `WpJsonPluginsStep`, `WpJsonThemesStep`, `WpJsonUsersStep`, `InactivePluginCheckStep` | 3/7 tested |
| 10 | **vuln** | `CoreVulnStep`, `PluginVulnStep`, `ThemeVulnStep` (all 3, zero coverage) | 0/3 |
| 11 | **passive** | `DnsStep`, `WhoisStep`, `CrtShStep`, `ShodanStep`, `WaymachineStep` (all 5, zero coverage) | 0/5 |
| 12 | **discovery** | `ReadmeStep`, `LicenseStep`, `SitemapStep`, `LoginPageStep`, `WpCronStep`, `UploadsListingStep`, `PluginBruteforceStep`, `ThemeBruteforceStep` (8/9 untested) | 1/9 |
| 13 | **fingerprint** | `WpVersionStep`, `ThemeStep`, `PluginStep`, `ScriptsStep`, `VersionedAssetsStep` (5/6 untested) | 1/6 |
| 14 | **xmlrpc** | All 5 steps (zero coverage) | 0/5 |
| 15 | **secrets** | All 5 steps (zero coverage) | 0/5 |
| 16 | **api** | All 3 steps (zero coverage) | 0/3 |
| 17 | **infrastructure** | `HeadersStep`, `TlsStep`, `WafStep`, `PortsStep` (4/5 untested) | 1/5 |
| 18 | **ssrf** | All 2 steps (zero coverage) | 0/2 |
| 19 | **users** | All 4 steps (zero coverage) | 0/4 |
| 20 | **tools** | `WpscanStep`, `NucleiStep` (2/6 untested) | 4/6 |
| 21 | **utils** | `PdfFormatter` — only 2 smoke tests | Minimal |

---

## Phase 3 — Code Quality & Docstrings (consistency)

| # | Module | What to fix |
|---|--------|-------------|
| 22 | **access** | Add WHAT/HOW/WHY headers to `login_bruteforce_step`, `inactive_plugin_check_step`, `site_health_step`, `rest_hardening_step` |
| 23 | **discovery** | Add WHAT/HOW/WHY to `plugin_bruteforce_step`, `theme_bruteforce_step`, `spider_step` |
| 24 | **infrastructure** | Add WHAT/HOW/WHY to `hosting_step` |
| 25 | **vuln** | All 3 steps — no module or class docstrings |
| 26 | **core/vulndb** | Zero docstrings on any class/method |
| 27 | **utils/report** | Document `HtmlFormatter._build_html` (70+ line f-string) |
| 28 | All modules | Remove `import re` inside method bodies (readme_step, xmlrpc_methods_step) |
| 29 | All modules | Replace `assert self.target is not None` with proper `if`/`raise` |
| 30 | **utils/report** | Fix `utcnow()` deprecation (50 warnings) |

---

## Phase 4 — Architecture & Dead Code

| # | Module | What to fix |
|---|--------|-------------|
| 31 | **base** | Remove `StepResult` dataclass (dead code, unused) |
| 32 | **base** | Remove `getBinary` abstract property (dead code, unused) |
| 33 | **utils/report** | Unify `_sarif_level` mapping — currently duplicated in `Finding.to_sarif()` and `SarifFormatter` |
| 34 | **core/finding** | Set `frozen=True` to match docstring claim of immutability |
| 35 | **base** | Merge `ToolVersionMixin` in `dependencies.py` with `BaseToolStep.check_version_compatibility` — duplicated logic |
| 36 | **core/http_client** | Remove unused `random` import; update user agents |
| 37 | **base** | `http` parameter on both `BaseStep` and `BaseHttpStep` — cleanup init chain |
| 38 | **utils/whois_parser** | Remove dead `use_wordlist` parameter in `__init__` |
| 39 | **base/dependencies** | Remove `WORDLIST_FALLBACK_WARNING` / `WORDLIST_DISABLED_WARNING` — unused templates |
| 40 | **utils/wordlist_loader** | Add `wordlists/external/` to resolution chain |

---

## Phase 5 — Security Hardening

| # | Module | What to fix |
|---|--------|-------------|
| 41 | **utils/report** | Escape single quotes in `HtmlFormatter._esc()` (XSS) |
| 42 | **utils/report** | Use canonical SARIF schema URL |
| 43 | **base/tool** | Wire `_redact_sensitive_from_output` into `ToolRunner.run()` and `AsyncToolRunner.run()` |
| 44 | **core/ssrf_protection** | Add DNS rebinding protection note (at minimum document the gap) |
| 45 | **core/ssrf_protection** | Consider removing port restriction in `is_safe_target` DNS resolution |
| 46 | **core/auth** | Strip whitespace from credentials in `get_wp_auth_header` |

---

## Phase 6 — Polish & Low-Effort Wins

| # | Module | What to fix |
|---|--------|-------------|
| 47 | **core/target** | Support IPv6 and port in URL validation |
| 48 | **core/logger** | Replace `print()` with proper `logging` module integration |
| 49 | **core/logger** | Remove misleading "Rich-powered" docstring |
| 50 | **base/runner** | Warn when module doesn't match any risk tier |
| 51 | **utils/rate_limiter** | Fix `Optional[callable]` → `Optional[Callable]` type hint |
| 52 | **core/vulndb** | Extract duplicated `_cache_get`/`_cache_set` into shared method |
| 53 | **core/vulndb** | Extract `_merge_results` helper for 3 duplicate vuln queries |
| 54 | **All** | Add `__eq__`/`__hash__` to `Finding` for dedup |
| 55 | **utils/wordlist_loader** | Log warning on unreadable wordlist files instead of silent skip |
| 56 | **modules/__init__** | Verify profile composition against actual risk tiers |

---

## Session Progress

| Session | Status | Items |
|---------|--------|-------|
| **1** | ✅ Complete | Bugs (Phase 1 — items 1-8) |
| **2** | ✅ Complete | Tests — `access` + `vuln` modules (items 9-10) |
| 3 | ⬜ Pending | Tests — `passive` module (item 11) |
| 4 | ⬜ Pending | Tests — `discovery` + `fingerprint` (items 12-13) |
| 5 | ⬜ Pending | Tests — `xmlrpc` + `secrets` + `api` (items 14-16) |
| 6 | ⬜ Pending | Tests — remaining steps (items 17-21) |
| 7 | ⬜ Pending | Code quality — docstrings + `assert` fixes (items 22-30) |
| 8 | ⬜ Pending | Architecture cleanup (items 31-40) |
| 9 | ⬜ Pending | Security + Polish (items 41-55) |

Each session represents ~2-4h of focused work.
