# Project References

**Purpose:** Index of external APIs, tools, wordlists, and documentation that this project depends on or integrates with. Keep this up to date as dependencies change.

**Last Updated:** 2026-06-17

---

## Vulnerability Databases

| URL | Why It Matters |
|-----|----------------|
| [WPVulnerability.net API](https://www.wpvulnerability.com/api/) | **Primary CVE source (planned).** Free, no API key, aggregates 6 databases (CVE, WPScan, Wordfence, Patchstack, EUVD, JVN). 47k+ plugin vulns, 4k+ theme vulns. Target endpoint: `GET /plugin/{slug}/`, `GET /theme/{slug}/`, `GET /core/{version}/`. |
| [WPScan API v3](https://wpscan.com/docs/api/v3/) | **Secondary CVE source (planned).** Free tier (25 req/day) with API token. Curated, manually verified vulnerabilities. Already partially integrated — the existing `config.py` has `wpscan_api_token` for WPScan CLI integration; can be reused for API lookups. |
| [WPScan Enterprise Data](https://enterprise-data.wpscan.com/) | Enterprise bulk download of the full vulnerability database (gzipped JSON). Relevant if the project ever needs an offline CVE cache. |
| [Wordfence Vulnerability Feed](https://www.wordfence.com/) | 117MB JSON feed with ~7,000 plugin CVEs. Requires free API key. Used by wpsecscan and wphunter as one of many sources. |

## Tool Integrations (Existing)

| URL | Why It Matters |
|-----|----------------|
| [WPScan CLI](https://github.com/wpscanteam/wpscan) | **Integrated in `tools` module.** The industry standard WordPress scanner. Invoked via `steps/tools/wpscan_step.py`. v4.0.0 (May 2026) added `--wp-auth` and SARIF output. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | **Integrated in `tools` module.** Fast vulnerability scanner with YAML templates. Invoked via `steps/tools/nuclei_step.py`. Has WordPress-specific templates under `fuzzing/wordpress-plugins-detect.yaml`. |
| [FFUF](https://github.com/ffuf/ffuf) | **Integrated in `tools` module.** Directory/file fuzzer. Invoked via `steps/tools/ffuf_*_step.py`. Used for wordlist-based path discovery. |
| [OpenDoor](https://github.com/stanislav-web/OpenDoor) | **Integrated in `tools` module.** WordPress-focused path scanner. Invoked via `steps/tools/opendoor_step.py`. Includes WP-specific mode. |

## External APIs (Existing)

| URL | Why It Matters |
|-----|----------------|
| [Shodan REST API](https://developer.shodan.io/api) | **Integrated in `steps/passive/shodan_step.py` (commit `836b50e`).** Queries `GET /shodan/host/{ip}` and `GET /shodan/host/search` for open ports, service banners, and WordPress fingerprints. Requires `WP_SHODAN_API_KEY`. |
| [Wayback Machine CDX API](https://web.archive.org/help/index.html) | **Integrated in `steps/passive/wayback_step.py`.** Discovers historical URLs and archived endpoints via `web.archive.org`. No API key required. |
| [crt.sh Certificate Search](https://crt.sh/) | **Integrated in `steps/passive/crt_sh_step.py`.** Queries certificate transparency logs for subdomain discovery. No API key required. |
| [WHOIS Servers](https://www.iana.org/domains/root/db) | **Integrated in `steps/passive/whois_step.py` via local `whois` binary.** Domain registration information. Uses wordlist files in `wordlists/whois/` for TLD-specific field extraction. |

## WordPress REST API Endpoints

| URL | Why It Matters |
|-----|----------------|
| [WP REST API Reference](https://developer.wordpress.org/rest-api/reference/) | **Core reference for the `access` module (commit `4571726`).** The authenticated steps query these endpoints with Application Password auth. Key endpoints: `GET /wp/v2/plugins`, `GET /wp/v2/themes`, `GET /wp/v2/users`. |
| [Application Passwords Integration Guide](https://make.wordpress.org/core/2020/11/05/application-passwords-integration-guide/) | **Auth mechanism reference.** Documents how Application Passwords work — built into WP 5.6+, use HTTP Basic Auth, bypass 2FA, individually revocable. The auth design in `core/auth.py` follows this spec. |
| [WP REST API Authentication Comparison (2026)](https://attowp.com/blog/wordpress-rest-api-authentication-methods-comparison/) | Auth method decision guide. Confirms Application Passwords are the right choice for server-to-server integrations. |
| [Headless WP Auth: JWT vs App Passwords vs OAuth](https://jwtauth.pro/blog/headless-wp-auth-comparison) | Industry comparison. Validates the choice of Application Passwords for the authenticated scan mode. |

## Wordlists

| URL | Why It Matters |
|-----|----------------|
| [SecLists — Web Content — CMS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/CMS) | **Wordlist source for plugin/theme brute-force (planned).** Contains `wordpress-plugins.fuzz.txt` (~20k plugins), `wp-plugins.fuzz.txt`, and common WP paths. Referenced in `wordlists/README.md` (commit `8abb857`). |
| [WPScan WordPress Detection Patterns](https://github.com/wpscanteam/wpscan/tree/master/app/views/json) | Reference for WP version fingerprinting patterns. The existing `WpVersionStep` uses similar techniques. |
| [WPProbe Plugin→Endpoint DB](https://github.com/Chocapikk/wpprobe) | REST API stealth detection DB mapping ~5k plugins to their exposed REST routes. Relevant if implementing REST API-based detection (Tier 1, item 2 in `next_steps.md`). |

## Competitor / Reference Tools

| URL | Why It Matters |
|-----|----------------|
| [WPSecScan](https://github.com/bryanflowers/wpsecscan) | **Most comprehensive open source WP scanner (268 checks).** Reference for check coverage — maps what a fully-built scanner looks like. 8-source CVE aggregator, SARIF output, companion plugin pattern. |
| [WPProbe](https://github.com/Chocapikk/wpprobe) | **REST API stealth detection reference.** 5k+ plugins detected via `?rest_route=` without brute-force. Hybrid stealth+bruteforce mode. |
| [WPHunter](https://github.com/elqahtani/wphunter) | **CVE correlation reference.** Uses WPVulnerability.net + WPScan API with deduplication. No API keys needed for basic operation. |
| [WP-Hijack](https://github.com/kdo2064/wp-hijack) | **Pipeline architecture reference.** 10-phase async pipeline from passive recon to AI exploit generation. Shows the potential end-state for the tool's architecture. |
| [WPScan Changelog (v4.0.0)](https://github.com/wpscanteam/wpscan/releases/tag/v4.0.0) | Industry reference for what a mature WP scanner ships in a major release. Notable additions: `--wp-auth`, SARIF, JSONL streaming, SAML support. |
| [WordPress Pentesting Cheatsheet (2026)](https://spyboy.blog/2026/01/29/the-ultimate-wordpress-pentesting-cheatsheet-for-2026/) | Pentest methodology reference. 11-phase methodology that maps to the tool's module structure. Helpful for identifying gaps in coverage. |

## Infrastructure / Security

| URL | Why It Matters |
|-----|----------------|
| [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) | Testing methodology framework. The project's checks should map to OWASP categories (as WPSecScan does). |
| [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Feed of actively exploited vulnerabilities. Relevant for CVE severity prioritization if CVE correlation is implemented. |
| [CVSS v3.1 Calculator](https://www.first.org/cvss/v3-1/) | Severity scoring reference. Maps CVSS scores to the tool's severity levels (`info`/`low`/`medium`/`high`/`critical`) in finding emission. |
| [MITRE ATT&CK — WordPress Techniques](https://attack.mitre.org/techniques/enterprise/) | Threat modeling framework. Some scanners tag findings with ATT&CK technique IDs (e.g., `T1190`, `T1592.002`). |

## Python Ecosystem

| URL | Why It Matters |
|-----|----------------|
| [httpx Documentation](https://www.python-httpx.org/) | **Core HTTP library.** Used throughout the codebase (`core/http_client.py`). Async, supports HTTP/1.1 + HTTP/2, cookie jars, custom headers. |
| [Typer Documentation](https://typer.tiangolo.com/) | **CLI framework.** Used in `main.py` for CLI argument parsing. Rich integration for help output. |
| [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) | **Configuration management.** Used in `config.py` for env var loading (prefix `WP_`), `.env` file support, and field validation. |
| [Rich Library](https://rich.readthedocs.io/) | **Terminal output.** Used for formatted tables (`list-profiles`, `list-modules`), colored output, and logging. |
