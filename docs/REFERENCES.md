# Project References

**Purpose:** Index of external APIs, tools, wordlists, and documentation that this project depends on or integrates with. Keep this up to date as dependencies change.

**Last Updated:** 2026-09-04

---

## Vulnerability Databases

| URL | Why It Matters |
|-----|----------------|
| [WPVulnerability.net API](https://www.wpvulnerability.com/api/) | **Primary CVE source (planned).** Free, no API key, aggregates 6 databases (CVE, WPScan, Wordfence, Patchstack, EUVD, JVN). 47k+ plugin vulns, 4k+ theme vulns. Target endpoint: `GET /plugin/{slug}/`, `GET /theme/{slug}/`, `GET /core/{version}/`. |
| [WPScan API v3](https://wpscan.com/docs/api/v3/) | **Secondary CVE source (planned).** Free tier (25 req/day) with API token. Curated, manually verified vulnerabilities. Already partially integrated — the existing `config.py` has `wpscan_api_token` for WPScan CLI integration; can be reused for API lookups. |
| [WPScan Enterprise Data](https://enterprise-data.wpscan.com/) | Enterprise bulk download of the full vulnerability database (gzipped JSON). Relevant if the project ever needs an offline CVE cache. |
| [Wordfence Vulnerability Feed](https://www.wordfence.com/) | 117MB JSON feed with ~7,000 plugin CVEs. Requires free API key. Used by wpsecscan and wphunter as one of many sources. |
| [NVD API 2.0](https://nvd.nist.gov/developers) | National Vulnerability Database API. Official CVE source with CVSS scores, CPE mappings, and references. Rate-limited (free API key available). |
| [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) | Bulk JSON/XML feeds of all CVEs. Daily updates. Alternative to API for offline CVE correlation. |
| [OSV.dev](https://osv.dev/) | Open Source Vulnerabilities database from Google. Aggregates from 17+ sources including GitHub, PyPI, npm, CVE. Free API, no key required. Relevant for plugin dependency vulns. |
| [OSV.dev API Docs](https://osv.dev/docs/) | Query API: `POST /v1/query` for package-based vuln lookup, `GET /v1/vuln/{id}` for single vuln. Useful for dependency scanning. |
| [Exploit-DB](https://www.exploit-db.com/) | Public exploit archive. Relevant for checking if a detected CVE has a publicly available exploit. |

## Tool Integrations (Existing)

| URL | Why It Matters |
|-----|----------------|
| [WPScan CLI](https://github.com/wpscanteam/wpscan) | **Integrated in `tools` module.** The industry standard WordPress scanner. Invoked via `steps/tools/wpscan_step.py`. v4.0.0 (May 2026) added `--wp-auth` and SARIF output. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | **Integrated in `tools` module.** Fast vulnerability scanner with YAML templates. Invoked via `steps/tools/nuclei_step.py`. Has WordPress-specific templates under `fuzzing/wordpress-plugins-detect.yaml`. |
| [Nuclei — WordPress Templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/wordpress) | Repository of WordPress-specific Nuclei templates. Covers known vulns, config issues, exposed files. |
| [Nuclei — CVE Templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/cves) | General CVE templates that may include WP-related CVEs. |
| [Nuclei — Fuzzing Templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/fuzzing) | Fuzzing templates including `wordpress-plugins-detect.yaml` for plugin brute-force. |
| [FFUF](https://github.com/ffuf/ffuf) | **Integrated in `tools` module.** Directory/file fuzzer. Invoked via `steps/tools/ffuf_*_step.py`. Used for wordlist-based path discovery. |
| [OpenDoor](https://github.com/stanislav-web/OpenDoor) | **Integrated in `tools` module.** WordPress-focused path scanner. Invoked via `steps/tools/opendoor_step.py`. Includes WP-specific mode. |
| [Nmap](https://nmap.org/) | **Integrated in `tools` module** via `steps/tools/nmap_step.py` (`NmapPortScanStep`, `NmapScriptScanStep`). Direct host port scanning (`-sT -sV --top-ports`) and default NSE scripts (`-sC`). JSON output to stdout with `-oJ -`. Requires nmap >= 7.92. |
| [Nmap Reference Guide — Output Formats](https://nmap.org/book/output.html) | Reference for the `-oJ` JSON output format used by `nmap_step.py` (`nmap-run.host[].ports[]` with `portid`, `state`, `service`, `scripts`). |
| [Nmap Reference Guide — NSE](https://nmap.org/book/nse.html) | Nmap Scripting Engine reference. `-sC` runs default scripts; structured output (`scripts{}`) is parsed by `NmapScriptScanStep`. |

## Generic Web App References (`webapp` module)

| URL | Why It Matters |
|-----|----------------|
| [OWASP WSTG — Test HTTP Methods (4.2.6)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods) | Methodology reference for `HttpMethodsStep` (TRACE/PUT/DELETE/PROPFIND). |
| [OWASP WSTG — Testing for Cookies Attributes (4.6.2)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes) | Methodology reference for `CookieFlagsStep` (Secure/HttpOnly/SameSite). |
| [OWASP WSTG — Testing Cross Origin Resource Sharing (4.11.7)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing) | Methodology reference for `CorsStep` (wildcard origin, origin reflection, credentials). |
| [OWASP WSTG — Error Handling (4.8)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/) | Methodology reference for `StackTraceStep` (stack traces, verbose errors). |
| [OWASP WSTG — Review Web Page Content for Information Leakage (4.1.5)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage) | Methodology reference for `ContentLeakStep` and `SourceReviewStep` info-leak rules. |
| [OWASP WSTG — HSTS (4.2.7) / CSP (4.2.12) / Other Headers (4.2.14)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/) | Methodology reference for `HeaderQualityStep` (HSTS max-age, X-Frame-Options, CSP frame-ancestors). Complements `infrastructure/headers_step.py` (missing-header check). |
| [gitleaks — default rules config](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) | **Source of the secret-detection regex rules** in `steps/webapp/source_review_step.py` (AWS, GitHub, Slack, JWT, PEM keys, GCP, Stripe, Twilio, SendGrid, npm, HuggingFace, Mailgun, DB connection strings, basic-auth URLs). Rules are adapted from Go RE2 to Python `re` syntax (gitleaks `(?-i)` flag-scopes are not supported by Python). |
| [gitleaks — documentation](https://github.com/gitleaks/gitleaks) | Secret scanner used as the pattern reference. Rule structure (`id`, `description`, `regex`, `keywords`, `entropy`) inspired the `SECRET_RULES` design. |
| [MDN — Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) | Cookie attribute reference (`Secure`, `HttpOnly`, `SameSite`) for `CookieFlagsStep` parsing. |
| [MDN — Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin) | CORS response header reference for `CorsStep` evaluation logic. |
| [Sourcemaps (source map spec)](https://docs.google.com/document/d/1g5kRt-i0SwhXf0kl1qz_w12F7Qw3fDnqhURxeYa2RKQ) | Source map v3 spec. `.js.map` files expose original unminified source — the target of `SourcemapStep`. |

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
| [WordPress.org Plugin API (`plugins/info/1.2`)](https://developer.wordpress.org/plugins/wordpress-org/api/) | Query plugin metadata (version, download count, rating) without hitting the target site. Used by some scanners for version comparison. |
| [WordPress.org Theme API (`themes/info/1.1`)](https://developer.wordpress.org/themes/wordpress-org/api/) | Query theme metadata same as plugin API. |
| [WordPress.org Version Check API (`core/version-check/1.7`)](https://api.wordpress.org/core/version-check/1.7/) | Returns latest WP versions by branch. Can be used to check if a detected version is current. |
| [WordPress.org Secret Services (`secret-service/1.1`)](https://api.wordpress.org/secret-service/1.1/) | Checksums for core files by version. Relevant for file integrity checks. |
| [WordPress Release Archive](https://wordpress.org/download/releases/) | Historical release archive. Useful for looking up old versions. |
| [WordPress Trac Tags](https://core.trac.wordpress.org/tags) | All WP version tags (SVN). Useful for release history verification. |
| [WordPress Versions (Codex)](https://codex.wordpress.org/WordPress_Versions) | Comprehensive list of all WP versions with dates. Reference for version detection validation. |
| [WordPress Developer Resources](https://developer.wordpress.org/) | Official dev docs. Covers hooks, REST API, CLI, coding standards. |
| [WP REST API Handbook](https://developer.wordpress.org/rest-api/) | Detailed REST API docs. Reference for endpoint detection and auth methods. |
 
## Wordlists

| URL | Why It Matters |
|-----|----------------|
| [SecLists — Web Content — CMS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/CMS) | **Wordlist source for plugin/theme brute-force (planned).** Contains `wordpress-plugins.fuzz.txt` (~20k plugins), `wp-plugins.fuzz.txt`, and common WP paths. Referenced in `wordlists/README.md` (commit `8abb857`). |
| [WPScan WordPress Detection Patterns](https://github.com/wpscanteam/wpscan/tree/master/app/views/json) | Reference for WP version fingerprinting patterns. The existing `WpVersionStep` uses similar techniques. |
| [WPProbe Plugin→Endpoint DB](https://github.com/Chocapikk/wpprobe) | REST API stealth detection DB mapping ~5k plugins to their exposed REST routes. Relevant if implementing REST API-based detection (Tier 1, item 2 in `NEXT_STEPS.md`). |

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
| [CISA KEV — JSON Feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Machine-readable JSON dump of the KEV catalog. Can be consumed directly for exploit-activity scoring. |
| [CISA KEV — GitHub Mirror](https://github.com/cisagov/KEV) | CISA-maintained GitHub mirror. Alternative access point with git history. |
| [CVSS v3.1 Calculator](https://www.first.org/cvss/v3-1/) | Severity scoring reference. Maps CVSS scores to the tool's severity levels (`info`/`low`/`medium`/`high`/`critical`) in finding emission. |
| [MITRE ATT&CK — WordPress Techniques](https://attack.mitre.org/techniques/enterprise/) | Threat modeling framework. Some scanners tag findings with ATT&CK technique IDs (e.g., `T1190`, `T1592.002`). |
| [Mozilla Observatory](https://observatory.mozilla.org/) | Security header scanner and grader. Reference for evaluating the `HeadersStep` findings. Grades TLS, CSP, HSTS, XFO, etc. |
| [SecurityHeaders.com](https://securityheaders.com/) | Header grading tool. Quick way to validate `HeadersStep` output. |
| [CSP Evaluator](https://csp-evaluator.withgoogle.com/) | Google's CSP analysis tool. Helps evaluate Content-Security-Policy findings. |
| [WPScan Vulnerability Statistics](https://wpscan.com/statistics) | Dashboard of WP vulnerability trends. Useful for understanding prevalence of plugin/theme vulns when prioritizing. |

## Python Ecosystem

| URL | Why It Matters |
|-----|----------------|
| [httpx Documentation](https://www.python-httpx.org/) | **Core HTTP library.** Used throughout the codebase (`core/http_client.py`). Async, supports HTTP/1.1 + HTTP/2, cookie jars, custom headers. |
| [Typer Documentation](https://typer.tiangolo.com/) | **CLI framework.** Used in `main.py` for CLI argument parsing. Rich integration for help output. |
| [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) | **Configuration management.** Used in `config.py` for env var loading (prefix `WP_`), `.env` file support, and field validation. |
| [Rich Library](https://rich.readthedocs.io/) | **Terminal output.** Used for formatted tables (`list-profiles`, `list-modules`), colored output, and logging. |
