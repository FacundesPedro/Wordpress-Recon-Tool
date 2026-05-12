# WordPress Testing Tool - Module Reference

**Tool:** WordPress Security Reconnaissance Tool  
**Version:** 2.1  
**Last Updated:** 2026-04-10

---

## Table of Contents

1. [Overview](#overview)
2. [Module: Passive](#module-passive)
3. [Module: Infrastructure](#module-infrastructure)
4. [Module: Discovery](#module-discovery)
5. [Module: Fingerprint](#module-fingerprint)
6. [Module: Users](#module-users)
7. [Module: XML-RPC](#module-xml-rpc)
8. [Module: Secrets](#module-secrets)
9. [Module: SSRF](#module-ssrf)
10. [Module: Tools](#module-tools)
11. [Module: API (Planned)](#module-api-planned)
12. [Dependency Matrix](#dependency-matrix)
13. [Severity Levels](#severity-levels)
14. [Common Patterns](#common-patterns)

---

## Overview

The tool is organized into **10 modules** containing **45 steps** total:

| Module | Steps | Purpose |
|--------|-------|---------|
| [passive](#module-passive) | 4 | External intelligence (WHOIS, DNS, certificates) |
| [infrastructure](#module-infrastructure) | 4 | Server configuration (headers, TLS, WAF) |
| [discovery](#module-discovery) | 6 | File enumeration (readme, sitemap, uploads) |
| [fingerprint](#module-fingerprint) | 6 | Version detection (WP, themes, plugins, plugin versions) |
| [users](#module-users) | 4 | User enumeration (REST, oEmbed, author IDs) |
| [api](#module-api) | 3 | REST API surface discovery |
| [xmlrpc](#module-xml-rpc) | 5 | XML-RPC testing (methods, SSRF, brute force) |
| [secrets](#module-secrets) | 5 | Sensitive file exposure (config, .env, .git) |
| [ssrf](#module-ssrf) | 2 | SSRF vulnerability testing |
| [tools](#module-tools) | 6 | External tool integrations (WPScan, Nuclei, FFUF, OpenDoor) |

---

## Module: Passive

**Profile:** `passive`  
**Risk Level:** None (no direct target interaction)  
**External Services:** WHOIS servers, DNS resolvers, crt.sh, Wayback Machine

### Steps

#### WhoisStep

| Property | Value |
|----------|-------|
| **File** | `steps/passive/whois_step.py` |
| **Base Class** | `BaseToolStep` |
| **Binary** | `whois` |
| **Severity** | Info |

**What it does:**
- Queries WHOIS servers for domain registration information
- Extracts registrar, dates, nameservers, and contact details

**How it works:**
```python
# Uses wordlist-based parsing for TLD-specific field extraction
self._parser = WhoisParser(use_wordlist=True)
```

**Data extracted:**
- Registrar name
- Creation, expiry dates
- Nameservers (NS records)
- Registrant country, organization
- Domain status

**Dependencies:**
| Dependency | Required | Fallback |
|------------|----------|----------|
| `whois` binary | No | Step skipped with warning |
| Wordlist (`~/.config/recon-wp/wordlists/whois/`) | No | ✅ Built-in patterns |

**Finding output:**
```
Title: WHOIS Information Retrieved
Severity: Info
Evidence: Registrar: GoDaddy, Created: 2020-01-15, Expires: 2026-01-15
```

---

#### DnsStep

| Property | Value |
|----------|-------|
| **File** | `steps/passive/dns_step.py` |
| **Base Class** | `BaseToolStep` |
| **Binary** | `dig` |
| **Severity** | Info |

**What it does:**
- Queries multiple DNS record types
- Analyzes SPF records for email security
- Detects hosting and email providers

**Record types queried:**
- A, AAAA (IPv4/IPv6 addresses)
- MX (mail servers)
- TXT (SPF, verification records)
- NS (nameservers)
- CNAME (aliases)

**Intelligence analysis:**
| Analysis | Finding |
|----------|---------|
| No SPF record | Medium severity - email spoofing risk |
| SPF with `~all` | Low severity - softfail |
| SPF with `-all` | Info - strict policy |
| Hosting provider patterns | Info - infrastructure identification |
| Google verification TXT | Info - domain ownership |

**Hosting providers detected:**
- AWS, Azure, GCP, Cloudflare, DigitalOcean, Locaweb, Linode, Vultr, OVH, GoDaddy, Namecheap, Hostgator, Bluehost, SiteGround

**Dependencies:**
| Dependency | Required | Fallback |
|------------|----------|----------|
| `dig` binary | Yes | Step skipped with finding |

---

#### CrtShStep

| Property | Value |
|----------|-------|
| **File** | `steps/passive/crt_sh_step.py` |
| **Base Class** | `BaseHttpStep` |
| **External API** | crt.sh |
| **Severity** | Info |

**What it does:**
- Queries Certificate Transparency logs via crt.sh API
- Discovers subdomains from SSL/TLS certificates

**Features:**
- Timeout: 60 seconds
- Retry logic: 2 attempts with 5s delay
- Multiple query patterns (domain, %.domain, _domainkey)
- HTML fallback parsing if JSON fails
- Wildcard certificate detection

**Dependencies:**
| Dependency | Required | Fallback |
|------------|----------|----------|
| crt.sh API | Yes | Error handling |

---

#### WaymachineStep

| Property | Value |
|----------|-------|
| **File** | `steps/passive/wayback_step.py` |
| **Base Class** | `BaseHttpStep` |
| **External API** | web.archive.org CDX API |
| **Severity** | Info |

**What it does:**
- Queries Wayback Machine for historical URLs
- Discovers sensitive endpoints from archives

**URL categories detected:**
| Category | Patterns |
|----------|----------|
| Admin | wp-admin, /admin, /dashboard |
| API | /api, /rest, /wp-json |
| Backup | .bak, .backup, .old, backup/ |
| Config | wp-config, .env, config/ |
| Login | wp-login, login, signin |
| Database | .sql, database/ |
| Debug | debug, .log, phpinfo |

**Dependencies:**
| Dependency | Required | Fallback |
|------------|----------|----------|
| Wayback API | Yes | Error handling |

---

## Module: Infrastructure

**Profile:** `infrastructure`  
**Risk Level:** Low (passive HTTP requests only)  
**Purpose:** Server and network configuration analysis

### Steps

#### HeadersStep

| Property | Value |
|----------|-------|
| **File** | `steps/infrastructure/headers_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Security headers checked:**

| Header | Purpose | Missing Severity |
|--------|---------|------------------|
| X-Frame-Options | Clickjacking protection | Info |
| X-Content-Type-Options | MIME-sniffing prevention | Info |
| X-XSS-Protection | XSS filtering (legacy) | Info |
| Strict-Transport-Security | Force HTTPS | Info |
| Content-Security-Policy | XSS/content injection | Info |
| Referrer-Policy | Referrer leakage control | Info |
| Permissions-Policy | Feature permissions | Info |

**Finding output:**
```
Title: Missing security headers
Severity: Info
Evidence: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security
```

---

#### TlsStep

| Property | Value |
|----------|-------|
| **File** | `steps/infrastructure/tls_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**What it does:**
- Analyzes TLS/SSL configuration
- Detects weak protocol versions
- Identifies certificate issues

---

#### WafStep

| Property | Value |
|----------|-------|
| **File** | `steps/infrastructure/waf_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**WAFs detected:**
- Cloudflare, Sucuri, Wordfence, Incapsula, Akamai, AWS WAF, Azure WAF, Google WAF, ModSecurity, BigIP, Cloudfront

---

#### PortsStep

| Property | Value |
|----------|-------|
| **File** | `steps/infrastructure/ports_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Medium |

**What it does:**
- Scans internal port ranges via XML-RPC pingback
- Tests if internal services are accessible

**Port ranges:**
- Well-known ports: 1-1024
- Commonly targeted: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB)

**SSRF Protection:**
- All targets validated against blocklist before scanning
- Blocks: RFC 1918, loopback, cloud metadata, link-local

---

## Module: Discovery

**Profile:** `discovery`  
**Risk Level:** Low (simple HTTP GET requests)  
**Purpose:** File and page enumeration

### Steps

#### ReadmeStep

| Property | Value |
|----------|-------|
| **File** | `steps/discovery/readme_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Low |

**Files checked:**
- `/readme.html`
- `/readme.txt`

**Risk:** README files often expose WordPress version and installation instructions.

---

#### LicenseStep

| Property | Value |
|----------|-------|
| **File** | `steps/discovery/license_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Low |

**Files checked:**
- `/license.txt`

**Risk:** License file exposes WordPress version.

---

#### SitemapStep

| Property | Value |
|----------|-------|
| **File** | `steps/discovery/sitemap_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Files checked:**
- `/wp-sitemap.xml` (WordPress 5.5+)
- `/sitemap.xml`

**Output:** List of URLs, page count, discovery of site structure.

---

#### LoginPageStep

| Property | Value |
|----------|-------|
| **File** | `steps/discovery/login_page_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Paths checked:**
- `/wp-login.php`
- `/wp-admin/`
- `/login/`

---

#### WpCronStep

| Property | Value |
|----------|-------|
| **File** | `steps/discovery/wp_cron_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Medium |

**Checks:** `/wp-cron.php` accessibility

**Risk:** wp-cron.php can be triggered to cause DoS if `DISABLE_WP_CRON` is not set.

---

#### UploadsListingStep

| Property | Value |
|----------|-------|
| **File** | `steps/discovery/uploads_listing_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Medium |

**Path:** `/wp-content/uploads/`

**Risk:** Directory listing enabled allows file enumeration.

---

## Module: Fingerprint

**Profile:** `fingerprint`  
**Risk Level:** Low (passive HTML parsing)  
**Purpose:** WordPress component identification and version detection

### Steps

#### WpVersionStep

| Property | Value |
|----------|-------|
| **File** | `steps/fingerprint/wp_version_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Detection methods (in order of priority):**

| Priority | Source | Pattern |
|----------|--------|---------|
| 1 | Meta generator tag | `<meta name="generator" content="WordPress X.X.X">` |
| 2 | Theme CSS | `/wp-content/themes/{name}/style.css?ver=X.X.X` |
| 3 | Core JS | `/wp-includes/js/wp-util.js?ver=X.X.X` |
| 4 | Generic pattern | `content="WordPress X.X.X"` |

**Finding output:**
```
Title: WordPress version 6.9.4
Severity: Info
Evidence: Version: 6.9.4 from theme CSS version
```

---

#### ThemeStep

| Property | Value |
|----------|-------|
| **File** | `steps/fingerprint/theme_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Detection:** Regex for `/wp-content/themes/{theme}/` paths in HTML

---

#### PluginStep

| Property | Value |
|----------|-------|
| **File** | `steps/fingerprint/plugin_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Detection:** Regex for `/wp-content/plugins/{plugin}/` paths in HTML

**Limitation:** Only detects plugins explicitly linked in HTML source. Hidden plugins require wordlist brute force.

---

#### PluginVersionStep

| Property | Value |
|----------|-------|
| **File** | `steps/fingerprint/plugin_version_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**What it does:**
- Extracts version information for detected plugins
- Fetches version files for each plugin found by PluginStep

**Version sources (in order of priority):**

| Priority | Source | URL Pattern | Regex |
|----------|--------|-------------|-------|
| 1 | readme.txt | `.../{plugin}/readme.txt` | `Stable tag:\s*([0-9.]+)` |
| 2 | readme.md | `.../{plugin}/readme.md` | `**Stable tag:**\s*([0-9.]+)` |
| 3 | Main PHP | `.../{plugin}/{plugin}.php` | `Version:\s*([0-9.]+)` |

**Dependencies:** None (uses only built-in HTTP client)

**Finding output:**
```
Title: WordPress plugin versions detected
Severity: Info
Evidence: contact-form-7: 5.8.2, akismet: unknown, jetpack: 12.1
```

**Finding structure (raw data):**
```python
{
    "plugins": {
        "contact-form-7": {"version": "5.8.2", "source": "readme.txt"},
        "akismet": {"version": "unknown", "source": None},
        "jetpack": {"version": "12.1", "source": "readme.md"}
    },
    "summary": {
        "total": 3,
        "known": 2,
        "unknown": 1
    }
}
```

---

#### VersionedAssetsStep

| Property | Value |
|----------|-------|
| **File** | `steps/fingerprint/versioned_assets_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Detection:** Extracts version strings from asset URLs (CSS, JS, fonts)

**Pattern:** `?ver=X.X.X` in resource URLs

---

#### ScriptsStep

| Property | Value |
|----------|-------|
| **File** | `steps/fingerprint/scripts_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**Detection:** Core WordPress scripts in HTML
- `wp-emoji-loader.min.js`
- `wp-emoji-release.min.js`

---

## Module: Users

**Profile:** `users`  
**Risk Level:** Low (enumeration only)  
**Purpose:** User account enumeration

### Steps

#### RestApiUsersStep

| Property | Value |
|----------|-------|
| **File** | `steps/users/rest_api_users_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/wp-json/wp/v2/users` |
| **Severity** | Info |

**Data extracted:**
- User ID
- Display name
- Username slug
- Avatar URL
- User URL

**Finding output:**
```
Title: Users enumerated via REST API
Severity: Info
Evidence: john.doe (johndoe), jane.smith (janesmith)
```

---

#### OembedUsersStep

| Property | Value |
|----------|-------|
| **File** | `steps/users/oembed_users_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/wp-json/oembed/1.0/embed` |
| **Severity** | Info |

**Method:** Queries oEmbed endpoint for author information from posts.

---

#### AuthorIdStep

| Property | Value |
|----------|-------|
| **File** | `steps/users/author_id_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/?author={id}` |
| **Severity** | Info |

**Range tested:** 1-100 (configurable)

**Finding:** Lists valid author IDs found

---

#### LoginVerbosityStep

| Property | Value |
|----------|-------|
| **File** | `steps/users/login_verbosity_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/wp-login.php` |
| **Severity** | Info |

**Detection:** Checks if error messages differ for valid vs invalid usernames

**Vulnerable pattern:**
- "Invalid username" vs generic "Invalid username or password"

---

## Module: XML-RPC

**Profile:** `xmlrpc`  
**Risk Level:** Medium-High (brute force, SSRF)  
**Purpose:** XML-RPC interface testing

### Steps

#### XmlrpcDetectStep

| Property | Value |
|----------|-------|
| **File** | `steps/xmlrpc/xmlrpc_detect_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/xmlrpc.php` |
| **Method** | `system.listMethods` |
| **Severity** | Info |

**Finding output:**
```
Title: XML-RPC is enabled
Severity: Info
Evidence: https://example.com/xmlrpc.php
Recommendation: Disable XML-RPC if not needed
```

---

#### XmlrpcMethodsStep

| Property | Value |
|----------|-------|
| **File** | `steps/xmlrpc/xmlrpc_methods_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/xmlrpc.php` |
| **Method** | `system.listMethods` |
| **Severity** | Info |

**Dangerous methods flagged:**
- `wp.getUsersBlogs` - User enumeration
- `wp.getCommentCount` - Content enumeration
- `wp.getOptions` - Configuration exposure
- `mt.setTempDate` - Date manipulation
- `pingback.ping` - SSRF potential

---

#### XmlrpcCredsStep

| Property | Value |
|----------|-------|
| **File** | `steps/xmlrpc/xmlrpc_creds_step.py` |
| **Base Class** | `BaseHttpStep`, `WordlistDependencyMixin` |
| **Method** | `wp.getUsersBlogs` |
| **Severity** | High |

**What it does:**
- Tests username:password combinations via XML-RPC
- Much faster than web login form
- Often less protected by WAF/IDS

**Security controls:**
| Control | Value |
|---------|-------|
| Rate limit | 5 requests/second |
| Backoff | Exponential (1s, 2s, 4s...) |
| Max retries | 3 |
| Lockout detection | Skip after 3 consecutive failures |

**Fallback credentials:** 20 common WordPress credential combinations

**Dependencies:**
| Dependency | Required | Fallback |
|------------|----------|----------|
| Wordlist (`username:password` format) | No | ✅ 20 common credentials |

**Finding output (if valid credentials found):**
```
Title: Valid credentials found via XML-RPC
Severity: High
Evidence: admin:password123
Recommendation: Disable XML-RPC, implement account lockout
```

---

#### XmlrpcMulticallStep

| Property | Value |
|----------|-------|
| **File** | `steps/xmlrpc/xmlrpc_multicall_step.py` |
| **Base Class** | `BaseHttpStep`, `WordlistDependencyMixin` |
| **Method** | `system.multicall` |
| **Severity** | High |

**What it does:**
- Tests 10 credentials in a single HTTP request
- Much faster than sequential testing

**Batch size:** 10 credentials per request

**Same fallback and security controls as XmlrpcCredsStep.

---

#### XmlrpcSsrfStep

| Property | Value |
|----------|-------|
| **File** | `steps/xmlrpc/xmlrpc_ssrf_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Method** | `pingback.ping` |
| **Severity** | Medium |

**Test targets (blocked by SSRF protection):**
- 169.254.169.254 (cloud metadata)
- 127.0.0.1 (localhost)
- 192.168.x.x (private)
- 10.x.x.x (private)

---

## Module: Secrets

**Profile:** `secrets`  
**Risk Level:** Low-Medium (GET requests only)  
**Purpose:** Sensitive file exposure detection

### Steps

#### WpConfigBackupStep

| Property | Value |
|----------|-------|
| **File** | `steps/secrets/wp_config_backup_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Critical |

**Backup patterns checked:**

| Pattern | Risk |
|---------|------|
| `wp-config.php.bak` | Common backup |
| `wp-config.php~` | Vim/Emacs swap |
| `wp-config.php.old` | Common backup |
| `wp-config.php.save` | Editor save |
| `wp-config.php.swp` | Vim swap |
| `wp-config.php.debian` | Debian package |
| `.wp-config.php.v1` | Versioned |
| `wp-config backup.php` | Spaces in name |

**Validation:** Checks for `DB_NAME`, `database`, `define(` strings

**Finding output:**
```
Title: wp-config.php backup found
Severity: Critical
Evidence: wp-config.php.bak, wp-config.php.old
Recommendation: Remove immediately - contains database credentials
```

---

#### EnvFileStep

| Property | Value |
|----------|-------|
| **File** | `steps/secrets/env_file_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Critical |

**Files checked:**
- `.env`
- `.env.local`
- `.env.production`
- `.env.backup`

**Risk:** Environment files contain API keys, database credentials, secrets.

---

#### GitExposureStep

| Property | Value |
|----------|-------|
| **File** | `steps/secrets/git_exposure_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | High |

**Paths checked:**
- `/.git/config`
- `/.git/HEAD`

**Risk:** Exposed .git directory allows source code download.

---

#### DebugLogStep

| Property | Value |
|----------|-------|
| **File** | `steps/secrets/debug_log_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Medium |

**Files checked:**
- `wp-content/debug.log`

**Risk:** Debug logs may expose error messages, stack traces, sensitive paths.

---

#### PhpinfoStep

| Property | Value |
|----------|-------|
| **File** | `steps/secrets/phpinfo_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Medium |

**Files checked:**
- `phpinfo.php`
- `info.php`

**Risk:** phpinfo exposes server configuration, loaded modules, paths.

---

## Module: SSRF

**Profile:** `ssrf`  
**Risk Level:** Medium (tests SSRF, but protected)  
**Purpose:** Server-Side Request Forgery testing

### Steps

#### OembedProxyStep

| Property | Value |
|----------|-------|
| **File** | `steps/ssrf/oembed_proxy_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/wp-json/oembed/1.0/proxy` |
| **Severity** | Medium |

**What it does:**
- Tests if oEmbed proxy allows SSRF to internal resources

---

#### PingbackSsrfStep

| Property | Value |
|----------|-------|
| **File** | `steps/ssrf/pingback_ssrf_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Endpoint** | `/xmlrpc.php` |
| **Method** | `pingback.ping` |
| **Severity** | Medium |

**What it does:**
- Tests if pingback.ping accepts arbitrary URLs

---

### SSRF Protection

Both steps use built-in SSRF protection that blocks:

| Range | Purpose |
|-------|---------|
| 10.0.0.0/8 | RFC 1918 private |
| 172.16.0.0/12 | RFC 1918 private |
| 192.168.0.0/16 | RFC 1918 private |
| 127.0.0.0/8 | Loopback |
| ::1 | IPv6 loopback |
| 169.254.169.254 | Cloud metadata |
| 169.254.0.0/16 | Link-local |
| 0.0.0.0 | Any address |

---

## Module: Tools

**Profile:** `tools`  
**Risk Level:** Varies (external tool execution)  
**Purpose:** External security tool integration

### Steps

#### WpscanStep

| Property | Value |
|----------|-------|
| **File** | `steps/tools/wpscan_step.py` |
| **Base Class** | `BaseToolStep` |
| **Binary** | `wpscan` (Ruby gem) |
| **Severity** | Info |
| **Enable Flag** | `--wpscan` |

**What it does:**
- Comprehensive WordPress vulnerability scanning
- CVE-based vulnerability detection
- Plugin, theme, user enumeration

**Enumeration modes:**
| Mode | Flag | Description |
|------|------|-------------|
| vp | Plugins (vulnerable) | Check known vulnerable plugins |
| vt | Themes (vulnerable) | Check known vulnerable themes |
| tt | Timthumbs | Check timthumb vulnerabilities |
| cb | Config backups | Check backup files |
| u | Users | Enumerate users |

**CLI options:**
```bash
--wpscan                    # Enable WPScan
--wpscan-api-token TOKEN    # API token for CVE data
--wpscan-enumerate "vp,vt,u" # Custom enumeration
--wpscan-timeout 900        # Timeout in seconds
```

**Installation:**
```bash
gem install wpscan
```

**API Token:**
- Free token available at https://wpscan.com/profile
- Enables vulnerability database access
- Without token, only basic enumeration available

**Finding output:**
```
Title: Vulnerable plugin: contact-form-7
Severity: High
Evidence: Version 5.0.1 has CVE-2019-10866
Recommendation: Update to latest version
```

#### NucleiStep

| Property | Value |
|----------|-------|
| **File** | `steps/tools/nuclei_step.py` |
| **Base Class** | `BaseToolStep` |
| **Binary** | `nuclei` (Go binary) |
| **Severity** | Info |
| **Enable Flag** | `--nuclei` |

**What it does:**
- Template-based vulnerability scanning
- WordPress-specific template detection
- Fast concurrent scanning with configurable threads

**CLI options:**
```bash
--nuclei                         # Enable Nuclei
--nuclei-severity critical,high   # Severity filter (default: medium,high,critical)
```

**Severity levels:**
- `critical` - Critical vulnerabilities
- `high` - High severity issues
- `medium` - Medium severity issues

**Installation:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/...@latest
```

**Finding output:**
```
Title: Nuclei: WordPress Debug Log Enabled
Severity: Medium
Evidence: https://example.com/wp-content/debug.log
Recommendation: Disable WordPress debug logging in production
```

**Configuration:**
```bash
# Via environment variable
export WP_NUCLEI_SEVERITY=critical,high
```

---

## Module: API

**Profile:** `api`  
**Status:** Implemented (3 steps)  
**Purpose:** REST API surface analysis

### Steps

#### RestSurfaceStep

| Property | Value |
|----------|-------|
| **File** | `steps/api/rest_surface_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**What it does:**
- Probes 19 common REST API routes (wp-json/wp/v2/, oembed, application-passwords, etc.)
- Uses HEAD requests to detect accessible endpoints
- Reports status codes, content types, and route paths

**Routes probed:**
- `wp-json/`, `wp-json/wp/v2/`, `wp-json/wp/v2/users`, `wp-json/wp/v2/posts`
- `wp-json/wp/v2/pages`, `wp-json/wp/v2/media`, `wp-json/wp/v2/types`
- `wp-json/wp/v2/statuses`, `wp-json/wp/v2/taxonomies`, `wp-json/wp/v2/categories`
- `wp-json/wp/v2/tags`, `wp-json/wp/v2/comments`, `wp-json/wp/v2/settings`
- `wp-json/wp/v2/themes`, `wp-json/wp/v2/plugins`, `wp-json/wp/v2/block-types`
- `wp-json/wp/v2/block-renderer`, `wp-json/oembed/1.0/`, `wp-json/application-passwords/1.0/`
- `rest_route/`

---

#### PagesIpLeakStep

| Property | Value |
|----------|-------|
| **File** | `steps/api/pages_ip_leak_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Medium |

**What it does:**
- Fetches `wp-json/wp/v2/pages` and inspects for private IPv4 addresses
- Checks against RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x) and loopback
- Deduplicates and validates findings to avoid false positives

---

#### AppPasswordsStep

| Property | Value |
|----------|-------|
| **File** | `steps/api/app_passwords_step.py` |
| **Base Class** | `BaseHttpStep` |
| **Severity** | Info |

**What it does:**
- Probes Application Passwords API endpoints
- Distinguishes between public and authenticated (401) endpoints
- Reports which routes require authentication vs publicly accessible

---



## Dependency Matrix

### External Binaries

| Binary | Step | Install Command | Required |
|--------|------|-----------------|----------|
| `whois` | WhoisStep | `brew install whois` (macOS) / `apt install whois` (Linux) | No |
| `dig` | DnsStep | `brew install bind` (macOS) / `apt install dnsutils` (Linux) | Yes |
| `wpscan` | WpscanStep | `gem install wpscan` | No |
| `nuclei` | NucleiStep | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | No |
| `ffuf` | FfufDirectoryStep, FfufFilesStep, FfufWpStep | `go install github.com/ffuf/ffuf/v2@latest` | No |
| `opendoor` | OpenDoorStep | `go install github.com/stevecotton/opendoor@latest` | No |

### External Services

| Service | Steps | Rate Limit |
|---------|-------|------------|
| crt.sh API | CrtShStep | 60s timeout |
| Wayback Machine CDX | WaymachineStep | None |

### Wordlists

| Wordlist | Steps | Location |
|----------|-------|----------|
| WHOIS patterns | WhoisStep | `~/.config/recon-wp/wordlists/whois/` |
| Credentials | XmlrpcCredsStep, XmlrpcMulticallStep | Config or fallback |

---

## Severity Levels

| Level | Color | Steps |
|-------|-------|-------|
| **Critical** | 🔴 | WpConfigBackupStep, EnvFileStep (if exposed) |
| **High** | 🟠 | XmlrpcCredsStep, XmlrpcMulticallStep |
| **Medium** | 🟡 | WpCronStep, UploadsListingStep, XmlrpcSsrfStep, PingbackSsrfStep |
| **Low** | 🔵 | ReadmeStep, LicenseStep, PortsStep |
| **Info** | ⚪ | Most steps |

---

## Common Patterns

### Step Structure

All steps follow this pattern:

```python
class MyStep(BaseHttpStep):
    name = "my_step"
    description = "What the step does"
    severity = "info"
    MODULE = "module_name"

    async def run(self) -> list[Finding]:
        self.logger.info("Starting my step...")
        
        try:
            # Step logic
            response = await self.http.get(self.urljoin("path"))
            
            if response.status_code == 200:
                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="Finding title",
                    description="Description",
                    evidence="Evidence",
                    recommendation="What to do",
                    raw={"key": "value"},
                )
        except Exception as e:
            self.logger.error(f"Error: {e}")
        
        return self.findings
```

### Adding a New Step

1. Create step file: `steps/{module}/my_step.py`
2. Inherit from `BaseHttpStep` or `BaseToolStep`
3. Implement `async def run()` method
4. Register in module: `modules/{module}_module.py`
5. Export in `steps/{module}/__init__.py`

### Base Classes

| Class | Use When |
|-------|----------|
| `BaseHttpStep` | Step makes HTTP requests |
| `BaseToolStep` | Step calls external binary |
| `WordlistDependencyMixin` | Step uses wordlists with fallback |
| `BinaryDependencyMixin` | Step requires external binary |

---

## Finding Schema

Every finding follows this structure:

```python
Finding(
    step="step_name",           # Step that generated it
    module="module_name",       # Module containing step
    severity="info|low|medium|high|critical",
    title="Finding Title",      # Short summary
    description="...",          # Extended description
    evidence="...",             # Raw evidence
    recommendation="...",       # Remediation advice
    raw={},                     # Structured data for reports
)
```

---

## Profiles

Quick scan configurations:

| Profile | Modules | Use Case |
|---------|---------|----------|
| `passive` | passive | External intel only |
| `light` | passive, infrastructure, discovery, fingerprint | Quick scan |
| `standard` | passive, infrastructure, discovery, fingerprint, users, api, xmlrpc, secrets, ssrf | Full scan |
| `full` | All modules including tools | Comprehensive |
| `aggressive` | users, xmlrpc, secrets, tools | High-impact only |

---

## See Also

- [Architecture Plan](./architecture_plan.md) - Technical design
- [Security Documentation](./SECURITY.md) - Security features
- [Changelog](./CHANGELOG.md) - Version history
- [Missing Wordlists](./missing_wordlists.md) - Planned wordlist features
