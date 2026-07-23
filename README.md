# WordPress Reconnaissance Tool

A security-focused WordPress reconnaissance and vulnerability scanning tool with passive reconnaissance, security hardening features, and comprehensive report generation.

## Quick Setup

```bash
git clone <repo-url> && cd wordpress_testing_tool
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Basic scan
python main.py main --target https://example.com

# Full scan with all modules
python main.py main --target https://example.com --profile full
```

See [Installation](#installation) for external tool setup and [Production Wordlists](#production-wordlists-optional) for production wordlists.

## Quick Start

### Basic Scan
```bash
python main.py main --target https://example.com
```

### Passive Reconnaissance Only
```bash
python main.py main --target https://example.com --modules passive
```

### Full Scan with Debug Output
```bash
python main.py main --target https://example.com --profile full --debug
```

### JSON / SARIF Output
```bash
python main.py main --target https://example.com --format json
python main.py main --target https://example.com --format sarif
```

### Vulnerability Scanning
```bash
python main.py main --target https://example.com --wpscan --wpscan-api-token YOUR_TOKEN
python main.py main --target https://example.com --nuclei
python main.py main --target https://example.com --wpscan --nuclei
```

### Authenticated Scan (requires WP >= 5.6 with Application Password)
```bash
python main.py main --target https://example.com --profile full \
  --wp-user admin --wp-app-password 'xxxx xxxx xxxx xxxx xxxx xxxx'
```

### List Available Options
```bash
python main.py list-profiles
python main.py list-modules
```

## Features

### Passive Reconnaissance
- **WHOIS Enumeration** - Domain registration data with TLD-aware parsing
- **DNS Enumeration** - A, AAAA, MX, TXT, NS, CNAME records with SPF analysis
- **Certificate Transparency** - Subdomain discovery via crt.sh
- **Wayback Machine** - Historical URL enumeration

### Vulnerability Scanning
- **CVE Correlation** — Maps plugin/theme/core versions to known CVEs via WPVulnerability.net (free, no key) + optional WPScan API
  - Core vulnerability detection
  - Plugin vulnerability detection (auth API + HTML fallback)
  - Theme vulnerability detection
- **WPScan Integration** - Comprehensive WordPress vulnerability scanner
  - WordPress version detection + CVE mapping
  - Plugin enumeration + vulnerability detection
  - Theme enumeration + vulnerability detection
  - User enumeration
  - Config backup discovery
  - Timthumb vulnerability detection
- **Nuclei Integration** - Template-based vulnerability scanning
  - WordPress-specific templates
  - Configurable severity filtering (critical, high, medium)
  - Fast concurrent scanning

### Plugin & Theme Discovery
- **Response-code oracle brute-force** — Probes `/wp-content/plugins/{slug}/` and `/wp-content/themes/{slug}/`
  - 200/301/403 = exists, 404 = absent
  - Version extraction from readme.txt / style.css
  - Fallback wordlists (30 plugins / 15 themes) with SecLists upgrade guide
- **Inactive plugin file accessibility** — Queries auth REST API, then probes files for deactivated plugins
- **Content spider** — Crawls same-origin links for forms, upload dirs, admin paths

### Authentication Testing
- **Login brute-force** — POST credential pairs to wp-login.php with redirect-based success detection
- **Cookie-based admin session** — `AdminSession` class for wp-admin surface inspection (site health, etc.)
- **REST API hardening audit** — CORS misconfiguration, route leakage, public user endpoint, plugin endpoint auth

### Host Fingerprinting
- **Hosting provider detection** — 12 platforms via response headers (WP Engine, Kinsta, Pantheon, etc.)
- **Bedrock detection** — roots.io path-structure analysis

### Security Hardening
- **SSRF Protection** - Blocks internal IP ranges and cloud metadata endpoints
- **Rate Limiting** - Configurable request throttling with exponential backoff
- **Safe XML Parsing** - XXE-protected XML-RPC handling
- **TLS Verification** - Control with `--insecure` flag for self-signed certs

### Report Generation
- JSON format output
- Markdown format output
- SARIF 2.1.0 format output (CI/CD integration)
- Custom filename support

### Concurrency
- **Risk Tier Parallel Execution**
  - Tier 1 (parallel): passive
  - Tier 2 (parallel): infrastructure, discovery, fingerprint, access, vuln
  - Tier 3 (parallel): users, api, xmlrpc, secrets, ssrf
  - Tier 4 (parallel): tools (wpscan, nuclei)

## Docker

Build and run the tool via Docker (no local Python setup needed):

```bash
# Build the image
docker compose build

# Quick scan
WP_TARGET=https://example.com docker compose run --rm recon

# Full scan with profile override
docker compose run --rm recon main --target https://example.com --profile full

# Generate SARIF output
docker compose run --rm recon main --target https://example.com --format sarif

# Use .env file for configuration
# (edit .env from .env.example first)
cp .env.example .env
docker compose up
```

Reports are written to `./reports/` (mounted as a volume).

## Installation

### External Tools (Optional)

For WPScan, Nuclei, FFUF, OpenDoor, and DNS modules:

```bash
# macOS
brew install wpscan nuclei bind  # whois included

# Ubuntu/Debian
apt install whois dnsutils
gem install wpscan
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Production Wordlists (Optional)

The tool works out-of-the-box with small fallback lists. For real scans, download SecLists:

```bash
# Download to project (git-ignored)
mkdir -p wordlists/external
curl -o wordlists/external/wp-plugins.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress-plugins.fuzz.txt
curl -o wordlists/external/wp-themes.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress-themes-fuzz.txt

# Or make them persistent (picked up automatically)
mkdir -p ~/.config/recon-wp/wordlists
cp wordlists/external/wp-plugins.txt ~/.config/recon-wp/wordlists/
```

See [wordlists/README.md](wordlists/README.md) for the full resolution chain and guide.

## CLI Options
| Flag | Description | Default |
|------|-------------|---------|
| `--target` / `-t` | Target WordPress URL (required) | - |
| `--profile` / `-p` | Scan profile (passive, light, standard, full, aggressive) | light |
| `--modules` / `-m` | Specific modules to run | profile default |
| `--output` / `-o` | Output directory | ./reports |
| `--format` / `-f` | Output format (json, markdown, sarif, all) | markdown |
| `--report-file` | Custom report filename | auto-generated |
| `--quiet` / `-q` | Report output only | false |
| `--threads` | Number of concurrent threads | 2 |
| `--timeout` | Request timeout in seconds | 10 |
| `--debug` / `-d` | Enable debug logging | false |
| `--insecure` | Skip TLS verification | false |
| `--wpscan` | Enable WPScan vulnerability scanner | false |
| `--wpscan-api-token` | WPScan API token for CVE data | env: WP_WPSCAN_API_TOKEN |
| `--wpscan-enumerate` | WPScan enumeration options | vp,vt,tt,cb,u |
| `--wpscan-timeout` | WPScan timeout in seconds | 600 |
| `--nuclei` | Enable Nuclei vulnerability scanner | false |
| `--nuclei-severity` | Nuclei severity filter (critical,high,medium) | medium,high,critical |
| `--wp-user` | WordPress username for authenticated scan | env: WP_USER |
| `--wp-app-password` | WordPress Application Password (WP >= 5.6) | env: WP_APPLICATION_PASSWORD |
| `--wp-auth-method` | Auth method: `app_password` or `cookie` | app_password |

## Profiles

| Profile | Modules |
|---------|---------|
| `passive` | passive |
| `light` | passive, infrastructure, discovery, fingerprint |
| `standard` | passive, infrastructure, discovery, fingerprint, users, api, xmlrpc, secrets, ssrf |
| `full` | All 12 modules including access and vuln |
| `aggressive` | users, xmlrpc, secrets, tools |

## Modules

| Module | Steps | Description |
|--------|-------|-------------|
| `access` | 7 | Auth REST API enumeration, login brute-force, cookie admin, REST hardening |
| `passive` | 5 | Passive reconnaissance (WHOIS, DNS, crt.sh, Wayback, Shodan) |
| `infrastructure` | 5 | Headers, TLS, WAF, port scanning, hosting fingerprint |
| `discovery` | 9 | Readme, license, sitemap, login, wp-cron, uploads, plugin/theme brute-force, spider |
| `fingerprint` | 6 | WordPress version, themes, plugins, asset versions |
| `vuln` | 3 | CVE correlation for core, plugins, and themes |
| `users` | 4 | REST API users, oEmbed, author ID enumeration |
| `api` | 3 | REST surface, IP leak, app passwords |
| `xmlrpc` | 5 | XML-RPC detection, methods, credentials, multicall, SSRF |
| `secrets` | 5 | Config backups, .env files, git exposure, debug logs |
| `ssrf` | 2 | oEmbed proxy, pingback SSRF |
| `tools` | 6 | External tool integrations (WPScan, Nuclei, FFUF, OpenDoor) |

## Environment Variables

Configuration can also be set via environment variables:

```bash
# Core settings
export WP_THREADS=4
export WP_TIMEOUT=10
export WP_LOG_LEVEL=DEBUG

# WPScan
export WP_WPSCAN_API_TOKEN=your_token

# Nuclei
export WP_NUCLEI_SEVERITY=critical,high

# Shodan
export WP_SHODAN_API_KEY=your_key

# WordPress auth
export WP_WP_USER=admin
export WP_WP_APPLICATION_PASSWORD=your_app_password
export WP_WP_AUTH_METHOD=app_password

# Content spider
export WP_SPIDER_MAX_DEPTH=2
export WP_SPIDER_MAX_PAGES=50
```

Or via `.env` file in project root:
```bash
WP_THREADS=4
WP_WPSCAN_API_TOKEN=your_token
WP_NUCLEI_SEVERITY=critical,high
WP_WP_USER=admin
WP_WP_APPLICATION_PASSWORD=your_app_password
WP_WP_AUTH_METHOD=app_password
WP_SPIDER_MAX_DEPTH=2
WP_SPIDER_MAX_PAGES=50
```

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for detailed security documentation.

### Protected Ranges
- RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x)
- Loopback (127.x, localhost)
- Cloud metadata (169.254.169.254, 100.100.100.200)

### Rate Limiting
- Default: 5 requests/second
- Exponential backoff on failure
- Configurable max retries

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_ssrf_protection.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing
```

## Project Structure

```
wordpress_testing_tool/
├── core/                   # Core atoms (HttpClient, Finding, Logger)
├── base/                   # Base classes (BaseStep, Runner)
├── steps/                  # Concrete step implementations
│   ├── access/             # Authenticated REST API + login brute-force + cookie admin
│   ├── passive/            # Passive reconnaissance steps
│   ├── infrastructure/     # Infrastructure checks + hosting fingerprint
│   ├── discovery/         # File/discovery checks + brute-force + spider
│   ├── fingerprint/        # Version/theme/plugin detection
│   ├── vuln/              # CVE correlation steps
│   ├── users/             # User enumeration
│   ├── api/               # REST API checks
│   ├── xmlrpc/            # XML-RPC checks
│   ├── secrets/           # Secret exposure checks
│   ├── ssrf/              # SSRF vulnerability checks
│   └── tools/             # External tool integrations (WPScan, Nuclei)
├── modules/                # Module definitions
├── utils/                  # Utilities (report, rate_limiter, etc.)
├── tests/                  # Test suite
└── main.py                 # CLI entry point
```

## Documentation

- [Module Reference](docs/MODULES.md) - Complete documentation of all steps across 12 modules
- [Architecture Plan](docs/architecture_plan.md) - Project architecture
- [Security Documentation](docs/SECURITY.md) - Security features
- [Changelog](CHANGELOG.md) - Change history
- [Code Documentation](docs/code.md) - Code abstractions and execution flow
- [Wordlists Guide](wordlists/README.md) - Wordlist configuration and production setup

## License

MIT License