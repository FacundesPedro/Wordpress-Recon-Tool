# WordPress Reconnaissance Tool

A security-focused WordPress reconnaissance and vulnerability scanning tool with passive reconnaissance, security hardening features, and comprehensive report generation.

## Features

### Passive Reconnaissance
- **WHOIS Enumeration** - Domain registration data with TLD-aware parsing
- **DNS Enumeration** - A, AAAA, MX, TXT, NS, CNAME records with SPF analysis
- **Certificate Transparency** - Subdomain discovery via crt.sh
- **Wayback Machine** - Historical URL enumeration

### Vulnerability Scanning
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

### Security Hardening
- **SSRF Protection** - Blocks internal IP ranges and cloud metadata endpoints
- **Rate Limiting** - Configurable request throttling with exponential backoff
- **Safe XML Parsing** - XXE-protected XML-RPC handling
- **TLS Verification** - Control with `--insecure` flag for self-signed certs

### Report Generation
- JSON format output
- Markdown format output
- Custom filename support

### Concurrency
- **Risk Tier Parallel Execution**
  - Tier 1 (parallel): passive
  - Tier 2 (parallel): infrastructure, discovery, fingerprint
  - Tier 3 (parallel): users, api, xmlrpc, secrets, ssrf
  - Tier 4 (parallel): tools (wpscan, nuclei)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd wordpress_testing_tool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### External Dependencies (Optional)

For full functionality, install these system tools:
```bash
# macOS
brew install bind wpscan nuclei

# Ubuntu/Debian
apt install dnsutils whois

# WPScan (Ruby)
gem install wpscan

# Nuclei (Go)
go install -v github.com/projectdiscovery/nuclei/v3/...@latest
```

### Wordlists (Optional)

Wordlists are stored externally at `~/.config/recon-wp/wordlists/`:

```bash
mkdir -p ~/.config/recon-wp/wordlists/whois
# Place WHOIS pattern files in this directory
```

See [docs/WHOIS_WORDLIST.md](docs/WHOIS_WORDLIST.md) for configuration.

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

### JSON Output
```bash
python main.py main --target https://example.com --format json
```

### Custom Report Filename
```bash
python main.py main --target https://example.com --report-file my_scan
```

### Skip TLS Verification (for self-signed certs)
```bash
python main.py main --target https://example.com --insecure
```

### WPScan Vulnerability Scanning
```bash
# Run WPScan with API token (recommended for CVE data)
python main.py main --target https://example.com --wpscan --wpscan-api-token YOUR_TOKEN

# WPScan with custom enumeration
python main.py main --target https://example.com --wpscan --wpscan-enumerate "vp,vt,u"

# WPScan with extended timeout (for large sites)
python main.py main --target https://example.com --wpscan --wpscan-timeout 900
```

### Nuclei Vulnerability Scanning
```bash
# Run Nuclei with default severity (medium, high, critical)
python main.py main --target https://example.com --nuclei

# Run Nuclei with critical and high severity only
python main.py main --target https://example.com --nuclei --nuclei-severity critical,high

# Run both WPScan and Nuclei
python main.py main --target https://example.com --wpscan --nuclei
```

### List Available Options
```bash
python main.py list-profiles
python main.py list-modules
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--target` / `-t` | Target WordPress URL (required) | - |
| `--profile` / `-p` | Scan profile (passive, light, standard, full, aggressive) | light |
| `--modules` / `-m` | Specific modules to run | profile default |
| `--output` / `-o` | Output directory | ./reports |
| `--format` / `-f` | Output format (json, markdown, both) | markdown |
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

## Profiles

| Profile | Modules |
|---------|---------|
| `passive` | passive |
| `light` | passive, infrastructure, discovery, fingerprint |
| `standard` | passive, infrastructure, discovery, fingerprint, users, api, xmlrpc, secrets, ssrf |
| `full` | All modules including tools |
| `aggressive` | users, xmlrpc, secrets, tools |

## Modules

| Module | Description |
|--------|-------------|
| `passive` | Passive reconnaissance (WHOIS, DNS, crt.sh, Wayback) |
| `infrastructure` | Headers, TLS, WAF, port scanning |
| `discovery` | Readme, license, sitemap, login page, wp-cron, uploads |
| `fingerprint` | WordPress version, themes, plugins |
| `users` | REST API users, oEmbed, author ID enumeration |
| `api` | REST surface, IP leak, app passwords |
| `xmlrpc` | XML-RPC detection, methods, credentials, multicall, SSRF |
| `secrets` | Config backups, .env files, git exposure |
| `ssrf` | oEmbed proxy, pingback SSRF |
| `tools` | External tool integrations (WPScan, Nuclei) |

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

# Other
export WP_SHODAN_API_KEY=your_key
```

Or via `.env` file in project root:
```bash
WP_THREADS=4
WP_WPSCAN_API_TOKEN=your_token
WP_NUCLEI_SEVERITY=critical,high
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
│   ├── passive/            # Passive reconnaissance steps
│   ├── infrastructure/     # Infrastructure checks
│   ├── discovery/         # File/discovery checks
│   ├── fingerprint/        # Version/theme/plugin detection
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

- [Module Reference](docs/MODULES.md) - Complete documentation of all steps across 10 modules
- [Architecture Plan](docs/architecture_plan.md) - Project architecture
- [Security Documentation](docs/SECURITY.md) - Security features
- [Changelog](CHANGELOG.md) - Change history
- [Code Documentation](docs/code.md) - Code abstractions and execution flow
- [WHOIS Wordlists](docs/WHOIS_WORDLIST.md) - Wordlist configuration

## License

MIT License