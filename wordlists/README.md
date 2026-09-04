# WordPress Testing Tool — Wordlists

This directory contains built-in wordlists for out-of-the-box scans.
The tool works with these defaults — no setup required.

For production scans, some steps benefit from larger external wordlists.
This guide covers which steps need them and how to set them up.

---

## Quick Reference: What Needs Production Wordlists

| Step / Module | Needs manual setup? | Why |
|---------------|-------------------|-----|
| `FfufDirectoryStep` | **Yes** — supply a large wordlist | Brute-force directory discovery — scales with wordlist size |
| `FfufFilesStep` | **Yes** — supply a large wordlist | Brute-force file discovery — scales with wordlist size |
| `FfufWpStep` | **Yes** — supply a large wordlist | WP path brute-force — scales with wordlist size |
| `OpenDoorStep` | **Yes** — supply a large wordlist | WP path brute-force — scales with wordlist size |
| `XmlrpcCredsStep` | **Optional** — 20 default pairs for quick check | Brute-force creds testing — more creds = more findings |
| `XmlrpcMulticallStep` | **Optional** — same defaults as above | Batch creds testing — same as above |
| `WhoisStep` (TLD patterns) | **Optional** — 22 hardcoded fallback patterns | TLD-specific parsing — only needed for uncommon TLDs |
| `HeadersStep` | **No** — 7 headers is exhaustive | Finite set of relevant headers |
| `WafStep` | **No** — 15 signatures is exhaustive | Finite set of major WAF products |
| `PortsStep` | **No** — 24 ports is exhaustive | Finite set of interesting service ports |
| `LoginPageStep` | **No** — 5 paths is exhaustive | Finite set of standard WP login URLs |
| `WpConfigBackupStep` | **No** — 9 patterns is exhaustive | Finite set of common backup extensions |
| `EnvFileStep` | **No** — 6 paths is exhaustive | Finite set of common env file names |
| `XmlrpcMethodsStep` | **No** — 5 methods is exhaustive | Finite set of dangerous XML-RPC methods |

**TL;DR**: Only **FFUF**, **OpenDoor**, **credentials**, and optionally **WHOIS patterns**
benefit from production wordlists. Everything else works with built-in defaults.

---

## Wordlist Resolution Chain

The tool resolves wordlists in this priority order:

```
1. CLI flag (e.g., --ffuf-wordlist /path/to/list.txt)
2. Config key (e.g., WP_FFUF_WORDLIST env var)
3. Local ./wordlists/<file> (this directory)
4. ~/.config/recon-wp/wordlists/<file> (user override)
5. Hardcoded defaults (always available)
```

You never need to edit files in this directory. To override a wordlist,
place your file at `~/.config/recon-wp/wordlists/<path>` and the tool
will pick it up automatically.

---

## FFUF (Directory, Files, WordPress Paths)

**Why production wordlists**: FFUF is a brute-force fuzzer. Its
effectiveness scales directly with wordlist size. The built-in
wordlists (~60-120 items) are samples — real scans use 10k-1M+
entries.

**Built-in files** (`wordlists/ffuf/`):
- `directories.txt` (70 items)
- `files.txt` (117 items)
- `wp_paths.txt` (61 items)
- `wp_plugins.txt` (~30 items)
- `wp_themes.txt` (8 items)

### Source 1: SecLists (70k+ stars, actively maintained)

The standard wordlist collection for web security testing. Latest
release: **2026.1** (March 2026).

```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/tools/SecLists
```

**Recommended paths** for FFUF:

| FFUF step | Best SecLists wordlist |
|-----------|------------------------|
| Directory discovery | `Discovery/Web-Content/combined_directories.txt` |
| File discovery | `Discovery/Web-Content/common.txt` |
| WordPress paths | `Discovery/Web-Content/wordpress/` |
| Aggressive directory | `Discovery/Web-Content/directory-list-2.3-medium.txt` |

Note: DirBuster wordlists now carry a `DirBuster-2007` prefix to
indicate their age. Prefer the `combined_*` or `raft-*` wordlists.

### Source 2: WPScan Data Files (50k+ plugin entries)

WPScan maintains wordlists for WordPress plugin and theme detection.

```bash
git clone --depth 1 https://github.com/wpscanteam/wpscan.git ~/tools/wpscan
# Wordlists at: /data/wordlists/
```

For plugin/theme brute-force via FFUF, combine WPScan's wordlists
with SecLists for maximum coverage.

### Source 3: FFUF Project Wordlists

```bash
git clone --depth 1 https://github.com/ffuf/ffuf-wordlists.git ~/tools/ffuf-wordlists
```

### Usage

```bash
# Single wordlist (applies to all three FFUF steps)
python main.py --ffuf --ffuf-wordlist ~/tools/SecLists/Discovery/Web-Content/common.txt

# Environment variable
export WP_FFUF_WORDLIST=~/tools/SecLists/Discovery/Web-Content/common.txt

# Persistent override (no flags needed)
cp ~/tools/SecLists/Discovery/Web-Content/combined_directories.txt \
   ~/.config/recon-wp/wordlists/ffuf/directories.txt
```

---

## OpenDoor (Paths, Backups, Configs, Sensitive Files)

**Why production wordlists**: Same as FFUF — OpenDoor is a
brute-force path discovery tool. Built-in wordlists are samples.

**Built-in files** (`wordlists/opendoor/`):
- `wp_paths.txt` (61 items)
- `backup_files.txt` (90 items)
- `config_files.txt` (76 items)
- `sensitive_paths.txt` (~108 items)

### Source: SecLists

```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/tools/SecLists
```

**OpenDoor modes → recommended SecLists paths**:

| Mode | Local file | SecLists path |
|------|-----------|---------------|
| `wp_paths` (default) | `opendoor/wp_paths.txt` | `Discovery/Web-Content/wordpress/` |
| `backup` | `opendoor/backup_files.txt` | `Discovery/Web-Content/backup_files/` |
| `config` | `opendoor/config_files.txt` | `Discovery/Web-Content/config/` |
| `sensitive` | `opendoor/sensitive_paths.txt` | `Discovery/Web-Content/sensitive/` |

### Usage

```bash
# Specific mode + wordlist
python main.py --opendoor --opendoor-mode backup \
  --opendoor-wordlist ~/tools/SecLists/Discovery/Web-Content/backup_files/combined.txt

# Environment variable
export WP_OPENDOOR_WORDLIST=~/tools/SecLists/Discovery/Web-Content/wordpress/combined.txt

# Persistent override
cp ~/tools/SecLists/Discovery/Web-Content/wordpress/combined.txt \
   ~/.config/recon-wp/wordlists/opendoor/wp_paths.txt
```

---

## Credential Wordlists (XML-RPC Brute Force)

**Why production wordlists**: The built-in 20 common credential pairs
let you quickly check for weak default creds. For real brute-forcing,
you need a larger, context-aware list.

**Built-in file**: `wordlists/credentials/common_wp.txt` (20 pairs)

### Source 1: Create a custom wordlist

```bash
# Format: username:password (one per line)
cat > my-wordlist.txt << 'EOF'
admin:Password123
admin:LetMeIn2026
admin:Welcome1
root:toor
EOF
```

### Source 2: RockYou (14M+ passwords)

Available on Kali via the `wordlists` package (current: **2026.2.0**):

```bash
# Debian/Kali
sudo apt install wordlists
gunzip /usr/share/wordlists/rockyou.txt.gz

# Or from the GitHub mirror
git clone https://github.com/zacheller/rockyou.git ~/tools/rockyou
```

### Source 3: Combine with user enumeration output

First enumerate users with the Users module, then feed them into
a targeted brute-force:

```bash
# Step 1: Find users
python main.py -t https://example.com -p passive,users

# Step 2: Create a targeted wordlist from discovered users
# (pairs each user with common passwords)

# Step 3: Run credential testing with custom wordlist
python main.py -t https://example.com -m xmlrpc \
  --override wordlist=./targeted-creds.txt
```

### Usage

```bash
# Environment variable
export WP_WORDLIST=~/tools/SecLists/Passwords/xato-net-10-million-passwords-100000.txt

# Persistent override
cp my-creds.txt ~/.config/recon-wp/wordlists/credentials/common_wp.txt
```

### ⚠️ Warnings

- Rate-limited to 5 req/s with exponential backoff (1s → 2s → 4s)
- Lockout detection: skips after 3 consecutive failures
- The tool does not bypass WAF or login lockout policies
- Public wordlists on production systems may trigger IDS/IPS alerts
- Start with a small targeted list before scaling up

---

## WHOIS TLD Patterns

**Why production wordlists**: Different TLD registries use different
WHOIS output formats. TLD-specific wordlists enable accurate field
extraction for less common TLDs.

**Built-in fallback**: 22 hardcoded patterns (always available)

**Pre-built files** (`wordlists/whois/`):

| File | TLDs | Patterns |
|------|------|----------|
| `tld_com.txt` | .com, .net, .org, .uk, .io, .info, .biz | 10 |
| `tld_br.txt` | .br | 15 |
| `tld_eu.txt` | .eu, .de, .fr, .es, .it | 10 |

### Creating custom TLD patterns

```bash
# 1. Inspect the raw WHOIS output
whois example.tld

# 2. Create a pattern file for that TLD
mkdir -p ~/.config/recon-wp/wordlists/whois
cat > ~/.config/recon-wp/wordlists/whois/tld_my.txt << 'EOF'
# field_name:regex_pattern
registrar:Registrar:\s*(.+)
name_server:Name\s+[Ss]erver:\s*(.+)
created:Creation\s+[Dd]ate:\s*(.+)
expires:Expir(y|ation)\s+[Dd]ate:\s*(.+)
EOF
```

### Available field names

| Field | Purpose |
|-------|---------|
| `registrar` | Domain registrar name |
| `whois_server` | Registrar WHOIS server |
| `name_server` | Nameserver (standard format) |
| `nserver` | Nameserver (alternative, e.g. .br) |
| `created` | Domain creation date |
| `creation_date` | Creation date (alternative) |
| `expires` | Expiration date |
| `expiry_date` | Expiry date (alternative) |
| `updated` | Last updated date |
| `changed` | Changed date (alternative, e.g. .br) |
| `owner` | Domain owner (e.g. .br) |
| `registrant` | Registrant name (standard) |
| `organization` | Organization name |
| `responsible` | Responsible person (e.g. .br) |
| `admin_c` | Admin contact handle |
| `tech_c` | Tech contact handle |
| `status` | Domain status |
| `domain_status` | Status (alternative) |
| `dnssec` | DNSSEC status |
| `ds_rdata` | DS record data (e.g. .br) |
| `country` | Country code |
| `nic_handle` | NIC handle (e.g. .br) |
| `email` | Contact email |

### Regex notes

- Patterns are compiled with `re.MULTILINE | re.IGNORECASE`
- Use `(.+)` as the capturing group
- Prefix with `^` for line-start matching
- Lines starting with `#` are comments
- Test patterns against real WHOIS output from your target TLD

---

## Webapp Asset Wordlist (Source Discovery Fuzzing)

Used by the `webapp` module's source discovery (`utils/source_discovery.py`)
to fuzz common static asset paths when `WP_SOURCE_SCAN_FUZZ=true` (default).

**Built-in file**: `wordlists/webapp/assets.txt` (~44 common JS/CSS/config paths)

### Custom list

```bash
# Via config key (highest priority)
export WP_SOURCE_ASSETS=/path/to/my-assets.txt

# Or persistent override
mkdir -p ~/.config/recon-wp/wordlists/webapp
cp my-assets.txt ~/.config/recon-wp/wordlists/webapp/assets.txt
```

One asset path per line; `#` comments and blank lines are ignored. Paths are
resolved relative to the target origin (absolute or root-relative).

---

## External Wordlist Directory (Persistent Overrides)

Place files at `~/.config/recon-wp/wordlists/<path>` to override both
the local `./wordlists/` files and hardcoded defaults without any
CLI flags:

```
~/.config/recon-wp/wordlists/
├── whois/
│   ├── tld_com.txt
│   ├── tld_br.txt
│   └── tld_eu.txt
├── credentials/
│   └── common_wp.txt
├── ffuf/
│   ├── directories.txt
│   ├── files.txt
│   ├── wp_paths.txt
│   ├── wp_plugins.txt
│   └── wp_themes.txt
├── opendoor/
    ├── backup_files.txt
    ├── config_files.txt
    ├── sensitive_paths.txt
    └── wp_paths.txt
└── webapp/
    └── assets.txt
```

---

## One-shot Examples

```bash
# Full production scan with SecLists
python main.py -t https://example.com -p full \
  --ffuf --ffuf-wordlist ~/tools/SecLists/Discovery/Web-Content/common.txt \
  --opendoor --opendoor-wordlist ~/tools/SecLists/Discovery/Web-Content/backup_files.txt

# Quick cred check with custom wordlist
python main.py -t https://example.com -m xmlrpc \
  --override wordlist=./my-creds.txt

# Light + FFUF with WPScan plugin wordlist
python main.py -t https://example.com \
  -p light --ffuf \
  --ffuf-wordlist ~/tools/wpscan/data/wordlists/wp_plugins.txt

# Persistent override (no flags needed)
cp ~/tools/SecLists/Discovery/Web-Content/combined_directories.txt \
   ~/.config/recon-wp/wordlists/ffuf/directories.txt
python main.py -t https://example.com --ffuf
```
