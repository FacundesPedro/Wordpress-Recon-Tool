# Missing Wordlists / External Data

The following steps require wordlists or external data that needs to be sourced.

---

## WHOIS Wordlists

**Location**: `~/.config/recon-wp/wordlists/whois/`

**Status**: ✅ **IMPLEMENTED**

| File | TLDs | Description | Status |
|------|------|-------------|--------|
| `fields.txt` | All | Generic field extraction patterns | ✅ |
| `tld_br.txt` | .br | Brazilian domain patterns | ✅ |
| `tld_eu.txt` | .eu, .de, .fr, .es, .it | European domain patterns | ✅ |
| `tld_com.txt` | .com, .net, .org | Standard TLD patterns | ✅ |
| `tld_default.txt` | All | Default fallback patterns | ✅ |

**Documentation**: See `docs/WHOIS_WORDLIST.md`

**Usage**:
```bash
# Wordlists are automatically loaded from:
~/.config/recon-wp/wordlists/whois/
```

---

## Wordlists Needed (Future)

> **Note**: Passive module is now complete with WHOIS, DNS, crt.sh, and Wayback Machine steps.

### Phase 2 - Wordlist-based Enumeration

| Step | File | Description | Source |
|------|------|-------------|--------|
| `PluginStep` | `wordlists/wp-plugins.txt` | Common WordPress plugin names | wpscan wordlist, fuzzdb, SecLists |
| `ThemeStep` | `wordlists/wp-themes.txt` | Common WordPress theme names | wpscan wordlist, fuzzdb, SecLists |
| `ScriptsStep` | `wordlists/wp-paths.txt` | Common WP paths/scripts | wpscan wordlist, SecLists |
| `PortsStep` | `wordlists/ports.txt` | Common ports for scanning | nmap-services |

---

## External Tool Integrations

| Step | Binary | Notes |
|------|--------|-------|
| `WpscanStep` | `wpscan` | Needs API token for full scans |
| `NucleiStep` | `nuclei` | Needs templates |
| `FfufStep` | `ffuf` | Needs wordlists for fuzzing |
| `OpenDoorStep` | `opendoor` | Known tool, needs installation |

---

## TODO

### Completed
- [x] Create `wordlists/whois/` directory structure
- [x] Add WHOIS field patterns (`fields.txt`)
- [x] Add TLD-specific patterns (`tld_br.txt`, `tld_eu.txt`, `tld_com.txt`, `tld_default.txt`)
- [x] Implement `utils/whois_parser.py` with wordlist support
- [x] Update `WhoisStep` to use wordlist parser

### Completed (2026-05-12)
- [x] Create `wordlists/` directory structure with subdirectories per module
- [x] Add default wordlist files for ffuf (directories, files, wp_plugins, wp_themes, wp_paths)
- [x] Add default wordlist files for opendoor (backup_files, config_files, sensitive_paths, wp_paths)
- [x] Add credentials wordlist (`common_wp.txt`)
- [x] Add security headers list, common ports, WAF signatures
- [x] Add discovery/login pages, secrets/env files, secrets/wp_config_backups
- [x] Add XML-RPC dangerous methods list
- [x] Document external wordlist usage in `wordlists/README.md`

### Pending
- [ ] Download larger `wp-plugins.txt` from wpscan project for production use
- [ ] Download larger `wp-themes.txt` from wpscan project for production use

---

## Sources

- **WPScan wordlists**: https://github.com/wpscanteam/wpscan/tree/master/data/wordlists
- **SecLists**: https://github.com/danielmiessler/SecLists
- **nmap-services**: typically in `/usr/share/nmap/nmap-services`
- **WHOIS patterns**: See `docs/WHOIS_WORDLIST.md`

---

## External Directory Structure

```
~/.config/recon-wp/
├── wordlists/
│   └── whois/           # WHOIS patterns (implemented)
│       ├── fields.txt
│       ├── tld_br.txt
│       ├── tld_eu.txt
│       ├── tld_com.txt
│       └── tld_default.txt
│   └── wpscan/          # Future: WPScan enumeration wordlists
│       ├── plugins.txt
│       ├── themes.txt
│       └── paths.txt
└── config.yaml          # Future: Configuration file
```
