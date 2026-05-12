# WHOIS Wordlist Configuration

This document describes how to configure external wordlists for WHOIS field extraction.

## Location

External wordlists should be placed in:

```
~/.config/recon-wp/wordlists/whois/
```

**Note**: Wordlists are NOT stored in the repository. They are stored externally to allow easy customization without modifying the codebase.

## Directory Structure

```
~/.config/recon-wp/
└── wordlists/
    └── whois/
        ├── fields.txt         # Generic field patterns (fallback)
        ├── tld_br.txt        # Brazilian domain patterns (.br)
        ├── tld_eu.txt        # European domain patterns (.eu, .de, .fr, etc.)
        ├── tld_com.txt       # Generic .com, .net, .org patterns
        └── tld_default.txt   # Default fallback patterns
```

## Files

| File | TLDs | Description | Required |
|------|------|-------------|----------|
| `fields.txt` | All | Generic field extraction patterns | No (uses fallback) |
| `tld_br.txt` | .br | Brazilian domain patterns | No |
| `tld_eu.txt` | .eu, .de, .fr, .es, .it | European domain patterns | No |
| `tld_com.txt` | .com, .net, .org | Standard TLD patterns | No |
| `tld_default.txt` | All | Fallback patterns | No |

## Pattern Format

Each line should be: `field_name:regex_pattern`

Example:
```
registrar:Registrar(?:\s+WHOIS\s+Server)?:\s*(.+)
name_server:Name\s+Server:\s*(.+)
nserver:^nserver:\s*(.+)
```

### Field Names

| Field | Description |
|-------|-------------|
| `registrar` | Domain registrar name |
| `whois_server` | Registrar WHOIS server |
| `whois` | WHOIS server (alternative) |
| `name_server` | Nameserver (standard format) |
| `nserver` | Nameserver (alternative format) |
| `created` | Domain creation date |
| `creation_date` | Creation date (alternative) |
| `expires` | Expiration date |
| `expiry_date` | Expiry date (alternative) |
| `updated` | Last updated date |
| `changed` | Changed date (alternative) |
| `owner` | Domain owner |
| `registrant` | Registrant name |
| `responsible` | Responsible person |
| `admin_c` | Admin contact handle |
| `tech_c` | Tech contact handle |
| `status` | Domain status |
| `dnssec` | DNSSEC status |
| `country` | Country code |

## Regex Guidelines

1. **Capturing Group**: Use `(.+)` to extract the value
2. **Line Start**: Use `^` for line-start matching where appropriate
3. **Flags**: The parser uses `re.MULTILINE | re.IGNORECASE` flags
4. **Non-greedy**: Use `.+?` instead of `.+` to avoid over-matching
5. **Comments**: Lines starting with `#` are ignored

## Examples

### Brazilian Domain (.br)
```
nserver:^nserver:\s*(.+)
owner:^owner:\s*(.+)
responsible:^responsible:\s*(.+)
changed:^changed:\s*(.+)
```

### Standard .com/.org
```
registrar:Registrar(?:\s+WHOIS\s+Server)?:\s*(.+)
name_server:Name\s+Server:\s*(.+)
created:Created:\s*(.+)
```

## Fallback Behavior

If wordlists are not found, the tool will:

1. Check `~/.config/recon-wp/wordlists/whois/`
2. Use hardcoded fallback patterns (always available)

When using fallback patterns, an INFO message will be shown:
```
[INFO] [WhoisStep] Wordlist not found, using fallback patterns. Set wordlists via: ~/.config/recon-wp/wordlists/whois/
```

## Adding Custom TLD Patterns

To add support for a new TLD:

1. Create a new file: `~/.config/recon-wp/wordlists/whois/tld_XX.txt`
2. Add patterns specific to that TLD's WHOIS format
3. The parser will automatically use TLD-specific patterns when available

## Troubleshooting

### Wordlist not loading

1. Check that files are in the correct directory:
   ```bash
   ls -la ~/.config/recon-wp/wordlists/whois/
   ```

2. Check file permissions (must be readable):
   ```bash
   chmod 644 ~/.config/recon-wp/wordlists/whois/*.txt
   ```

3. Verify pattern syntax (no validation errors)

### Patterns not matching

1. Use `--debug` flag to see which patterns are loaded
2. Check WHOIS output format with:
   ```bash
   whois example.com
   ```
3. Adjust regex patterns to match actual output format

## Future Extensions

- [ ] Support for TLD-specific wordlists auto-detection
- [ ] Pattern validation on load
- [ ] Built-in pattern testing utility
