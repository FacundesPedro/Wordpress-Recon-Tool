# WordPress Testing Tool - Wordlists

This directory contains local wordlists for various security testing tools and steps. These are small, curated wordlists for quick testing. For production use, refer to the external references below.

## Local Wordlists

### FFUF Wordlists
- `directories.txt` - Common directory names
- `files.txt` - Common file names
- `wp_plugins.txt` - Top WordPress plugins
- `wp_themes.txt` - Top WordPress themes
- `wp_paths.txt` - WordPress-specific paths

### OpenDoor Wordlists
- `backup_files.txt` - Backup file patterns
- `config_files.txt` - Configuration file pattern
- `sensitive_paths.txt` - Sensitive paths
- `wp_paths.txt` - WordPress-specific paths

### Credentials
- `common_wp.txt` - Common WordPress credentials (username:password pairs)

### Infrastructure
- `security_headers.txt` - HTTP security headers to check
- `common.txt` - Common network ports to scan
- `waf_signatures.json` - WAF detection signatures (JSON format)

### Secrets
- `wp_config_backups.txt` - WP-config backup file patterns
- `env_files.txt` - Environment file paths to check

### Discovery
- `login_pages.txt` - WordPress login page paths

### XML-RPC
- `dangerous_methods.txt` - Potentially dangerous XML-RPC methods

## Production-Ready Wordlists

### SecLists (Recommended)

The most comprehensive wordlist collection for web security testing.

```bash
# Clone the repository
git clone --depth 1 https://github.com/danielmiessler/SecLists.git

# Install location
mv SecLists ~/tools/
```

**FFUF Wordlists from SecLists:**
```bash
# General web content
~/tools/SecLists/Discovery/Web-Content/
~/tools/SecLists/Discovery/Web-Content/ffuf/

# WordPress-specific
~/tools/SecLists/Discovery/Web-Content/wordpress/

# Directory fuzzing
~/tools/SecLists/Discovery/Web-Content/Dirb/
```

**OpenDoor Wordlists from SecLists:**
```bash
# Backup files
~/tools/SecLists/Discovery/Web-Content/Backup_Files/

# Sensitive files
~/tools/SecLists/Discovery/Web-Content/Sensitive/

# Configuration files
~/tools/SecLists/Discovery/Web-Content/Config_Files/
```

### Other Wordlist Sources

- **Kali Wordlists**: `/usr/share/wordlists/`
- **DirBuster wordlists**: https://github.com/Hackplayers/dirbuster
- **Gobuster wordlists**: https://github.com/OJ Reeves/gobuster
- **FFUF wordlists**: https://github.com/ffuf/wordlists
- **SecList WordPress**: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/wordpress

## How to Use External Wordlists

### Option 1: Command Line
```bash
# FFUF with external wordlist
python3 main.py --ffuf --ffuf-wordlist ~/tools/SecLists/Discovery/Web-Content/ffuf/directory-list-2.3-medium.txt

# OpenDoor with external wordlist
python3 main.py --opendoor --opendoor-wordlist ~/tools/SecLists/Discovery/Web-Content/Backup_Files/
```

### Option 2: Configuration File
```python
# In config.py
class ScanConfig(BaseSettings):
    # FFUF settings
    ffuf_wordlist: str = Field(default="~/tools/SecLists/Discovery/Web-Content/ffuf/directory-list-2.3-medium.txt")
    
    # OpenDoor settings
    opendoor_wordlist: str = Field(default="~/tools/SecLists/Discovery/Web-Content/Backup_Files/")
```

### Option 3: Environment Variables
```bash
# FFUF
export WP_FFUF_WORDLIST="~/tools/SecLists/Discovery/Web-Content/ffuf/directory-list-2.3-medium.txt"

# OpenDoor
export WP_OPENDOOR_WORDLIST="~/tools/SecLists/Discovery/Web-Content/Backup_Files/"
```

## Adding Custom Wordlists

1. Create a new directory in `wordlists/`
2. Add your wordlist files
3. Update the configuration to reference your wordlists
4. Use the wordlist via command line or configuration

Example:
```
wordlists/
├── ffuf/
│   ├── directories.txt
│   └── custom_wordlist.txt  # Your custom wordlist
└── opendoor/
    ├── backup_files.txt
    └── custom_wordlist.txt  # Your custom wordlist
```
