# recon_wp/utils/whois_parser.py
"""WHOIS output parser with wordlist-based field extraction.

This module provides flexible WHOIS parsing using wordlist patterns
with fallback to hardcoded patterns if wordlists are not available.

Usage:
    parser = WhoisParser()
    data = parser.parse(whois_output)
    finding_data = parser.to_finding_dict(data)
"""

import re
from dataclasses import dataclass
from typing import Optional

from utils.wordlist_loader import (
    get_wordlist_dir_message,
    get_wordlist_path,
    load_key_value_lines,
)


@dataclass
class WhoisPattern:
    """A WHOIS field extraction pattern."""

    name: str
    pattern: str
    tld_specific: bool = False


HARDCODED_PATTERNS: list[WhoisPattern] = [
    WhoisPattern("registrar", r"Registrar(?:\s+WHOIS\s+Server)?:\s*(.+)"),
    WhoisPattern("whois_server", r"Whois\s+Server:\s*(.+)"),
    WhoisPattern("whois", r"^whois:\s*(.+)"),
    WhoisPattern("name_server", r"Name\s+Server:\s*(.+)"),
    WhoisPattern("nserver", r"^nserver:\s*(.+)"),
    WhoisPattern("created", r"(?:Created|Creation\s+Date|Created\s+On):\s*(.+)"),
    WhoisPattern("creation_date", r"^created:\s*(.+)"),
    WhoisPattern(
        "expires",
        r"(?:Expires?|Expiry\s+Date|Expiration\s+Date|Registry\s+Expiry\s+Date):\s*(.+)",
    ),
    WhoisPattern("expiry_date", r"^expires:\s*(.+)"),
    WhoisPattern(
        "updated", r"(?:Updated|Updated\s+Date|Last\s+Updated|Modified):\s*(.+)"
    ),
    WhoisPattern("changed", r"^changed:\s*(.+)"),
    WhoisPattern("owner", r"^owner:\s*(.+)"),
    WhoisPattern("registrant", r"Registrant:\s*(.+)"),
    WhoisPattern("organization", r"(?:Organization|Org):\s*(.+)"),
    WhoisPattern("responsible", r"^responsible:\s*(.+)"),
    WhoisPattern("admin_c", r"^admin-c:\s*(.+)"),
    WhoisPattern("tech_c", r"^tech-c:\s*(.+)"),
    WhoisPattern("status", r"(?:Domain\s+)?Status:\s*(.+)"),
    WhoisPattern("domain_status", r"^status:\s*(.+)"),
    WhoisPattern("dnssec", r"DNSSEC:\s*(.+)"),
    WhoisPattern("ds_rdata", r"^ds-rdata:\s*(.+)"),
    WhoisPattern("country", r"^country:\s*(.+)"),
    WhoisPattern("nic_handle", r"^nic-hdl-br:\s*(.+)"),
    WhoisPattern("email", r"^e-?mail:\s*(.+)"),
]


class WhoisParser:
    """Parse WHOIS output using wordlist patterns with fallback.

    Gracefully handles missing wordlists by falling back to hardcoded patterns.
    """

    TLD_PATTERNS = {
        "br": "tld_br.txt",
        "eu": "tld_eu.txt",
        "de": "tld_eu.txt",
        "fr": "tld_eu.txt",
        "es": "tld_eu.txt",
        "it": "tld_eu.txt",
        "uk": "tld_com.txt",
        "com": "tld_com.txt",
        "net": "tld_com.txt",
        "org": "tld_com.txt",
        "io": "tld_com.txt",
        "info": "tld_com.txt",
        "biz": "tld_com.txt",
    }

    def __init__(self, use_wordlist: bool = True):
        self.patterns: list[WhoisPattern] = []
        self.using_wordlist = False
        self.loaded_tld: Optional[str] = None
        self._load_patterns(use_wordlist)

    def _load_patterns(self, use_wordlist: bool):
        """Load hardcoded patterns as base.

        Wordlist patterns (if loaded) will replace these.
        """
        self.patterns = list(HARDCODED_PATTERNS)

    def load_tld_patterns(self, tld: str) -> bool:
        """Load TLD-specific patterns from wordlist.

        Args:
            tld: TLD to load patterns for (e.g., "br", "com")

        Returns:
            True if patterns were loaded from wordlist, False if using fallback
        """
        tld_lower = tld.lower()

        if tld_lower not in self.TLD_PATTERNS:
            return False

        filename = f"whois/{self.TLD_PATTERNS[tld_lower]}"
        path = get_wordlist_path(filename)

        if not path:
            return False

        try:
            field_dict = load_key_value_lines(path)
            if not field_dict:
                return False

            new_patterns = []
            for name, pattern_str in field_dict.items():
                if not name or not pattern_str:
                    continue
                try:
                    re.compile(pattern_str)
                    new_patterns.append(
                        WhoisPattern(name=name, pattern=pattern_str, tld_specific=True)
                    )
                except re.error:
                    continue

            if new_patterns:
                self.patterns = new_patterns
                self.using_wordlist = True
                self.loaded_tld = tld_lower
                return True

        except Exception:
            return False

        return False

    def _detect_tld(self, domain: str) -> str:
        """Detect TLD from domain."""
        if not domain:
            return "generic"
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            return parts[-1]
        return "generic"

    def parse(self, whois_output: str, domain: str = "") -> dict[str, list[str]]:
        """Parse WHOIS output extracting all matching fields.

        Args:
            whois_output: Raw WHOIS command output
            domain: Domain name (for TLD-specific parsing)

        Returns:
            Dict mapping field names to list of values found
        """
        if not whois_output:
            return {}

        if domain:
            tld = self._detect_tld(domain)
            if tld != self.loaded_tld:
                self.load_tld_patterns(tld)

        results: dict[str, list[str]] = {}
        cleaned = self._clean_output(whois_output)

        for pattern in self.patterns:
            try:
                regex = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
                for match in regex.finditer(cleaned):
                    value = match.group(1).strip()
                    if value and value not in results.get(pattern.name, []):
                        if pattern.name not in results:
                            results[pattern.name] = []
                        results[pattern.name].append(value)
            except re.error:
                continue

        return results

    def _clean_output(self, output: str) -> str:
        """Remove WHOIS disclaimers and comments."""
        lines = []
        for line in output.split("\n"):
            if line.strip() and not line.strip().startswith("%"):
                lines.append(line)
        return "\n".join(lines)

    def to_finding_dict(self, parsed: dict[str, list[str]]) -> dict:
        """Convert parsed data to Finding-compatible dict.

        Args:
            parsed: Output from parse()

        Returns:
            Dict with normalized field names for Finding.raw
        """

        def first(values: list[str]) -> Optional[str]:
            return values[0] if values else None

        def all_values(values: list[str], max_items: int = 10) -> list[str]:
            return values[:max_items]

        all_ns = all_values(parsed.get("name_server", []) + parsed.get("nserver", []))
        all_status = all_values(
            parsed.get("status", []) + parsed.get("domain_status", [])
        )

        return {
            "registrar": first(parsed.get("registrar", []))
            or first(parsed.get("whois", [])),
            "whois_server": first(parsed.get("whois_server", [])),
            "creation_date": first(parsed.get("created", []))
            or first(parsed.get("creation_date", [])),
            "expiry_date": first(parsed.get("expires", []))
            or first(parsed.get("expiry_date", [])),
            "updated_date": first(parsed.get("updated", []))
            or first(parsed.get("changed", [])),
            "nameservers": all_ns,
            "owner": first(parsed.get("owner", []))
            or first(parsed.get("registrant", [])),
            "organization": first(parsed.get("organization", [])),
            "responsible": first(parsed.get("responsible", [])),
            "country": first(parsed.get("country", [])),
            "status": all_status,
            "dnssec": first(parsed.get("dnssec", []))
            or first(parsed.get("ds_rdata", [])),
            "admin_c": first(parsed.get("admin_c", [])),
            "tech_c": first(parsed.get("tech_c", [])),
        }

    def get_status_message(self) -> str:
        """Get a status message about pattern loading."""
        if self.using_wordlist and self.loaded_tld:
            return f"wordlist (TLD: .{self.loaded_tld})"
        else:
            return f"fallback patterns. Set wordlists via: {get_wordlist_dir_message()}/whois/"
