# recon_wp/utils/wordlist_loader.py
"""Wordlist loading utilities for the reconnaissance tool.

Provides utilities for loading wordlists from external directories with
fallback support.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Optional

DEFAULT_WORDLIST_DIR = Path.home() / ".config" / "recon-wp" / "wordlists"


def get_wordlist_path(
    filename: str, custom_dir: Optional[str] = None
) -> Optional[Path]:
    """Resolve wordlist path with fallback.

    Priority:
    1. Custom directory if provided
    2. ~/.config/recon-wp/wordlists/
    3. ./wordlists/external/ (production wordlists)
    4. ./wordlists/ (project relative)
    5. None (not found)

    Args:
        filename: Wordlist filename (e.g., "whois/fields.txt")
        custom_dir: Override directory path

    Returns:
        Path to wordlist, or None if not found
    """
    search_paths = []

    if custom_dir:
        search_paths.append(Path(custom_dir) / filename)

    search_paths.extend(
        [
            DEFAULT_WORDLIST_DIR / filename,
            Path(__file__).parent.parent / "wordlists" / "external" / filename,
            Path(__file__).parent.parent / "wordlists" / filename,
        ]
    )

    for path in search_paths:
        if path.exists() and path.is_file():
            return path

    return None


def load_lines(
    path: Path, skip_comments: bool = True, strip: bool = True
) -> Iterator[str]:
    """Load lines from a wordlist file.

    Args:
        path: Path to wordlist file
        skip_comments: Skip lines starting with #
        strip: Strip whitespace from lines

    Yields:
        Non-empty, processed lines
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if skip_comments and line.strip().startswith("#"):
                    continue
                if strip:
                    line = line.strip()
                if line:
                    yield line
    except (OSError, FileNotFoundError) as e:
        import logging
        logging.getLogger(__name__).warning(f"Could not read wordlist '{path}': {e}")
        return


def load_key_value_lines(path: Path) -> dict[str, str]:
    """Load key:value lines from wordlist.

    Format: key:value or key::pattern

    Args:
        path: Path to wordlist file

    Returns:
        Dict mapping keys to values/patterns
    """
    result = {}
    for line in load_lines(path):
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def ensure_wordlist_dir() -> Path:
    """Ensure the default wordlist directory exists.

    Returns:
        Path to the wordlist directory
    """
    DEFAULT_WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_WORDLIST_DIR


def get_wordlist_dir_message() -> str:
    """Get the default wordlist directory path message.

    Returns:
        Formatted message with directory path
    """
    return str(DEFAULT_WORDLIST_DIR)
