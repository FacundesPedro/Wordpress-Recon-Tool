# recon_wp/utils/slugs.py
"""WordPress plugin/theme slug normalization and validation.

WHAT: Normalizes wordlist entries and HTML-derived tokens into bare
      WordPress plugin/theme slugs, and rejects parse junk.
HOW:  Strips known path prefixes (``wp-content/plugins/``, ``themes/``),
      query/fragment, duplicate and trailing slashes, percent-decodes the
      remainder, then validates it structurally.
WHY:  SecLists lists (``wp-plugins.fuzz.txt``) already contain full paths
      (``wp-content/plugins/<slug>/``) while the discovery steps prepend the
      directory again, producing ``wp-content/plugins/wp-content/plugins/…``.
      Broken HTML/regex parses also yield junk such as ``*","`` that must not
      be treated as a slug.
"""

from __future__ import annotations

import contextlib
import re
from urllib.parse import unquote

# Characters that never appear in a legitimate WordPress plugin/theme slug.
# Their presence means the token came from a broken HTML/regex parse.
_JUNK_CHARS = frozenset(' \t\r\n/\\"\'`,<>*?=#%&')

_SLUG_MAX = 200

# The response-code oracle only accepts plain WP-style directory names; a
# single character or a fragment from a broken parse can never be a real
# plugin/theme directory.
_ORACLE_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

_KINDS = {"plugin": "plugins", "plugins": "plugins", "theme": "themes", "themes": "themes"}


def is_valid_slug(slug: str) -> bool:
    """Return True when ``slug`` looks like a real plugin/theme directory name.

    Deliberately permissive about non-ASCII characters (WordPress allows
    unicode directory names) - it only rejects structurally impossible or
    parse-derived junk and hidden/dot entries.
    """
    if not slug or len(slug) > _SLUG_MAX:
        return False
    if slug.startswith("."):
        return False
    return not any(ch in _JUNK_CHARS for ch in slug)


def is_oracle_slug(slug: str) -> bool:
    """Return True when a slug is plausible for the response-code oracle.

    Stricter than :func:`is_valid_slug`: the oracle only probes plain
    lowercase WordPress-style directory names of length >= 2, so a fragment
    such as ``c`` or ``pa`` from a broken parse never reaches the wordlist.
    """
    return bool(slug) and len(slug) >= 2 and bool(_ORACLE_SLUG_RE.match(slug))


def normalize_wp_slug(entry: str, kind: str) -> str:
    """Normalize a wordlist entry to a bare plugin/theme slug.

    ``kind`` is ``"plugins"``/``"plugin"`` or ``"themes"``/``"theme"``.
    Returns ``""`` for comments, blanks, and entries that do not reduce to a
    valid slug.
    """
    directory = _KINDS.get((kind or "").strip().lower(), "plugins")
    value = (entry or "").strip()
    if not value or value.startswith("#"):
        return ""

    value = value.split("#", 1)[0].split("?", 1)[0].strip()

    # Strip any leading ``wp-content/<dir>/`` or bare ``<dir>/`` prefix.
    value = re.sub(rf"^/?wp-content/{directory}/?", "", value, flags=re.I)
    value = re.sub(rf"^/?{directory}/", "", value, flags=re.I)

    value = re.sub(r"/+", "/", value).strip("/")

    with contextlib.suppress(Exception):
        value = unquote(value)

    value = value.strip().strip("/")
    return value if is_valid_slug(value) else ""


def normalize_wp_slugs(entries, kind: str) -> list[str]:
    """Normalize an iterable of wordlist entries, deduplicating in order."""
    out: list[str] = []
    seen: set[str] = set()
    for entry in entries or []:
        slug = normalize_wp_slug(str(entry), kind)
        if slug and slug not in seen:
            seen.add(slug)
            out.append(slug)
    return out


# Plugin directory references in HTML: /wp-content/plugins/<slug>/
_PLUGIN_PATH_RE = re.compile(r"/wp-content/plugins/([^/\"'?#<>]+)/")


def detect_plugins_from_html(html: str) -> list[str]:
    """Extract valid plugin slugs from page/asset HTML.

    Shares the same normalization and ``is_valid_slug`` guard as the
    wordlist path so broken HTML parses (``*","``, ``pa``-style fragments)
    never leak into version/CVE correlation. Order of first appearance is
    preserved for stable output.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in _PLUGIN_PATH_RE.findall(html or ""):
        slug = normalize_wp_slug(raw, "plugins")
        if slug and slug not in seen:
            seen.add(slug)
            out.append(slug)
    return out
