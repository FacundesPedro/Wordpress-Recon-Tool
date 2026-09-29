"""Small, dependency-free semantic-version helpers.

Used to decide whether a detected component version is affected by a
vulnerability fixed in a later release.
"""

import re
from typing import Optional

_COMPONENT_SPLIT_RE = re.compile(r"[.\-_+]")


def version_tuple(version: str) -> tuple[int, ...]:
    """Convert a version string into a comparable integer tuple.

    Only the leading numeric dotted components are used; a suffix such as
    ``-beta1`` or ``-1build1`` stops parsing. Missing components are handled
    by Python's tuple comparison (``(1, 2) < (1, 2, 1)``).
    """
    if not version:
        return ()
    parts: list[int] = []
    for piece in _COMPONENT_SPLIT_RE.split(str(version)):
        if piece.isdigit():
            parts.append(int(piece))
        else:
            break
    return tuple(parts)


def is_version_less(candidate: str, other: str) -> bool:
    """Return True when ``candidate`` is strictly older than ``other``."""
    c, o = version_tuple(candidate), version_tuple(other)
    if not c or not o:
        return False
    return c < o


def is_version_at_least(candidate: str, minimum: str) -> bool:
    """Return True when ``candidate`` is equal to or newer than ``minimum``."""
    c, m = version_tuple(candidate), version_tuple(minimum)
    if not c or not m:
        return False
    return c >= m


def cve_applies(
    installed: Optional[str], fixed_in: Optional[str]
) -> Optional[bool]:
    """Return whether a CVE applies given the installed and fixed versions.

    Returns ``True`` when the installed version predates ``fixed_in``,
    ``False`` when it is already patched, and ``None`` when the answer cannot
    be determined (version unknown or no fixed release published).
    """
    if not installed or installed == "unknown" or not fixed_in:
        return None
    if is_version_at_least(installed, fixed_in):
        return False
    if is_version_less(installed, fixed_in):
        return True
    return None
