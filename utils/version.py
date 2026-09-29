"""Small, dependency-free semantic-version helpers.

Used to decide whether a detected component version is affected by a
vulnerability fixed in a later release.
"""

import re
from typing import Optional

_VERSION_RE = re.compile(r"\d+")


def version_tuple(version: str) -> tuple[int, ...]:
    """Convert a version string into a comparable integer tuple.

    Missing components are zero-padded implicitly by Python's tuple
    comparison (``(1, 2) < (1, 2, 1)``), and non-numeric suffixes such as
    ``-beta1`` are ignored.
    """
    if not version:
        return ()
    return tuple(int(n) for n in _VERSION_RE.findall(str(version)))


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
