# recon_wp/utils/limits.py
"""Small helpers to bound list sizes stored in findings.

WHAT: Truncate long lists so a single finding cannot bloat the JSON/HTML/PDF
      reports (the mundosenaiba run produced a 5.5 MB report dominated by one
      13,343-entry plugin finding).
HOW:  ``cap_list`` slices an iterable to a limit; ``truncation_note`` renders
      a human-readable "(showing N of M)" suffix.
WHY:  Discovery/brute-force steps can return thousands of rows; the report
      only needs the top rows plus the total.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TypeVar

T = TypeVar("T")


def cap_list(items: Iterable[T], limit: int = 200) -> list[T]:
    """Return at most ``limit`` items (0 or negative means unlimited)."""
    materialized = list(items or [])
    if limit and limit > 0:
        return materialized[:limit]
    return materialized


def truncation_note(total: int, shown: int) -> str:
    """Return a ' (showing N of M)' suffix when ``total`` exceeds ``shown``."""
    if total > shown:
        return f" (showing {shown} of {total})"
    return ""


def cap_lines(lines: Sequence[str], limit: int = 200) -> list[str]:
    """Cap a sequence of display lines and append a truncation note."""
    capped = cap_list(lines, limit)
    note = truncation_note(len(lines), len(capped))
    if note:
        capped = list(capped) + [note.strip()]
    return capped
