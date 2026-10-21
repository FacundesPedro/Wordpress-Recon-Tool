"""Terminal-text sanitization helpers.

External tools (OpenDoor, WPScan, ffuf) emit ANSI colour codes and
box-drawing banners. Those bytes are useless in a report and actively break
PDF rendering: xhtml2pdf's base-14 fonts cannot draw ``\\x1b`` or the block
glyphs, so the page renders blank boxes and logs "No font ... can draw".

Use :func:`strip_ansi` for raw artifacts (keeps the text readable) and
:func:`strip_ansi_and_box` for anything that ends up in ``Finding.evidence``.
"""

from __future__ import annotations

import re

# CSI/OSC/other ESC sequences: ESC [ ... final-byte, ESC ] ... BEL/ST, ESC x.
_ANSI_RE = re.compile(
    r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\)|[@-Z\\-_])"
)

# Box-drawing (U+2500-U+257F) and block-element (U+2580-U+259F) ranges.
_BOX_CHARS = "".join(
    chr(cp) for cp in range(0x2500, 0x25A0)
)
_BOX_RE = re.compile(f"[{re.escape(_BOX_CHARS)}]")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences (colour, cursor movement, OSC titles)."""
    if not text:
        return text
    return _ANSI_RE.sub("", text)


def strip_ansi_and_box(text: str) -> str:
    """Remove ANSI escapes and box-drawing/block glyphs from report text.

    Decoration-only lines (a banner frame) are dropped entirely; glyphs that
    appear inside otherwise meaningful lines are replaced with a space so the
    surrounding text stays readable.
    """
    if not text:
        return text
    stripped = strip_ansi(text)
    lines: list[str] = []
    for line in stripped.splitlines():
        without_box = _BOX_RE.sub("", line)
        if without_box.strip():
            lines.append(_BOX_RE.sub(" ", line).rstrip())
        # else: pure decoration/frame line -> dropped
    return "\n".join(lines)
