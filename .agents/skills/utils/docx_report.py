"""Render a SOC – Data Center report Markdown into a styled .docx.

The Markdown report produced by the ``security-assessment-report`` and
``security-reassessment-report`` skills is the source of truth.  This module
converts it into the house .docx layout (Arial/Letter, severity tables, cover,
header/footer, findings, embedded evidence figures and placeholders).

Usage::

    python .agents/skills/utils/docx_report.py \
      --input "Relatório ....md" --output "Relatório ....docx"

Dependencies:

- ``python-docx>=1.2`` — required.
- ``pypdf`` + LibreOffice ``soffice`` — optional; used only to bake real page
  numbers into the Índice (two-pass: render → read PDF bookmarks → rebuild).
  Without them the Índice keeps a Word TOC field and the renderer fills the
  numbers.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

# ---------------------------------------------------------------------------
# Design tokens (see references/docx-standard.md in both report skills)
# ---------------------------------------------------------------------------

# Severity / risk scale (5 levels)
SEVERITY = {
    "critica": {"fill": "000000", "text": "FFFFFF"},
    "alta": {"fill": "A61C00", "text": "FFFFFF"},
    "media": {"fill": "F1C232", "text": "000000"},
    "baixa": {"fill": "38761D", "text": "FFFFFF"},
    "info": {"fill": "666666", "text": "FFFFFF"},
}

# 3-level rating scale (probability / impact / remediation)
SCALE_HIGH = {"fill": "E06666", "text": "000000"}
SCALE_MED = {"fill": "FFD966", "text": "000000"}
SCALE_LOW = {"fill": "93C47D", "text": "000000"}

# Treatment status (reassessment)
STATUS = {
    "mitigado": {"fill": "38761D", "text": "FFFFFF"},
    "parcial": {"fill": "FFBF00", "text": "000000"},
    "nao_mitigado": {"fill": "C9211E", "text": "FFFFFF"},
}

HEADER_NEUTRAL = {"fill": "666666", "text": "FFFFFF"}
HEADER_PRIMARY = {"fill": "2A6099", "text": "FFFFFF"}
HEADER_CONTEXT = {"fill": "039BE5", "text": "FFFFFF"}
LABEL = {"fill": "CCCCCC", "text": "000000"}

BORDER_COLOR = "000000"
CODE_FILL = "F2F2F2"
CODE_BORDER = "CCCCCC"
BODY_COLOR = "000000"
MUTED_COLOR = "666666"
PLACEHOLDER_FILL = "FAFAFA"
PLACEHOLDER_BORDER = "B7B7B7"

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff"}

LOGO_CANDIDATES = (
    Path(__file__).resolve().parent.parent
    / "security-assessment-report/assets/logo-senai-cimatec.png",
    Path(__file__).resolve().parent.parent
    / "security-reassessment-report/assets/logo-senai-cimatec.png",
)

BADGE_CANDIDATES = (
    Path(__file__).resolve().parent.parent
    / "security-assessment-report/assets/restrito.png",
    Path(__file__).resolve().parent.parent
    / "security-reassessment-report/assets/restrito.png",
)

ACCENT_COLOR = "009DDC"

SEVERITY_WORDS = (
    ("critica", ("crítica", "crítico", "critica", "critico")),
    ("alta", ("alta", "alto")),
    ("media", ("média", "médio", "media", "medio")),
    ("baixa", ("baixa", "baixo")),
    ("info", ("informação", "informacao", "info")),
)

SEVERITY_RE = re.compile(
    r"^\*\*\s*(Crítico|Crítica|Alto|Alta|Médio|Média|Baixo|Baixa|Informação|Informacao)\s*"
    r"\((\d+)\)\s*\*\*$",
    re.IGNORECASE,
)

FINDING_HEADING_RE = re.compile(r"^(\d+)\s*[–-]\s*(.+)$")


def _hex(value: str) -> str:
    return value.upper().lstrip("#")


def _severity_token(label: str) -> str | None:
    low = label.lower().strip()
    for token, words in SEVERITY_WORDS:
        for word in words:
            if re.search(rf"\b{re.escape(word)}\b", low):
                return token
    return None


def _scale_token(label: str) -> dict | None:
    low = label.lower()
    if "parcialmente" in low:
        return STATUS["parcial"]
    if "não mitigado" in low or "nao mitigado" in low:
        return STATUS["nao_mitigado"]
    if "mitigado" in low:
        return STATUS["mitigado"]
    if low.startswith(("provável", "provavel", "maior", "difícil", "dificil")):
        return SCALE_HIGH
    if low.startswith(("possível", "possivel", "moderada")):
        return SCALE_MED
    if low.startswith(("improvável", "improvavel", "menor", "fácil", "facil")):
        return SCALE_LOW
    return None


# ---------------------------------------------------------------------------
# OOXML helpers
# ---------------------------------------------------------------------------


def _shade(cell, token: dict) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    for old in tc_pr.findall(qn("w:shd")):
        tc_pr.remove(old)
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), token["fill"])
    tc_pr.append(shd)


def _cell_margins(cell, top=60, bottom=60, left=100, right=100) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for side, value in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:w"), str(value))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tc_pr.append(mar)


def _valign(cell, value="center") -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    val = OxmlElement("w:vAlign")
    val.set(qn("w:val"), value)
    tc_pr.append(val)


def _table_borders(table, color=BORDER_COLOR, size="8") -> None:
    tbl_pr = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), size)
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), color)
        borders.append(el)
    tbl_pr.append(borders)


def _repeat_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    header = OxmlElement("w:tblHeader")
    header.set(qn("w:val"), "true")
    tr_pr.append(header)


def _no_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    cant = OxmlElement("w:cantSplit")
    tr_pr.append(cant)


def _row_height(row, inches: float) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    height = OxmlElement("w:trHeight")
    height.set(qn("w:val"), str(int(inches * 1440)))
    height.set(qn("w:hRule"), "atLeast")
    tr_pr.append(height)


def _bottom_rule(table, color=ACCENT_COLOR, size="48") -> None:
    """Full-width accent rule under a header/footer table."""
    tbl_pr = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{side}")
        if side == "bottom":
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), size)
            el.set(qn("w:space"), "0")
            el.set(qn("w:color"), color)
        else:
            el.set(qn("w:val"), "nil")
        borders.append(el)
    tbl_pr.append(borders)


def _clear_paragraphs(container) -> None:
    for paragraph in list(container.paragraphs):
        paragraph._element.getparent().remove(paragraph._element)


def _badge_path() -> Path | None:
    return next((p for p in BADGE_CANDIDATES if p.exists()), None)


def _add_field(paragraph, instruction: str, placeholder: str = "") -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    run._r.append(begin)
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    run._r.append(instr)
    sep = OxmlElement("w:fldChar")
    sep.set(qn("w:fldCharType"), "separate")
    run._r.append(sep)
    if placeholder:
        run.add_text(placeholder)
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(end)


def _set_update_fields(doc) -> None:
    settings = doc.settings.element
    if settings.find(qn("w:updateFields")) is None:
        el = OxmlElement("w:updateFields")
        el.set(qn("w:val"), "true")
        settings.append(el)


def _paragraph_border(paragraph, color=BORDER_COLOR, size="8") -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), size)
    bottom.set(qn("w:space"), "1")
    bottom.set(qn("w:color"), color)
    borders.append(bottom)
    p_pr.append(borders)

def _paragraph_shading(paragraph, fill: str) -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    p_pr.append(shd)


# ---------------------------------------------------------------------------
# Inline text
# ---------------------------------------------------------------------------

INLINE_RE = re.compile(r"(\*\*.+?\*\*|`.+?`|\*[^*]+?\*)")


def _write_inline(paragraph, text: str, size=None, color=BODY_COLOR, bold=False) -> None:
    """Add text with **bold**, *italic* and `code` support."""
    size = size or Pt(11)
    for part in INLINE_RE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            run = paragraph.add_run(part[2:-2])
            run.bold = True
            run.font.name = "Arial"
            run.font.size = size
            run.font.color.rgb = RGBColor.from_string(color)
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            run = paragraph.add_run(part[1:-1])
            run.font.name = "Consolas"
            run.font.size = Pt(max(9, size.pt - 1))
            run.font.color.rgb = RGBColor.from_string(color)
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            run = paragraph.add_run(part[1:-1])
            run.italic = True
            run.font.name = "Arial"
            run.font.size = size
            run.font.color.rgb = RGBColor.from_string(color)
        else:
            run = paragraph.add_run(part)
            run.bold = bold
            run.font.name = "Arial"
            run.font.size = size
            run.font.color.rgb = RGBColor.from_string(color)


# ---------------------------------------------------------------------------
# Markdown parsing
# ---------------------------------------------------------------------------


def _is_separator(cells: list[str]) -> bool:
    return all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in cells if c)


def _split_row(line: str) -> list[str]:
    line = line.strip().strip("|")
    return [c.strip() for c in line.split("|")]


def parse_markdown(text: str) -> list[dict]:
    blocks: list[dict] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("```"):
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1
            blocks.append({"type": "code", "text": "\n".join(code)})
            continue

        if stripped == "---":
            blocks.append({"type": "hr"})
            i += 1
            continue

        heading = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if heading:
            blocks.append(
                {
                    "type": "h",
                    "level": len(heading.group(1)),
                    "text": heading.group(2).strip(),
                }
            )
            i += 1
            continue

        if stripped.startswith("|"):
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = _split_row(lines[i])
                if not _is_separator(cells):
                    rows.append(cells)
                i += 1
            blocks.append({"type": "table", "rows": rows})
            continue

        if stripped.startswith(">"):
            quote: list[str] = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip().lstrip(">").strip())
                i += 1
            blocks.append({"type": "quote", "text": " ".join(quote)})
            continue

        if re.match(r"^\s*[-*]\s+", line):
            items: list[dict] = []
            while i < len(lines) and re.match(r"^\s*[-*]\s+", lines[i]):
                indent = len(lines[i]) - len(lines[i].lstrip())
                text_item = re.sub(r"^\s*[-*]\s+", "", lines[i]).strip()
                items.append({"level": 2 if indent >= 2 else 1, "text": text_item})
                i += 1
            blocks.append({"type": "ul", "items": items})
            continue

        if re.match(r"^\s*\d+\.\s+", line):
            items = []
            while i < len(lines) and re.match(r"^\s*\d+\.\s+", lines[i]):
                text_item = re.sub(r"^\s*\d+\.\s+", "", lines[i]).strip()
                items.append({"level": 1, "text": text_item})
                i += 1
            blocks.append({"type": "ol", "items": items})
            continue

        image = re.match(r"^!\[(.*?)\]\((.+?)\)\s*$", stripped)
        if image:
            blocks.append({"type": "image", "alt": image.group(1), "path": image.group(2)})
            i += 1
            continue

        para: list[str] = []
        while i < len(lines) and lines[i].strip() and not re.match(
            r"^(#{1,4}\s|\||```|>\s*|[-*]\s+|\d+\.\s+|!\[)", lines[i].strip()
        ):
            if lines[i].strip() == "---":
                break
            if para and re.match(r"^(Data da|Avaliação de referência|Data:)", lines[i].strip()):
                break
            para.append(lines[i].strip())
            i += 1
        if para:
            blocks.append({"type": "p", "text": " ".join(para)})
        else:
            i += 1

    return blocks


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class ReportRenderer:
    def __init__(
        self,
        doc: Document,
        doc_type: str = "auto",
        logo=None,
        page_map=None,
        base_dir: str | Path | None = None,
    ) -> None:
        self.doc = doc
        self.doc_type = doc_type
        self.logo = Path(logo) if logo else None
        self.page_map = page_map
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()
        self.toc_entries: list[tuple[int, str]] = []
        self._cover_done = False
        self._current_finding = ""
        self._figure = 0
        self._finding_has_figure = False
        self._boilerplate = False

    # -- primitives ---------------------------------------------------------

    def h1(self, text: str, toc: bool = True) -> None:
        p = self.doc.add_paragraph(style="Heading 1")
        _write_inline(p, text, size=Pt(20), bold=True)
        if toc:
            self.toc_entries.append((1, text))

    def h2(self, text: str, toc: bool = True) -> None:
        p = self.doc.add_paragraph(style="Heading 2")
        _write_inline(p, text, size=Pt(16), bold=True)
        if toc:
            self.toc_entries.append((2, text))

    def finding_heading(self, text: str) -> None:
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(18)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        _write_inline(p, text, size=Pt(16), bold=True)

    def paragraph(self, text: str, size=None, bold=False, muted=False, italic=False) -> None:
        p = self.doc.add_paragraph()
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.15
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        color = MUTED_COLOR if muted else BODY_COLOR
        _write_inline(p, text, size=size or Pt(11), color=color, bold=bold)
        if italic:
            for run in p.runs:
                run.italic = True

    def bullets(self, items: list[dict]) -> None:
        for item in items:
            style = "List Bullet 2" if item["level"] >= 2 else "List Bullet"
            p = self.doc.add_paragraph(style=style)
            p.paragraph_format.space_after = Pt(2)
            _write_inline(p, item["text"])

    def numbered(self, items: list[dict]) -> None:
        """Numbered list that restarts at 1 for every block (explicit numbers)."""
        for idx, item in enumerate(items, start=1):
            p = self.doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.3)
            p.paragraph_format.first_line_indent = Inches(-0.3)
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.tab_stops.add_tab_stop(Inches(0.3))
            p.add_run(f"{idx}.")
            p.add_run("\t")
            _write_inline(p, item["text"])

    def quote(self, text: str) -> None:
        p = self.doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.25)
        p.paragraph_format.space_after = Pt(6)
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        _write_inline(p, text, size=Pt(10), color=MUTED_COLOR)
        for run in p.runs:
            run.italic = True

    def code(self, text: str) -> None:
        table = self.doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = True
        _table_borders(table, color=CODE_BORDER, size="6")
        cell = table.cell(0, 0)
        _shade(cell, {"fill": CODE_FILL, "text": BODY_COLOR})
        _cell_margins(cell, 100, 100, 140, 140)
        cell.text = ""
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.0
        lines = text.splitlines() or [""]
        for idx, line in enumerate(lines):
            run = p.add_run(line)
            run.font.name = "Consolas"
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor.from_string(BODY_COLOR)
            if idx < len(lines) - 1:
                p.add_run().add_break()
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def image(self, path: str, alt: str = "") -> None:
        """Embed the screenshot when the file exists; otherwise keep a placeholder."""
        resolved = self._resolve_image(path)
        if resolved is not None:
            self._embed_image(resolved, caption=alt)
            return
        self._placeholder(path=path, caption=alt)

    def _resolve_image(self, path: str) -> Path | None:
        candidate = Path(path.strip())
        if not candidate.is_absolute():
            candidate = self.base_dir / candidate
        try:
            if candidate.is_file() and candidate.suffix.lower() in IMAGE_SUFFIXES:
                return candidate
        except OSError:
            pass
        return None

    def _embed_image(self, path: Path, caption: str = "") -> None:
        self._finding_has_figure = True
        match = re.match(r"\s*Figura\s+(\d+)", caption)
        if match:
            self._figure = max(self._figure, int(match.group(1)))
        width = Inches(6.0)
        try:
            from docx.image.image import Image as DocxImage

            info = DocxImage.from_file(str(path))
            if info.width:
                ratio = info.height / info.width
                max_height = Inches(7.5)
                if width * ratio > max_height:
                    width = int(max_height / ratio)
        except Exception:
            pass  # unreadable dimensions: fall back to the default width
        picture = self.doc.add_paragraph()
        picture.alignment = WD_ALIGN_PARAGRAPH.CENTER
        picture.paragraph_format.space_before = Pt(4)
        picture.paragraph_format.space_after = Pt(2)
        picture.add_run().add_picture(str(path), width=width)
        if caption:
            cap = self.doc.add_paragraph()
            cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            cap.paragraph_format.space_after = Pt(4)
            _write_inline(cap, caption, size=Pt(9), color=MUTED_COLOR)
            for run in cap.runs:
                run.italic = True
        else:
            self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def _placeholder(self, path: str = "", caption: str = "", label: str = "") -> None:
        table = self.doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _table_borders(table, color=PLACEHOLDER_BORDER, size="8")
        cell = table.cell(0, 0)
        _shade(cell, {"fill": PLACEHOLDER_FILL, "text": MUTED_COLOR})
        _cell_margins(cell, 160, 160, 160, 160)
        _valign(cell, "center")
        _row_height(table.rows[0], 1.9)
        cell.text = ""
        first = cell.paragraphs[0]
        first.alignment = WD_ALIGN_PARAGRAPH.CENTER
        first.paragraph_format.space_after = Pt(2)
        run = first.add_run("[ INSERIR CAPTURA DE TELA ]")
        run.bold = True
        run.font.size = Pt(10)
        run.font.name = "Arial"
        run.font.color.rgb = RGBColor.from_string(MUTED_COLOR)

        if label:
            p = cell.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(label)
            r.font.size = Pt(9)
            r.font.name = "Arial"
            r.font.color.rgb = RGBColor.from_string(MUTED_COLOR)

        if path:
            p = cell.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(0)
            for idx, item in enumerate(path.split("\n")):
                if idx:
                    p.add_run().add_break()
                r = p.add_run(item)
                r.font.size = Pt(9)
                r.font.name = "Consolas"
                r.font.color.rgb = RGBColor.from_string("000000")

        if caption:
            cap = self.doc.add_paragraph()
            cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            cap.paragraph_format.space_before = Pt(2)
            _write_inline(cap, caption, size=Pt(9), color=MUTED_COLOR)
            for run in cap.runs:
                run.italic = True
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def figure_caption(self, text: str) -> None:
        match = re.match(r"\*?Figura\s+(\d+)", text.strip())
        self._figure = int(match.group(1)) if match else self._figure + 1
        self._finding_has_figure = True
        self._placeholder(label=f"Figura {self._figure}")
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _write_inline(p, text, size=Pt(9), color=MUTED_COLOR)
        for run in p.runs:
            run.italic = True

    def evidence_placeholder(self, paths: str) -> None:
        """Mark where the analyst inserts the screenshot for a finding."""
        if self._finding_has_figure:
            return
        self._figure += 1
        title = re.sub(r"^\d+\s*[–-]\s*", "", self._current_finding) or "Evidência"
        clean = paths.replace("`", "").strip().rstrip(".")
        items = [p.strip() for p in clean.split(",") if p.strip()]
        self._placeholder(
            path="\n".join(items),
            label=f"Figura {self._figure} – {title}",
        )
        self._finding_has_figure = True

    # -- tables -------------------------------------------------------------

    def _header_row(self, table, headers: list[str], token) -> None:
        row = table.rows[0]
        tokens = token if isinstance(token, list) else [token] * len(headers)
        for idx, text in enumerate(headers):
            cell = row.cells[idx]
            cell.text = ""
            _shade(cell, tokens[idx] if idx < len(tokens) else HEADER_NEUTRAL)
            _cell_margins(cell)
            _valign(cell)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(text)
            run.bold = True
            run.font.name = "Arial"
            run.font.size = Pt(11)
            token_used = tokens[idx] if idx < len(tokens) else HEADER_NEUTRAL
            run.font.color.rgb = RGBColor.from_string(token_used["text"])
        _repeat_header(row)

    def _body_cell(
        self,
        cell,
        text: str,
        token: dict | None = None,
        bold=False,
        align=None,
    ) -> None:
        cell.text = ""
        if token:
            _shade(cell, token)
        _cell_margins(cell)
        _valign(cell)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        if align is not None:
            p.alignment = align
        _write_inline(p, text, size=Pt(11), color=token["text"] if token else BODY_COLOR, bold=bold)

    def table(self, rows: list[list[str]]) -> None:
        if not rows:
            return
        headers = rows[0]
        body = [r for r in rows[1:] if r]
        cols = max(len(r) for r in rows)

        # Special case: assessment finding detail (3 rating columns -> 4x2 block)
        if self._is_rating_row(headers):
            self._rating_block(headers, body[0] if body else [])
            return

        kind = self._table_kind(headers)
        table = self.doc.add_table(rows=1 + len(body), cols=cols)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = True
        _table_borders(table)
        if kind in ("summary", "summary_period"):
            header_tokens = [
                SEVERITY.get(_severity_token(h) or "", HEADER_NEUTRAL)
                for h in headers
            ]
        else:
            header_tokens = self._header_token(kind)
        self._header_row(table, headers, header_tokens)

        for r_idx, row in enumerate(body, start=1):
            _no_split(table.rows[r_idx])
            row_token = None
            if kind == "findings":
                risk_idx = next(
                    (
                        idx
                        for idx, h in enumerate(headers)
                        if "risco" in h.lower() and "pontuação" not in h.lower()
                    ),
                    None,
                )
                if risk_idx is not None and risk_idx < len(row):
                    row_token = SEVERITY.get(_severity_token(row[risk_idx]) or "")
            for c_idx in range(cols):
                text = row[c_idx] if c_idx < len(row) else ""
                colored = kind == "findings" and c_idx in self._color_cols(headers)
                token = row_token if colored else self._cell_token(kind, headers, c_idx, text)
                align = (
                    WD_ALIGN_PARAGRAPH.CENTER
                    if kind in ("summary", "findings", "treated")
                    else None
                )
                self._body_cell(table.cell(r_idx, c_idx), text, token, align=align)

        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def _is_rating_row(self, headers: list[str]) -> bool:
        joined = " ".join(headers).lower()
        return "probabilidade" in joined and "impacto" in joined and "dificuldade" in joined

    def _table_kind(self, headers: list[str]) -> str:
        joined = " ".join(headers).lower()
        if "período" in joined or "periodo" in joined:
            return "summary_period"
        if all(w in joined for w in ("crítica", "alta", "média", "baixa")):
            return "summary"
        if "nível" in joined and "pontuação" in joined:
            return "risk_scale"
        if "tratamento" in joined and "descrição" in joined:
            return "treatment_scale"
        if "probabilidade" in joined and "descrição" in joined:
            return "probability_scale"
        if "impacto" in joined and "descrição" in joined:
            return "impact_scale"
        if "dificuldade" in joined and "descrição" in joined:
            return "difficulty_scale"
        if "classificação do tratamento" in joined:
            return "treated"
        if "número" in joined and "achado" in joined and "risco" in joined:
            return "findings"
        if "endereço" in joined or "nome do host" in joined:
            return "context"
        return "neutral"

    def _header_token(self, kind: str) -> dict:
        if kind in ("findings", "summary"):
            return HEADER_PRIMARY
        if kind == "context":
            return HEADER_CONTEXT
        return HEADER_NEUTRAL

    def _color_cols(self, headers: list[str]) -> set[int]:
        return {
            idx
            for idx, header in enumerate(headers)
            if "risco" in header.lower() or "pontuação de risco" in header.lower()
        }

    def _cell_token(self, kind: str, headers: list[str], col: int, text: str) -> dict | None:
        header = headers[col].lower() if col < len(headers) else ""
        if kind in ("summary", "summary_period"):
            return None
        if kind == "risk_scale":
            return SEVERITY.get(_severity_token(text) or "")
        if kind in ("neutral", "treatment_scale"):
            is_treatment = bool(headers) and "tratamento" in headers[0].lower()
            return _scale_token(text) if col == 0 and is_treatment else None
        if kind in ("probability_scale", "impact_scale", "difficulty_scale"):
            return _scale_token(text) if col == 0 else None
        if kind == "findings":
            if "risco" in header:
                return SEVERITY.get(_severity_token(text) or "")
            return None
        if kind == "treated":
            if "tratamento" in header:
                return _scale_token(text)
            return None
        return None

    def _rating_block(self, headers: list[str], values: list[str]) -> None:
        table = self.doc.add_table(rows=4, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _table_borders(table)
        merged = table.cell(0, 0).merge(table.cell(0, 1))
        merged.text = ""
        _shade(merged, SEVERITY["info"])
        _cell_margins(merged)
        note = self._pending_severity or SEVERITY["info"]
        _shade(merged, note)
        p = merged.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(self._pending_severity_text or "")
        run.bold = True
        run.font.size = Pt(11)
        run.font.color.rgb = RGBColor.from_string(note["text"])

        for idx, header in enumerate(headers[:3], start=1):
            value = values[idx - 1] if idx - 1 < len(values) else ""
            label_cell = table.cell(idx, 0)
            self._body_cell(label_cell, header, LABEL, bold=True)
            value_cell = table.cell(idx, 1)
            self._body_cell(value_cell, value, _scale_token(value))
        self._pending_severity = None
        self._pending_severity_text = ""
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def treated_block(self, rows: list[list[str]]) -> None:
        table = self.doc.add_table(rows=1, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        _table_borders(table)
        label = rows[0][0] if rows and rows[0] else "Tratamento aplicado"
        value = rows[0][1] if rows and len(rows[0]) > 1 else ""
        self._body_cell(table.cell(0, 0), label, LABEL, bold=True)
        self._body_cell(table.cell(0, 1), value, _scale_token(value))
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # -- document -----------------------------------------------------------

    def cover(self, title: str, subtitle: str, meta: list[str]) -> None:
        logo = self.logo if self.logo and self.logo.exists() else None
        if logo is None:
            logo = next((p for p in LOGO_CANDIDATES if p.exists()), None)
        if logo is not None:
            p = self.doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(48)
            p.add_run().add_picture(str(logo), width=Inches(6.5))
        else:
            self.doc.add_paragraph()

        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(60)
        run = p.add_run(title)
        run.italic = True
        run.font.size = Pt(26)
        run.font.name = "Arial"

        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(subtitle)
        run.italic = True
        run.font.size = Pt(20)
        run.font.name = "Arial"

        for item in meta:
            p = self.doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            _write_inline(p, item, size=Pt(11))

        self.doc.add_page_break()

    def toc(self, items: list[dict], page_map: dict | None = None) -> None:
        self.doc.add_page_break()
        heading = self.doc.add_paragraph()
        run = heading.add_run("Índice")
        run.bold = True
        run.font.size = Pt(18)

        if page_map is not None:
            # Static entries (same layout in both passes); page numbers come
            # from the rendered PDF, empty in the first pass.
            for item in items:
                p = self.doc.add_paragraph()
                p.paragraph_format.space_after = Pt(2)
                p.paragraph_format.left_indent = Inches(0.25 * (item["level"] - 1))
                p.paragraph_format.tab_stops.add_tab_stop(
                    Inches(6.3), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS
                )
                _write_inline(p, item["text"], size=Pt(11))
                page = page_map.get(_normalize(item["text"]))
                p.add_run("\t")
                p.add_run(str(page) if page else "")
            return

        # Fallback: Word TOC field; the renderer fills the page numbers.
        field_p = self.doc.add_paragraph()
        field_run = field_p.add_run()
        begin = OxmlElement("w:fldChar")
        begin.set(qn("w:fldCharType"), "begin")
        field_run._r.append(begin)
        instr = OxmlElement("w:instrText")
        instr.set(qn("xml:space"), "preserve")
        instr.text = ' TOC \\o "1-2" \\h \\z \\u '
        field_run._r.append(instr)
        sep = OxmlElement("w:fldChar")
        sep.set(qn("w:fldCharType"), "separate")
        field_run._r.append(sep)

        for item in items:
            p = self.doc.add_paragraph()
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.left_indent = Inches(0.25 * (item["level"] - 1))
            _write_inline(p, item["text"], size=Pt(11))

        end_p = self.doc.add_paragraph()
        end_run = end_p.add_run()
        end = OxmlElement("w:fldChar")
        end.set(qn("w:fldCharType"), "end")
        end_run._r.append(end)

    def _should_page_break(self, text: str) -> bool:
        """Start a new page when the topic changes context."""
        return text.lower().startswith(
            (
                "sumário executivo",
                "escopo",
                "metodologia da avaliação",
                "classificações",
                "achados da avaliação",
                "recomendações gerais",
                "apêndice",
            )
        )

    def render(self, blocks: list[dict]) -> None:
        self._pending_severity: dict | None = None
        self._pending_severity_text = ""
        i = 0
        cover_meta: list[str] = []
        cover_title = ""
        cover_subtitle = ""
        cover_started = False

        while i < len(blocks):
            block = blocks[i]
            btype = block["type"]

            if btype == "h":
                level, text = block["level"], block["text"]
                numeric = FINDING_HEADING_RE.match(text)

                if level == 1 and not cover_started:
                    cover_title = text
                    cover_started = True
                    i += 1
                    continue
                if level == 2 and cover_title and not cover_subtitle and text.startswith("SOC"):
                    cover_subtitle = text
                    i += 1
                    continue

                if not cover_title:
                    cover_title = text
                    i += 1
                    continue

                if not self._cover_done:
                    self.cover(cover_title, cover_subtitle or "SOC – Data Center", cover_meta)
                    self._cover_done = True

                if numeric:
                    self.finding_heading(text)
                    self._current_finding = text
                    self._finding_has_figure = False
                    # severity line + rating/treated table follow
                    if i + 1 < len(blocks) and blocks[i + 1]["type"] == "p":
                        sev = SEVERITY_RE.match(blocks[i + 1]["text"].strip())
                        if sev:
                            token = SEVERITY[_severity_token(sev.group(1)) or "info"]
                            self._pending_severity = token
                            self._pending_severity_text = f"{sev.group(1)} ({sev.group(2)})"
                            i += 2
                            continue
                    i += 1
                    continue

                if level <= 2:
                    self._current_finding = ""
                    self._finding_has_figure = False
                    self._boilerplate = False

                if level == 2 and text.lower() == "índice":
                    items: list[dict] = []
                    if i + 1 < len(blocks) and blocks[i + 1]["type"] == "ul":
                        items = blocks[i + 1]["items"]
                        i += 1
                    self.toc(items, self.page_map)
                    i += 1
                    continue
                elif level == 2:
                    if self._should_page_break(text):
                        self.doc.add_page_break()
                    self.h1(text)
                elif level == 3 or level == 4:
                    if re.search(r"achados (encontrados|tratados) \(detalhes\)", text, re.I):
                        self.doc.add_page_break()
                    self.h2(text)
                    if text.lower().startswith(
                        ("aviso de confidencialidade", "isenção de responsabilidade")
                    ):
                        self._boilerplate = True
                i += 1
                continue

            if btype == "table" and not self._cover_done:
                self.cover(cover_title, cover_subtitle or "SOC – Data Center", cover_meta)
                self._cover_done = True

            if not self._cover_done:
                if btype == "p":
                    cover_meta.append(block["text"])
                i += 1
                continue

            if btype == "hr":
                i += 1
                continue
            if btype == "p":
                text = block["text"].strip()
                # treated detail: next table is "Tratamento aplicado"
                if text.lower().startswith("tratamento aplicado"):
                    i += 1
                    continue
                if re.fullmatch(r"\*Figura\s+[^*]+\*", text):
                    self.figure_caption(text.strip("*"))
                elif self._boilerplate:
                    self.paragraph(text, size=Pt(12), italic=True)
                else:
                    self.paragraph(text)
                    if re.match(r"^evid[êe]ncias:", text, re.IGNORECASE):
                        paths = re.sub(r"^Evid[êe]ncias:\s*", "", text, flags=re.IGNORECASE)
                        self.evidence_placeholder(paths)
            elif btype == "ul":
                self.bullets(block["items"])
            elif btype == "ol":
                self.numbered(block["items"])
            elif btype == "quote":
                self.quote(block["text"])
            elif btype == "code":
                self.code(block["text"])
                if self._current_finding:
                    # a command/output block is already evidence; do not add a
                    # duplicate screenshot placeholder for the same finding
                    self._finding_has_figure = True
            elif btype == "image":
                self.image(block["path"], block["alt"])
            elif btype == "table":
                rows = block["rows"]
                if rows and rows[0] and rows[0][0].strip().lower() == "tratamento aplicado":
                    self.treated_block(rows)
                elif self._is_rating_row(rows[0] if rows else []):
                    # severity line precedes the table; pending token already set
                    values = rows[1] if len(rows) > 1 else []
                    self._rating_block(rows[0], values)
                else:
                    self.table(rows)
            i += 1

        if not self._cover_done:
            self.cover(cover_title, cover_subtitle or "SOC – Data Center", cover_meta)


# ---------------------------------------------------------------------------
# Document setup
# ---------------------------------------------------------------------------


def _setup_document() -> Document:
    doc = Document()
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)
    section.header_distance = Inches(0.35)
    section.footer_distance = Inches(0.25)
    section.different_first_page_header_footer = True

    normal = doc.styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(11)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), "Arial")
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.15

    for name, size, color in (
        ("Heading 1", 20, "000000"),
        ("Heading 2", 16, "000000"),
        ("Heading 3", 16, "434343"),
        ("Heading 4", 12, "666666"),
    ):
        style = doc.styles[name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor.from_string(color)
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.space_before = Pt(16 if name == "Heading 1" else 12)
        style.paragraph_format.space_after = Pt(6)

    _brand_header(section.header)
    _brand_footer(section.footer, show_page=True)
    section.first_page_header.paragraphs[0].text = ""
    _brand_footer(section.first_page_footer, show_page=False)

    _set_update_fields(doc)
    return doc


def _brand_header(header, rule: bool = True) -> None:
    """Header = full-width blue rule only (the RESTRITO badge lives in the footer)."""
    _clear_paragraphs(header)
    if not rule:
        return
    paragraph = header.add_paragraph()
    paragraph.paragraph_format.space_after = Pt(0)
    _paragraph_border(paragraph, color=ACCENT_COLOR, size="48")


def _brand_footer(footer, show_page: bool = True) -> None:
    badge = _badge_path()
    table = footer.add_table(rows=1, cols=3, width=Inches(6.5))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    for idx, width in enumerate((Inches(2.2), Inches(2.1), Inches(2.2))):
        table.columns[idx].width = width
        table.cell(0, idx).width = width

    center = table.cell(0, 1)
    center.text = ""
    p = center.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(0)
    if badge is not None:
        p.add_run().add_picture(str(badge), width=Inches(0.55))

    right = table.cell(0, 2)
    right.text = ""
    p = right.paragraphs[0]
    if show_page:
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run("Página ")
        run.font.size = Pt(9)
        run.font.name = "Arial"
        _add_field(p, " PAGE ", "1")
        for r in p.runs:
            r.font.size = Pt(9)
            r.font.name = "Arial"

    _bottom_rule(table)
    _clear_paragraphs(footer)


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _find_soffice() -> str | None:
    candidate = shutil.which("soffice")
    if candidate:
        return candidate
    mac = Path("/Applications/LibreOffice.app/Contents/MacOS/soffice")
    return str(mac) if mac.exists() else None


def _compute_page_map(docx_path: Path) -> dict[str, int] | None:
    """Render the DOCX to PDF with LibreOffice and read heading bookmarks."""
    soffice = _find_soffice()
    if not soffice:
        return None
    try:
        from pypdf import PdfReader
    except ImportError:
        return None

    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(
                [
                    soffice,
                    "--headless",
                    "--convert-to",
                    "pdf",
                    "--outdir",
                    tmp,
                    str(docx_path),
                ],
                check=True,
                capture_output=True,
                timeout=240,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        pdfs = list(Path(tmp).glob("*.pdf"))
        if not pdfs:
            return None
        try:
            reader = PdfReader(str(pdfs[0]))
        except Exception:
            return None

        page_map: dict[str, int] = {}

        def walk(outline) -> None:
            for item in outline:
                if isinstance(item, list):
                    walk(item)
                    continue
                try:
                    title = getattr(item, "title", None)
                    if not title:
                        continue
                    page = reader.get_destination_page_number(item) + 1
                except Exception:
                    continue
                page_map[_normalize(title)] = page

        try:
            walk(reader.outline)
        except Exception:
            return None
        return page_map or None


def build_docx(
    markdown_path: str | Path,
    output_path: str | Path,
    doc_type: str = "auto",
    logo: str | Path | None = None,
    page_map: dict[str, int] | None = None,
) -> Path:
    md_path = Path(markdown_path)
    out_path = Path(output_path)
    text = md_path.read_text(encoding="utf-8")
    doc = _setup_document()
    renderer = ReportRenderer(
        doc,
        doc_type=doc_type,
        logo=logo,
        page_map=page_map,
        base_dir=md_path.parent,
    )
    blocks = parse_markdown(text)
    renderer.render(blocks)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_path))
    return out_path


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render a SOC – Data Center report Markdown to .docx"
    )
    parser.add_argument("--input", required=True, help="Markdown report path")
    parser.add_argument("--output", required=True, help="Output .docx path")
    parser.add_argument(
        "--type",
        choices=("auto", "assessment", "reassessment"),
        default="auto",
        help="Report type (auto-detected from the title by default)",
    )
    parser.add_argument("--logo", default=None, help="Cover logo PNG (default: skill asset)")
    parser.add_argument(
        "--page-numbers",
        choices=("auto", "off"),
        default="auto",
        help="Bake real page numbers into the Índice using LibreOffice (auto = when available)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        page_map = None
        if args.page_numbers == "auto":
            with tempfile.TemporaryDirectory() as tmp:
                first = build_docx(
                    args.input,
                    Path(tmp) / "pass1.docx",
                    doc_type=args.type,
                    logo=args.logo,
                    page_map={},
                )
                page_map = _compute_page_map(first)
        out = build_docx(
            args.input,
            args.output,
            doc_type=args.type,
            logo=args.logo,
            page_map=page_map,
        )
    except ImportError as exc:  # pragma: no cover
        print(f"python-docx is required: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover
        print(f"Failed to build {args.output}: {exc}", file=sys.stderr)
        return 1

    print(f"DOCX report: {out}")
    if page_map:
        print(f"Índice: {len(page_map)} page numbers baked from the rendered PDF")
    else:
        print("Índice: TOC field (LibreOffice/pypdf unavailable; renderer fills the numbers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
