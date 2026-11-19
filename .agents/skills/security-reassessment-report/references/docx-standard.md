# DOCX standard — SOC – Data Center

The Markdown report is the source of truth. The `.docx` is generated from it, never hand-edited:

```bash
python .agents/skills/utils/docx_report.py --input "Relatório ... - <target>.md" --output "Relatório ... - <target>.docx"
```

Generator: `.agents/skills/utils/docx_report.py` (requires `python-docx>=1.2`).
Cover asset: `assets/logo-senai-cimatec.png` (SENAI CIMATEC, 936×292 px, used at 6.5 in wide).
Header/footer asset: `assets/restrito.png` (RESTRITO badge, used at 0.55 in).

Accent colour: `#009DDC` (blue rules in header/footer).

## Dependencies

| Dependency | Needed for | If missing |
|------------|------------|------------|
| `python-docx>=1.2` | Generating the DOCX | Generator cannot run — install with `pip install python-docx` |
| `pypdf>=6` + LibreOffice (`soffice`) | Baking **real page numbers** into the Índice (two-pass: render DOCX → read PDF heading bookmarks → rebuild) | The Índice keeps a Word TOC field and the renderer fills the numbers; no page numbers are invented |

LibreOffice is a desktop application, not a pip package: macOS `brew install --cask libreoffice`, Debian/Ubuntu `apt install libreoffice`, Windows the official installer. The generator finds it via `soffice` on `PATH` or `/Applications/LibreOffice.app/Contents/MacOS/soffice`. Use `--page-numbers off` to skip the render pass; `--page-numbers auto` (default) uses it when available. The DOCX itself never depends on LibreOffice.

The two reference documents this standard was derived from:
`Relatório de Avaliação de Segurança - hml-kitsdidaticos...docx` and
`Relatório de Reavaliação de Segurança - hml-kitsdidaticos...docx`.
Where they disagreed (e.g. `#FF0000` vs `#A61C00` for "Alta"), this standard keeps **one** token per meaning.

---

## 1. Page and typography

| Property | Value |
|----------|-------|
| Page | Letter 8.5 × 11 in (12240 × 15840 twips), portrait |
| Margins | top/bottom/left/right 1 in (1440 twips) |
| Header / footer distance | 0.5 in / 0.3 in |
| Font | Arial (body, headings, tables); Consolas 9 pt for code |
| Body | 11 pt, line spacing 1.15, space after 6 pt |
| Boilerplate (Aviso/Isenção) | 12 pt **bold** |
| Title (cover) | 26 pt **italic**, centred |
| Subtitle ("SOC – Data Center") | 20 pt **italic**, centred |
| Cover metadata (Alvo/Data) | 11 pt, centred |
| Boilerplate (Aviso/Isenção) | 12 pt **italic** |
| H1 (`## section`) | 20 pt bold `#000000` |
| H2 (`### section`) | 16 pt bold `#000000` |
| H3 (`#### section`) | 16 pt bold `#434343` |
| H4 | 12 pt bold `#666666` |
| Finding heading (`## 1 – …` / `#### 1 – …`) | 16 pt bold `#000000`, **not** in the TOC |
| Table text | 11 pt; header bold white |
| Code block | Consolas 9 pt, fill `#F2F2F2`, border `#CCCCCC` |
| Figure caption | 9 pt italic `#666666`, centred |

Page breaks: one after the cover (logo/title/metadata) and one before the **Índice**.

Numbered lists (methodology, each finding's recommendations, general recommendations) are rendered with **explicit numbers** and restart at **1** in every block, independent of the renderer.

---

## 2. Colour tokens

### 2.1 Severity / risk (5 levels)

| Token | Fill | Text | Used in |
|-------|------|------|---------|
| Crítica | `#000000` | white | summary bar, risk table, findings "Risco"/"Pontuação" |
| Alta | `#A61C00` | white | same |
| Média | `#F1C232` | black | same |
| Baixa | `#38761D` | white | same |
| Informação | `#666666` | white | risk table and findings |

### 2.2 Rating scales (probability / impact / remediation)

| Token | Fill | Text | Values |
|-------|------|------|--------|
| High | `#E06666` | black | Provável · Maior · Difícil |
| Medium | `#FFD966` | black | Possível · Moderada |
| Low | `#93C47D` | black | Improvável · Menor · Fácil |

### 2.3 Treatment status (reassessment only)

| Token | Fill | Text | Values |
|-------|------|------|--------|
| Mitigado | `#38761D` | white | Mitigado |
| Parcialmente mitigado | `#FFBF00` | black | Parcialmente mitigado |
| Não mitigado | `#C9211E` | white | Não mitigado |

### 2.4 Structure

| Token | Fill | Text | Used in |
|-------|------|------|---------|
| Header neutral | `#666666` | white | classification tables, Servidores, Ferramentas, Siglas, evidence index |
| Header primary | `#2A6099` | white | findings summary tables |
| Header context | `#039BE5` | white | Endereço / Servidores / Sites tables |
| Label cell | `#CCCCCC` | black | first column of the finding/treated detail blocks |
| Placeholder | `#FAFAFA` + border `#B7B7B7` | `#666666` | missing-screenshot fallback |
| Table borders | `#000000`, 1 pt | — | all tables |
| Body text | `#000000` | — | — |
| Muted text | `#666666` | — | captions, quotes, placeholders |

**Rules**

- Colour only classification, severity, treatment or header cells. Never colour a description/body cell.
- Header text is always bold white.
- Every coloured cell keeps its text (colour is never the only signal).
- No gradients, shadows, rounded corners or extra accent colours.

---

## 3. Tables

### 3.1 Exact colours for the classification tables

These are the canonical values. The two reference documents disagreed (e.g. `#FF0000` vs `#A61C00` for "Alta", `#00A933` vs `#38761D` for "Baixa", and `#FF0000`/`#FFBF00`/`#127622` vs `#E06666`/`#FFD966`/`#93C47D` for the 3-level scales) — use only the right-hand column below.

| Table | Cell | Value | Fill | Text |
|-------|------|-------|------|------|
| Classificação de Riscos | first column | Crítico | `#000000` | white |
| | | Alto | `#A61C00` | white |
| | | Médio | `#F1C232` | black |
| | | Baixo | `#38761D` | white |
| | | Informação | `#666666` | white |
| Classificação de Probabilidade | first column | Provável | `#E06666` | black |
| | | Possível | `#FFD966` | black |
| | | Improvável | `#93C47D` | black |
| Classificação de Impacto | first column | Maior | `#E06666` | black |
| | | Moderada | `#FFD966` | black |
| | | Menor | `#93C47D` | black |
| Classificação de Dificuldade | first column | Difícil | `#E06666` | black |
| | | Moderada | `#FFD966` | black |
| | | Fácil | `#93C47D` | black |
| Classificação do Tratamento | first column | Mitigado | `#38761D` | white |
| | | Parcialmente mitigado | `#FFBF00` | black |
| | | Não mitigado | `#C9211E` | white |

Rules: header `#666666`; **only the first column is coloured**; the "Descrição"/"Pontuação" columns stay white with black text. The same tokens are used in the summary bar, the findings "Risco" column and the finding detail block, so a level has one colour everywhere.

Implementation: `.agents/skills/utils/docx_report.py` → `SEVERITY`, `SCALE_HIGH/MED/LOW`, `STATUS`, `HEADER_*`.

| Table | Header | Body colouring |
|-------|--------|----------------|
| Summary bar (assessment) | Crítica/Alta/Média/Baixa/Informação in severity colours | none (counts only) |
| Summary bar (reassessment) | Período `#666666` + severity columns | none (Antes/Depois) |
| Classificação de Riscos | `#666666` | first column by severity |
| Probabilidade / Impacto / Dificuldade | `#666666` | first column by rating scale |
| Tratamento aplicado (classification) | `#666666` | first column by status |
| Achados encontrados (resumo) | `#2A6099` | "Pontuação de risco" and "Risco" by severity |
| Achados tratados (resumo) | `#666666` | "Classificação do tratamento" by status |
| Endereço / Servidores / Sites | `#039BE5` | none |
| Servidores/Ferramentas/Siglas/Evidências | `#666666` | none |

Header row repeats on page break; rows do not split across pages.
Column widths: "Achado" is the widest; numeric/score columns are centred.

---

## 4. Finding anatomy

### Assessment (`Achados encontrados (detalhes)`)

```
## N – Título                                 16 pt bold
Médio (5)                                    severity bar table (merged, coloured)
┌──────────────────────────────┬─────────────┐
│ Probabilidade de Exploração  │ Possível    │  label #CCCCCC / value rating colour
│ Impacto ao Negócio           │ Moderada    │
│ Dificuldade de Remediação    │ Fácil       │
└──────────────────────────────┴─────────────┘
**Implicações de Segurança**                 bold body
<paragraph>
**Análise**
<paragraph>
**Evidências**
<code block>                                 9 pt Consolas on #F2F2F2
Evidências: <artifact paths>                 body
[ INSERIR CAPTURA DE TELA ]                  placeholder box (see §5)
Figura N – <finding title>
**Recomendação**
<paragraph>
```

### Reassessment

Found findings use the same anatomy. Treated findings use a single row:

```
## N – Título
┌──────────────────────┬──────────────────┐
│ Tratamento aplicado  │ Não mitigado     │   label #CCCCCC / status colour
└──────────────────────┴──────────────────┘
**Controle empregado** / **Análise** / **Evidências** / **Recomendações** / **Referências**
```

---

## 5. Evidence and screenshots (automatic)

The generator **embeds the screenshot when the referenced file exists**; otherwise it keeps the manual placeholder box. Prepare the file beforehand — crop and redact in an image editor, never inside Word.

- `![Figura N – <legenda>](<path>)` → embedded image, centred, max 6.0 in wide (height capped at 7.5 in), followed by the caption (the alt text) in italic 9 pt. The path resolves relative to the input `.md`; absolute paths also work. This is the preferred form.
- Missing/unreadable file, or a non-image extension → placeholder box labelled with `Arquivo de origem: <path>` + caption.
- Each `**Evidências:**` line → placeholder `Figura N – <finding>` carrying the artifact paths, unless that finding already has a figure (embedded or caption).
- `*Figura N – caption*` → placeholder `Figura N` followed by the italic caption (legacy reports without image links).
- Placeholder box: 1.9 in minimum height, fill `#FAFAFA`, border `#B7B7B7`, text `[ INSERIR CAPTURA DE TELA ]` 10 pt bold + path in Consolas 9 pt.

The generator never crops or redacts: the embedded file is exactly the file on disk. Cropping inside Word hides pixels without deleting them from the document, and a box drawn over a screenshot in Word/PDF is not redaction — use an image editor with an opaque fill before referencing the file.

---

## 6. Cover, header, footer, TOC

- **Cover:** logo (`assets/logo-senai-cimatec.png`, 6.5 in, centred), title 26 pt italic, subtitle 20 pt italic, then `Alvo:` / `Data …:` on separate centred lines. Page break after the cover; the first-page header is empty.
- **Header (content pages):** full-width `#009DDC` rule 6 pt; **no badge** (the `RESTRITO` badge lives only in the footer).
- **Footer:** `RESTRITO` badge centred, `Página ` + `PAGE` field (9 pt) right-aligned, full-width `#009DDC` rule below. First-page footer: badge + rule, no page number.
- **Page breaks:** after the cover, before the **Índice**, and again when the topic changes context — **Sumário Executivo**, **Classificações**, **Achados da Avaliação**, **Recomendações Gerais** and each **Apêndice** start on a new page. Inside the findings, the summary table (`– Achados … (resumo)`) and the detail blocks (`– Achados … (detalhes)`) are always on separate pages.
- **Índice:** static entries with **real page numbers** baked from a LibreOffice render (two-pass: build → convert to PDF → read heading bookmarks with `pypdf` → rebuild). Numbers are never invented. If LibreOffice/`pypdf` are unavailable, the generator falls back to a Word **TOC field** (`TOC \o "1-2" \h \z \u`, `updateFields=true`) and the renderer fills the numbers. The Índice always starts on its own page (break before **Sumário Executivo**). Findings headings are excluded from the TOC.

---

## 7. Do / Don't

| Do | Don't |
|----|-------|
| Keep one token per meaning | Mix `#FF0000` and `#A61C00` for "Alta" |
| Use the finding detail block for the 3 rating values | Leave the rating values as an uncoloured 3-column table |
| Reference prepared screenshots with `![Figura N – …](path)` and let the generator embed them | Crop/redact inside Word, or embed an image with a visible secret |
| Regenerate the docx from the Markdown | Hand-edit the docx (the next generation overwrites it) |
| Keep the four fixed classification tables verbatim | Recolour or reorder them |
