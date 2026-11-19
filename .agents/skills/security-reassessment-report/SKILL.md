---
name: Security Reassessment Report
description: Generate a security re-assessment report ("Relatório de Reavaliação de Segurança") in the SOC – Data Center template from a previous assessment report plus retest artifacts (FINDINGS.md, UPDATE.md, raw/, reports/, screenshots). Use when the client applied fixes and asked for a re-check, retest or "reavaliação", when reporting which findings were mitigated, partially mitigated or remain open, or when producing before/after severity counts.
---

# Security Reassessment Report

Produce a re-assessment report that matches the house template: SOC – Data Center, pt-BR, non-destructive. This is a different document from the assessment report: findings are grouped by scope, split into **encontrados** (new or residual, with a risk score) and **tratados** (previous findings, with a treatment status), and the Sumário Executivo carries before/after severity counts instead of a single snapshot. The structure is fixed; only the content changes per re-engagement.

Supporting files:

- `templates/report.md` — the fill-in skeleton, in the exact section order.
- `references/template-spec.md` — section-by-section rules, the five fixed classification tables, the treatment-classification and mitigation-verification rules, the before/after counting rules, the deliberate deviations from the source PDF, and a worked example.
- `references/docx-standard.md` — DOCX visual standard (palette, typography, table recipes, embedded figures/placeholders).
- `assets/logo-senai-cimatec.png` — cover logo used by the generator.

Read `references/template-spec.md` before assembling a report and `templates/report.md` as the base to copy.

## Ground rules (non-negotiable)

These apply to every step. If a rule conflicts with "finishing the report", the rule wins.

### 1. Be pragmatic with tools

- Read what already exists first: the **previous assessment report**, `FINDINGS.md`, `UPDATE.md`, `raw/` (raw tool stdout/stderr), `reports/` (tool reports), `exploits/evidence/`, screenshots. Reuse existing artifacts instead of re-scanning.
- Use the dedicated tool for the job and batch independent calls. Run the **minimum** needed to fill a gap.
- Never re-run a scan just to look thorough. If data is missing, state that it is missing — do not pad.
- Never invent tool output, versions, commands, endpoints, or evidence paths.

### 2. Understand the context before classifying

- Characterize the target first: stack, exact version, deployment shape (internal vs public, split-horizon DNS, load-balanced nodes), and the actually-reachable surface.
- Compare with the previous assessment: same hosts and ports? same versions? did the deployment change (new node, new WAF, migration)?
- Assign severity only after interpreting context (banner ≠ patch level, a CVE only counts if its precondition is present, framework/CMS must match). Reconcile scanner output against reality; a heuristic hit is not a confirmed finding.
- A finding is **new** only if it was not reported in the previous assessment. A previously discarded candidate that is now proven is a **new finding** — say so. A finding previously reported and still present is **residual** and keeps its original number.

### 3. Always have proof

- Every finding (encontrado **or** tratado) must cite a concrete artifact: a command plus its output snippet, a figure caption backed by an existing file (`screenshots/...`), and/or a file path (`raw/tools/...`, `reports/...`, `exploits/evidence/...`).
- **No proof → not a finding.** Move it to **Observação** as an observation, clearly labeled as such — or drop it.
- Never claim exploitation. Proof means **non-destructive** evidence: affected version + precondition met, a reachable endpoint, a real header, a service banner.
- The proof must support the exact verdict claimed.
- **Screenshot-first:** when a capture exists, the figure is the primary proof — figure, then a trimmed snippet (≤ ~8 decisive lines), then the artifact paths. See `references/template-spec.md` § *Evidence, figures and secrets*.

### 4. A fix is never assumed

- Every treatment verdict (`Mitigado`, `Parcialmente mitigado`, `Não mitigado`) must come from a **fresh re-verification performed in this re-assessment**, never from the client's remediation note or from the previous report's recommendation.
- The client's note says what was intended; the report states what was observed.
- A control that blocks by class proves the block, not the fix: if every `*.save` returns 403, the file may still exist — report `Parcialmente mitigado` unless absence is proven.
- If an item cannot be re-verified (local privilege, out of scope, service down), report it as `Não mitigado` with the reason stated in the Análise — never as `Mitigado`.

### 5. Exposure is not exploitability

- A reachable port, open service or exposed file is **exposure**, not a confirmed vulnerability. It caps at **Baixa (3)**, normally **Informação (0)**.
- Escalate only with **confirmed exploitability**: default/leaked credentials that actually authenticate, unauthenticated access to sensitive data, or a verified exploit precondition. State explicitly when a test was not performed.
- A residual exposure keeps its previous low score unless the retest confirmed exploitability — see `references/template-spec.md` § *Exposure ≠ exploitability*.

### 6. Never ingest secrets into your context

- **Do not** `cat`, read in full, or paste any file that may contain secrets: config backups (`wp-config.php*`, `.env`, `*.bak`, `*.old`), credential dumps, cookie jars, database exports.
- Inspect **shape only**: grep for field names, or mask values before displaying anything (`... | sed -E "s/=.*/= ********/"`).
- The report body shows field names + `********`; the unredacted value stays only in the access-controlled raw artifact, cited by path.
- If a secret already appeared in tool output, do not repeat it — mask it immediately and treat the transcript as contaminated.
- Screenshots: redact with an opaque fill in an image editor **before** the file enters the report folder; never blur/pixelate, never draw the box in Word, and never open or OCR an unmasked screenshot of secrets.

## Workflow

1. **Gather inputs.** The **previous assessment report is mandatory** (it supplies the `tratados` rows and the "Antes" counts); ask the user if it is missing. Inventory `FINDINGS.md`, `UPDATE.md`, `raw/`, `reports/`, `exploits/evidence/`, screenshots, and target metadata (hosts, IPs, URLs, dates).
2. **Reconcile every previous finding.** List the prior findings, re-verify each one non-destructively, and assign the treatment verdict with proof (rule 4). A carried-over finding keeps its number across `tratados` and `encontrados`.
3. **Hunt new paths.** Run the re-assessment methodology: enumerate/validate exposed services against the prior findings, test new paths, re-test the known vulnerabilities.
4. **Group by scope.** `Serviços` first, then one section per site in the order used in Escopo. Each group gets `encontrados` (new/residual, with score) and/or `tratados` (treatment status); drop a block that is empty for that group.
5. **Assemble the report** by copying `templates/report.md` and replacing every `{{placeholder}}`. Keep the confidentiality/disclaimer boilerplate verbatim.
6. **Validate.** All of the following must hold before finishing:
   - "Antes" counts equal the previous report's severity summary; "Depois" counts equal the sum of all `Achados encontrados (resumo)` rows.
   - Every previous finding appears in exactly one `Achados tratados (resumo)` row; every `Mitigado` row appears **only** there.
   - Each `Parcialmente mitigado` or `Não mitigado` row also appears in `Achados encontrados` with the same number and title.
   - Resumo and detalhe agree on the treatment value for every finding.
   - The Índice matches the actual headings, in order.
   - Every finding and every verdict passes the checklists in the spec and cites an existing artifact.
   - Figure numbers are sequential and unique; every cited `Figura N` has a caption and an existing file; captions state what the figure proves.
   - The Sumário Executivo fits one page, has no jargon and ends with 3 prioritized actions.
   - No secret value appears anywhere in the report body; masked fields keep their names; screenshot redaction was done with an opaque fill.
   - Every Recomendações list ends with a "como conferir" step.
   - Language is pt-BR and non-destructive; no exploitation claims; no leftover placeholders.
7. **Write the file** as `Relatório de Reavaliação de Segurança - <target>.md`, then generate the DOCX from it (see **Output**). The Markdown is the source of truth; do not hand-edit the DOCX.

## Output

Two files per report, both in `reports/<target>/`:

1. **Markdown (source of truth)** — `Relatório de Reavaliação de Segurança - <target>.md`, following the template.
2. **DOCX (deliverable)** — generated from the Markdown:
   ```bash
   python .agents/skills/utils/docx_report.py \
     --input "Relatório de Reavaliação de Segurança - <target>.md" \
     --output "Relatório de Reavaliação de Segurança - <target>.docx"
   ```

The DOCX follows `references/docx-standard.md`: Arial/Letter, SOC palette, before/after summary bar, treatment colours (Mitigado `#38761D`, Parcialmente mitigado `#FFBF00`, Não mitigado `#C9211E`), cover logo (`assets/logo-senai-cimatec.png`), header/footer with the blue rule and `RESTRITO` badge (`assets/restrito.png`), `Página N` footer, static TOC, and **automatic evidence figures**: `![Figura N – …](path)` is embedded when the file exists, capped at 6.0 in wide; a missing file keeps the manual `[ INSERIR CAPTURA DE TELA ]` box. Requires `python-docx>=1.2`.

Generator (shared by both report skills): `.agents/skills/utils/docx_report.py`.

Dependencies: `python-docx` (required). For **real page numbers in the Índice**, the generator uses LibreOffice (`soffice`) + `pypdf` in a two-pass render; without them the Índice falls back to a Word TOC field and the renderer fills the numbers. See `references/docx-standard.md` § Dependencies.

The five classification tables use the exact hex values in `references/docx-standard.md` §3.1 — one colour per level, reused in the before/after bar, the "Risco" column and the finding detail block.

Edit the Markdown and regenerate; do not hand-edit the DOCX. Nothing else in the workspace is modified.
