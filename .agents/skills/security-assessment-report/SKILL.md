---
name: Security Assessment Report
description: Generate a security assessment report ("Relatório de Avaliação de Segurança") in the SOC – Data Center template from assessment artifacts (FINDINGS.md, raw/, reports/, exploits/evidence/). Use when asked to write, format, or assemble a pentest/vulnerability assessment report, turn findings into a report, or reproduce the existing report template for a new target.
---

# Security Assessment Report

Produce a security assessment report that matches the house template: SOC – Data Center, pt-BR, non-destructive language. The structure is fixed; only the content changes per target.

Supporting files:

- `templates/report.md` — the fill-in skeleton, in the exact section order.
- `references/template-spec.md` — section-by-section rules, the four fixed classification tables verbatim, the finding admission checklist, and a worked example.
- `references/docx-standard.md` — DOCX visual standard (palette, typography, table recipes, embedded figures/placeholders).
- `assets/logo-senai-cimatec.png` — cover logo used by the generator.

Read `references/template-spec.md` before assembling a report and `templates/report.md` as the base to copy.

## Ground rules (non-negotiable)

These apply to every step. If a rule conflicts with "finishing the report", the rule wins.

### 1. Be pragmatic with tools

- Read what already exists first: `FINDINGS.md`, `raw/` (raw tool stdout/stderr), `reports/` (tool reports), `exploits/evidence/`. Reuse existing artifacts instead of re-scanning.
- Use the dedicated tool for the job and batch independent calls. Run the **minimum** needed to fill a gap.
- Never re-run a scan just to look thorough. If data is missing, state that it is missing — do not pad.
- Never invent tool output, versions, commands, endpoints, or evidence paths.

### 2. Understand the context before classifying

- Characterize the target first: stack, exact version, deployment shape (internal vs public, split-horizon DNS), and the actually-reachable surface.
- Assign severity only after interpreting context. Examples of context that changes the verdict:
  - Banner version ≠ patch level (e.g. Debian backports fix CVEs without bumping the upstream version).
  - A CVE only counts if its **precondition/config** is present on the target.
  - Issues that depend on a feature that is not negotiated (e.g. HTTP/2, a module not loaded) do not apply.
  - Framework/CMS mismatch (e.g. WordPress checks against a non-WordPress app).
- Reconcile scanner output against reality. A heuristic or co-occurrence hit is **not** a confirmed finding.
- When something cannot be established from context, downgrade it or mark it explicitly as unverified.

### 3. Always have proof

- Every finding **must** cite a concrete artifact: a command plus its output snippet, and/or a file path (`raw/tools/...`, `reports/...`, `exploits/evidence/...`).
- **No proof → not a finding.** Move it to **Apêndice C – Observações e Falsos Positivos** as an observation/assumption, clearly labeled as such.
- Never claim exploitation. Proof means **non-destructive** evidence: affected version + precondition met, a reachable endpoint, a real header, a service banner.
- The proof must support the exact severity claimed. A "critical" needs evidence of both the affecting version **and** the exploited precondition.
- **Screenshot-first:** when a capture exists, the figure is the primary proof — figure, then a trimmed snippet (≤ ~8 decisive lines), then the artifact paths. See `references/template-spec.md` § *Evidence, figures and secrets*.

### 4. Exposure is not exploitability

- A reachable port, open service or exposed file is **exposure**, not a confirmed vulnerability. It caps at **Baixa (3)**, normally **Informação (0)**.
- Escalate only with **confirmed exploitability**: default/leaked credentials that actually authenticate, unauthenticated access to sensitive data, or a verified exploit precondition. State explicitly when a test was not performed.
- "It could be brute-forced" / "it might be vulnerable" is never a severity argument — see `references/template-spec.md` § *Exposure ≠ exploitability*.

### 5. Never ingest secrets into your context

- **Do not** `cat`, read in full, or paste any file that may contain secrets: config backups (`wp-config.php*`, `.env`, `*.bak`, `*.old`), credential dumps, cookie jars, database exports.
- Inspect **shape only**: grep for field names, or mask values before displaying anything (`... | sed -E "s/=.*/= ********/"`).
- The report body shows field names + `********`; the unredacted value stays only in the access-controlled raw artifact, cited by path.
- If a secret already appeared in tool output, do not repeat it — mask it immediately and treat the transcript as contaminated.
- Screenshots: redact with an opaque fill in an image editor **before** the file enters the report folder; never blur/pixelate, never draw the box in Word, and never open or OCR an unmasked screenshot of secrets.

## Workflow

1. **Gather inputs.** Inventory `FINDINGS.md`, `raw/`, `reports/`, `exploits/evidence/`, and any target metadata (host, IPs, URLs, dates). Note gaps.
2. **Derive metadata.** Target host, assessment date, address(es)/URL(s), server/stack table.
3. **Build findings.** For each candidate: understand context (rule 2), confirm the precondition, capture the proof (rule 3), then assign risk score, exploit probability, business impact, and remediation difficulty. Use the finding-detail shape in `templates/report.md`.
4. **Assemble the report** by copying `templates/report.md` and replacing every `{{placeholder}}`. Keep the confidentiality notice and disclaimer boilerplate verbatim.
5. **Validate.** All of the following must hold before finishing:
   - Severity summary counts equal the findings list (and its rows match).
   - The index matches the actual headings, in order.
   - Every finding passes the **finding admission checklist** (context understood? precondition verified? proof artifact cited?).
   - Any item lacking proof is moved to Appendix C.
   - The Sumário Executivo fits one page, has no jargon and ends with 3 prioritized actions.
   - Every finding has a figure when a capture exists, with a caption that states what the figure proves; figures are referenced by number in the Análise.
   - No secret value appears anywhere in the report body; masked fields keep their names; screenshot redaction was done with an opaque fill.
   - Every Recomendação ends with a "como conferir" step.
   - Language is pt-BR and non-destructive; no exploitation claims.
6. **Write the file** as `Relatório de Avaliação de Segurança - <target>.md`, then generate the DOCX from it (see **Output**). The Markdown is the source of truth; do not hand-edit the DOCX.

## Output

Two files per report, both in `reports/<target>/`:

1. **Markdown (source of truth)** — `Relatório de Avaliação de Segurança - <target>.md`, following the template.
2. **DOCX (deliverable)** — generated from the Markdown:
   ```bash
   python .agents/skills/utils/docx_report.py \
     --input "Relatório de Avaliação de Segurança - <target>.md" \
     --output "Relatório de Avaliação de Segurança - <target>.docx"
   ```

The DOCX follows `references/docx-standard.md`: Arial/Letter, SOC palette, severity and classification tables, cover logo (`assets/logo-senai-cimatec.png`), header/footer with the blue rule and `RESTRITO` badge (`assets/restrito.png`), `Página N` footer, static TOC, and **automatic evidence figures**: `![Figura N – …](path)` is embedded when the file exists, capped at 6.0 in wide; a missing file keeps the manual `[ INSERIR CAPTURA DE TELA ]` box. Requires `python-docx>=1.2`.

Generator (shared by both report skills): `.agents/skills/utils/docx_report.py`.

Dependencies: `python-docx` (required). For **real page numbers in the Índice**, the generator uses LibreOffice (`soffice`) + `pypdf` in a two-pass render; without them the Índice falls back to a Word TOC field and the renderer fills the numbers. See `references/docx-standard.md` § Dependencies.

The four classification tables use the exact hex values in `references/docx-standard.md` §3.1 — one colour per level, reused in the summary bar, the "Risco" column and the finding detail block.

Edit the Markdown and regenerate; do not hand-edit the DOCX. Nothing else in the workspace is modified.
