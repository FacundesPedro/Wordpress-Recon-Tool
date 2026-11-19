# Reassessment Report Template Spec — SOC – Data Center

Rules for filling `templates/report.md`. The section order and the classification tables are **fixed**; only the placeholder content changes. This template is derived from the published "Relatório de Reavaliação de Segurança" for `ma.senaicimatec.com.br` / `seja.senaicimatec.com.br` (Nov 2024, 43 pages), which is the source of truth for the structure. Deliberate deviations from that PDF are listed at the end — read them before changing the template.

## Language and boilerplate

- Output is **pt-BR**. Technical terms (RCE, SQL Injection, CORS, CVEs, tool names) stay as-is.
- The Aviso de Confidencialidade and Isenção de responsabilidade are **verbatim** — never rewrite them. Only the trailing non-destructive clause may be adapted to the target.
- The report is written in a **non-destructive** voice. Never state that exploitation succeeded.
- The source PDF's Isenção omits the non-destructive clause and says "todas os problemas"; the house standard (assessment skill) is authoritative for this boilerplate — keep it as in the template.

## Section-by-section

| Section | Rules |
|---------|-------|
| Title block | `Alvo:` target(s); `Data da reavaliação:` human date in pt-BR (e.g. `8 de novembro de 2024`); `Avaliação de referência:` date of the previous report. These three lines are a Markdown-only identifier (the PDF cover carries only the title and `SOC – Data Center`). |
| Confidencialidade / Isenção | Verbatim, plus the one-clause non-destructive statement. |
| Índice | Must list exactly the headings actually present, in order. No page numbers (the export adds them). Delete optional sections that do not exist (`Observação`, a scope group, a block). |
| Sumário Executivo | Concise and non-technical, **≤ 1 page** (max ~250 words, excluding the table): one short paragraph of context (what/when/where, authorization, purpose — "verificar se as recomendações foram aplicadas e efetuar testes não feitos na avaliação anterior"); **the headline in one sentence** in plain words (worst residual risk + net improvement); one short result paragraph with the persistence/new/mitigated counts in plain language, **never numbers without context**; then the **Antes/Depois** table (4 severities; Informação excluded). Add 3–5 bullets with the main residual risks written as *what + business consequence* and **"O que fazer agora"** — 3 numbered actions in priority order. **Do not** list tools, test types, HTTP headers, CVE IDs or methodology — those belong in the findings and Apêndice A. **No `Destaque`** — priorities are the numbered actions here and in Recomendações Gerais. |
| Escopo | Concise: one intro sentence + `### Serviços` (host + IP) and `### Sites` (URL + IP) tables. List only what was authorized; state out-of-scope items explicitly. Use one row per host/site actually re-tested. Do **not** list test types, tools or methodology — those belong to Metodologia and the findings. |
| Metodologia da Reavaliação | Fixed sentence + the 4 steps, verbatim from the template. |
| Classificação de Definições | The five fixed tables — copy verbatim from the template. |
| Achados da Avaliação – `<escopo>` | One `##` section per scope group: `Serviços` first, then one per site in the same order as the Escopo `Sites` table. Each contains `– Achados encontrados (resumo/detalhes)` and/or `– Achados tratados (resumo/detalhes)`; drop empty blocks. Numbering restarts at 1 per group. |
| Observação | Optional. Client-relevant observations, previously discarded candidates that are still unproven, and limitations that are not findings (e.g. a development/validation copy referenced in source, an item that could not be re-verified). No risk score. Include figures when they add proof. |
| Recomendações Gerais | The three fixed house items plus engagement-specific actions, ordered by priority; can reference finding numbers. |
| Apêndice A | Tools actually used, one row each, followed by the caption `**Tabela A.1:** Ferramentas usadas durante a reavaliação.` |
| Apêndice B | Acronyms actually used in the report. |

## Risk scoring rubric (Classificação de Riscos)

Pick the score from the fixed table, then the label follows from it. Do not invent intermediate labels.

| Pontuação | Risco |
|-----------|-------|
| 10 | Crítica |
| 7–9 | Alta |
| 4–6 | Média |
| 1–3 | Baixa |
| 0 | Informação |

Also assign, from the fixed tables in the template:

- **Probabilidade de Exploração:** Provável / Possível / Improvável.
- **Impacto ao Negócio:** Maior / Moderada / Menor.
- **Dificuldade de Remediação:** Difícil / Moderada / Fácil.

## Treatment classification (Classificação do Tratamento Aplicado)

Use exactly one of three values, in the resumo table, in the detalhe table, and in any prose reference:

| Tratamento | Meaning | Required proof |
|------------|---------|----------------|
| **Mitigado** | The original weakness is no longer reproducible and the control covers the exact item reported. | Fresh re-verification showing the weakness blocked/absent (e.g. `install.php` → 404, port closed, header present), plus a negative control proving the target is reachable and the result is not a generic error/WAF page. Appears **only** under `tratados`; does not count in "Depois". |
| **Parcialmente mitigado** | At least one item of the original finding is fixed and proven, and at least one remains exploitable. | Proof of the controls confirmed **and** proof of each residual, listed individually. Appears under `tratados` **and** under `encontrados` (same number and title) with the residual score. |
| **Não mitigado** | The weakness remains reproducible, or no control was observed. | Fresh re-verification reproducing the weakness. Appears under `tratados` **and** under `encontrados`. |

Rules:

- **Never** classify from the client's remediation note. The note goes into **Controle empregado**; the **Análise** states what the re-assessment observed.
- A control that blocks by class proves the block, not the fix (e.g. every `*.save` returns 403 → the file may still exist): use `Parcialmente mitigado` and say what could not be proven.
- If an item cannot be re-verified (local privilege, out of scope, service down), classify as `Não mitigado` with the reason stated — never `Mitigado`.
- Do not carry over items that were false positives in the previous report; if one is now proven, it is a new `encontrado`, and the correction is noted in Observação.
- Resumo and detalhe must always show the same treatment value. The source PDF contradicts itself on this (resumo "Parcialmente mitigado", detalhe "Mitagado") — the conservative value wins.

## Scope grouping and numbering

- Group order: `Serviços`, then the sites in Escopo order.
- Numbering restarts per group (`1..n`); the same number is reused across groups (e.g. finding 1 of each site).
- **Within each table, order findings by severity (Crítica → Alta → Média → Baixa → Informação); the number column follows that order.** In the DOCX, each `– Achados … (resumo)` block ends the page and its `– Achados … (detalhes)` block starts on a new page.
- A carried-over finding keeps its number across its group's `tratados` and `encontrados` tables.
- A `Mitigado` finding appears only in `tratados`; its number is not reused by another finding in the same group.
- `Interno/Externo` values: `Interno`, `Externo` or `Ambos` (the last when the exposure is both internal and external).

## Finding detail formats

### Encontrado (new or residual)

````markdown
#### N – Título curto do achado

**Risco (score)**

| Probabilidade de Exploração | Impacto ao Negócio | Dificuldade de Remediação |
|-----------------------------|--------------------|---------------------------|
| <Probabilidade> | <Impacto> | <Dificuldade> |

**Implicações de Segurança**

<2–3 frases em linguagem simples: o que pode acontecer e a quem. Sem jargão.>

**Análise**

<Como o achado foi encontrado/verificado, versão, pré-condição e raciocínio técnico. Referencie as figuras.>

**Evidências**

![Figura N – <o que a figura prova, em uma frase>](<caminho relativo ao .md>)

```
<comando principal — no máximo ~8 linhas, só as linhas decisivas>
```

Evidências: <caminhos dos arquivos>.

**Recomendações**

1. <primeiro passo, imperativo, em linguagem simples>;
2. <próximo passo>;
3. <como conferir: o teste que comprova que a correção funcionou>.

**Referências**

- <URL de referência do achado>;
````

> The PDF renders the rating as a label/value table (Probabilidade \| Provável, etc.); the Markdown uses the assessment template's 3-column single-row table — same content, house Markdown standard.

**Audience split inside a finding** (same as the assessment skill; the full plain-language checklist and examples are in `security-assessment-report/references/template-spec.md` § *Audience split inside a finding*):

| Part | Audience | Rules |
|------|----------|-------|
| **Implicações de Segurança** | Business / non-technical | 2–3 short sentences, plain Portuguese: what can happen and who is affected. No tool names, header names, CVE IDs, acronyms, config keys or command lines. Explain before naming ("um arquivo de backup do site que guarda a senha do banco"). Numbers always with context. |
| **Análise** / **Controle empregado** | Technical | Technical detail is expected: how it was re-verified, version, precondition, config value, reasoning. Must state how the verdict was obtained. |
| **Recomendações** | Business / non-technical | Short imperative steps, **numbered**, ordered by priority; no code blocks, flags or config keys. Use as many steps as the finding requires. **The last step is always how to verify the fix.** Exact settings go in the **Análise**. |

### Tratado (previous finding)

````markdown
#### N – Título do achado anterior (mesmo título do relatório anterior)

| Tratamento aplicado | <Mitigado|Parcialmente mitigado|Não mitigado> |
|---------------------|-------------------|

**Controle empregado**

<O que o cliente declarou ter feito.>

**Análise**

<O que a reavaliação observou, com as figuras. Para parcialmente mitigado: o que foi comprovado e o que permanece (aponte para o mesmo número em Achados encontrados). Para não mitigado: a reprodução da fragilidade.>

**Evidências**

![Figura N – <o que a figura prova, em uma frase>](<caminho relativo ao .md>)

```
<comando principal — no máximo ~8 linhas, só as linhas decisivas>
```

Evidências: <caminhos dos arquivos>.

**Recomendações**

1. <manter o controle / concluir os itens pendentes / revisar periodicamente>;
2. <como conferir: o teste que comprova que a correção está completa>.

**Referências**

- <URL de referência>;
````

The `**Evidências**` block (command/output or an existing screenshot file with its caption) is mandatory in both shapes. A finding without proof is not a finding.

## Before/after counting rules

- **Antes** — the severity counts of the **previous assessment report's** summary table: Crítica / Alta / Média / Baixa. Informação is not shown in this table (matches the PDF).
- **Depois** — the severity counts of **currently open** findings: the sum of all `Achados encontrados (resumo)` rows across all scope groups, using the score shown in each row.
- A residual carried-over finding keeps its original score in `Depois` unless the re-assessment explicitly re-scores it; if re-scored, the Análise must justify the change.
- A `Mitigado` finding is excluded from `Depois`.
- Do not count the same finding twice: a `Parcialmente mitigado` finding appears in both tables but contributes to `Depois` **once**, through its `encontrados` row.
- Reconcile before finishing: `Antes` == previous report; `Depois` == sum of `encontrados`; every prior finding appears exactly once in `tratados`.

Worked example (source PDF): `Antes` = 0 Crítica / 3 Alta / 0 Média / 0 Baixa; `Depois` = 0 / 2 / 0 / 0, which equals the two `Achados encontrados` rows (seja #1 and ma #1, both Alto 7). The fully mitigated prior findings appear only under `tratados` and do not count in `Depois`.

## Finding admission checklist (encontrados)

Before a candidate becomes a finding, all must pass. If any fails, it does **not** go in the findings list — move it to **Observação** or drop it.

1. **Context understood** — the target's stack/version/deployment was checked, and the issue actually applies (feature negotiated, module loaded, app/framework matches, precondition present). Banner version alone is not enough when patch level is ambiguous.
2. **Precondition verified** — for a CVE, the specific prerequisite was confirmed on the target (not assumed).
3. **Proof artifact exists** — a command + output snippet or an existing evidence file that supports the exact severity claimed.
4. **Novelty checked** — it is genuinely new, or it is the proven residual of a prior finding (then it keeps that finding's number and appears in both tables).
5. **Severity matches what was proven** — a reachable service, open port or exposed file is **exposure**, not exploitability. Exposure alone caps at **Baixa (3)**, normally **Informação (0)**. Média or above requires confirmed exploitability (see below).

## Exposure ≠ exploitability (severity discipline)

Classify only what the re-assessment **confirmed**; state explicitly when a test was not performed.

| Confirmed on the target | Maximum severity |
|-------------------------|------------------|
| Port/service reachable, no authentication attempt | **Informação (0)** / **Baixa (3)** — hardening item |
| Default or leaked credentials **authenticated successfully** (e.g. DB login with a default/blank password, or a credential found in the app) and data reached | **Alta/Crítica**, proportional to the data and privileges |
| Unauthenticated read of sensitive data / bypass proven with a real request | According to the data exposed |
| Version with a CVE but the exploit precondition **not** verified | **Baixa**, `confidence=low` — or Observação |
| Only "it could be brute-forced", "it might be vulnerable", "if the network is flat…" | **Caps at Baixa** — or an observation |

A residual exposure keeps its previous low score unless the retest **confirmed** exploitability; if re-scored upward, the Análise must show the confirmation (working credential, data read, verified precondition).

## Mitigation verification checklist (tratados)

Before assigning `Mitigado` or `Parcialmente mitigado`, all must pass:

1. The control was observed in **this** re-assessment (fresh request/scan), not reported by the client.
2. The observation proves the control for the **exact** weakness — not a blanket block, not a different path, not a WAF/error page.
3. A **negative control** confirms the target is reachable (a request that should still work), so "site down" is not mistaken for "fixed".
4. The artifact (command + output, or screenshot) is stored and cited.
5. For `Parcialmente mitigado`, every residual is listed individually and appears in `encontrados` with proof.

## Evidence, figures and secrets

### Citation

- Prefer a real command and its real output: `$ curl -sk https://<host>/wp-login.php -o /dev/null -w '%{http_code}\n'` → show only the relevant lines.
- Always finish the finding with `Evidências: <path1>, <path2>.` pointing at artifacts in `raw/`, `reports/`, `exploits/evidence/` or the screenshots folder.
- Cite CVE/version sources (vendor advisory, Debian Security Tracker) after the evidence line when a CVE drives the finding.
- Do not cite a path that does not exist. Do not reuse a figure number (the source PDF uses "Figura 6" twice — that is a defect, not a convention).

### Figures (screenshot-first)

The figure is the **primary proof for a non-technical reader**; the command snippet is the technical backup. Order inside **Evidências**: figure → caption → trimmed snippet (≤ ~8 decisive lines) → artifact paths.

- Every finding (encontrado **and** tratado) should have **at least one figure** when a capture exists. If no capture exists, the snippet is the proof and the finding cites the artifacts; state why in Observação.
- Preferred Markdown form: `![Figura N – <o que a figura prova>](<caminho relativo ao .md>)`. The DOCX generator embeds it automatically; a missing file falls back to a placeholder box. The legacy `*Figura N – <legenda>.*` caption still renders a placeholder box.
- The **caption states what the figure proves**: "Figura 5 – O servidor .202 agora envia os cabeçalhos de segurança que faltavam" — not "Figura 5 – Terminal".
- Introduce the figure in the **Análise** by number ("A Figura 5 mostra…"). Never write "a captura abaixo".
- **N is sequential and unique across the whole document**; 1–2 figures per finding. Bulk output goes to the raw artifact.
- Capture with context (URL/hostname, account when relevant), crop to the proof in an image editor, legible at print size. For retests, a figure showing the **current state** is preferred; a reused figure from the previous assessment must say so in the caption ("Evidência da avaliação anterior").

### Secrets: mask in the report, never ingest

**Do not bring secret values into your context window.** Reading a config backup, `.env`, credential dump or cookie jar contaminates the agent transcript and can leak the value into the report, a log or a later message.

- Inspect **shape, not values**: grep for field names, or mask before displaying anything (`... | sed -E "s/=.*/= ********/"`).
- **Never** `cat`, read in full, or paste a file that may contain secrets. Use the scanner finding (field names) or the masked excerpt as evidence.
- In the report body, mask passwords, keys, tokens, salts, session cookies and personal data as `********`, keeping the field name and syntax visible. Full values stay only in the access-controlled raw artifact, cited by path.
- Screenshots: redact with an **opaque fill in an image editor before** the file enters the report folder; never blur/pixelate, never draw the box in Word/PDF, and never open or OCR an unmasked screenshot of secrets.
- Use the same mask/pseudonym for the same value everywhere; if a secret already appeared in tool output, do not repeat it — mask immediately and treat the transcript as contaminated.
- Final check: search the finished Markdown/DOCX/PDF for the value; if it is found, the report is not ready.

## Deliberate deviations from the source PDF

The published PDF is the structural source of truth, but it contains defects. This skill fixes them as follows (do not "restore" the PDF's version):

1. **Tratamento table missing** — the índice lists `Classificação do Tratamento Aplicado` (p.9) but the body contains only the tail of the Dificuldade table; the section and its descriptions are absent. Added with the three values above (descriptions inferred in house style).
2. **"Mitagado"** (pp.10, 14, 22, 27, 32) → `Mitigado`.
3. **"Metodologia da Avaliação"** in the índice (p.3) vs **"Metodologia da Reavaliação"** in the body (p.6) → use `Metodologia da Reavaliação` in both.
4. **"Endereços IPs"** in the índice (p.3) vs **"Sites"** in the body (p.5) → use `Sites` in both.
5. **Observação** exists in the body (p.38) but is absent from the índice → index it when present; delete the line when the section does not exist.
6. **Missing `– Achados tratados (detalhes)` heading** before the details in the seja and ma groups (pp.22, 32) → always present.
7. **Resumo/detalhe treatment mismatch** — resumo says `Parcialmente mitigado`, detalhe says `Mitagado` for the same finding (pp.22, 32) → values must agree; use the conservative one.
8. **Apêndice B header "Ferramenta"** (p.43, copied from Apêndice A) → `Sigla`.
9. **Tabela A.1 caption "durante a avaliação"** (p.43) → `durante a reavaliação`.
10. **"fuff"** in Apêndice A (p.43) → `ffuf`; list only tools actually used.
11. **Duplicate Figura 6** (pp.13–14) → sequential, unique figure numbers.
12. **Unfilled `XXXXXXX`/`YYYYYY` placeholders** in the Sumário Executivo (p.4) → never leave placeholders; state the real counts by level.
13. **Isenção without the non-destructive clause** (p.2) → the house boilerplate keeps it.
14. **No `Destaque`** in the Sumário Executivo (p.4) → none in the retest template; priorities go to Recomendações Gerais.
15. **Antes/Depois rendered as paired columns** (p.4) → Markdown renders one row per period (`Antes`, `Depois`); same content, export-friendly.
16. **Grammar** — "todas os problemas" (p.2), "relacionados ao serviços expostos", "as vulnerabilidade conhecidas" (p.6) → corrected.
17. **"Classificação de Definições"** (p.3) instead of the assessment template's "Classificações" → this skill keeps the PDF's name.

## Worked example

Source of truth: the 43-page PDF above (ma/seja, Nov 2024). Its shape, to reproduce:

- **Servidores** — 2 tratados, both `Mitigado` (OpenSSH hardening, Portmapper disabled), figures 1–6.
- **seja.senaicimatec.com.br** — 1 encontrado (`Múltiplas configurações inadequadas no WordPress`, Alto 7) + 2 tratados (same WordPress finding, `Parcialmente mitigado`; `Listagem de diretórios`, `Mitigado`).
- **ma.senaicimatec.com.br** — 1 encontrado (same WordPress finding, Alto 7) + 1 tratado (`Parcialmente mitigado`).
- **Observação** — a development/validation copy (`devlevel131.com.br`) referenced in the page source, with its own figures.
- **Recomendações Gerais** — 3 fixed items + 1 engagement-specific.

Tone/density reference in this workspace: `reports/hml-kitsdidaticos.senaicimatec.com.br/Relatório de Reavaliação de Segurança - hml-kitsdidaticos.senaicimatec.com.br.md` — regenerated in this format on 21/10/2026. It shows a `Servidores` group (1 tratado) plus one site group (9 encontrados, 7 tratados), the Antes/Depois reconciliation (`0/1/1/4` → `0/1/2/5`), a blanket-block `Parcialmente mitigado` verdict (`wp-config.php.save` → 403 by extension) and the context-driven low/info severities (Bootstrap widgets not used, GTM without a stable hash, test cookie, modern browsers). Use it for tone, density and evidence conventions.

## Final validation

- [ ] `Antes` counts == previous report; `Depois` counts == sum of `encontrados` rows (across all groups).
- [ ] Every previous finding appears exactly once in `tratados`; every `Mitigado` appears only there.
- [ ] Every `Parcialmente mitigado` / `Não mitigado` also appears in `encontrados` with the same number and title.
- [ ] Resumo and detalhe agree on every treatment value.
- [ ] Índice matches the headings actually present, in order.
- [ ] Every finding (both shapes) cites an existing proof artifact; every cited path exists.
- [ ] Sumário Executivo ≤ 1 page, no jargon, one-sentence headline, 3 prioritized actions.
- [ ] Figure numbers sequential and unique; every cited `Figura N` has a caption and a file; captions state what the figure proves.
- [ ] No secret value anywhere in the Markdown/DOCX body; masked fields keep the field name; screenshot redaction verified (opaque fill, not blur/overlay).
- [ ] Every Recomendações list ends with a "como conferir" verification step.
- [ ] No leftover `{{placeholder}}`, `XXXX`, or `YYYY`.
- [ ] No exploitation claims; non-destructive language throughout.
- [ ] Output file is `Relatório de Reavaliação de Segurança - <target>.md`.
