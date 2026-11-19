# Report Template Spec — SOC – Data Center

Rules for filling `templates/report.md`. The section order and the classification tables are **fixed**; only the placeholder content changes.

## Language and boilerplate

- Output is **pt-BR**. Technical terms (RCE, SQL Injection, CORS, CVEs, tool names) stay as-is.
- The Aviso de Confidencialidade and Isenção de responsabilidade paragraphs are **verbatim** — never rewrite them. Only the trailing non-destructive clause may be adapted to the target.
- The report is written in a **non-destructive** voice. Never state that exploitation succeeded.

## Section-by-section

| Section | Rules |
|---------|-------|
| Title block | `Alvo:` target host; `Data da avaliação:` human date in pt-BR (e.g. `24 de setembro de 2026`). |
| Confidencialidade / Isenção | Verbatim, plus a one-clause non-destructive statement. |
| Índice | Must list exactly the headings actually present, in order. |
| Sumário Executivo | Concise and non-technical, **≤ 1 page** (max ~250 words excluding the table), in this order: (1) one short paragraph of context — what/when/authorization; (2) **the headline in one sentence** — the single most important result in plain words; (3) one short paragraph of business impact — what could happen to data, operations, money or reputation, **without tool, header, CVE or acronym**; (4) the severity table; (5) 3–5 bullets with the main risks as *what + business consequence*; (6) **"O que fazer agora"** — 3 numbered actions in priority order (the first is the most urgent). Never state counts without context: "8 achados" alone means nothing — add what they mean in one line. **Do not** list tools, test types (SQLi, XSS, nmap, nuclei…), HTTP headers, CVE IDs or methodology — those belong in the findings, Metodologia and Apêndice A. Assume the reader is a manager who will read only this page. |
| Escopo | Concise: one short paragraph (what/when/where, exposure, provenance of any client-provided host) + 3–5 bullets with the surface actually tested + one out-of-scope line. Do **not** list test types, tools or methodology — those belong to Metodologia and the findings. |
| Serviços | One row per service with version/detail. `{{servico}}` values come from banners and tool output. |
| Endereço | IP(s) + URL(s). Note split-horizon (internal IP vs public IP) explicitly if relevant. |
| Metodologia | Fixed 4 steps; keep as-is unless engagement type differs. |
| Classificações | Four fixed tables — copy verbatim from the template. |
| Achados (resumo) | Table row per finding, **ordered by severity (Crítica → Alta → Média → Baixa → Informação)**; the number column follows that order and must match the detail sections. In the DOCX the summary starts on a new page and the details block starts on the next page. |
| Achados (detalhes) | One `## N – Título` block per finding, in the same severity order (ties keep a stable order). See the finding format below. In the DOCX the details always start on a new page, separate from the summary. |
| Recomendações Gerais | Numbered, ordered by priority; can reference finding numbers. |
| Apêndice A | Tools actually used, one row each. |
| Apêndice B | Acronyms actually used in the report. |
| Apêndice C | Observations, discarded false positives, and items that could not be proven. Plus the evidence index table. |

## Risk scoring rubric (Classificação de Riscos)

Pick the score from the fixed table, then the label follows from it. Do not invent intermediate labels.

| Pontuação | Risco |
|-----------|-------|
| 10 | Crítica |
| 7–9 | Alta |
| 4–6 | Média |
| 1–3 | Baixa |
| 0 | Informação |

**Ceiling rule:** an exposure without confirmed exploitability caps at **Baixa (3)** — see § *Exposure ≠ exploitability*. Do not use "Média" for an open port, an exposed file or a version banner alone.

Also assign, from the fixed tables:

- **Probabilidade de Exploração:** Provável / Possível / Improvável.
- **Impacto ao Negócio:** Maior / Moderada / Menor.
- **Dificuldade de Remediação:** Difícil / Moderada / Fácil.

## Finding detail format

````markdown
## N – Título curto do achado

**<Risco> (<score>)**

| Probabilidade de Exploração | Impacto ao Negócio | Dificuldade de Remediação |
|-----------------------------|--------------------|---------------------------|
| <Probabilidade> | <Impacto> | <Dificuldade> |

**Implicações de Segurança**

<2–3 frases em linguagem simples: o que pode acontecer e a quem. Sem jargão.>

**Análise**

<Como o achado foi encontrado (teste/comando), versão, pré-condição e raciocínio técnico.>

**Evidências**

![Figura N – <o que a figura prova, em uma frase>](<caminho relativo ao .md>)

```
<comando principal — no máximo ~8 linhas, só as linhas decisivas>
```

Evidências: <caminhos dos arquivos>.

**Recomendação**

1. <primeiro passo, imperativo, em linguagem simples>;
2. <próximo passo>;
3. <como conferir: o teste que comprova que a correção funcionou.>
````

The `**Evidências**` block is mandatory. A finding without a figure, a command/output snippet or an artifact path is not a finding. Prefer the figure when a capture exists — see § *Evidence, figures and secrets*.

### Audience split inside a finding

The report is read by managers **and** by the technical team. Each part has a different audience and a different style:

| Part | Audience | Rules |
|------|----------|-------|
| **Implicações de Segurança** | Business / non-technical | 2–3 short sentences, plain Portuguese. Say what can happen and who is affected. **Never** use tool names, HTTP header names, CVE IDs, acronyms (CSP, CSRF, SSRF…), "credential stuffing", config keys or command lines. If a technical term is unavoidable, explain it in the same sentence. |
| **Análise** | Technical | Technical detail is expected and welcome: how it was found (`test`, request, command), affected version, precondition, config value, evidence reasoning. CVE IDs, headers, flags and settings belong **here**, not above. Must state explicitly how the finding was verified. |
| **Recomendação** | Business / non-technical | Short imperative steps ("Restringir…", "Ativar…", "Revisar…"), **numbered**, ordered by priority, no code blocks, no flags and no config keys. Use as many steps as the finding requires — never pad and never truncate to hit a count. **The last step is always how to verify the fix** ("como conferir"), phrased as something the client can do. If an exact setting is essential, give it in the **Análise** and keep the recommendation at the level of "ativar o bloqueio após 5 tentativas". |

**Practical rule:** if a sentence only makes sense to an engineer, it belongs in **Análise**. Read the Implicações aloud: if it sounds like a log line, rewrite it.

**Plain-language checklist (Implicações and Recomendação):**

- No tool names, commands, flags, HTTP header names, config keys, CVE IDs or acronyms. If a term is unavoidable, explain it in the same sentence.
- **Explain before naming:** "um arquivo de backup do site que guarda a senha do banco (`wp-config.php.save`)" — never just the file name.
- One idea per sentence, active voice, aim for ≤ 20 words.
- Business terms, not security terms: data, access, money, deadline, reputation — not "CWE-200", "attack surface" or "vector".
- Numbers always with context: "8 achados, sendo 1 que permite assumir o site" instead of "8 achados".
- The headline in the Sumário Executivo must be understandable by someone who stops reading after the first paragraph.

Examples — the same fact, two audiences:

- Implicações (good): "Qualquer pessoa na rede interna pode baixar um arquivo de backup do site que contém a senha do banco e as chaves de acesso. Com elas, é possível entrar como administrador sem saber nenhuma senha."
- Implicações (bad): "Exposição de `wp-config.php.save` permite forjar cookies `AUTH_KEY`/`JWT_AUTH_SECRET_KEY` e obter sessões administrativas."
- Implicações (good): "É possível testar senhas de usuários sem limite, o que permite que uma pessoa mal-intencionada descubra uma senha fraca e acesse notas e dados pessoais."
- Implicações (bad): "Ausência de rate limiting permite credential stuffing e brute force contra `/login/index.php`."
- Recomendação (good): "Remover o arquivo de backup do servidor hoje e, em seguida, trocar a senha do banco e as chaves do site, pois devem ser consideradas vazadas."
- Recomendação (bad): "Rotacionar `AUTH_KEY`, `SECURE_AUTH_KEY`… e `JWT_AUTH_SECRET_KEY`."
- Como conferir (good): "Abrir o endereço do arquivo no navegador e confirmar que ele não é mais baixado (erro 404)."

## Finding admission checklist

Before a candidate becomes a finding, all four must pass. If any fails, it does **not** go in the findings list.

1. **Context understood** — the target's stack/version/deployment was checked, and the issue actually applies (feature negotiated, module loaded, app/framework matches, precondition present). Banner version alone is not enough when patch level is ambiguous.
2. **Precondition verified** — for a CVE, the specific prerequisite was confirmed on the target (not assumed).
3. **Proof artifact exists** — there is a command + output snippet or an evidence file that supports the exact severity claimed.
4. **Severity matches what was proven** — a reachable service, open port or exposed file is **exposure**, not exploitability. Exposure alone caps at **Baixa (3)**, normally **Informação (0)**. Média or above requires confirmed exploitability (see next section).

Candidates that fail go to **Apêndice C** as observations/false positives, labeled as unverified where applicable.

## Exposure ≠ exploitability (severity discipline)

Do not infer impact from what *could* happen. Classify only what the assessment **confirmed**; state explicitly when a test was not performed.

| Confirmed on the target | Maximum severity |
|-------------------------|------------------|
| Port/service reachable, no authentication attempt | **Informação (0)** / **Baixa (3)** — hardening item |
| Default or leaked credentials **authenticated successfully** (e.g. DB login with `root`/empty or a credential found in the app source) and data reached | **Alta/Crítica**, proportional to the data and privileges |
| Unauthenticated read of sensitive data / bypass proven with a real request | According to the data exposed |
| Version with a CVE but the exploit precondition **not** verified | **Baixa**, `confidence=low` — or Apêndice C |
| Only "it could be brute-forced", "it might be vulnerable", "if the network is flat…" | **Caps at Baixa** — or Apêndice C as an observation |

Worked example (from a Moodle engagement): MariaDB `3306/tcp` reachable from the internal network, **no credential test performed** → **Baixa (3)**. If `root` with a default/blank password had connected and `SHOW DATABASES` returned the LMS schema, the same exposure would be **Crítica**. The difference is a confirmed authentication, not the open port.

Apply the same logic to: open SSH, exposed admin consoles, `.git`/`.env` reachable but empty, S3 buckets listing disabled, TLS banners, and "missing header" findings.

## Evidence, figures and secrets

### Citation (mandatory)

- Prefer a real command and its real output:
  `$ nmap -oX - -Pn -sT -T4 -sV --top-ports 1000 <host>` → show only the relevant lines.
- Always finish the finding with `Evidências: <path1>, <path2>.` pointing at the artifacts in `raw/`, `reports/`, `exploits/evidence/` or the screenshots folder.
- Cite CVE/version sources (vendor advisory, Debian Security Tracker) after the evidence line when a CVE drives the finding.
- Do not cite a path that does not exist.

### Figures (screenshot-first)

A screenshot is the **primary proof for a non-technical reader**; the command snippet is the technical backup. Order inside **Evidências**: figure → caption → trimmed snippet → artifact paths.

- Every finding should have **at least one figure** when a capture exists. If no capture exists, the snippet is the proof and the finding cites the artifacts; record the reason in Apêndice C.
- Reference the figure in the Markdown as `![Figura N – <o que a figura prova>](<caminho relativo ao .md>)`. The DOCX generator embeds it automatically; a missing file falls back to a placeholder box.
- The **caption states what the figure proves**, not what it is: "Figura 7 – O painel administrativo, acessado sem login, lista todos os usuários" — not "Figura 7 – Terminal".
- Introduce the figure in the **Análise** by number ("A Figura 3 mostra…"). Never write "a captura abaixo".
- Number figures sequentially across the whole document; never reuse a number.
- 1–2 figures per finding. Bulk output (full directory listings, long scans) goes to the raw artifact, not the finding.
- Capture with context: keep the URL/hostname (and the account, when the finding is about access) in frame, crop to the proof **in an image editor**, and keep the text legible at print size. Never crop inside Word — the full pixels stay in the file.

### Secrets: mask in the report, never ingest

**Do not bring secret values into your context window.** Reading a config backup, `.env`, credential dump or cookie jar contaminates the agent transcript and can leak the value into the report, a log or a later message.

- Inspect **shape, not values**: `grep -oE '^[[:space:]]*define\( *.[A-Z_]+'` or `grep -E 'DB_(NAME|USER|HOST)'` to confirm which fields exist; pipe through a masker before displaying anything, e.g. `grep -E 'DB_|AUTH_KEY|SALT|JWT' wp-config.php.save | sed -E "s/=.*/= ********/"`.
- **Never** `cat`, read in full, or paste a file that may contain secrets. Use the scanner finding (which reports field names) or the masked excerpt as evidence.
- In the report body, mask passwords, keys, tokens, salts, session cookies and personal data as `********`, keeping the **field name and syntax** visible. Full values stay only in the access-controlled raw artifact, cited by path. This is the house rule even when the secret is already considered compromised.
- Screenshots: redact with an **opaque fill in an image editor before** the file enters the report folder. Blur/pixelation are reversible and a box drawn in Word/PDF is not redaction. Never open or OCR an unmasked screenshot of secrets.
- Use the same mask/pseudonym for the same value everywhere; keep the pseudonym mapping outside the report.
- If a secret already appeared in tool output, do not repeat it — mask it immediately and treat the transcript as contaminated.
- Final check: search the finished Markdown/DOCX/PDF for the value; if it is found, the report is not ready.

## Worked example (REDCap engagement)

A complete filled instance exists in this workspace:

- `REPORT.md` — the finished report for `redcap.fieb.org.br`.
- `FINDINGS.md`, `UPDATE.md` — the raw/technical findings and tool defects.
- `raw/`, `reports/`, `exploits/evidence/` — the evidence artifacts.

Use it as the reference for tone and density. Note how Finding 1 is admitted: version `13.7.7` **and** the public-survey precondition were both evidenced — that is what justifies `Crítica (10)` — while unproven scanner hits (weak-HSTS, hardcoded-password, DOM-XSS) were discarded to Apêndice C.

## Final validation

- [ ] Severity summary counts == findings list == detail sections.
- [ ] Índice matches headings, in order.
- [ ] Every finding cites a proof artifact; every cited path exists.
- [ ] Sumário Executivo ≤ 1 page, no jargon, one-sentence headline, 3 prioritized actions.
- [ ] Every finding has a figure when a capture exists; captions state what the figure proves; figures referenced by number in the Análise.
- [ ] No secret value anywhere in the Markdown/DOCX body; masked fields keep the field name; screenshot redaction verified (opaque fill, not blur/overlay).
- [ ] Every Recomendação ends with a "como conferir" verification step.
- [ ] No exploitation claims; non-destructive language throughout.
- [ ] Appendix C lists every discarded/unverified candidate.
- [ ] Output file is `Relatório de Avaliação de Segurança - <target>.md`.
