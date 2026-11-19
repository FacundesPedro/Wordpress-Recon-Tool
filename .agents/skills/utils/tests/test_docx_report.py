"""Tests for the SOC – Data Center DOCX report generator."""

from __future__ import annotations

import base64
import sys
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("docx")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from docx_report import build_docx  # noqa: E402

ASSESSMENT_MD = """# Relatório de Avaliação de Segurança
## SOC – Data Center

Alvo: **app.example.com**
Data da avaliação: **1 de janeiro de 2026**

### Aviso de Confidencialidade

Texto.

### Isenção de responsabilidade

Texto.

---

## Índice

- Sumário Executivo

---

## Sumário Executivo

Resumo.

| Crítica | Alta | Média | Baixa | Informação |
|---------|------|-------|-------|------------|
| 0 | 0 | 1 | 1 | 0 |

**Destaque:** corrigir.

---

## Classificações

### Classificação de Riscos

| Nível | Pontuação | Descrição |
|-------|-----------|-----------|
| Crítico | 10 | A vulnerabilidade possui uma imediata ameaça para a organização. |
| Alto | 7-9 | Ameaça imediata. |
| Médio | 4-6 | Exploração possível. |
| Baixo | 1-3 | Ameaça mínima. |
| Informação | 0 | Sem ameaça clara. |

### Classificação de Probabilidade de Exploração

| Probabilidade | Descrição |
|---------------|-----------|
| Provável | Métodos conhecidos. |
| Possível | Requer configuração. |
| Improvável | Requer profundo conhecimento. |

---

## Achados da Avaliação

### – Achados encontrados (resumo)

| Número | Achado | Pontuação de risco | Risco | Interno/Externo |
|--------|--------|--------------------|-------|-----------------|
| 1 | Falha X | 5 | Médio | Interno |
| 2 | Falha Y | 3 | Baixo | Interno |

### – Achados encontrados (detalhes)

## 1 – Falha X

**Médio (5)**

| Probabilidade de Exploração | Impacto ao Negócio | Dificuldade de Remediação |
|-----------------------------|--------------------|---------------------------|
| Possível | Moderada | Fácil |

**Implicações de Segurança**

Impacto.

**Análise**

Análise.

**Evidências**

```
$ curl -I https://app.example.com
HTTP/2 200
```

Evidências: `raw/manual/evidencia.txt`.

**Recomendação**

Corrigir.

---

## Recomendações Gerais

1. Corrigir.

---

## Apêndice A – Ferramentas Usadas

| Ferramenta | Descrição |
|------------|-----------|
| curl | Requisições HTTP |

## Apêndice B – Siglas

| Sigla | Descrição de uso |
|-------|------------------|
| CSP | Content Security Policy |

## Apêndice C – Observações e Falsos Positivos

- Observação.

### Índice de evidências

| Arquivo | Conteúdo |
|---------|----------|
| `raw/manual/evidencia.txt` | Evidência |
"""

REASSESSMENT_MD = """# Relatório de Reavaliação de Segurança
## SOC – Data Center

Alvo: **app.example.com**
Data da reavaliação: **1 de janeiro de 2026**

---

| Período | Crítica | Alta | Média | Baixa |
|---------|---------|------|-------|-------|
| **Antes** | 0 | 0 | 1 | 1 |
| **Depois** | 0 | 0 | 0 | 2 |

---

## Classificação de Definições

### Classificação do Tratamento Aplicado

| Tratamento | Descrição |
|------------|-----------|
| Mitigado | Corrigida. |
| Parcialmente mitigado | Parte corrigida. |
| Não mitigado | Permanece. |

---

## Achados da Avaliação – Servidores

### – Achados tratados (resumo)

| Número | Achado | Classificação do tratamento | Interno/Externo |
|--------|--------|------------------------------|-----------------|
| 1 | Falha X | Não mitigado | Interno |
| 2 | Falha Y | Mitigado | Interno |

### – Achados tratados (detalhes)

#### 1 – Falha X

| Tratamento aplicado | Não mitigado |
|---------------------|--------------|

**Controle empregado**

Nenhum.

**Análise**

Permanece.

**Evidências**

```
$ curl -I https://app.example.com
HTTP/2 200
```

*Figura 1 – Cabeçalho observado.*

Evidências: `raw/manual/evidencia.txt`.
"""


def _xml(path) -> str:
    with zipfile.ZipFile(path) as z:
        return z.read("word/document.xml").decode("utf-8")


def test_assessment_docx_has_severity_colours_and_evidence(tmp_path):
    md = tmp_path / "report.md"
    md.write_text(ASSESSMENT_MD, encoding="utf-8")
    out = build_docx(md, tmp_path / "report.docx")

    assert out.exists()
    xml = _xml(out)
    assert "000000" in xml  # Crítica
    assert "A61C00" in xml  # Alta
    assert "F1C232" in xml  # Média
    assert "38761D" in xml  # Baixa
    assert "E06666" in xml  # rating scale high
    assert "FFD966" in xml  # rating scale medium
    assert "93C47D" in xml  # rating scale low
    # command-only evidence: no figure slot, artifact path still rendered
    assert "INSERIR CAPTURA" not in xml
    assert "raw/manual/evidencia.txt" in xml


def test_assessment_docx_has_logo_and_no_screenshots(tmp_path):
    md = tmp_path / "report.md"
    md.write_text(ASSESSMENT_MD, encoding="utf-8")
    out = build_docx(md, tmp_path / "report.docx")

    with zipfile.ZipFile(out) as z:
        media = [n for n in z.namelist() if n.startswith("word/media/")]
    # cover logo + RESTRITO badge, no evidence screenshots
    assert len(media) == 2


def test_reassessment_docx_uses_treatment_colours(tmp_path):
    md = tmp_path / "report.md"
    md.write_text(REASSESSMENT_MD, encoding="utf-8")
    out = build_docx(md, tmp_path / "report.docx")

    xml = _xml(out)
    assert "38761D" in xml  # Mitigado
    assert "C9211E" in xml  # Não mitigado
    assert "FFBF00" in xml or "F1C232" in xml
    assert "INSERIR CAPTURA" in xml


def test_toc_and_page_numbers(tmp_path):
    md = tmp_path / "report.md"
    md.write_text(ASSESSMENT_MD, encoding="utf-8")
    out = build_docx(md, tmp_path / "report.docx")

    with zipfile.ZipFile(out) as z:
        doc = z.read("word/document.xml").decode("utf-8")
        footer = z.read("word/footer1.xml").decode("utf-8")
        header = z.read("word/header1.xml").decode("utf-8")
        settings = z.read("word/settings.xml").decode("utf-8")
    assert "Índice" in doc
    assert "Sumário Executivo" in doc
    assert "PAGE" in footer
    assert "009DDC" in header and "009DDC" in footer
    assert "updateFields" in settings


PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
    "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def _md_with_figure(tmp_path: Path, image_path: str, create: bool) -> Path:
    if create:
        target = tmp_path / image_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(PNG_1PX)
    figure = f"![Figura 1 – Evidência do achado]({image_path})"
    body = ASSESSMENT_MD.replace(
        "**Evidências**\n\n```",
        f"**Evidências**\n\n{figure}\n\n```",
    )
    md = tmp_path / "report.md"
    md.write_text(body, encoding="utf-8")
    return md


def test_existing_screenshot_is_embedded(tmp_path):
    md = _md_with_figure(tmp_path, "img/figura-1.png", create=True)
    out = build_docx(md, tmp_path / "report.docx")

    assert "INSERIR CAPTURA" not in _xml(out)
    assert "Evidência do achado" in _xml(out)
    with zipfile.ZipFile(out) as z:
        media = [n for n in z.namelist() if n.startswith("word/media/")]
    assert len(media) == 3  # cover logo + RESTRITO badge + embedded screenshot


def test_missing_screenshot_keeps_placeholder(tmp_path):
    md = _md_with_figure(tmp_path, "img/nao-existe.png", create=False)
    out = build_docx(md, tmp_path / "report.docx")

    xml = _xml(out)
    assert "INSERIR CAPTURA" in xml
    assert "img/nao-existe.png" in xml
