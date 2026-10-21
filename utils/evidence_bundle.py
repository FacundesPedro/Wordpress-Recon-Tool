"""Per-finding evidence bundle (command + output excerpt + artifact path).

The client requires, for every reported finding, the exact command that
produced it and the raw artifact that proves the observation. Tool steps
already persist ``raw/<step>.cmd``/``.output``; this module links those files
to findings and renders a standalone ``EVIDENCIAS.md``.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from core.finding import Finding

MAX_EXCERPT_LINES = 25
_MAX_READ_BYTES = 200_000

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def raw_dir_for(config) -> Path:
    """Resolve the raw artifact directory for a config (no writer needed)."""
    configured = getattr(config, "raw_output_dir", "") or ""
    if configured:
        return Path(str(configured))
    output_dir = getattr(config, "output_dir", None) or Path("./reports")
    return Path(str(output_dir)) / "raw"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:_MAX_READ_BYTES]
    except OSError:
        return ""


def attach_commands(
    findings: Iterable[Finding], config
) -> list[Finding]:
    """Return findings with ``command`` filled from ``raw/<step>.cmd``."""
    base = raw_dir_for(config)
    cache: dict[str, str] = {}
    out: list[Finding] = []
    for finding in findings:
        if finding.command:
            out.append(finding)
            continue
        step = finding.step
        if step not in cache:
            path = base / f"{step}.cmd"
            cache[step] = _read(path).strip() if path.exists() else ""
        out.append(finding.with_command(cache[step]))
    return out


def _artifact_path(step: str, config) -> Path:
    return raw_dir_for(config) / f"{step}.output"


def _excerpt(path: Path, hint: str = "") -> str:
    """Return a short, relevant slice of the tool output."""
    text = _read(path)
    if not text:
        return ""
    lines = text.splitlines()
    needle = ""
    for line in (hint or "").splitlines():
        candidate = line.strip()
        if candidate:
            needle = candidate[:80]
            break
    if needle:
        for index, line in enumerate(lines):
            if needle in line:
                start = max(0, index - 2)
                return "\n".join(lines[start : index + 3])
    return "\n".join(lines[:MAX_EXCERPT_LINES])


def render_evidence_markdown(
    findings: Iterable[Finding], config, target: str = ""
) -> str:
    """Render the evidence bundle as Markdown."""
    findings = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.index(f.severity)
            if f.severity in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER),
            f.title,
        ),
    )
    base = raw_dir_for(config)
    lines = ["# Evidências por achado", ""]
    if target:
        lines.append(f"Alvo: `{target}`")
    lines.append(f"Artefatos brutos: `{base}`")
    lines.append("")
    if not findings:
        lines.append("Nenhum achado registrado.")
        return "\n".join(lines) + "\n"

    command_cache: dict[str, str] = {}
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"## {index}. [{finding.severity}] {finding.title}"
        )
        lines.append("")
        lines.append(f"- Módulo/passo: `{finding.module}.{finding.step}`")
        lines.append(f"- Confiança: `{finding.confidence}`")
        command = finding.command.strip()
        if not command:
            if finding.step not in command_cache:
                cmd_path = base / f"{finding.step}.cmd"
                command_cache[finding.step] = (
                    _read(cmd_path).strip() if cmd_path.exists() else ""
                )
            command = command_cache[finding.step]
        if command:
            lines.append("- Comando:")
            lines.append("")
            lines.append("```shell")
            lines.append(command)
            lines.append("```")
        else:
            lines.append("- Comando: (passo interno, sem ferramenta externa)")
        artifact = _artifact_path(finding.step, config)
        if artifact.exists():
            lines.append(f"- Artefato: `{artifact}`")
            excerpt = _excerpt(artifact, finding.evidence)
            if excerpt:
                lines.append("- Trecho da saída:")
                lines.append("")
                lines.append("```text")
                lines.append(excerpt)
                lines.append("```")
        else:
            lines.append("- Artefato: (não persistido nesta execução)")
        lines.append("")
    return "\n".join(lines) + "\n"


def write_evidence_bundle(
    findings: Iterable[Finding], config, path: Path, target: str = ""
) -> Path | None:
    """Write ``EVIDENCIAS.md`` next to the reports. Never raises."""
    try:
        content = render_evidence_markdown(findings, config, target=target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
    except Exception:
        return None
