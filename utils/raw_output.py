"""Raw external-tool output persistence.

Writes the exact stdout/stderr/argv of every external tool step to disk so the
evidence survives even when ``parse_output`` discards it (e.g. a tool failing
with an unexpected flag yet the step reporting "0 findings").

Layout (under ``<output>/raw`` by default)::

    <step>.output       single combined record (header + command + streams +
                        native) - written ALWAYS, even on an empty result, so
                        its presence proves the tool ran
    <step>.stdout
    <step>.stderr
    <step>.cmd          shell command wrapped at CMD_WIDTH columns (line
                        continuations) so it does not overflow horizontally
    <step>.meta.json    {step, tool, version, returncode, duration_ms, ...}
    <native file>       optional best-effort machine-format copy (written even
                        when empty, so presence == "the tool ran")
    history/<run-id>/   previous artifacts are moved here before being
                        overwritten, so a re-run never destroys the last attempt

Writing is best-effort: failures are logged and never abort a scan.
"""

from __future__ import annotations

import json
import secrets
import shlex
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from base.tool import ToolResult, _redact_sensitive_from_output

DEFAULT_MAX_BYTES = 5_000_000

# Wrap the persisted command at this width with `\` continuations so the file
# is readable and copy-pasteable without horizontal overflow.
CMD_WIDTH = 100


def format_command(cmd: list[str] | None, width: int = CMD_WIDTH) -> str:
    """Render argv as a shell command wrapped to ``width`` columns.

    Arguments are quoted with :func:`shlex.quote` and joined with spaces,
    inserting a trailing ``\\`` + newline when the next argument would exceed
    the width. The result is a single, pasteable shell command.
    """
    tokens = [shlex.quote(str(a)) for a in (cmd or [])]
    if not tokens:
        return ""
    lines: list[str] = []
    current = tokens[0]
    for token in tokens[1:]:
        if len(current) + 1 + len(token) > width:
            lines.append(current + " \\")
            current = "  " + token
        else:
            current += " " + token
    lines.append(current)
    return "\n".join(lines) + "\n"


def _iso(value: datetime | None) -> str:
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _byte_len(text: str) -> int:
    return len((text or "").encode("utf-8", errors="replace"))


class RawArtifactWriter:
    """Persist raw tool artifacts for a configured scan."""

    def __init__(self, config: Any, logger: Any = None):
        self._config = config
        self._logger = logger
        self._run_id: str | None = None

    @property
    def enabled(self) -> bool:
        # Strict identity: a real config stores a bool. MagicMock test doubles
        # return an arbitrary Mock here and must be treated as disabled.
        return getattr(self._config, "save_raw", False) is True

    def directory(self) -> Path:
        """Resolve the raw output directory."""
        configured = getattr(self._config, "raw_output_dir", "") or ""
        if configured:
            return Path(str(configured))
        output_dir = getattr(self._config, "output_dir", None) or Path("./reports")
        return Path(str(output_dir)) / "raw"

    def run_id(self) -> str:
        """Stable identifier for this writer's run (used to archive history)."""
        if self._run_id is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            self._run_id = f"{stamp}-{secrets.token_hex(3)}"
        return self._run_id

    def _history_enabled(self) -> bool:
        # Strict identity so MagicMock configs do not trigger archiving.
        return getattr(self._config, "raw_history", True) is True

    def _archive(self, base: Path, names: list[str]) -> None:
        """Move any existing artifact into ``history/<run-id>/`` before rewrite.

        The archive folder is named after the *previous* run (read from the
        existing ``.meta.json``) when available, so history reads naturally;
        it falls back to the current run id. Best-effort: a failure to archive
        must never block writing the new run.
        """
        if not self._history_enabled():
            return
        try:
            archive_id = self._existing_run_id(base, names) or self.run_id()
            history = base / "history" / archive_id
            for name in names:
                source = base / name
                if not source.exists():
                    continue
                history.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.move(str(source), str(history / name))
                except OSError:
                    # Cross-device or permission issue - fall back to copy/remove.
                    try:
                        shutil.copy2(source, history / name)
                        source.unlink()
                    except OSError:
                        pass
        except Exception as exc:  # pragma: no cover - defensive
            if self._logger is not None:
                self._logger.debug(f"Raw history archive skipped: {exc}")

    @staticmethod
    def _existing_run_id(base: Path, names: list[str]) -> str | None:
        """Return the run_id recorded in an existing artifact's meta.json."""
        for name in names:
            if not name.endswith(".meta.json"):
                continue
            meta_path = base / name
            if not meta_path.exists():
                continue
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            run_id = data.get("run_id")
            if isinstance(run_id, str) and run_id:
                return run_id
        return None

    def _redact(self, text: str) -> str:
        if getattr(self._config, "raw_no_redact", False):
            return text
        return _redact_sensitive_from_output(text)

    def _cap(self, text: str) -> str:
        try:
            max_bytes = int(getattr(self._config, "raw_max_bytes", DEFAULT_MAX_BYTES) or 0)
        except (TypeError, ValueError):
            max_bytes = DEFAULT_MAX_BYTES
        if max_bytes <= 0:
            return text
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= max_bytes:
            return text
        truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
        return f"{truncated}\n... [truncated at {max_bytes} bytes]\n"

    def _write(self, base: Path, name: str, content: str) -> None:
        (base / name).write_text(self._cap(content), encoding="utf-8", errors="replace")

    def _combined(
        self,
        step: str,
        tool: str,
        cmd: list[str] | None,
        result: ToolResult,
        started_at: datetime | None,
        finished_at: datetime | None,
        duration_ms: float | None,
        native_name: str | None,
        native: str,
        stdout: str,
        stderr: str,
    ) -> str:
        """Render one combined, proof-of-execution record for a tool run."""
        rc = getattr(result, "returncode", None)
        header = [
            f"# step: {step}",
            f"# tool: {tool} ({self._tool_version(tool)})",
            f"# returncode: {rc}",
            f"# started_at: {_iso(started_at)}",
            f"# finished_at: {_iso(finished_at)}",
            f"# duration_ms: {duration_ms}",
            f"# native: {native_name or '-'}",
        ]
        parts = [
            "\n".join(header),
            "",
            "########## command ##########",
            (format_command(cmd) or "(none)").rstrip("\n"),
            "",
            "########## stdout ##########",
            stdout if stdout else "(empty)",
            "",
            "########## stderr ##########",
            stderr if stderr else "(empty)",
        ]
        # Include the native payload only when it differs from stdout (avoids
        # duplicating nmap XML, which is already printed above).
        if native_name is not None and native != stdout:
            parts.extend(
                [
                    "",
                    f"########## native: {native_name} ##########",
                    native if native else "(empty)",
                ]
            )
        return "\n".join(parts) + "\n"

    def persist(
        self,
        step: str,
        tool: str,
        cmd: list[str] | None,
        result: ToolResult | None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        native_name: str | None = None,
        native_content: str | None = None,
        extra: dict | None = None,
    ) -> Path | None:
        """Write artifacts for a single tool invocation.

        Returns the raw directory on success, or None if disabled/failed.
        """
        if not self.enabled:
            return None

        result = result or ToolResult(stdout="", stderr="", returncode=-1, success=False)
        try:
            base = self.directory()
            base.mkdir(parents=True, exist_ok=True)

            stdout = result.stdout or ""
            stderr = result.stderr or ""
            # `None` means "no native artifact requested"; an empty string is a
            # legitimate empty artifact and is still written.
            native = native_content if native_content is not None else stdout

            artifact_names = [f"{step}.stdout", f"{step}.stderr", f"{step}.cmd"]
            if native_name is not None:
                artifact_names.append(native_name)
            artifact_names.extend([f"{step}.output", f"{step}.meta.json"])
            self._archive(base, artifact_names)

            self._write(base, f"{step}.stdout", self._redact(stdout))
            self._write(base, f"{step}.stderr", self._redact(stderr))
            # Wrapped shell command: readable, no horizontal overflow, and
            # still pasteable as a single command (trailing `\` continuations).
            self._write(base, f"{step}.cmd", format_command(cmd))
            if native_name is not None:
                self._write(base, native_name, self._redact(native))

            duration_ms = None
            if started_at and finished_at:
                duration_ms = round(
                    (finished_at - started_at).total_seconds() * 1000, 1
                )

            meta = {
                "step": step,
                "tool": tool,
                "version": self._tool_version(tool),
                "returncode": getattr(result, "returncode", None),
                "duration_ms": duration_ms,
                "started_at": _iso(started_at),
                "finished_at": _iso(finished_at),
                "stdout_bytes": _byte_len(stdout),
                "stderr_bytes": _byte_len(stderr),
                "native": native_name,
                "run_id": self.run_id(),
            }
            if isinstance(extra, dict):
                meta.update(extra)

            combined = self._combined(
                step,
                tool,
                cmd,
                result,
                started_at,
                finished_at,
                duration_ms,
                native_name,
                native,
                stdout,
                stderr,
            )
            self._write(base, f"{step}.output", self._redact(combined))

            (base / f"{step}.meta.json").write_text(
                json.dumps(meta, indent=2), encoding="utf-8"
            )
            return base
        except Exception as exc:  # never fail the scan on raw persistence
            if self._logger is not None:
                self._logger.warning(f"Raw output persistence failed for {step}: {exc}")
            return None

    def persist_evidence(
        self,
        step: str,
        records: list[dict],
        tool: str = "http",
        extra: dict | None = None,
    ) -> Path | None:
        """Persist per-request evidence for HTTP/active steps.

        Writes ``<step>.requests.jsonl`` (one JSON record per probe) plus a
        ``<step>.meta.json`` summary, so an intrusive run is independently
        reviewable even when it produced no findings. Best-effort: never raises.
        """
        if not self.enabled or not records:
            return None
        try:
            base = self.directory()
            base.mkdir(parents=True, exist_ok=True)
            names = [f"{step}.requests.jsonl", f"{step}.meta.json"]
            self._archive(base, names)

            payload = "\n".join(
                json.dumps(record, default=str) for record in records
            ) + "\n"
            self._write(base, f"{step}.requests.jsonl", self._redact(payload))

            meta = {
                "step": step,
                "tool": tool,
                "type": "http-evidence",
                "records": len(records),
                "run_id": self.run_id(),
            }
            if isinstance(extra, dict):
                meta.update(extra)
            (base / f"{step}.meta.json").write_text(
                json.dumps(meta, indent=2), encoding="utf-8"
            )
            return base
        except Exception as exc:  # never fail a scan on evidence persistence
            if self._logger is not None:
                self._logger.warning(
                    f"Raw evidence persistence failed for {step}: {exc}"
                )
            return None

    @staticmethod
    def _tool_version(tool: str) -> str:
        try:
            from utils.tool_version_checker import VersionChecker

            return VersionChecker().get_installed_version(tool)
        except Exception:
            return "unknown"
