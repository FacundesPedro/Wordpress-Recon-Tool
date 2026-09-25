"""Raw external-tool output persistence.

Writes the exact stdout/stderr/argv of every external tool step to disk so the
evidence survives even when ``parse_output`` discards it (e.g. a tool failing
with an unexpected flag yet the step reporting "0 findings").

Layout (under ``<output>/raw`` by default)::

    <step>.stdout
    <step>.stderr
    <step>.cmd          one argv entry per line
    <step>.meta.json    {step, tool, version, returncode, duration_ms, ...}
    <native file>       optional best-effort machine-format copy

Writing is best-effort: failures are logged and never abort a scan.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from base.tool import ToolResult, _redact_sensitive_from_output

DEFAULT_MAX_BYTES = 5_000_000


def _iso(value: datetime | None) -> str:
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


class RawArtifactWriter:
    """Persist raw tool artifacts for a configured scan."""

    def __init__(self, config: Any, logger: Any = None):
        self._config = config
        self._logger = logger

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
            self._write(base, f"{step}.stdout", self._redact(stdout))
            self._write(base, f"{step}.stderr", self._redact(stderr))
            self._write(base, f"{step}.cmd", "\n".join(str(a) for a in (cmd or [])))

            native = native_content if native_content is not None else stdout
            if native_name and native:
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
            }
            (base / f"{step}.meta.json").write_text(
                json.dumps(meta, indent=2), encoding="utf-8"
            )
            return base
        except Exception as exc:  # never fail the scan on raw persistence
            if self._logger is not None:
                self._logger.warning(f"Raw output persistence failed for {step}: {exc}")
            return None

    @staticmethod
    def _tool_version(tool: str) -> str:
        try:
            from utils.tool_version_checker import VersionChecker

            return VersionChecker().get_installed_version(tool)
        except Exception:
            return "unknown"
