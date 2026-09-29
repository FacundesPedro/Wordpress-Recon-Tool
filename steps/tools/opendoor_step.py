# recon_wp/steps/tools/opendoor_step.py
"""
OpenDoor WordPress path discovery step.

OpenDoor is a Python-based recon/directory discovery CLI for WordPress
and generic web targets. This step drives the modern (5.x) CLI, which
writes a JSON report to disk, then parses that report into findings.

Reference: https://github.com/stanislav-web/OpenDoor
"""

import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional, cast
from urllib.parse import urlsplit

from base.dependencies import config_float, config_int, config_str
from base.step import BaseToolStep
from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.finding import Finding
from core.target import Target
from utils.wordlist_loader import get_wordlist_path

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_WORDLISTS_DIR = PROJECT_ROOT / "wordlists" / "opendoor"

MODE_WORDLISTS = {
    "wp_paths": "wp_paths.txt",
    "backup": "backup_files.txt",
    "config": "config_files.txt",
    "sensitive": "sensitive_paths.txt",
}

# Buckets reported as findings (failed/redirect noise is not reported).
REPORTED_BUCKETS = {
    "success": "info",
    "indexof": "low",
}

# Names that indicate a sensitive artefact when discovered by discovery modes
# that do not content-validate the response (OpenDoor reports status only).
_SENSITIVE_PATH_RE = re.compile(
    r"(\.env|wp-config|/\.git|id_rsa|\.sql\b|\.dump\b|\.bak\b|\.old\b|"
    r"\.zip\b|\.tar\.gz\b|/backup|/dump)",
    re.IGNORECASE,
)


def _is_sensitive_path(url: str, mode: str) -> bool:
    """Return True when a discovered path is likely to be a secret/backup."""
    if mode in ("backup", "config"):
        return True
    return bool(_SENSITIVE_PATH_RE.search(url or ""))


def _operational_finding(step_name: str, title: str, evidence: str) -> Finding:
    return Finding(
        module="tools",
        step=step_name,
        severity="low",
        title=title,
        description=(
            "OpenDoor did not produce a usable report - the scan may not have "
            "run correctly"
        ),
        evidence=(evidence or "")[:300],
        recommendation="Verify the OpenDoor version/CLI and re-run the scan",
        raw={"operational": True},
    )


class OpenDoorStep(BaseToolStep):
    """OpenDoor WordPress path discovery step.

    SECURITY:
    - Verifies opendoor binary exists before execution
    - Uses async subprocess to prevent blocking
    - Parses the JSON report safely

    CAPABILITIES:
    - WordPress path discovery
    - Backup file detection
    - Configuration file detection
    - Sensitive path discovery
    """

    name = "opendoor"
    description = "OpenDoor WordPress path discovery"
    severity = "high"
    _tool_binary = "opendoor"
    MODULE = "tools"

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        http=None,
        wordlist: Optional[str] = None,
        timeout: Optional[int] = None,
        threads: Optional[int] = None,
        delay: Optional[float] = None,
        mode: Optional[str] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self.mode = mode or config_str(config, "opendoor_mode", "wp_paths") or "wp_paths"
        if self.mode not in MODE_WORDLISTS:
            self.mode = "wp_paths"
        default_wordlist = get_wordlist_path(
            f"opendoor/{MODE_WORDLISTS[self.mode]}"
        ) or (DEFAULT_WORDLISTS_DIR / MODE_WORDLISTS[self.mode])
        self.wordlist = (
            wordlist or config_str(config, "opendoor_wordlist") or str(default_wordlist)
        )
        self.timeout = (
            timeout
            if timeout is not None
            else config_int(config, "opendoor_timeout", 300)
        )
        configured_threads = config_int(config, "opendoor_rate_limit", 0)
        self.threads = threads if threads is not None else (configured_threads or 20)
        self.delay = (
            delay
            if delay is not None
            else config_float(config, "opendoor_delay", 0.5)
        )
        self._reports_dir: Optional[str] = None

    def _host_and_port(self) -> tuple[str, Optional[int]]:
        """Split an explicit port out of the target URL.

        OpenDoor validates ``--host`` strictly and rejects a host:port
        combination; non-standard ports must go through ``--port``.

        The scheme is parsed by OpenDoor from the ``--host`` URL itself
        (``--scheme`` only applies to ``--raw-request``), so the full URL is
        passed here and the scheme is retained.
        """
        url = str(self.target.url) if self.target else ""
        from utils.target_net import pinned_url

        url = pinned_url(self.target) if self.target else url
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return url, None
        if not port:
            return url, None
        host = f"{parsed.scheme}://{parsed.hostname}" if parsed.scheme else parsed.hostname
        return host or url, port

    async def _confirm_wordpress(self) -> bool:
        """Gate WP-path discovery on an actual WordPress target.

        Generic modes (backup/config/sensitive) are useful on any web target;
        ``wp_paths`` spends the wordlist on ``/wp-admin``, ``/wp-login.php``,
        ``xmlrpc.php``, etc. and is skipped when no WP markers are present.
        """
        if self.mode != "wp_paths" or self.http is None:
            return True
        from utils.wordpress_detect import is_wordpress

        target_url = str(self.target.url) if self.target else ""
        if await is_wordpress(self.http, target_url, self.logger):
            return True
        self.logger.info(
            "OpenDoor: target is not WordPress - skipping wp_paths discovery"
        )
        return False

    def build_command(self) -> list[str]:
        """Build the OpenDoor directory discovery command."""
        host, port = self._host_and_port()
        cmd = [
            self._tool_binary,
            "--host",
            host,
            "--scan",
            "directories",
            "--method",
            "GET",
            "--wordlist",
            self.wordlist,
            "--threads",
            str(self.threads),
            "--timeout",
            str(self.timeout),
            "--auto-calibrate",
            "--reports",
            "json",
            "--reports-dir",
            self._reports_dir or tempfile.gettempdir(),
        ]

        if port:
            cmd.extend(["--port", str(port)])

        # Split-horizon: scan the pinned IP but keep the real Host header.
        from utils.target_net import host_header

        host_header_value = host_header(self.target)
        if host_header_value:
            cmd.extend(["--header", f"Host: {host_header_value}"])

        if self.delay and self.delay > 0:
            cmd.extend(["--delay", str(self.delay)])

        if getattr(self.config, "quiet", False) is True:
            cmd.extend(["--debug", "-1"])

        return cmd

    @staticmethod
    def _find_report(reports_dir: str) -> Optional[Path]:
        """Locate the JSON report emitted by OpenDoor."""
        candidates = sorted(Path(reports_dir).rglob("*.json"))
        return candidates[0] if candidates else None

    @staticmethod
    def _word_from_url(url: str) -> str:
        """Derive a human-readable label from a discovered URL."""
        try:
            path = url.split("?", 1)[0].split("#", 1)[0].rstrip("/")
            return path.rsplit("/", 1)[-1] or url
        except Exception:
            return url

    def parse_output(self, result: ToolResult) -> list[Finding]:
        """Parse an OpenDoor JSON report into findings."""
        findings: list[Finding] = []

        if not result.stdout:
            if result.stderr:
                self.logger.debug(f"OpenDoor stderr: {result.stderr[:500]}")
            return findings

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse OpenDoor JSON report: {e}")
            findings.append(
                _operational_finding(
                    self.name, "OpenDoor Output Unparseable", result.stdout
                )
            )
            return findings

        if not isinstance(data, dict):
            findings.append(
                _operational_finding(
                    self.name, "OpenDoor Output Unparseable", result.stdout
                )
            )
            return findings

        report_items = data.get("report_items") or {}
        if not report_items:
            legacy_items = data.get("items") or {}
            if isinstance(legacy_items, dict):
                report_items = {
                    bucket: [
                        {"url": url, "code": None, "size": None}
                        for url in urls or []
                        if isinstance(url, str)
                    ]
                    for bucket, urls in legacy_items.items()
                }

        for bucket, severity in REPORTED_BUCKETS.items():
            for item in report_items.get(bucket, []) or []:
                if isinstance(item, str):
                    item = {"url": item}
                if not isinstance(item, dict):
                    continue

                url = item.get("url", "")
                if not url:
                    continue

                status = item.get("code", item.get("status", 0))
                size = item.get("size", item.get("length", 0))
                word = item.get("word") or self._word_from_url(url)

                # `severity` is the bucket default; use a per-item copy so a
                # sensitive path cannot leak its band to later items.
                item_severity = severity
                finding_confidence = "high"
                if bucket == "success":
                    title_prefix = "OpenDoor Path Found"
                    # OpenDoor only reports status/size, not content, so a
                    # sensitive-looking name is a high-impact lead but not a
                    # confirmed exposure.
                    if _is_sensitive_path(url, self.mode):
                        item_severity = "high"
                        finding_confidence = "low"
                else:
                    title_prefix = "OpenDoor Directory Listing"
                findings.append(
                    Finding(
                        module=self.MODULE,
                        step=self.name,
                        severity=cast(
                            Literal["info", "low", "medium", "high", "critical"],
                            item_severity,
                        ),
                        confidence=cast(
                            Literal["low", "medium", "high"], finding_confidence
                        ),
                        title=f"{title_prefix}: {word}",
                        description=(
                            "Path discovered via OpenDoor directory scanning "
                            f"(bucket: {bucket})"
                        ),
                        evidence=f"URL: {url}\nStatus: {status}\nSize: {size}",
                        recommendation="Review path access controls and functionality",
                        raw={
                            "word": word,
                            "url": url,
                            "status": status,
                            "size": size,
                            "bucket": bucket,
                            "mode": self.mode,
                        },
                    )
                )

        return findings

    async def run(self) -> list[Finding]:
        """Execute OpenDoor directory discovery and parse its JSON report."""
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.error(error)
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="OpenDoor Not Available",
                description="OpenDoor binary not found or not installed",
                evidence=error,
                recommendation=(
                    "Install OpenDoor: pipx install opendoor "
                    "(https://github.com/stanislav-web/OpenDoor)"
                ),
            )
            return self.findings

        if not await self._confirm_wordpress():
            return self.findings

        target_url = str(self.target.url) if self.target else ""
        self.logger.info(f"Running OpenDoor directory discovery on {target_url}")

        # Keep the reports directory when raw persistence is enabled instead of
        # discarding the JSON report with the temporary directory.
        tmpdir: Optional[tempfile.TemporaryDirectory] = None
        reports_dir = ""
        if self._raw_writer.enabled:
            try:
                candidate = self._raw_writer.directory() / "opendoor"
                candidate.mkdir(parents=True, exist_ok=True)
                reports_dir = str(candidate)
            except Exception as e:
                self.logger.warning(f"Could not create raw OpenDoor dir: {e}")
                reports_dir = ""
        if not reports_dir:
            tmpdir = tempfile.TemporaryDirectory(prefix="opendoor-")
            reports_dir = tmpdir.name

        started_at = datetime.now(timezone.utc)
        cmd: list[str] = []
        try:
            self._reports_dir = reports_dir
            cmd = self.build_command()
            self.logger.debug(f"Command: {' '.join(cmd)}")

            result = await self._async_tool_runner.run(cmd, timeout=self.timeout)

            report_file = self._find_report(reports_dir)
            if report_file is None:
                if result.stderr:
                    self.logger.debug(f"OpenDoor stderr: {result.stderr[:500]}")
                self._persist_raw(cmd, result, started_at, datetime.now(timezone.utc))
                self.logger.info("OpenDoor completed without a JSON report")
                self.findings.append(
                    _operational_finding(
                        self.name,
                        "OpenDoor Report Missing",
                        result.stderr or result.stdout or "no report file produced",
                    )
                )
                return self.findings

            try:
                report_text = report_file.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.logger.error(f"Failed to read OpenDoor report: {e}")
                self._persist_raw(cmd, result, started_at, datetime.now(timezone.utc))
                self.findings.append(
                    _operational_finding(self.name, "OpenDoor Report Unreadable", str(e))
                )
                return self.findings

            report_result = ToolResult(
                stdout=report_text,
                stderr=result.stderr,
                returncode=result.returncode,
                success=result.success,
            )
            self._persist_raw(
                cmd,
                result,
                started_at,
                datetime.now(timezone.utc),
                native_name="opendoor.json",
                native_content=report_text,
            )
            self.findings = self.parse_output(report_result)
            self.logger.info(
                f"OpenDoor completed: {len(self.findings)} path(s) found"
            )
        except ToolTimeoutError:
            self.logger.error(f"OpenDoor timed out after {self.timeout}s")
            self._persist_raw(
                cmd,
                ToolResult(
                    stdout="",
                    stderr=f"TIMEOUT after {self.timeout}s",
                    returncode=-1,
                    success=False,
                ),
                started_at,
                datetime.now(timezone.utc),
            )
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="OpenDoor Timeout",
                description=f"OpenDoor exceeded timeout of {self.timeout} seconds",
                evidence=f"Timeout: {self.timeout}s",
                recommendation="Increase timeout or reduce wordlist size",
            )
        except Exception as e:
            self.logger.error(f"OpenDoor error: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="OpenDoor Error",
                description="OpenDoor encountered an unexpected error",
                evidence=str(e),
                recommendation="Check OpenDoor installation",
            )
        finally:
            if tmpdir is not None:
                tmpdir.cleanup()

        return self.findings
