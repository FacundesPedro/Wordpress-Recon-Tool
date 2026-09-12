# recon_wp/steps/tools/opendoor_step.py
"""
OpenDoor WordPress path discovery step.

OpenDoor is a Python-based recon/directory discovery CLI for WordPress
and generic web targets. This step drives the modern (5.x) CLI, which
writes a JSON report to disk, then parses that report into findings.

Reference: https://github.com/stanislav-web/OpenDoor
"""

import json
import tempfile
from pathlib import Path
from typing import Optional
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
    severity = "info"
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
        """
        url = str(self.target.url)
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return url, None
        if not port:
            return url, None
        host = f"{parsed.scheme}://{parsed.hostname}" if parsed.scheme else parsed.hostname
        return host or url, port

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
            return findings

        if not isinstance(data, dict):
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

                if bucket == "success":
                    title_prefix = "OpenDoor Path Found"
                else:
                    title_prefix = "OpenDoor Directory Listing"
                findings.append(
                    Finding(
                        module=self.MODULE,
                        step=self.name,
                        severity=severity,
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

        self.logger.info(
            f"Running OpenDoor directory discovery on {self.target.url}"
        )

        try:
            with tempfile.TemporaryDirectory(prefix="opendoor-") as reports_dir:
                self._reports_dir = reports_dir
                cmd = self.build_command()
                self.logger.debug(f"Command: {' '.join(cmd)}")

                result = await self._async_tool_runner.run(cmd, timeout=self.timeout)

                report_file = self._find_report(reports_dir)
                if report_file is None:
                    if result.stderr:
                        self.logger.debug(f"OpenDoor stderr: {result.stderr[:500]}")
                    self.logger.info("OpenDoor completed without a JSON report")
                    return self.findings

                try:
                    report_text = report_file.read_text(encoding="utf-8", errors="replace")
                except OSError as e:
                    self.logger.error(f"Failed to read OpenDoor report: {e}")
                    return self.findings

                report_result = ToolResult(
                    stdout=report_text,
                    stderr=result.stderr,
                    returncode=result.returncode,
                    success=result.success,
                )
                self.findings = self.parse_output(report_result)
                self.logger.info(
                    f"OpenDoor completed: {len(self.findings)} path(s) found"
                )
        except ToolTimeoutError:
            self.logger.error(f"OpenDoor timed out after {self.timeout}s")
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

        return self.findings
