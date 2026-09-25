# recon_wp/steps/tools/ffuf_base.py
"""Shared FFUF step implementation.

FFUF (Fuzz Faster U Fool) is a fast web fuzzer. The directory, file and
WordPress path steps only differ in their wordlist, URL suffix and finding
wording, so the command construction, output parsing and failure handling
live here.

Version note:
- ``-ik`` never existed in ffuf; ``-ic`` ignores wordlist comments.
- ``-t`` controls threads, ``-rate`` caps requests/second.
- ffuf does not verify TLS certificates, so no insecure flag is needed.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from base.dependencies import config_int, config_str
from base.step import BaseToolStep
from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.finding import Finding
from core.target import Target
from utils.wordlist_loader import get_wordlist_path

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_WORDLISTS_DIR = PROJECT_ROOT / "wordlists" / "ffuf"


class FfufBaseStep(BaseToolStep):
    """Base class for FFUF-based discovery steps.

    SECURITY:
    - Verifies ffuf binary exists before execution
    - Uses async subprocess to prevent blocking
    - Parses JSON output safely
    - Respects rate limiting

    SUBCLASS CONTRACT:
    - ``wordlist_file``: relative path under ``wordlists/``
    - ``url_suffix``: path appended to the target URL (must contain ``FUZZ``)
    - ``finding_title`` / ``finding_description`` / ``finding_recommendation``
    """

    name = "ffuf"
    description = "FFUF discovery"
    severity = "info"
    _tool_binary = "ffuf"
    MODULE = "tools"
    min_version = "2.0.0"

    wordlist_file: str = ""
    url_suffix: str = "/FUZZ"
    finding_title: str = "Path Found"
    finding_description: str = "Path discovered via FFUF fuzzing"
    finding_recommendation: str = "Review path access controls and functionality"

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        http=None,
        wordlist: Optional[str] = None,
        timeout: Optional[int] = None,
        rate_limit: Optional[int] = None,
        filter_status: Optional[str] = None,
        threads: Optional[int] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        default_wordlist = get_wordlist_path(self.wordlist_file) or (
            DEFAULT_WORDLISTS_DIR / Path(self.wordlist_file).name
        )
        self.wordlist = (
            wordlist or config_str(config, "ffuf_wordlist") or str(default_wordlist)
        )
        self.timeout = (
            timeout if timeout is not None else config_int(config, "ffuf_timeout", 300)
        )
        self.rate_limit = (
            rate_limit
            if rate_limit is not None
            else config_int(config, "ffuf_rate_limit", 0)
        )
        self.threads = (
            threads
            if threads is not None
            else config_int(config, "ffuf_threads", 40)
        )
        self.http_timeout = config_int(config, "ffuf_http_timeout", 10)
        self.filter_status = (
            filter_status
            if filter_status is not None
            else config_str(config, "ffuf_filter_status", "404") or "404"
        )

    def _target_url(self) -> str:
        return str(self.target.url) if self.target is not None else ""

    def build_command(self) -> list[str]:
        """Build the FFUF command for discovery."""
        cmd = [
            self._tool_binary,
            "-u",
            self._target_url() + self.url_suffix,
            "-w",
            self.wordlist,
            "-json",
            "-t",
            str(self.threads),
            "-fc",
            self.filter_status,
            "-timeout",
            str(self.http_timeout),
            "-ic",
        ]

        if self.rate_limit and self.rate_limit > 0:
            cmd.extend(["-rate", str(self.rate_limit)])

        if getattr(self.config, "quiet", False):
            cmd.append("-s")

        return cmd

    def _parse_records(self, stdout: str) -> tuple[list[Finding], int]:
        """Parse newline-delimited JSON records.

        Returns:
            Tuple of (findings, invalid_line_count). ``invalid_line_count``
            counts non-empty lines that are not valid JSON.
        """
        findings: list[Finding] = []
        invalid = 0

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue

            if not isinstance(data, dict) or not data:
                continue

            url = data.get("url", "")
            status = data.get("status", 0)
            length = data.get("length", 0)
            word = data.get("word", "")

            if not word or not url:
                continue

            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title=f"{self.finding_title}: {word}",
                    description=self.finding_description,
                    evidence=f"URL: {url}\nStatus: {status}\nSize: {length}",
                    recommendation=self.finding_recommendation,
                    raw={"word": word, "url": url, "status": status, "length": length},
                )
            )

        return findings, invalid

    def parse_output(self, result: ToolResult) -> list[Finding]:
        """Parse FFUF JSON output into findings."""
        findings, _ = self._parse_records(result.stdout or "")
        return findings

    def _handle_result(self, result: ToolResult) -> None:
        """Interpret a completed ffuf run, failing loudly on tool errors."""
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        if result.returncode != 0:
            self.logger.error(
                f"FFUF exited with code {result.returncode}: {stderr[:300]}"
            )
            self._add_finding(
                module=self.MODULE,
                severity="high",
                title="FFUF Execution Failed",
                description=(
                    f"FFUF exited with code {result.returncode}; the scan did not "
                    "complete and results are unreliable."
                ),
                evidence=stderr[:1000]
                or stdout[:1000]
                or f"returncode={result.returncode}",
                recommendation=(
                    "Verify the ffuf version (>= 2.0), wordlist path and flags. "
                    "Review the raw stderr for details."
                ),
                raw={"returncode": result.returncode, "stderr": stderr[:2000]},
            )
            return

        findings, invalid = self._parse_records(stdout)
        if stdout and not findings and invalid:
            self.logger.error("FFUF output was not valid JSON")
            self._add_finding(
                module=self.MODULE,
                severity="high",
                title="FFUF Output Unparseable",
                description=(
                    "FFUF returned output that could not be parsed as JSON records; "
                    "the output format may have changed."
                ),
                evidence=stdout[:1000],
                recommendation="Check the ffuf version and its JSON output format.",
                raw={"invalid_lines": invalid},
            )
            return

        self.findings = findings
        if not findings:
            self.logger.info("FFUF completed: 0 results")
        else:
            self.logger.info(f"FFUF completed: {len(findings)} result(s)")

    async def run(self) -> list[Finding]:
        """Execute FFUF discovery with loud failure handling."""
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.error(error)
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="FFUF Not Available",
                description="FFUF binary not found or not installed",
                evidence=error,
                recommendation=(
                    "Install FFUF: brew install ffuf (macOS) or download from "
                    "https://github.com/ffuf/ffuf/releases"
                ),
            )
            return self.findings

        if not self.check_version_compatibility():
            return self.findings

        self.logger.info(f"Running FFUF on {self._target_url()}")

        cmd = self.build_command()
        self.logger.debug(f"Command: {' '.join(cmd)}")

        started_at = datetime.now(timezone.utc)
        try:
            result = await self._async_tool_runner.run(cmd, timeout=self.timeout)
            self._persist_raw(
                cmd,
                result,
                started_at,
                datetime.now(timezone.utc),
                native_name=f"ffuf-{self.name}.json",
            )
            self._handle_result(result)
        except ToolTimeoutError:
            self.logger.error(f"FFUF timed out after {self.timeout}s")
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
                title="FFUF Timeout",
                description=f"FFUF exceeded timeout of {self.timeout} seconds",
                evidence=f"Timeout: {self.timeout}s",
                recommendation="Increase timeout or reduce wordlist size",
            )
        except Exception as e:
            self.logger.error(f"FFUF error: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="FFUF Error",
                description="FFUF encountered an unexpected error",
                evidence=str(e),
                recommendation="Check FFUF installation",
            )

        return self.findings
