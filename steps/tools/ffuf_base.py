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

import contextlib
import json
import math
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from base.dependencies import config_float, config_int, config_str
from base.step import BaseToolStep
from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.finding import Finding
from core.target import Target
from utils.wordlist_loader import get_wordlist_path, load_lines

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
    severity = "low"
    _tool_binary = "ffuf"
    MODULE = "tools"
    min_version = "2.0.0"

    wordlist_file: str = ""
    url_suffix: str = "/FUZZ"
    finding_title: str = "Path Found"
    finding_description: str = "Path discovered via FFUF fuzzing"
    finding_recommendation: str = "Review path access controls and functionality"

    # Per-step wordlist override key on ScanConfig (e.g. "ffuf_directory_wordlist").
    config_wordlist_key: str = ""

    # WordPress-only steps set this so the fuzzing wordlist is not spent on a
    # non-WordPress target (the WP paths would all fail/calibrate out).
    wp_only: bool = False

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
        per_step = (
            config_str(config, self.config_wordlist_key)
            if self.config_wordlist_key
            else ""
        )
        self.wordlist = (
            wordlist
            or per_step
            or config_str(config, "ffuf_wordlist")
            or str(default_wordlist)
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
        self.effective_timeout = self.timeout
        self._temp_wordlist: Optional[str] = None

    def _target_url(self) -> str:
        if self.target is None:
            return ""
        from utils.target_net import pinned_url

        return pinned_url(self.target)

    async def _confirm_wordpress(self) -> bool:
        """Return True when this step is allowed to run.

        WP-only steps (``wp_only=True``) are skipped on targets that do not
        show WordPress markers, so their wordlist is not wasted on generic
        SPA/soft-404 servers. When no HTTP client is attached (standalone or
        unit tests) the gate is a no-op.
        """
        if not self.wp_only or self.http is None:
            return True
        from utils.wordpress_detect import is_wordpress

        if await is_wordpress(self.http, self._target_url(), self.logger):
            return True
        self.logger.info(
            f"{self.name}: target is not WordPress - skipping WP-specific fuzzing"
        )
        return False

    def _wordlist_details(self) -> dict:
        """Wordlist name, path and entry count (cached) for evidence/reporting."""
        cached = getattr(self, "_wordlist_meta", None)
        if cached is not None:
            return cached
        path = Path(self.wordlist)
        lines = 0
        try:
            if path.is_file():
                lines = sum(1 for _ in load_lines(path, skip_comments=True))
        except Exception:  # pragma: no cover - defensive
            lines = 0
        self._wordlist_meta = {
            "wordlist": path.name,
            "wordlist_path": str(path),
            "wordlist_lines": lines,
        }
        return self._wordlist_meta

    def _seconds_per_probe(self) -> float:
        """Best-effort seconds per request for timeout sizing.

        ``-rate`` is an upper bound ffuf may not reach on a slow target, so
        the caller applies a safety factor on top. Without ``-rate`` ffuf runs
        up to ``threads`` concurrent requests, each bounded by
        ``-timeout``; that ratio is the pessimistic baseline.
        """
        if self.rate_limit > 0:
            return 1.0 / float(self.rate_limit)
        return max(
            float(self.http_timeout) / max(self.threads, 1),
            1.0 / max(self.threads, 1),
        )

    def _plan_timeout(self, lines: int) -> tuple[int, int]:
        """Return ``(timeout_seconds, probes_that_fit)`` for this wordlist.

        The configured timeout is a floor; the estimate is
        ``lines / rate * factor`` capped by ``ffuf_timeout_max``. When even
        the cap cannot cover the wordlist, the caller trims it so the step
        always completes and reports explicit partial coverage.
        """
        configured = self.timeout
        if getattr(self.config, "ffuf_auto_timeout", True) is not True:
            return configured, max(lines, 1)
        factor = config_float(self.config, "ffuf_timeout_factor", 3.0)
        cap = config_int(self.config, "ffuf_timeout_max", 3600)
        if lines <= 0:
            return configured, 0
        per_probe = self._seconds_per_probe()
        estimated = int(math.ceil(lines * per_probe * factor))
        timeout = max(configured, estimated)
        if cap > 0:
            timeout = min(timeout, cap)
        fit = lines
        if per_probe > 0:
            fit = max(1, min(lines, int(timeout / (per_probe * factor))))
            # If the estimate fits within the cap, keep the full wordlist.
            if timeout >= estimated:
                fit = lines
        return timeout, fit

    def _write_trimmed_wordlist(self, limit: int) -> Optional[str]:
        """Write the first ``limit`` wordlist entries to a temp file."""
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                suffix=f"-{self.name}.txt",
                prefix="ffuf-wordlist-",
                delete=False,
                encoding="utf-8",
            ) as handle:
                for count, line in enumerate(
                    load_lines(Path(self.wordlist), skip_comments=True), start=1
                ):
                    handle.write(line + "\n")
                    if count >= limit:
                        break
            self._temp_wordlist = handle.name
            return handle.name
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.debug(f"Could not trim ffuf wordlist: {exc}")
            return None

    def _cleanup_temp_wordlist(self) -> None:
        if not self._temp_wordlist:
            return
        with contextlib.suppress(OSError):
            Path(self._temp_wordlist).unlink(missing_ok=True)
        self._temp_wordlist = None

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

        # Split-horizon: fuzz the pinned IP but keep the real Host header.
        from utils.target_net import host_header, sni_hostname

        host = host_header(self.target)
        if host:
            cmd.extend(["-H", f"Host: {host}"])

        # ffuf derives TLS SNI from the URL host (the pinned IP); point it at
        # the real hostname so the virtual host serves its certificate.
        sni = sni_hostname(self.target)
        if sni:
            cmd.extend(["-sni", sni])

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
                    raw={
                        "word": word,
                        "url": url,
                        "status": status,
                        "length": length,
                        **self._wordlist_details(),
                    },
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
                severity="low",
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
                severity="low",
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

        # Keep pre-run operational findings (e.g. wordlist trimming) and append
        # the parsed results instead of discarding them.
        self.findings.extend(findings)
        if not findings:
            error_count = self._count_errors(stderr)
            if error_count:
                # ffuf exits 0 even when every request fails (TLS/SNI, DNS,
                # connection refused); surface that instead of a silent "0 results".
                self.logger.error(
                    f"FFUF reported {error_count} request error(s) and no results"
                )
                self._add_finding(
                    module=self.MODULE,
                    severity="low",
                    title="FFUF requests failed",
                    description=(
                        f"FFUF completed with 0 results and {error_count} request "
                        "error(s); the scan did not reach the target (check TLS "
                        "SNI/Host for pinned targets)."
                    ),
                    evidence=stderr[-1000:],
                    recommendation=(
                        "For pinned/IP targets pass -sni <host> (handled "
                        "automatically when --resolve/--target-ip is used); verify "
                        "the target is reachable."
                    ),
                    raw={"errors": error_count},
                )
                return
            self.logger.info("FFUF completed: 0 results")
        else:
            self.logger.info(f"FFUF completed: {len(findings)} result(s)")

    @staticmethod
    def _count_errors(stderr: str) -> int:
        """Return the highest 'Errors: N' count reported by ffuf, else 0."""
        counts = [int(m) for m in re.findall(r"Errors:\s*(\d+)", stderr or "")]
        return max(counts) if counts else 0

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

        if not await self._confirm_wordpress():
            return self.findings

        self.logger.info(f"Running FFUF on {self._target_url()}")
        details = self._wordlist_details()
        original_wordlist = self.wordlist
        total_lines = details["wordlist_lines"]
        self.effective_timeout, fits = self._plan_timeout(total_lines)
        if 0 < fits < total_lines:
            trimmed_path = self._write_trimmed_wordlist(fits)
            if trimmed_path:
                self.logger.warning(
                    f"FFUF wordlist trimmed to {fits}/{total_lines} entries "
                    f"to fit the {self.effective_timeout}s timeout budget"
                )
                details["wordlist_lines_total"] = total_lines
                details["wordlist_lines_used"] = fits
                details["wordlist_trimmed"] = True
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title="FFUF wordlist trimmed for the timeout budget",
                    description=(
                        f"Wordlist '{details['wordlist']}' has {total_lines} "
                        f"entries but only ~{fits} fit in "
                        f"{self.effective_timeout}s at the configured rate. "
                        "The first entries were scanned; coverage is partial."
                    ),
                    evidence=(
                        f"Wordlist: {details['wordlist']} "
                        f"({fits}/{total_lines} entries used)\n"
                        f"Timeout budget: {self.effective_timeout}s "
                        f"(WP_FFUF_TIMEOUT_MAX)"
                    ),
                    recommendation=(
                        "Raise WP_FFUF_TIMEOUT_MAX/--ffuf-timeout, increase the "
                        "rate limit, or use a smaller wordlist for full coverage"
                    ),
                    raw={
                        "operational": True,
                        "wordlist_lines_total": total_lines,
                        "wordlist_lines_used": fits,
                    },
                )
                self.wordlist = trimmed_path

        self.logger.info(
            f"FFUF wordlist: {details['wordlist']} "
            f"({total_lines} entries, timeout {self.effective_timeout}s)"
        )

        cmd = self.build_command()
        self.logger.debug(f"Command: {' '.join(cmd)}")

        started_at = datetime.now(timezone.utc)
        try:
            result = await self._async_tool_runner.run(
                cmd, timeout=self.effective_timeout
            )
            self._persist_raw(
                cmd,
                result,
                started_at,
                datetime.now(timezone.utc),
                native_name=f"ffuf-{self.name}.json",
                extra=details,
            )
            self._handle_result(result)
        except ToolTimeoutError:
            timeout = self.effective_timeout
            self.logger.error(f"FFUF timed out after {timeout}s")
            self._persist_raw(
                cmd,
                ToolResult(
                    stdout="",
                    stderr=f"TIMEOUT after {timeout}s",
                    returncode=-1,
                    success=False,
                ),
                started_at,
                datetime.now(timezone.utc),
                extra=details,
            )
            per_probe = self._seconds_per_probe()
            attempted = min(
                total_lines, int(timeout / per_probe) if per_probe > 0 else 0
            )
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="FFUF Timeout",
                description=(
                    f"FFUF exceeded the {timeout}s timeout "
                    f"(~{attempted}/{total_lines} entries attempted; ffuf "
                    "writes JSON only at exit, so partial results were lost)."
                ),
                evidence=(
                    f"Timeout: {timeout}s\n"
                    f"Wordlist: {details['wordlist']} ({total_lines} entries)\n"
                    f"Estimated coverage: {attempted}/{total_lines}"
                ),
                recommendation=(
                    "Raise WP_FFUF_TIMEOUT_MAX / --ffuf-timeout, lower "
                    "--ffuf-rate-limit, or use a smaller wordlist"
                ),
                raw={
                    "operational": True,
                    "timeout_seconds": timeout,
                    "wordlist_lines": total_lines,
                    "estimated_attempted": attempted,
                },
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
        finally:
            self._cleanup_temp_wordlist()
            self.wordlist = original_wordlist

        return self.findings
