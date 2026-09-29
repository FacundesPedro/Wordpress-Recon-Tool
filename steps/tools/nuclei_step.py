# recon_wp/steps/tools/nuclei_step.py
"""
Nuclei integration - fast vulnerability scanner using templates.

Nuclei is a fast vulnerability scanner based on templates that can detect
various security issues including WordPress-specific vulnerabilities.
"""

import json
from datetime import datetime, timezone
from typing import Literal, Optional, cast

from base.dependencies import config_int
from base.step import BaseToolStep
from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.finding import Finding
from core.target import Target


class NucleiStep(BaseToolStep):
    """Nuclei vulnerability scanner wrapper.

    SECURITY:
    - Verifies nuclei binary exists before execution
    - Uses async subprocess to prevent blocking
    - Parses JSON output safely
    - Respects severity filtering

    CAPABILITIES:
    - WordPress-specific template scanning
    - CVE detection via template matching
    - Configurable severity filtering
    - Fast concurrent scanning
    """

    name = "nuclei"
    description = "Nuclei vulnerability scanner using templates"
    severity = "medium"
    _tool_binary = "nuclei"
    MODULE = "tools"

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        http=None,  # Accepted for BaseToolStep compatibility
        severity: Optional[str] = None,
        threads: Optional[int] = None,
        timeout: Optional[int] = None,
        rate_limit: Optional[int] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self.severity_filter = severity or getattr(
            config, "nuclei_severity", "medium,high,critical"
        )
        self.threads = (
            threads if threads is not None else config_int(config, "nuclei_threads", 25)
        )
        self.rate_limit = (
            rate_limit
            if rate_limit is not None
            else config_int(config, "nuclei_rate_limit", 150)
        )
        self.timeout = (
            timeout if timeout is not None else config_int(config, "nuclei_timeout", 300)
        )

    def _target_url(self) -> str:
        if self.target is None:
            return ""
        from utils.target_net import pinned_url

        return pinned_url(self.target)

    def build_command(self) -> list[str]:
        """Build Nuclei command with all options."""
        cmd = [
            self._tool_binary,
            "-u",
            self._target_url(),
            "-severity",
            self.severity_filter,
            "-jsonl",  # -json was deprecated, use -jsonl for JSON Lines output
            "-concurrency",
            str(self.threads),
            "-rl",
            str(self.rate_limit),
            "-silent",
        ]

        # Split-horizon: scan the pinned IP but keep the real Host header.
        from utils.target_net import host_header

        host = host_header(self.target)
        if host:
            cmd.extend(["-H", f"Host: {host}"])

        # Nuclei disables TLS certificate validation by default, so there is
        # no insecure flag to pass (and no --insecure warning to emit).

        if getattr(self.config, "quiet", False):
            cmd.append("-quiet")

        return cmd

    def parse_output(self, result: ToolResult) -> list[Finding]:
        """Parse Nuclei JSON output into findings."""
        findings = []

        if not result.stdout:
            if result.stderr:
                self.logger.debug(f"Nuclei stderr: {result.stderr[:500]}")
                if "no templates found" in result.stderr.lower():
                    self.logger.warning(
                        "No Nuclei templates found - run 'nuclei -ut' to update templates"
                    )
            return findings

        lines = result.stdout.strip().split("\n")
        parsed_count = 0
        skipped_lines = 0
        log_lines = 0

        for line in lines:
            if not line.strip():
                continue

            if line.startswith("["):
                # Nuclei log/status lines (e.g. "[INF] ...", "[Nuclei] ...") are
                # expected and do not indicate a parse failure.
                log_lines += 1
                continue

            if not line.startswith("{"):
                skipped_lines += 1
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse Nuclei JSON line: {e}")
                skipped_lines += 1
                continue

            finding = self._parse_nuclei_finding(data)
            if finding:
                findings.append(finding)
                parsed_count += 1

        if skipped_lines > 0:
            self.logger.debug(f"Nuclei: skipped {skipped_lines} non-JSON lines")

        if not findings:
            if skipped_lines > 0:
                # Nuclei produced output we could not parse into findings. This
                # is an assurance gap, not a clean scan, so it must be visible.
                findings.append(
                    Finding(
                        module=self.MODULE,
                        step=self.name,
                        severity="medium",
                        title="Nuclei Output Unparseable",
                        description=(
                            "Nuclei produced output that could not be parsed into "
                            "findings - the scan may not have run correctly"
                        ),
                        evidence=f"Target: {self._target_url()} | skipped_lines={skipped_lines}",
                        recommendation="Verify the Nuclei version/output format and re-run",
                        raw={
                            "scan_type": "nuclei",
                            "parsed": parsed_count,
                            "skipped_lines": skipped_lines,
                            "operational": True,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        module=self.MODULE,
                        step=self.name,
                        severity="info",
                        title="Nuclei Completed",
                        description="Nuclei scan completed without notable findings",
                        evidence=f"Target: {self._target_url()}",
                        recommendation="Manual review may reveal additional details",
                        raw={"scan_type": "nuclei", "parsed": parsed_count},
                    )
                )

        return findings

    def _parse_nuclei_finding(self, data: dict) -> Optional[Finding]:
        """Parse a single Nuclei result into a Finding."""
        info = data.get("info", {})
        matched_at = data.get("matched-at", "")

        severity_str = str(info.get("severity", "")).lower()
        # `unknown` is a first-class nuclei severity used by untagged/triage
        # templates; it must not be silently downgraded to `info`. Any other
        # unrecognised value is treated the same way and flagged in `raw`.
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        known = severity_str in severity_map
        severity = cast(
            Literal["info", "low", "medium", "high", "critical"],
            severity_map.get(severity_str, "low"),
        )

        title = info.get("name", "Unknown vulnerability")
        description = info.get("description", "")
        recommendation = info.get("remediation", "Review and remediate the finding")

        template_id = info.get("template-id", "") or data.get("template-id", "")
        tags = info.get("tags", [])

        raw = {
            "template_id": template_id,
            "tags": tags,
            "nuclei_data": data,
        }
        if not known:
            raw["severity_unknown"] = True

        return Finding(
            module=self.MODULE,
            step=self.name,
            severity=severity,
            title=f"Nuclei: {title}",
            description=description[:500]
            if description
            else "Vulnerability detected via Nuclei template",
            evidence=matched_at,
            recommendation=recommendation[:500]
            if recommendation
            else "Review and remediate",
            raw=raw,
        )

    def _detect_nuclei_error(
        self, stderr: str, stdout: str
    ) -> tuple[bool, Optional[Finding]]:
        """Detect specific Nuclei errors and return helpful findings.

        Args:
            stderr: Nuclei stderr output
            stdout: Nuclei stdout output

        Returns:
            Tuple of (error_detected, finding_if_any)
        """
        combined_output = (stderr + stdout).lower()

        if "no templates found" in combined_output:
            return True, Finding(
                module=self.MODULE,
                step=self.name,
                severity="low",
                title="Nuclei Templates Missing",
                description="Nuclei could not find any scan templates. Templates are required for scanning.",
                evidence=stderr[:500] if stderr else stdout[:500],
                recommendation="Update templates: nuclei -ut\nInstall templates directory if missing",
            )

        # Only treat a connection problem as a scan-level error when nothing was
        # produced on stdout; otherwise a stray "timeout" warning in stderr would
        # discard valid findings.
        if (
            "connection refused" in combined_output or "timeout" in combined_output
        ) and not stdout.strip():
            return True, Finding(
                module=self.MODULE,
                step=self.name,
                severity="low",
                title="Nuclei Network Error",
                description="Nuclei could not connect to the target",
                evidence=stderr[:500] if stderr else stdout[:500],
                recommendation="Verify target URL is accessible and try again",
            )

        if (
            "flag provided but not defined" in combined_output
            or "unknown flag" in combined_output
        ):
            return True, Finding(
                module=self.MODULE,
                step=self.name,
                severity="medium",
                title="Nuclei Flag Error",
                description="Nuclei encountered an unknown command-line flag",
                evidence=stderr[:500] if stderr else stdout[:500],
                recommendation="Update Nuclei to latest version: go install -v github.com/projectdiscovery/nuclei/v3/...@latest",
            )

        if "permission denied" in combined_output or "eacces" in combined_output:
            return True, Finding(
                module=self.MODULE,
                step=self.name,
                severity="low",
                title="Nuclei Permission Error",
                description="Nuclei encountered a permission error",
                evidence=stderr[:500] if stderr else stdout[:500],
                recommendation="Check file permissions for Nuclei and its template directory",
            )

        return False, None

    async def run(self) -> list[Finding]:
        """Execute Nuclei and parse results."""
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.error(error)
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Nuclei Not Available",
                description="Nuclei binary not found or not installed",
                evidence=error,
                recommendation="Install Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/...@latest",
            )
            return self.findings

        self.logger.info(f"Running Nuclei on {self._target_url()}")

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
                native_name="nuclei.jsonl",
            )

            detected, error_finding = self._detect_nuclei_error(
                result.stderr or "", result.stdout or ""
            )
            if detected and error_finding:
                self.logger.error(
                    f"Nuclei specific error detected: {error_finding.title}"
                )
                self.findings.append(error_finding)
                return self.findings

            if result.success or result.stdout:
                self.findings = self.parse_output(result)
                self.logger.info(f"Nuclei completed: {len(self.findings)} findings")
            else:
                self.logger.error(
                    f"Nuclei failed: {result.stderr[:500] if result.stderr else 'Unknown error'}"
                )
                self._add_finding(
                    module=self.MODULE,
                    severity="low",
                    title="Nuclei Execution Failed",
                    description="Nuclei completed with errors",
                    evidence=result.stderr[:500]
                    if result.stderr
                    else result.output[:500],
                    recommendation="Check Nuclei installation and network connectivity",
                )

        except ToolTimeoutError:
            self.logger.error(f"Nuclei timed out after {self.timeout}s")
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
                title="Nuclei Timeout",
                description=f"Nuclei exceeded timeout of {self.timeout} seconds",
                evidence=f"Timeout: {self.timeout}s",
                recommendation="Increase timeout or reduce template scope",
            )
        except Exception as e:
            self.logger.error(f"Nuclei error: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Nuclei Error",
                description="Nuclei encountered an unexpected error",
                evidence=str(e),
                recommendation="Check Nuclei installation",
            )

        return self.findings
