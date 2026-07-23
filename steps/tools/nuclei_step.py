# recon_wp/steps/tools/nuclei_step.py
"""
Nuclei integration - fast vulnerability scanner using templates.

Nuclei is a fast vulnerability scanner based on templates that can detect
various security issues including WordPress-specific vulnerabilities.
"""

import json
from typing import Optional

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
    severity = "info"
    _tool_binary = "nuclei"
    MODULE = "tools"

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        http=None,  # Accepted for BaseToolStep compatibility
        severity: Optional[str] = None,
        threads: int = 100,
        timeout: int = 300,
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
        self.threads = threads or getattr(config, "nuclei_threads", 100)
        self.timeout = timeout or getattr(config, "nuclei_timeout", 300)

    def build_command(self) -> list[str]:
        """Build Nuclei command with all options."""
        cmd = [
            self._tool_binary,
            "-u",
            str(self.target.url),
            "-severity",
            self.severity_filter,
            "-jsonl",  # -json was deprecated, use -jsonl for JSON Lines output
            "-concurrency",
            str(self.threads),
            "-silent",
        ]

        if getattr(self.config, "insecure", False):
            self.logger.warning(
                "Nuclei does not support --insecure flag, TLS verification cannot be disabled"
            )

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

        for line in lines:
            if not line.strip():
                continue

            if line.startswith("[") or not line.startswith("{"):
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
            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title="Nuclei Completed",
                    description="Nuclei scan completed without notable findings",
                    evidence=f"Target: {self.target.url}",
                    recommendation="Manual review may reveal additional details",
                    raw={"scan_type": "nuclei", "parsed": parsed_count},
                )
            )

        return findings

    def _parse_nuclei_finding(self, data: dict) -> Optional[Finding]:
        """Parse a single Nuclei result into a Finding."""
        info = data.get("info", {})
        matched_at = data.get("matched-at", "")

        severity_str = info.get("severity", "info").lower()
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        severity = severity_map.get(severity_str, "info")

        title = info.get("name", "Unknown vulnerability")
        description = info.get("description", "")
        recommendation = info.get("remediation", "Review and remediate the finding")

        matched_by = info.get("matched-at", "")
        template_id = info.get("template-id", "")
        tags = info.get("tags", [])

        return Finding(
            module=self.MODULE,
            step=self.name,
            severity=severity,
            title=f"Nuclei: {title}",
            description=description[:500]
            if description
            else "Vulnerability detected via Nuclei template",
            evidence=matched_at or matched_by,
            recommendation=recommendation[:500]
            if recommendation
            else "Review and remediate",
            raw={
                "template_id": template_id,
                "tags": tags,
                "nuclei_data": data,
            },
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

        if "connection refused" in combined_output or "timeout" in combined_output:
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

        self.logger.info(f"Running Nuclei on {self.target.url}")

        cmd = self.build_command()
        self.logger.debug(f"Command: {' '.join(cmd)}")

        try:
            result = await self._async_tool_runner.run(cmd, timeout=self.timeout)

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
