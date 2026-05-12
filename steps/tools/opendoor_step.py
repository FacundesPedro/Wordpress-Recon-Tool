# recon_wp/steps/tools/opendoor_step.py
"""
OpenDoor WordPress path discovery step.

OpenDoor is a tool for discovering open/accessible files and directories
specifically for WordPress sites.
"""

import json
from pathlib import Path
from typing import Optional

from base.step import BaseToolStep
from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.finding import Finding
from core.target import Target

PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_WORDLISTS_DIR = PROJECT_ROOT / "wordlists" / "opendoor"


class OpenDoorStep(BaseToolStep):
    """OpenDoor WordPress path discovery step.

    SECURITY:
    - Verifies opendoor binary exists before execution
    - Uses async subprocess to prevent blocking
    - Parses JSON output safely
    - Respects rate limiting

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
        timeout: int = 300,
        rate_limit: int = 0,
        mode: str = "wp_paths",
    ):
        super().__init__(
            target=target,
            config=config,
            http=http,
            name=self.name,
            description=self.description,
        )
        self.wordlist = wordlist or str(DEFAULT_WORDLISTS_DIR / "wp_paths.txt")
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.mode = mode

    @property
    def getBinary(self) -> str:
        return self._tool_binary

    def build_command(self) -> list[str]:
        """Build OpenDoor command for WordPress path discovery."""
        cmd = [
            self._tool_binary,
            "-u",
            str(self.target.url),
            "-w",
            self.wordlist,
            "-json",
            "-t",
            str(self.rate_limit) if self.rate_limit else "100",
            "-timeout",
            str(self.timeout),
        ]

        if self.mode:
            cmd.extend(["-mode", self.mode])

        if getattr(self.config, "insecure", False):
            cmd.append("-ik")

        if getattr(self.config, "quiet", False):
            cmd.append("-s")

        return cmd

    def parse_output(self, result: ToolResult) -> list[Finding]:
        """Parse OpenDoor JSON output into findings."""
        findings = []

        if not result.stdout:
            if result.stderr:
                self.logger.debug(f"OpenDoor stderr: {result.stderr[:500]}")
            return findings

        lines = result.stdout.strip().split("\n")
        for line in lines:
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not data:
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
                    title=f"OpenDoor Path Found: {word}",
                    description="WordPress-specific path discovered via OpenDoor scanning",
                    evidence=f"URL: {url}\nStatus: {status}\nSize: {length}",
                    recommendation="Review path access controls and functionality",
                    raw={"word": word, "url": url, "status": status, "length": length},
                )
            )

        return findings

    async def run(self) -> list[Finding]:
        """Execute OpenDoor WordPress path discovery."""
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.error(error)
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="OpenDoor Not Available",
                description="OpenDoor binary not found or not installed",
                evidence=error,
                recommendation="Install OpenDoor: download from https://github.com/owasp/opendoor/releases",
            )
            return self.findings

        self.logger.info(f"Running OpenDoor WordPress path discovery on {self.target.url}")

        cmd = self.build_command()
        self.logger.debug(f"Command: {' '.join(cmd)}")

        try:
            result = await self._async_tool_runner.run(cmd, timeout=self.timeout)

            if result.stdout:
                self.findings = self.parse_output(result)
                self.logger.info(f"OpenDoor completed: {len(self.findings)} paths found")
            else:
                self.logger.info("OpenDoor completed without findings")

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
