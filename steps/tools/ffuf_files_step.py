# recon_wp/steps/tools/ffuf_files_step.py
"""
FFUF file discovery step.

FFUF (Fuzz Faster U Fool) is a fast web fuzzer that can discover hidden
files on web servers.
"""

import json
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


class FfufFilesStep(BaseToolStep):
    """FFUF file discovery step.

    SECURITY:
    - Verifies ffuf binary exists before execution
    - Uses async subprocess to prevent blocking
    - Parses JSON output safely
    - Respects rate limiting

    CAPABILITIES:
    - File discovery
    - Hidden file detection
    - Configurable wordlist selection
    """

    name = "ffuf_files"
    description = "FFUF file discovery"
    severity = "info"
    _tool_binary = "ffuf"
    MODULE = "tools"

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        http=None,
        wordlist: Optional[str] = None,
        timeout: Optional[int] = None,
        rate_limit: Optional[int] = None,
        filter_status: str = "404",
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        default_wordlist = get_wordlist_path("ffuf/files.txt") or (
            DEFAULT_WORDLISTS_DIR / "files.txt"
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
        self.filter_status = filter_status

    def build_command(self) -> list[str]:
        """Build FFUF command for file discovery."""
        cmd = [
            self._tool_binary,
            "-u",
            str(self.target.url) + "/FUZZ",
            "-w",
            self.wordlist,
            "-json",
            "-t",
            str(self.rate_limit) if self.rate_limit else "100",
            "-fc",
            self.filter_status,
            "-timeout",
            str(self.timeout),
        ]

        if getattr(self.config, "insecure", False):
            cmd.append("-ik")

        if getattr(self.config, "quiet", False):
            cmd.append("-s")

        return cmd

    def parse_output(self, result: ToolResult) -> list[Finding]:
        """Parse FFUF JSON output into findings."""
        findings = []

        if not result.stdout:
            if result.stderr:
                self.logger.debug(f"FFUF stderr: {result.stderr[:500]}")
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
                    title=f"File Found: {word}",
                    description="Hidden file discovered via FFUF fuzzing",
                    evidence=f"URL: {url}\nStatus: {status}\nSize: {length}",
                    recommendation="Review file contents and access controls",
                    raw={"word": word, "url": url, "status": status, "length": length},
                )
            )

        return findings

    async def run(self) -> list[Finding]:
        """Execute FFUF file discovery."""
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.error(error)
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="FFUF Not Available",
                description="FFUF binary not found or not installed",
                evidence=error,
                recommendation="Install FFUF: brew install ffuf (macOS) or download from https://github.com/ffuf/ffuf/releases",
            )
            return self.findings

        self.logger.info(f"Running FFUF file discovery on {self.target.url}")

        cmd = self.build_command()
        self.logger.debug(f"Command: {' '.join(cmd)}")

        try:
            result = await self._async_tool_runner.run(cmd, timeout=self.timeout)

            if result.stdout:
                self.findings = self.parse_output(result)
                self.logger.info(f"FFUF completed: {len(self.findings)} files found")
            else:
                self.logger.info("FFUF completed without findings")

        except ToolTimeoutError:
            self.logger.error(f"FFUF timed out after {self.timeout}s")
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
