# recon_wp/base/base_step.py
"""
BaseStep ABC - the contract for all steps.

This is the abstract base class that all steps must inherit from.
All steps must implement the run() method which returns a list of Findings.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Optional

from base.tool import (
    AsyncToolRunner,
    ToolNotFoundError,
    ToolResult,
    ToolRunner,
    ToolTimeoutError,
)
from config import Config
from core.finding import Finding
from core.logger import Logger
from core.target import Target
from utils.tool_version_checker import (
    VersionChecker,
    VersionMismatchError,
    VersionRequirement,
)

if TYPE_CHECKING:
    from core.http_client import HttpClient


@dataclass
class StepResult:
    """Result of running a step."""

    success: bool
    findings: list[Finding] = field(default_factory=list)
    error: str = ""


class BaseStep(ABC):
    name: str = "base_step"
    description: str = "Base step - override in subclasses"
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"

    def __init__(
        self,
        target: Optional[Target] = None,
        config: Optional[Config] = None,
        http: Optional["HttpClient"] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ):
        self.name = name or self.__class__.__name__
        self.target = target
        self.description = description or getattr(self, "description", "")
        self.config = config or Config()
        self.http = http
        self.findings: list[Finding] = []
        log_level = getattr(self.config, "log_level", "INFO") if self.config else "INFO"
        self.logger = Logger(self.name, log_level)

    @abstractmethod
    async def run(self) -> list[Finding]:
        """
        Execute the step and return findings.

        Must be implemented by all concrete steps.
        """
        pass

    def _add_finding(
        self,
        module: str,
        severity: Literal["info", "low", "medium", "high", "critical"],
        title: str,
        description: str = "",
        evidence: str = "",
        recommendation: str = "",
        raw: Optional[dict] = None,
    ) -> None:
        """Add a finding to the findings list."""
        finding = Finding(
            step=self.name,
            module=module,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            raw=raw or {},
        )

        self.findings.append(finding)

    def clear_findings(self) -> None:
        """Clear all findings (useful for re-runs)."""
        self.findings.clear()


class BaseToolStep(BaseStep):
    """
    Interface Segregation: only tool steps know about binaries.
    Liskov: valid BaseStep - Runner uses it through the base interface.

    Extends BaseStep with tool-specific concerns:
    - _tool_binary: name or path of the external tool
    - build_command: construct CLI arguments
    - parse_output: convert tool output to Findings

    Version Pinning:
    - required_version: exact version required (e.g., "3.8.23")
    - min_version: minimum version required (e.g., "2.0.0")
    - max_version: maximum version supported
    - supported_versions: list of compatible versions

    The default run() implementation executes the tool asynchronously via
    AsyncToolRunner (non-blocking), calls build_command() to get CLI args,
    and parse_output() to convert results into Findings.
    """

    _tool_binary: str = ""

    # Version requirements (set in subclasses)
    required_version: Optional[str] = None
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    supported_versions: Optional[list[str]] = None

    def __init__(
        self,
        target: Optional[Target] = None,
        config: Optional[Config] = None,
        http: Optional["HttpClient"] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            http=http,
            name=name,
            description=description,
        )
        self._async_tool_runner: AsyncToolRunner = AsyncToolRunner(self._tool_binary)
        self._tool_runner: ToolRunner = ToolRunner(self._tool_binary)
        self._version_checker = VersionChecker()

    def get_version_requirement(self) -> Optional[VersionRequirement]:
        """Get version requirement from class attributes."""
        if not any([
            self.required_version,
            self.min_version,
            self.max_version,
            self.supported_versions,
        ]):
            return None

        return VersionRequirement(
            tool=self._tool_binary,
            required_version=self.required_version,
            min_version=self.min_version,
            max_version=self.max_version,
            supported_versions=self.supported_versions,
        )

    def check_version_compatibility(self) -> bool:
        """Check version compatibility for this tool.

        Returns:
            True if version is compatible or no requirement specified
        """
        requirement = self.get_version_requirement()
        if not requirement:
            return True

        if getattr(self.config, "skip_version_check", False):
            return True

        try:
            result = self._version_checker.validate(
                tool=self._tool_binary,
                requirement=requirement,
                strict=getattr(self.config, "require_version", False),
            )

            if getattr(self.config, "verbose_version_check", False):
                self.logger.info(
                    f"{self._tool_binary} version: {result.installed} "
                    f"(required: {result.requirements}) - "
                    f"{'compatible' if result.is_compatible else 'incompatible'}"
                )

            if not result.is_compatible:
                self.logger.warning(result.message)
                self._add_finding(
                    module=getattr(self, "MODULE", "tools"),
                    severity="low",
                    title=f"{self._tool_binary.title()} Version Incompatible",
                    description=result.message,
                    evidence=f"Installed: {result.installed}",
                    recommendation=f"Update {self._tool_binary} to meet requirements"
                )

            return result.is_compatible
        except VersionMismatchError as e:
            self.logger.error(str(e))
            return False

    @property
    @abstractmethod
    def getBinary(self) -> str:
        """Return the binary name or path for this tool."""
        ...

    @abstractmethod
    def build_command(self) -> list[str]:
        """Build the command-line arguments for this tool.

        Returns:
            List of command arguments (without the binary name prefix;
            AsyncToolRunner will prepend it automatically).
        """
        ...

    @abstractmethod
    def parse_output(self, result: ToolResult) -> list[Finding]:
        """
        Parse tool output into findings.

        Args:
            result: ToolResult containing stdout, stderr, returncode

        Returns:
            List of Finding objects extracted from output
        """
        ...

    @staticmethod
    def check_binary(binary: str) -> tuple[bool, str]:
        """
        Check if a binary exists and is executable.

        Args:
            binary: Binary name or path to check

        Returns:
            Tuple of (exists: bool, error_message: str)
            If exists=True, error_message is empty.
        """
        runner = ToolRunner(binary)
        if not runner.binary_exists():
            resolved = runner.binary_resolve()
            if resolved:
                return True, ""
            return (
                False,
                f"Binary '{binary}' not found in PATH. Install it or add to system PATH.",
            )
        return True, ""

    def verify_binary(self) -> bool:
        """
        Verify that the required binary exists.

        Returns:
            True if binary exists

        Raises:
            ToolNotFoundError: If binary cannot be resolved
        """
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            raise ToolNotFoundError(error)
        return True

    async def run(self) -> list[Finding]:
        """Execute the tool step asynchronously.

        Default implementation:
        1. Verify binary exists
        2. Check version compatibility (if version requirements specified)
        3. Build command via build_command()
        4. Execute via AsyncToolRunner (non-blocking)
        5. Parse output via parse_output()

        Subclasses may override this for custom execution flow (e.g.
        WpscanStep which needs special error handling).
        """
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.error(error)
            self._add_finding(
                module=getattr(self, "MODULE", "tools"),
                severity="low",
                title=f"{self._tool_binary.title()} Not Available",
                description=f"{self._tool_binary} binary not found or not installed",
                evidence=error,
                recommendation=f"Install {self._tool_binary}",
            )
            return self.findings

        if not self.check_version_compatibility():
            return self.findings

        cmd = self.build_command()
        self.logger.debug(f"Command: {' '.join(cmd)}")

        try:
            result = await self._async_tool_runner.run(cmd)

            if result.success or result.stdout:
                self.findings = self.parse_output(result)
                self.logger.info(
                    f"{self._tool_binary} completed: {len(self.findings)} findings"
                )
            else:
                self.logger.error(
                    f"{self._tool_binary} failed: {result.stderr[:500] if result.stderr else 'Unknown error'}"
                )
                self._add_finding(
                    module=getattr(self, "MODULE", "tools"),
                    severity="low",
                    title=f"{self._tool_binary.title()} Execution Failed",
                    description=f"{self._tool_binary} completed with errors",
                    evidence=result.stderr[:500]
                    if result.stderr
                    else result.output[:500],
                    recommendation=f"Check {self._tool_binary} installation and network connectivity",
                )

        except ToolTimeoutError:
            self.logger.error(f"{self._tool_binary} timed out")
            self._add_finding(
                module=getattr(self, "MODULE", "tools"),
                severity="low",
                title=f"{self._tool_binary.title()} Timeout",
                description=f"{self._tool_binary} exceeded timeout",
                evidence="Timeout",
                recommendation="Increase timeout or reduce enumeration scope",
            )
        except Exception as e:
            self.logger.error(f"{self._tool_binary} error: {e}")
            self._add_finding(
                module=getattr(self, "MODULE", "tools"),
                severity="low",
                title=f"{self._tool_binary.title()} Error",
                description=f"{self._tool_binary} encountered an unexpected error",
                evidence=str(e),
                recommendation=f"Check {self._tool_binary} installation",
            )

        return self.findings
