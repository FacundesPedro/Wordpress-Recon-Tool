"""Tool version checker - ensures external tool compatibility.

Provides version pinning and compatibility checking for external security tools.
Allows steps to specify version requirements and validates installed versions
before execution.
"""

import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from packaging import version as pkg_version


@dataclass
class VersionRequirement:
    """Defines version requirements for a tool."""

    tool: str
    required_version: Optional[str] = None
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    supported_versions: Optional[list[str]] = None

    def is_compatible(self, installed_version: str) -> bool:
        """Check if installed version meets requirements."""
        try:
            installed = pkg_version.parse(installed_version)

            if self.required_version:
                return installed == pkg_version.parse(self.required_version)

            if self.min_version:
                result = installed >= pkg_version.parse(self.min_version)
                if self.max_version:
                    result = result and installed <= pkg_version.parse(self.max_version)
                return result

            if self.supported_versions:
                return installed_version in self.supported_versions

            return True
        except Exception:
            return False


@dataclass
class VersionCheckResult:
    """Result of version compatibility check."""

    tool: str
    installed: str
    requirements: str
    is_compatible: bool
    message: str


class VersionMismatchError(Exception):
    """Raised when tool version is incompatible."""

    def __init__(self, tool: str, installed: str, required: str):
        self.tool = tool
        self.installed = installed
        self.required = required
        super().__init__(
            f"{tool}: incompatible version - installed {installed}, "
            f"required {required}"
        )


class VersionChecker:
    """Checks and validates external tool versions."""

    def __init__(self):
        pass

    def get_installed_version(self, tool: str) -> str:
        """Get installed version of a tool.

        Args:
            tool: Tool binary name

        Returns:
            Version string or "unknown"
        """
        try:
            result = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return self._parse_version(result.stdout, tool)
        except Exception:
            return "unknown"

    def check_compatibility(
        self,
        tool: str,
        requirement: VersionRequirement,
    ) -> VersionCheckResult:
        """Check if installed tool version is compatible.

        Args:
            tool: Tool binary name
            requirement: Version requirement specification

        Returns:
            VersionCheckResult with compatibility status
        """
        installed = self.get_installed_version(tool)
        is_compatible = requirement.is_compatible(installed)

        requirements_str = self._format_requirements(requirement)
        message = self._generate_message(installed, requirement, is_compatible)

        return VersionCheckResult(
            tool=tool,
            installed=installed,
            requirements=requirements_str,
            is_compatible=is_compatible,
            message=message,
        )

    def validate(
        self,
        tool: str,
        requirement: VersionRequirement,
        strict: bool = False,
    ) -> VersionCheckResult:
        """Validate tool version, optionally raising on incompatibility.

        Args:
            tool: Tool binary name
            requirement: Version requirement
            strict: If True, raise exception on incompatibility

        Returns:
            VersionCheckResult

        Raises:
            VersionMismatchError: If strict=True and version incompatible
        """
        result = self.check_compatibility(tool, requirement)

        if strict and not result.is_compatible:
            raise VersionMismatchError(
                tool=tool,
                installed=result.installed,
                required=requirement.required_version or result.requirements,
            )

        return result

    @staticmethod
    def _parse_version(output: str, tool: str) -> str:
        """Parse version from tool output.

        Args:
            output: Tool version command output
            tool: Tool name for specific parsing

        Returns:
            Parsed version string
        """
        version_patterns = {
            "wpscan": r"WPScan\s+(\d+\.\d+\.\d+)",
            "nuclei": r"nuclei version (\d+\.\d+\.\d+)",
            "ffuf": r"FFUF:\s+(\d+\.\d+\.\d+)",
            "opendoor": r"OpenDoor\s+(\d+\.\d+\.\d+)",
            "default": r"(\d+\.\d+\.\d+)",
        }

        pattern = version_patterns.get(tool, version_patterns["default"])
        match = re.search(pattern, output)
        return match.group(1) if match else "unknown"

    @staticmethod
    def _format_requirements(req: VersionRequirement) -> str:
        """Format requirements as human-readable string."""
        if req.required_version:
            return f"== {req.required_version}"
        if req.min_version:
            base = f">= {req.min_version}"
            if req.max_version:
                base += f", <= {req.max_version}"
            return base
        if req.supported_versions:
            return f"in {req.supported_versions}"
        return "any"

    @staticmethod
    def _generate_message(
        installed: str, req: VersionRequirement, is_compatible: bool
    ) -> str:
        """Generate descriptive message."""
        if is_compatible:
            return "Version is compatible"

        if req.required_version:
            return f"Required {req.required_version}, found {installed}"
        if req.min_version:
            return f"Minimum {req.min_version} required, found {installed}"
        return f"Installed version {installed} not in supported list"



