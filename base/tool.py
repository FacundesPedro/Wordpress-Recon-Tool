"""ToolRunner - subprocess wrapper with binary verification.
AsyncToolRunner - non-blocking subprocess execution for async contexts.
"""

import asyncio
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from core.exceptions import ToolNotFoundError, ToolTimeoutError

SENSITIVE_PATTERN = re.compile(
    r'(api[_-]?key|token|password|secret|credential|auth)["\']?\s*[:=]\s*["\']?([^\s"\'&]+)',
    re.IGNORECASE,
)


def _sanitize_arg(arg: str) -> str:
    """Sanitize a command argument to prevent injection.

    Args:
        arg: Raw argument string

    Returns:
        Sanitized argument safe for subprocess
    """
    if not arg:
        return ""

    dangerous_chars = [";", "&&", "||", "|", "`", "$(", "\n", "\r", "\0", ">", "<", "{", "}", "~"]
    sanitized = arg
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "_")

    return sanitized


def _redact_sensitive_from_output(output: str) -> str:
    """Redact sensitive data from command output for logging.

    Args:
        output: Raw command output

    Returns:
        Output with sensitive data redacted
    """
    if not output:
        return output

    return SENSITIVE_PATTERN.sub(r"\1=[REDACTED]", output)


@dataclass
class ToolResult:
    stdout: str
    stderr: str
    returncode: int
    success: bool

    @property
    def output(self) -> str:
        """Return stdout, fallback to stderr if empty."""
        return self.stdout or self.stderr


class ToolRunner:
    """Executes external tools safely with subprocess.

    SECURITY:
    - Uses shell=False to prevent shell injection
    - Validates binary exists before execution
    - Sanitizes all arguments
    - Redacts sensitive data from logs
    - Supports timeout to prevent hanging

    RISKS:
    - Binary must be verified as safe before execution
    - Arguments are sanitized but not fully validated
    - Environment variables can affect tool behavior
    """

    def __init__(self, binary_path: str):
        self._binary_path = binary_path

    def binary_exists(self) -> bool:
        """Check if a binary exists in PATH or at specified location."""
        return shutil.which(self._binary_path) is not None

    def binary_resolve(self) -> Optional[str]:
        """Resolve full path to binary, or None if not found."""
        return shutil.which(self._binary_path)

    def _build_cmd(self, args: list[str]) -> list[str]:
        """Build command list with sanitized arguments.

        Args:
            args: Command arguments (first element should be the binary)

        Returns:
            Sanitized command list

        Raises:
            ValueError: If no arguments provided
        """
        if not args:
            raise ValueError("No command arguments provided")

        sanitized_args = [_sanitize_arg(str(arg)) for arg in args]

        if sanitized_args[0] != self._binary_path:
            return [self._binary_path] + sanitized_args
        return sanitized_args

    def run(
        self,
        args: list[str],
        timeout: int = 600,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> ToolResult:
        """Execute a command safely with timeout.

        SECURITY:
        - Verifies binary exists before execution
        - Uses shell=False to prevent injection
        - Sanitizes all arguments
        - Redacts sensitive data from logged output
        - Enforces timeout to prevent hanging

        Args:
            args: Command and arguments as list
            timeout: Maximum execution time in seconds
            cwd: Working directory for execution
            env: Environment variables override

        Returns:
            ToolResult with stdout, stderr, returncode, success

        Raises:
            ToolNotFoundError: If binary doesn't exist
            ToolTimeoutError: If execution exceeds timeout
        """
        if not self.binary_exists():
            raise ToolNotFoundError(self._binary_path)

        safe_env = None
        if env:
            safe_env = {k: str(v) for k, v in env.items() if v is not None}

        try:
            result = subprocess.run(
                self._build_cmd(args),
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                env=safe_env,
                shell=False,
            )

            stdout = _redact_sensitive_from_output(self._decode_output(result.stdout))
            stderr = _redact_sensitive_from_output(self._decode_output(result.stderr))

            return ToolResult(
                stdout=stdout,
                stderr=stderr,
                returncode=result.returncode,
                success=result.returncode == 0,
            )
        except subprocess.TimeoutExpired:
            raise ToolTimeoutError(self._binary_path, timeout)
        except OSError as e:
            raise RuntimeError(f"Error executing {self._binary_path}: {str(e)}") from e

    @staticmethod
    def _decode_output(data: bytes) -> str:
        """Decode subprocess output with fallback encodings."""
        if not data:
            return ""

        encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]

        for encoding in encodings:
            try:
                return data.decode(encoding)
            except (UnicodeDecodeError, AttributeError):
                continue

        return data.decode("utf-8", errors="replace")


class AsyncToolRunner:
    """Async subprocess runner that does not block the event loop.

    SECURITY:
    - Uses asyncio.create_subprocess_exec (equivalent to shell=False)
    - Validates binary exists before execution
    - Sanitizes all arguments via shared _sanitize_arg
    - Redacts sensitive data from logs
    - Supports timeout via asyncio.timeout

    Uses the same ToolResult interface as ToolRunner so parse_output() works
    with either runner transparently.
    """

    def __init__(self, binary_path: str):
        self._binary_path = binary_path

    def binary_exists(self) -> bool:
        return shutil.which(self._binary_path) is not None

    def binary_resolve(self) -> Optional[str]:
        return shutil.which(self._binary_path)

    def _build_cmd(self, args: list[str]) -> list[str]:
        if not args:
            raise ValueError("No command arguments provided")

        sanitized_args = [_sanitize_arg(str(arg)) for arg in args]

        if sanitized_args[0] != self._binary_path:
            return [self._binary_path] + sanitized_args
        return sanitized_args

    async def run(
        self,
        args: list[str],
        timeout: int = 600,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> ToolResult:
        """Execute a command asynchronously without blocking the event loop.

        Args:
            args: Command and arguments as list
            timeout: Maximum execution time in seconds
            cwd: Working directory for execution
            env: Environment variables override

        Returns:
            ToolResult with stdout, stderr, returncode, success

        Raises:
            ToolNotFoundError: If binary doesn't exist
            ToolTimeoutError: If execution exceeds timeout
        """
        if not self.binary_exists():
            raise ToolNotFoundError(self._binary_path)

        safe_env = None
        if env:
            safe_env = {k: str(v) for k, v in env.items() if v is not None}

        proc: Optional[asyncio.subprocess.Process] = None
        try:
            async with asyncio.timeout(timeout):
                proc = await asyncio.create_subprocess_exec(
                    *self._build_cmd(args),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=safe_env,
                )

                stdout_bytes, stderr_bytes = await proc.communicate()

            stdout = _redact_sensitive_from_output(ToolRunner._decode_output(stdout_bytes))
            stderr = _redact_sensitive_from_output(ToolRunner._decode_output(stderr_bytes))

            return ToolResult(
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode if proc.returncode is not None else -1,
                success=(proc.returncode == 0)
                if proc.returncode is not None
                else False,
            )

        except TimeoutError:
            if proc is not None and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
            raise ToolTimeoutError(self._binary_path, timeout)
        except OSError as e:
            raise RuntimeError(f"Error executing {self._binary_path}: {str(e)}") from e
