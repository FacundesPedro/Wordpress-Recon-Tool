# recon_wp/core/exceptions.py
"""Custom exceptions for the recon tool."""

class ReconError(Exception):
    """Base exception for all recon errors."""
    pass


class ToolNotFoundError(ReconError):
    """Raised when a required binary is not found in PATH."""
    def __init__(self, binary: str):
        self.binary = binary
        super().__init__(f"Binary not found: {binary}")


class ToolTimeoutError(ReconError):
    """Raised when a tool execution times out."""
    def __init__(self, binary: str, timeout: int):
        self.binary = binary
        self.timeout = timeout
        super().__init__(f"Tool '{binary}' timed out after {timeout}s")


class ValidationError(ReconError):
    """Raised when target validation fails."""
    pass
