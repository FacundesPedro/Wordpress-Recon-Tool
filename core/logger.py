# recon_wp/core/logger.py
"""Logger - Rich-powered timestamped logging with level control."""

from datetime import datetime


class Logger:
    """Logger with level-based output control.

    Args:
        name: Logger name (usually module/class name)
        level: Log level - DEBUG, INFO, WARN, ERROR (default: INFO)
    """

    LEVELS = {
        "DEBUG": 0,
        "INFO": 1,
        "WARN": 2,
        "ERROR": 3,
    }

    def __init__(self, name: str, level: str = "INFO"):
        self.name = name
        self.level = level.upper()
        if self.level not in self.LEVELS:
            self.level = "INFO"

    def _format(self, level: str, message: str) -> str:
        timestamp = datetime.utcnow().isoformat()
        return f"[{timestamp}] [{level:5}] [{self.name}] {message}"

    def _should_log(self, level: str) -> bool:
        """Check if message should be logged based on current level."""
        return self.LEVELS.get(self.level, 1) <= self.LEVELS.get(level, 1)

    def debug(self, message: str) -> None:
        """Log debug message if level is DEBUG."""
        if self._should_log("DEBUG"):
            print(self._format("DEBUG", message))

    def info(self, message: str) -> None:
        """Log info message if level is INFO or lower."""
        if self._should_log("INFO"):
            print(self._format("INFO", message))

    def warning(self, message: str) -> None:
        """Log warning message if level is WARN or lower."""
        if self._should_log("WARN"):
            print(self._format("WARN", message))

    def warn(self, message: str) -> None:
        """Alias for warning."""
        self.warning(message)

    def error(self, message: str) -> None:
        """Log error message (always logged)."""
        if self._should_log("ERROR"):
            print(self._format("ERROR", message))
