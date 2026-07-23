# recon_wp/core/logger.py
"""Logger - timestamped logging with level control."""

import logging
from typing import Optional

LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
}


class Logger:
    """Logger with level-based output control.

    Wraps Python's logging module while exposing a simple interface.

    Args:
        name: Logger name (usually module/class name)
        level: Log level - DEBUG, INFO, WARN, ERROR (default: INFO)
    """

    def __init__(self, name: str, level: str = "INFO"):
        self.name = name
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LEVEL_MAP.get(level.upper(), logging.INFO))
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("[%(asctime)s] [%(levelname)-5s] [%(name)s] %(message)s")
            )
            self._logger.addHandler(handler)

    def debug(self, message: str) -> None:
        """Log debug message."""
        self._logger.debug(message)

    def info(self, message: str) -> None:
        """Log info message."""
        self._logger.info(message)

    def warning(self, message: str) -> None:
        """Log warning message."""
        self._logger.warning(message)

    def warn(self, message: str) -> None:
        """Alias for warning."""
        self._logger.warning(message)

    def error(self, message: str) -> None:
        """Log error message."""
        self._logger.error(message)

    def critical(self, message: str) -> None:
        """Log critical message."""
        self._logger.critical(message)
