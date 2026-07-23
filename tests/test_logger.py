# tests/test_logger.py
"""Unit tests for core/logger.py — Logger."""

import io
import logging

from core.logger import LEVEL_MAP, Logger


class TestLevelMap:
    def test_debug_maps_to_debug(self):
        assert LEVEL_MAP["DEBUG"] == logging.DEBUG

    def test_info_maps_to_info(self):
        assert LEVEL_MAP["INFO"] == logging.INFO

    def test_warn_maps_to_warning(self):
        assert LEVEL_MAP["WARN"] == logging.WARNING

    def test_error_maps_to_error(self):
        assert LEVEL_MAP["ERROR"] == logging.ERROR


class TestLoggerInit:
    def test_sets_name(self):
        logger = Logger("TestModule")
        assert logger.name == "TestModule"

    def test_creates_handler_once(self):
        logger = Logger("DedupTest")
        original_handlers = list(logger._logger.handlers)
        logger2 = Logger("DedupTest")
        assert logger2._logger.handlers == original_handlers

    def test_sets_level_info_by_default(self):
        logger = Logger("DefaultLevel")
        assert logger._logger.level == logging.INFO

    def test_sets_level_from_arg(self):
        logger = Logger("DebugLevel", level="DEBUG")
        assert logger._logger.level == logging.DEBUG

    def test_sets_level_case_insensitive(self):
        logger = Logger("CaseTest", level="debug")
        assert logger._logger.level == logging.DEBUG

    def test_invalid_level_defaults_to_info(self):
        logger = Logger("BadLevel", level="UNKNOWN")
        assert logger._logger.level == logging.INFO


class TestLoggerMethods:
    def test_debug_logs(self):
        stream = io.StringIO()
        logger = Logger("LogTest", level="DEBUG")
        logger._logger.handlers[0].stream = stream
        logger.debug("debug msg")
        assert "debug msg" in stream.getvalue()

    def test_info_logs(self):
        stream = io.StringIO()
        logger = Logger("LogTest", level="DEBUG")
        logger._logger.handlers[0].stream = stream
        logger.info("info msg")
        assert "info msg" in stream.getvalue()

    def test_warning_logs(self):
        stream = io.StringIO()
        logger = Logger("LogTest", level="DEBUG")
        logger._logger.handlers[0].stream = stream
        logger.warning("warn msg")
        assert "warn msg" in stream.getvalue()

    def test_warn_alias_logs(self):
        stream = io.StringIO()
        logger = Logger("LogTest", level="DEBUG")
        logger._logger.handlers[0].stream = stream
        logger.warn("alias msg")
        assert "alias msg" in stream.getvalue()

    def test_error_logs(self):
        stream = io.StringIO()
        logger = Logger("LogTest", level="DEBUG")
        logger._logger.handlers[0].stream = stream
        logger.error("error msg")
        assert "error msg" in stream.getvalue()

    def test_critical_logs(self):
        stream = io.StringIO()
        logger = Logger("LogTest", level="DEBUG")
        logger._logger.handlers[0].stream = stream
        logger.critical("critical msg")
        assert "critical msg" in stream.getvalue()
