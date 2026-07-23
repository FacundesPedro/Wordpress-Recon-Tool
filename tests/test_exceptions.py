# tests/test_exceptions.py
"""Unit tests for core/exceptions.py — exception hierarchy."""

import pytest

from core.exceptions import ReconError, ToolNotFoundError, ToolTimeoutError, ValidationError


class TestReconError:
    def test_is_base_exception(self):
        assert issubclass(ReconError, Exception)

    def test_can_be_raised(self):
        with pytest.raises(ReconError):
            raise ReconError("test")

    def test_message(self):
        err = ReconError("something went wrong")
        assert str(err) == "something went wrong"


class TestToolNotFoundError:
    def test_is_recon_error(self):
        assert issubclass(ToolNotFoundError, ReconError)

    def test_stores_binary(self):
        err = ToolNotFoundError("nmap")
        assert err.binary == "nmap"

    def test_message(self):
        err = ToolNotFoundError("wpscan")
        assert "wpscan" in str(err)
        assert "not found" in str(err).lower()


class TestToolTimeoutError:
    def test_is_recon_error(self):
        assert issubclass(ToolTimeoutError, ReconError)

    def test_stores_binary_and_timeout(self):
        err = ToolTimeoutError("nmap", 120)
        assert err.binary == "nmap"
        assert err.timeout == 120

    def test_message(self):
        err = ToolTimeoutError("nmap", 60)
        assert "nmap" in str(err)
        assert "60" in str(err)
        assert "timed out" in str(err).lower()


class TestValidationError:
    def test_is_recon_error(self):
        assert issubclass(ValidationError, ReconError)

    def test_message(self):
        err = ValidationError("invalid target")
        assert str(err) == "invalid target"
