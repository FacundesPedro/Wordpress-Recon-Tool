"""Tests for utils.version helpers and CVE applicability mapping."""

from core.vulndb import cve_finding_severity
from utils.version import (
    cve_applies,
    is_version_at_least,
    is_version_less,
    version_tuple,
)


class TestVersionTuple:
    def test_basic(self):
        assert version_tuple("1.2.3") == (1, 2, 3)
        assert version_tuple("1.2") == (1, 2)
        assert version_tuple("") == ()

    def test_ignores_suffix(self):
        assert version_tuple("8.3.33-1build1") == (8, 3, 33)
        assert version_tuple("1.2.3-beta1") == (1, 2, 3)


class TestComparisons:
    def test_less(self):
        assert is_version_less("1.2.3", "1.2.4")
        assert is_version_less("1.2", "1.2.1")
        assert not is_version_less("1.3", "1.2.9")

    def test_at_least(self):
        assert is_version_at_least("1.2.3", "1.2.3")
        assert is_version_at_least("2.0", "1.9.9")
        assert not is_version_at_least("1.2", "1.2.1")

    def test_unknown_returns_false(self):
        assert not is_version_less("", "1.0")
        assert not is_version_at_least("unknown", "1.0")


class TestCveApplies:
    def test_applies_when_older(self):
        assert cve_applies("1.0.0", "1.1.0") is True

    def test_patched_when_at_or_above(self):
        assert cve_applies("1.1.0", "1.1.0") is False
        assert cve_applies("2.0", "1.1.0") is False

    def test_unknown_when_no_version_or_fix(self):
        assert cve_applies(None, "1.0") is None
        assert cve_applies("unknown", "1.0") is None
        assert cve_applies("1.0", None) is None


class TestCveFindingSeverity:
    def test_patched_returns_none(self):
        sev, conf = cve_finding_severity("critical", "1.2.0", "1.1.0")
        assert sev is None
        assert conf == "high"

    def test_scored_cve_keeps_band(self):
        sev, conf = cve_finding_severity("critical", "1.0.0", "1.1.0")
        assert sev == "critical"
        assert conf == "high"

    def test_real_cve_never_info(self):
        # Missing upstream score maps to info; a real CVE must be floored.
        sev, conf = cve_finding_severity("info", "1.0.0", "1.1.0")
        assert sev == "medium"
        assert conf == "high"

    def test_unknown_version_capped_and_low_confidence(self):
        sev, conf = cve_finding_severity("critical", "unknown", "1.1.0")
        assert sev == "medium"
        assert conf == "low"

    def test_genuine_low_stays_low(self):
        sev, conf = cve_finding_severity("low", "1.0.0", "1.1.0")
        assert sev == "low"
        assert conf == "high"
