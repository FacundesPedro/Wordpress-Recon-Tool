"""Tests for the Finding.confidence field and its serialization."""

from core.finding import Finding


def _finding(**kwargs) -> Finding:
    base = dict(
        module="webapp",
        step="demo",
        severity="high",
        title="Title",
        description="Desc",
        evidence="Ev",
        recommendation="Rec",
    )
    base.update(kwargs)
    return Finding(**base)


class TestFindingConfidence:
    def test_defaults_to_high(self):
        assert _finding().confidence == "high"

    def test_to_dict_includes_confidence(self):
        data = _finding(confidence="low").to_dict()
        assert data["confidence"] == "low"

    def test_to_sarif_includes_confidence(self):
        sarif = _finding(confidence="medium").to_sarif()
        assert sarif["properties"]["confidence"] == "medium"

    def test_confidence_excluded_from_dedup(self):
        a = _finding(confidence="high")
        b = _finding(confidence="low")
        # Same evidence/severity/title => same finding regardless of confidence.
        assert a == b
        assert hash(a) == hash(b)

    def test_severity_still_part_of_dedup(self):
        assert _finding(severity="high") != _finding(severity="low")
