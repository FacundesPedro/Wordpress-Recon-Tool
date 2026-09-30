"""Tests for list-size caps used by discovery/brute-force findings."""

from utils.limits import cap_lines, cap_list, truncation_note


class TestCapList:
    def test_truncates(self):
        assert cap_list([1, 2, 3, 4], 2) == [1, 2]

    def test_zero_means_unlimited(self):
        assert cap_list([1, 2, 3], 0) == [1, 2, 3]

    def test_negative_means_unlimited(self):
        assert cap_list([1, 2, 3], -5) == [1, 2, 3]

    def test_handles_none(self):
        assert cap_list(None, 5) == []


class TestTruncationNote:
    def test_note_when_truncated(self):
        assert truncation_note(10, 3) == " (showing 3 of 10)"

    def test_no_note_when_complete(self):
        assert truncation_note(3, 3) == ""


class TestCapLines:
    def test_appends_note(self):
        lines = [f"line {i}" for i in range(10)]
        capped = cap_lines(lines, 2)
        assert capped[:2] == ["line 0", "line 1"]
        assert "showing 2 of 10" in capped[-1]

    def test_no_note_when_within_limit(self):
        assert cap_lines(["a", "b"], 5) == ["a", "b"]
