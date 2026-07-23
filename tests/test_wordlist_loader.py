"""Tests for wordlist_loader utilities."""

from pathlib import Path

import pytest

from utils.wordlist_loader import (
    DEFAULT_WORDLIST_DIR,
    ensure_wordlist_dir,
    get_wordlist_dir_message,
    get_wordlist_path,
    load_key_value_lines,
    load_lines,
)


class TestGetWordlistPath:
    def test_custom_dir(self, tmp_path):
        wordlist = tmp_path / "custom.txt"
        wordlist.write_text("word1\nword2\n")
        result = get_wordlist_path("custom.txt", custom_dir=str(tmp_path))
        assert result == wordlist

    def test_custom_dir_not_found_returns_none(self, tmp_path):
        result = get_wordlist_path("nonexistent.txt", custom_dir=str(tmp_path))
        assert result is None

    def test_project_wordlist_dir(self, tmp_path, monkeypatch):
        project_wordlists = Path(__file__).parent.parent / "wordlists"
        if not project_wordlists.exists():
            pytest.skip("Project wordlists directory does not exist")
        result = get_wordlist_path("README.md")
        if result:
            assert "wordlists" in str(result)

    def test_no_wordlist_found(self):
        result = get_wordlist_path("__impossible_file_42__.txt")
        assert result is None


class TestLoadLines:
    def test_basic_lines(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("alpha\nbeta\ngamma\n")
        lines = list(load_lines(f))
        assert lines == ["alpha", "beta", "gamma"]

    def test_skip_comments(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("# comment\nreal\n# another\nvalue\n")
        lines = list(load_lines(f))
        assert lines == ["real", "value"]

    def test_empty_lines_skipped(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("a\n\nb\n  \nc\n")
        lines = list(load_lines(f))
        assert lines == ["a", "b", "c"]

    def test_strip_whitespace(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("  spaced  \n\ttabbed\t\nnormal\n")
        lines = list(load_lines(f, strip=True))
        assert lines == ["spaced", "tabbed", "normal"]

    def test_file_not_found(self):
        lines = list(load_lines(Path("/nonexistent/path.txt")))
        assert lines == []


class TestLoadKeyValueLines:
    def test_basic_pairs(self, tmp_path):
        f = tmp_path / "fields.txt"
        f.write_text("name:John\nemail:john@test.com\n")
        result = load_key_value_lines(f)
        assert result == {"name": "John", "email": "john@test.com"}

    def test_with_colon_in_value(self, tmp_path):
        f = tmp_path / "fields.txt"
        f.write_text("pattern:^test:\s*(.+)\n")
        result = load_key_value_lines(f)
        assert "pattern" in result

    def test_lines_without_colon_skipped(self, tmp_path):
        f = tmp_path / "fields.txt"
        f.write_text("name:John\nno-colon-here\nemail:john@test.com\n")
        result = load_key_value_lines(f)
        assert len(result) == 2
        assert "no-colon-here" not in result


class TestEnsureWordlistDir:
    def test_creates_directory(self, tmp_path, monkeypatch):
        fake_dir = tmp_path / "recon-wp" / "wordlists"
        monkeypatch.setattr(
            "utils.wordlist_loader.DEFAULT_WORDLIST_DIR", fake_dir
        )
        result = ensure_wordlist_dir()
        assert result == fake_dir
        assert fake_dir.exists()

    def test_idempotent(self, tmp_path, monkeypatch):
        fake_dir = tmp_path / "recon-wp" / "wordlists"
        fake_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(
            "utils.wordlist_loader.DEFAULT_WORDLIST_DIR", fake_dir
        )
        result = ensure_wordlist_dir()
        assert result == fake_dir


class TestGetWordlistDirMessage:
    def test_returns_string(self):
        result = get_wordlist_dir_message()
        assert isinstance(result, str)
        assert ".config" in result
        assert result == str(DEFAULT_WORDLIST_DIR)
