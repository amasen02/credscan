from pathlib import Path

from credscan.allowlist import Allowlist


def test_load_with_no_ignore_file_returns_empty_allowlist(tmp_path: Path):
    allowlist = Allowlist.load(tmp_path)
    assert allowlist.path_patterns == ()
    assert allowlist.is_path_ignored("anything.txt") is False


def test_load_parses_patterns_and_skips_comments_and_blank_lines(tmp_path: Path):
    (tmp_path / ".credscanignore").write_text(
        "# comment line\n\nvendor/*\n*.lock\n", encoding="utf-8"
    )

    allowlist = Allowlist.load(tmp_path)

    assert allowlist.path_patterns == ("vendor/*", "*.lock")


def test_is_path_ignored_matches_a_directory_glob(tmp_path: Path):
    (tmp_path / ".credscanignore").write_text("vendor/*\n", encoding="utf-8")
    allowlist = Allowlist.load(tmp_path)

    assert allowlist.is_path_ignored("vendor/lib.js") is True
    assert allowlist.is_path_ignored("src/lib.js") is False


def test_is_path_ignored_matches_by_filename_pattern_regardless_of_directory(tmp_path: Path):
    (tmp_path / ".credscanignore").write_text("*.lock\n", encoding="utf-8")
    allowlist = Allowlist.load(tmp_path)

    assert allowlist.is_path_ignored("deep/nested/package.lock") is True


def test_is_path_ignored_normalizes_windows_style_separators(tmp_path: Path):
    (tmp_path / ".credscanignore").write_text("vendor/*\n", encoding="utf-8")
    allowlist = Allowlist.load(tmp_path)

    assert allowlist.is_path_ignored("vendor\\lib.js") is True


def test_is_line_ignored_detects_the_inline_marker():
    assert Allowlist.is_line_ignored('token = "abc"  # credscan:ignore') is True
    assert Allowlist.is_line_ignored('token = "abc"') is False
