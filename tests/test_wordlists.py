"""Tests for the word list freeze (issue #10): SHA256SUMS next to the lists.

Every test but the last writes its own lists under tmp_path. The last one
checks the real wordlists/ directory against its SHA256SUMS, so it fails
whenever a list changes until `python -m graphwatch.cli freeze` is run again.
"""

import hashlib
from pathlib import Path

import pytest

from graphwatch.slugify import (
    SUMS_FILE,
    WordlistsChanged,
    file_sha256,
    load_wordlists,
    read_sums,
    verify_wordlists,
    write_sums,
)

WORDLISTS = Path(__file__).resolve().parents[1] / "wordlists"


def write_lists(tmp_path, **files):
    for name, text in files.items():
        (tmp_path / f"{name}.txt").write_text(text, encoding="utf-8")
    return tmp_path


# --- file_sha256 ---------------------------------------------------------------


def test_file_sha256_matches_hashlib(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"Hello\n")
    assert file_sha256(f) == hashlib.sha256(b"Hello\n").hexdigest()


def test_file_sha256_is_lowercase_hex_of_length_64(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("Привет\n", encoding="utf-8")
    digest = file_sha256(f)
    assert len(digest) == 64
    assert digest == digest.lower()
    int(digest, 16)  # every character is a hex digit


def test_file_sha256_accepts_a_string_path(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"x")
    assert file_sha256(str(f)) == file_sha256(f)


# --- write_sums -----------------------------------------------------------------


def test_write_sums_writes_sha256sum_format(tmp_path):
    d = write_lists(tmp_path, zed="Z\n", alpha="A\n")
    out = write_sums(d)
    assert out == d / SUMS_FILE
    lines = out.read_text(encoding="utf-8").splitlines()
    # sorted by file name, two spaces between digest and name, name only (no directory)
    assert lines == [
        f"{file_sha256(d / 'alpha.txt')}  alpha.txt",
        f"{file_sha256(d / 'zed.txt')}  zed.txt",
    ]


def test_write_sums_ends_with_a_newline(tmp_path):
    d = write_lists(tmp_path, a="A\n")
    assert write_sums(d).read_text(encoding="utf-8").endswith("\n")


def test_write_sums_lists_only_txt_files(tmp_path):
    d = write_lists(tmp_path, a="A\n")
    (d / "notes.md").write_text("no\n", encoding="utf-8")
    write_sums(d)
    assert list(read_sums(d / SUMS_FILE)) == ["a.txt"]


def test_write_sums_overwrites_a_previous_freeze(tmp_path):
    d = write_lists(tmp_path, a="A\n")
    write_sums(d)
    (d / "a.txt").write_text("B\n", encoding="utf-8")
    write_sums(d)
    assert read_sums(d / SUMS_FILE) == {"a.txt": file_sha256(d / "a.txt")}


def test_write_sums_on_an_empty_directory_writes_an_empty_file(tmp_path):
    out = write_sums(tmp_path)
    assert out.read_text(encoding="utf-8") == "\n"
    assert read_sums(out) == {}


# --- read_sums ------------------------------------------------------------------


def test_read_sums_round_trips_write_sums(tmp_path):
    d = write_lists(tmp_path, a="A\n", b="B\n")
    assert read_sums(write_sums(d)) == {
        "a.txt": file_sha256(d / "a.txt"),
        "b.txt": file_sha256(d / "b.txt"),
    }


def test_read_sums_accepts_the_binary_mode_marker(tmp_path):
    f = tmp_path / SUMS_FILE
    f.write_text("ab" * 32 + " *a.txt\n", encoding="utf-8")
    assert read_sums(f) == {"a.txt": "ab" * 32}


def test_read_sums_skips_blank_and_comment_lines(tmp_path):
    f = tmp_path / SUMS_FILE
    f.write_text(f"# frozen 2026-11-06\n\n{'ab' * 32}  a.txt\n", encoding="utf-8")
    assert read_sums(f) == {"a.txt": "ab" * 32}


def test_read_sums_lowercases_the_digest(tmp_path):
    f = tmp_path / SUMS_FILE
    f.write_text("AB" * 32 + "  a.txt\n", encoding="utf-8")
    assert read_sums(f) == {"a.txt": "ab" * 32}


def test_read_sums_ignores_a_line_without_a_name(tmp_path):
    f = tmp_path / SUMS_FILE
    f.write_text("ab" * 32 + "\n" + "cd" * 32 + "  b.txt\n", encoding="utf-8")
    assert read_sums(f) == {"b.txt": "cd" * 32}


def test_read_sums_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_sums(tmp_path / SUMS_FILE)


# --- verify_wordlists ----------------------------------------------------------


def test_verify_fresh_freeze_has_no_problems(tmp_path):
    d = write_lists(tmp_path, a="A\n", b="B\n")
    write_sums(d)
    assert verify_wordlists(d) == []


def test_verify_without_a_sums_file_says_not_frozen(tmp_path):
    d = write_lists(tmp_path, a="A\n")
    problems = verify_wordlists(d)
    assert len(problems) == 1
    assert problems[0].startswith("not frozen:")
    assert str(d / SUMS_FILE) in problems[0]


def test_verify_reports_a_modified_list(tmp_path):
    d = write_lists(tmp_path, a="A\n", b="B\n")
    write_sums(d)
    (d / "b.txt").write_text("B\nC\n", encoding="utf-8")
    assert verify_wordlists(d) == ["modified: b.txt"]


def test_verify_reports_a_missing_list(tmp_path):
    d = write_lists(tmp_path, a="A\n", b="B\n")
    write_sums(d)
    (d / "a.txt").unlink()
    assert verify_wordlists(d) == ["missing: a.txt"]


def test_verify_reports_an_unlisted_list(tmp_path):
    d = write_lists(tmp_path, a="A\n")
    write_sums(d)
    (d / "new.txt").write_text("N\n", encoding="utf-8")
    assert verify_wordlists(d) == ["unlisted: new.txt"]


def test_verify_reports_every_problem_sorted(tmp_path):
    d = write_lists(tmp_path, a="A\n", b="B\n", c="C\n")
    write_sums(d)
    (d / "a.txt").unlink()
    (d / "b.txt").write_text("changed\n", encoding="utf-8")
    (d / "zz.txt").write_text("Z\n", encoding="utf-8")
    assert verify_wordlists(d) == ["missing: a.txt", "modified: b.txt", "unlisted: zz.txt"]


def test_verify_ignores_non_txt_files(tmp_path):
    d = write_lists(tmp_path, a="A\n")
    write_sums(d)
    (d / "README.md").write_text("docs\n", encoding="utf-8")
    assert verify_wordlists(d) == []


def test_verify_a_whitespace_only_change_counts_as_modified(tmp_path):
    # The freeze is byte-exact on purpose: a trailing newline is a change.
    d = write_lists(tmp_path, a="A\n")
    write_sums(d)
    (d / "a.txt").write_text("A", encoding="utf-8")
    assert verify_wordlists(d) == ["modified: a.txt"]


# --- load_wordlists(verify=...) ------------------------------------------------


def test_load_wordlists_does_not_verify_by_default(tmp_path):
    d = write_lists(tmp_path, a="Hello\n")  # no SHA256SUMS at all
    assert [e.slug for e in load_wordlists(d)] == ["Hello"]


def test_load_wordlists_verify_passes_on_a_fresh_freeze(tmp_path):
    d = write_lists(tmp_path, a="Hello\n")
    write_sums(d)
    assert [e.slug for e in load_wordlists(d, verify=True)] == ["Hello"]


def test_load_wordlists_verify_raises_when_not_frozen(tmp_path):
    d = write_lists(tmp_path, a="Hello\n")
    with pytest.raises(WordlistsChanged) as exc:
        load_wordlists(d, verify=True)
    assert "not frozen" in str(exc.value)


def test_load_wordlists_verify_raises_naming_the_changed_file(tmp_path):
    d = write_lists(tmp_path, a="Hello\n", b="Test\n")
    write_sums(d)
    (d / "b.txt").write_text("Test\nTest2\n", encoding="utf-8")
    with pytest.raises(WordlistsChanged) as exc:
        load_wordlists(d, verify=True)
    assert str(exc.value) == "modified: b.txt"


def test_load_wordlists_verify_message_has_one_problem_per_line(tmp_path):
    d = write_lists(tmp_path, a="Hello\n", b="Test\n")
    write_sums(d)
    (d / "a.txt").unlink()
    (d / "b.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(WordlistsChanged) as exc:
        load_wordlists(d, verify=True)
    assert str(exc.value).splitlines() == ["missing: a.txt", "modified: b.txt"]


def test_load_wordlists_verify_is_keyword_only(tmp_path):
    d = write_lists(tmp_path, a="Hello\n")
    with pytest.raises(TypeError):
        load_wordlists(d, True)


def test_load_wordlists_missing_directory_still_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_wordlists(tmp_path / "nope", verify=True)


def test_wordlists_changed_is_an_exception():
    assert issubclass(WordlistsChanged, Exception)


# --- the real lists -------------------------------------------------------------


def test_the_real_wordlists_are_frozen():
    # Fails after any edit to wordlists/*.txt until the freeze is rerun:
    #   .venv/bin/python -m graphwatch.cli freeze
    assert verify_wordlists(WORDLISTS) == []


def test_the_real_freeze_lists_every_list():
    sums = read_sums(WORDLISTS / SUMS_FILE)
    assert set(sums) == {f.name for f in WORDLISTS.glob("*.txt")}
    assert len(sums) >= 9
