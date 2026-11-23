"""Tests for the freeze in graphwatch.cli (issue #10): load_frozen, run_freeze
and the `freeze` command, and what crowd and sweep do with changed lists.

The workdir fixture mirrors the one in test_cli: one list, frozen, and a
config file with a key. Nothing here touches the network. The options
themselves (freeze --wordlists, --unfrozen on crowd and sweep and on nothing
else) are in the parse_args tables of test_cli.
"""

import hashlib

import pytest

from graphwatch.cli import load_frozen, main, run_freeze
from graphwatch.db import connect
from graphwatch.slugify import SUMS_FILE, read_sums, verify_wordlists


@pytest.fixture
def workdir(tmp_path):
    lists = tmp_path / "wordlists"
    lists.mkdir()
    (lists / "greetings.txt").write_text("Hello\n", encoding="utf-8")
    digest = hashlib.sha256((lists / "greetings.txt").read_bytes()).hexdigest()
    (lists / SUMS_FILE).write_text(f"{digest}  greetings.txt\n", encoding="utf-8")
    (tmp_path / "config.env").write_text("HMAC_KEY=" + "00ff" * 16 + "\n", encoding="utf-8")
    return tmp_path


def run_argv(workdir, command, *extra):
    """A crowd or a sweep of one day with a budget of 0, which keeps it off the network."""
    return [
        "--config",
        str(workdir / "config.env"),
        command,
        "--db",
        str(workdir / "g.sqlite"),
        "--wordlists",
        str(workdir / "wordlists"),
        "--budget",
        "0",
        "--days",
        "1",
        *extra,
    ]


def change_the_list(workdir):
    (workdir / "wordlists" / "greetings.txt").write_text("Hello\nTest\n", encoding="utf-8")


# --------------------------------------------------------------------------
# the freeze (issue #10): load_frozen, run_freeze, the freeze command
# --------------------------------------------------------------------------


def test_load_frozen_returns_entries_for_frozen_lists(workdir):
    entries = load_frozen(workdir / "wordlists")
    assert [e.slug for e in entries] == ["Hello"]


def test_load_frozen_exits_when_a_list_changed(workdir):
    change_the_list(workdir)
    with pytest.raises(SystemExit) as exc:
        load_frozen(workdir / "wordlists")
    message = str(exc.value)
    assert "modified: greetings.txt" in message
    # and it says both ways out
    assert "run `freeze` to accept the changes or pass --unfrozen" in message


def test_load_frozen_exits_when_not_frozen(workdir):
    (workdir / "wordlists" / SUMS_FILE).unlink()
    with pytest.raises(SystemExit) as exc:
        load_frozen(workdir / "wordlists")
    assert "not frozen" in str(exc.value)


def test_load_frozen_unfrozen_skips_the_check(workdir):
    change_the_list(workdir)
    entries = load_frozen(workdir / "wordlists", unfrozen=True)
    assert [e.slug for e in entries] == ["Hello", "Test"]


def test_run_freeze_writes_the_sums_file_and_logs_one_line_per_list_then_a_summary(tmp_path):
    (tmp_path / "a.txt").write_text("Hello\nTest\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("Привет\n# comment\n\n", encoding="utf-8")
    lines = []
    out = run_freeze(tmp_path, log=lines.append)
    assert out == tmp_path / SUMS_FILE
    sums = read_sums(out)
    assert set(sums) == {"a.txt", "b.txt"}
    assert lines == [
        f"{'a.txt':24}     2 titles  {sums['a.txt']}",
        f"{'b.txt':24}     1 titles  {sums['b.txt']}",
        f"3 titles in 2 lists, wrote {out}",
    ]


def test_run_freeze_counts_titles_after_dedup(tmp_path):
    (tmp_path / "a.txt").write_text("Test\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("TEST\ntest\nOk\n", encoding="utf-8")
    lines = []
    run_freeze(tmp_path, log=lines.append)
    assert " 1 titles" in lines[0]
    assert " 1 titles" in lines[1]
    assert lines[2].startswith("2 titles in 2 lists")


def test_run_freeze_refreezes_after_an_edit(tmp_path):
    (tmp_path / "a.txt").write_text("Hello\n", encoding="utf-8")
    run_freeze(tmp_path, log=lambda s: None)
    (tmp_path / "a.txt").write_text("Hello\nTest\n", encoding="utf-8")
    assert verify_wordlists(tmp_path) == ["modified: a.txt"]
    run_freeze(tmp_path, log=lambda s: None)
    assert verify_wordlists(tmp_path) == []


def test_main_freeze_writes_the_file_needs_no_config_and_touches_nothing_else(workdir, capsys):
    (workdir / "wordlists" / SUMS_FILE).unlink()
    main(["--config", str(workdir / "nope.env"), "freeze", "--wordlists", str(workdir / "wordlists")])
    out = capsys.readouterr().out
    assert (workdir / "wordlists" / SUMS_FILE).exists()
    assert "1 titles in 1 lists" in out
    assert not (workdir / "g.sqlite").exists()


@pytest.mark.parametrize("command", ["crowd", "sweep"])
def test_main_refuses_changed_lists_before_touching_the_db(workdir, command):
    change_the_list(workdir)
    with pytest.raises(SystemExit) as exc:
        main(run_argv(workdir, command))
    assert "modified: greetings.txt" in str(exc.value)
    assert not (workdir / "g.sqlite").exists()


def test_main_sweep_checks_the_key_before_the_lists(workdir):
    # so that a missing config still names the config
    change_the_list(workdir)
    argv = run_argv(workdir, "sweep")
    argv[1] = str(workdir / "nope.env")
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert "nope.env" in str(exc.value)


@pytest.mark.parametrize(
    "command, last_line",
    [("crowd", "checked 0 title-days, 0 requests, "), ("sweep", "Stored 0 pages, 0 requests, ")],
)
def test_main_unfrozen_runs_with_the_changed_lists(workdir, capsys, command, last_line):
    change_the_list(workdir)
    main(run_argv(workdir, command, "--unfrozen"))
    assert capsys.readouterr().out.splitlines()[-1].startswith(last_line)
    # both titles of the changed list were loaded
    c = connect(workdir / "g.sqlite")
    assert [r["slug"] for r in c.execute("SELECT slug FROM titles ORDER BY id")] == ["hello", "test"]
    c.close()
