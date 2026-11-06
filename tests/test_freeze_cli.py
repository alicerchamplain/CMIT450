"""Tests for the freeze in graphwatch.cli (issue #10): load_frozen, run_freeze
and the `freeze` command, plus the --unfrozen flag on crowd and sweep.

The workdir fixture mirrors the one in test_cli: one list, frozen, and a
config file with a key. Nothing here touches the network.
"""

import hashlib

import pytest

from graphwatch.cli import load_frozen, main, parse_args, run_freeze
from graphwatch.slugify import SUMS_FILE, read_sums, verify_wordlists


@pytest.fixture
def workdir(tmp_path):
    lists = tmp_path / "wordlists"
    lists.mkdir()
    (lists / "greetings.txt").write_text("Hello\n", encoding="utf-8")
    digest = hashlib.sha256((lists / "greetings.txt").read_bytes()).hexdigest()
    (lists / SUMS_FILE).write_text(f"{digest}  greetings.txt\n", encoding="utf-8")
    (tmp_path / "config.env").write_text("HMAC_KEY=00ff\n", encoding="utf-8")
    return tmp_path


def common(workdir):
    return [
        "--db",
        str(workdir / "g.sqlite"),
        "--wordlists",
        str(workdir / "wordlists"),
        "--budget",
        "0",
    ]


# --------------------------------------------------------------------------
# the freeze (issue #10): load_frozen, run_freeze, the freeze command
# --------------------------------------------------------------------------


def test_parse_args_freeze_defaults():
    args = parse_args(["freeze"])
    assert args.command == "freeze"
    assert str(args.wordlists) == "wordlists"


def test_parse_args_freeze_override():
    assert str(parse_args(["freeze", "--wordlists", "w"]).wordlists) == "w"


def test_parse_args_unfrozen_is_a_flag_on_crowd_and_sweep():
    assert parse_args(["crowd", "--unfrozen"]).unfrozen is True
    assert parse_args(["sweep", "--unfrozen"]).unfrozen is True
    assert parse_args(["sweep"]).unfrozen is False


def test_parse_args_meta_and_freeze_have_no_unfrozen_flag():
    with pytest.raises(SystemExit):
        parse_args(["meta", "--stale", "1", "--unfrozen"])
    with pytest.raises(SystemExit):
        parse_args(["freeze", "--unfrozen"])


def test_load_frozen_returns_entries_for_frozen_lists(workdir):
    entries = load_frozen(workdir / "wordlists")
    assert [e.slug for e in entries] == ["Hello"]


def test_load_frozen_exits_when_a_list_changed(workdir):
    (workdir / "wordlists" / "greetings.txt").write_text("Hello\nTest\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        load_frozen(workdir / "wordlists")
    message = str(exc.value)
    assert "modified: greetings.txt" in message
    assert "--unfrozen" in message
    assert "freeze" in message


def test_load_frozen_exits_when_not_frozen(workdir):
    (workdir / "wordlists" / SUMS_FILE).unlink()
    with pytest.raises(SystemExit) as exc:
        load_frozen(workdir / "wordlists")
    assert "not frozen" in str(exc.value)


def test_load_frozen_unfrozen_skips_the_check(workdir):
    (workdir / "wordlists" / "greetings.txt").write_text("Hello\nTest\n", encoding="utf-8")
    entries = load_frozen(workdir / "wordlists", unfrozen=True)
    assert [e.slug for e in entries] == ["Hello", "Test"]


def test_run_freeze_writes_the_sums_file_and_returns_it(tmp_path):
    (tmp_path / "a.txt").write_text("Hello\nTest\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("Привет\n", encoding="utf-8")
    out = run_freeze(tmp_path, log=lambda s: None)
    assert out == tmp_path / SUMS_FILE
    assert set(read_sums(out)) == {"a.txt", "b.txt"}


def test_run_freeze_logs_one_line_per_list_then_a_summary(tmp_path):
    (tmp_path / "a.txt").write_text("Hello\nTest\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("Привет\n# comment\n\n", encoding="utf-8")
    lines = []
    run_freeze(tmp_path, log=lines.append)
    assert len(lines) == 3
    assert lines[0].startswith("a.txt") and " 2 titles" in lines[0]
    assert lines[1].startswith("b.txt") and " 1 titles" in lines[1]
    assert "3 titles in 2 lists" in lines[2]
    assert str(tmp_path / SUMS_FILE) in lines[2]
    sums = read_sums(tmp_path / SUMS_FILE)
    assert sums["a.txt"] in lines[0] and sums["b.txt"] in lines[1]


def test_run_freeze_counts_titles_after_dedup(tmp_path):
    (tmp_path / "a.txt").write_text("Test\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("TEST\ntest\nOk\n", encoding="utf-8")
    lines = []
    run_freeze(tmp_path, log=lines.append)
    assert " 1 titles" in lines[0]
    assert " 1 titles" in lines[1]
    assert "2 titles in 2 lists" in lines[2]


def test_run_freeze_refreezes_after_an_edit(tmp_path):
    (tmp_path / "a.txt").write_text("Hello\n", encoding="utf-8")
    run_freeze(tmp_path, log=lambda s: None)
    (tmp_path / "a.txt").write_text("Hello\nTest\n", encoding="utf-8")
    run_freeze(tmp_path, log=lambda s: None)
    assert verify_wordlists(tmp_path) == []


def test_run_freeze_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_freeze(tmp_path / "nope", log=lambda s: None)


def test_main_freeze_writes_the_file_and_touches_nothing_else(workdir, capsys):
    (workdir / "wordlists" / SUMS_FILE).unlink()
    main(["freeze", "--wordlists", str(workdir / "wordlists")])
    out = capsys.readouterr().out
    assert (workdir / "wordlists" / SUMS_FILE).exists()
    assert "1 titles in 1 lists" in out
    assert not (workdir / "g.sqlite").exists()


def test_main_freeze_does_not_need_the_config(workdir):
    main(["--config", str(workdir / "nope.env"), "freeze", "--wordlists", str(workdir / "wordlists")])


def test_main_crowd_refuses_changed_lists_before_touching_the_db(workdir):
    (workdir / "wordlists" / "greetings.txt").write_text("Hello\nTest\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["crowd", *common(workdir), "--days", "1"])
    assert "modified: greetings.txt" in str(exc.value)
    assert not (workdir / "g.sqlite").exists()


def test_main_crowd_unfrozen_runs_with_changed_lists(workdir, capsys):
    (workdir / "wordlists" / "greetings.txt").write_text("Hello\nTest\n", encoding="utf-8")
    main(["crowd", *common(workdir), "--days", "1", "--unfrozen"])
    assert "checked 0 title-days" in capsys.readouterr().out


def test_main_sweep_refuses_changed_lists_after_the_key_check(workdir):
    # Order: key first (so a missing config still names the config), then the lists.
    (workdir / "wordlists" / "greetings.txt").write_text("Hello\nTest\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(workdir / "config.env"), "sweep", *common(workdir), "--days", "1"])
    assert "modified: greetings.txt" in str(exc.value)
    assert not (workdir / "g.sqlite").exists()


def test_main_sweep_unfrozen_runs_with_changed_lists(workdir, capsys):
    (workdir / "wordlists" / "greetings.txt").write_text("Hello\nTest\n", encoding="utf-8")
    main(
        [
            "--config",
            str(workdir / "config.env"),
            "sweep",
            *common(workdir),
            "--days",
            "1",
            "--today",
            "2026-11-01",
            "--unfrozen",
        ]
    )
    assert "budget exceeded" in capsys.readouterr().out
