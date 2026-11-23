"""Tests for graphwatch.cli, the runner.

The runner is split so the wiring can be tested without the network: main()
parses arguments and builds real objects; run_crowd() takes those objects and
does the work. Here run_crowd gets a client whose session answers from a set
of existing paths.
"""

import hashlib
import json
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import pytest

from graphwatch.cli import (
    main,
    make_fetch,
    make_probe,
    parse_args,
    require_key,
    run_classify,
    run_crowd,
    run_explain,
    run_meta,
    run_sweep,
)
from graphwatch.config import CONFIG
from graphwatch.crowd import DayCount, save_day_count
from graphwatch.db import (
    add_snapshot,
    connect,
    http_logger,
    latest_snapshots,
    load_progress,
    save_score,
    upsert_page,
)
from graphwatch.rules import RULES, apply_rules
from graphwatch.slugify import Entry
from graphwatch.telegraph import Outcome, TelegraphClient

FIXTURES = Path(__file__).resolve().parents[1] / "plan" / "fixtures"
FOUND_BODY = (FIXTURES / "Vizit-12-28.json").read_bytes()
MISSING_BODY = (FIXTURES / "not-found.json").read_bytes()


class Resp:
    def __init__(self, body):
        self.status_code = 200
        self.content = body


class PathSession:
    """Answers FOUND for paths in `existing`, NOT_FOUND otherwise; records paths."""

    def __init__(self, existing):
        self.existing = set(existing)
        self.paths = []

    def get(self, url, **kwargs):
        path = urllib.parse.unquote(url.split("/getPage/", 1)[1].split("?", 1)[0])
        self.paths.append(path)
        return Resp(FOUND_BODY if path in self.existing else MISSING_BODY)


def make_client(existing, **kwargs):
    session = PathSession(existing)
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=0, **kwargs)
    return client, session


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


ENTRIES = [
    Entry("Hello", "Hello", "greetings", False),
    Entry("Повістка", "Povіstka", "lures", False),
]
DAYS = [(10, 23), (10, 24)]


# --------------------------------------------------------------------------
# make_probe
# --------------------------------------------------------------------------


def test_make_probe_returns_the_outcome_only():
    client, session = make_client({"Hello-10-24"})
    probe = make_probe(client)
    assert probe("Hello-10-24") is Outcome.FOUND
    assert probe("Hello-10-23") is Outcome.NOT_FOUND


def test_make_probe_asks_without_content():
    client, session = make_client(set())
    make_probe(client)("Hello-10-24")
    # the client records the URL; the probe must not pull page bodies
    assert client.requests_made == 1
    assert session.paths == ["Hello-10-24"]


# --------------------------------------------------------------------------
# run_crowd
# --------------------------------------------------------------------------


def test_run_crowd_saves_one_row_per_slug_per_day(conn):
    client, _ = make_client({"Hello-10-24", "Hello-10-24-2", "Povіstka-10-23"})
    checked = run_crowd(conn, client, ENTRIES, DAYS, gap=0, log=lambda s: None)
    assert checked == 4
    rows = conn.execute(
        "SELECT slug, month, day, highest FROM crowd ORDER BY slug, month, day"
    ).fetchall()
    assert [tuple(r) for r in rows] == [
        ("hello", 10, 23, 0),
        ("hello", 10, 24, 2),
        ("povіstka", 10, 23, 1),
        ("povіstka", 10, 24, 0),
    ]


def test_run_crowd_registers_the_titles(conn):
    client, _ = make_client(set())
    run_crowd(conn, client, ENTRIES, DAYS, log=lambda s: None)
    rows = conn.execute("SELECT title, slug, source FROM titles ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [
        ("Hello", "hello", "greetings"),
        ("Повістка", "povіstka", "lures"),
    ]


def test_run_crowd_resumes_and_spends_nothing_on_done_days(conn):
    client1, _ = make_client({"Hello-10-24"})
    run_crowd(conn, client1, ENTRIES, DAYS, gap=0, log=lambda s: None)
    client2, session2 = make_client({"Hello-10-24"})
    checked = run_crowd(conn, client2, ENTRIES, DAYS, gap=0, log=lambda s: None)
    assert checked == 0
    assert session2.paths == []
    assert conn.execute("SELECT COUNT(*) FROM crowd").fetchone()[0] == 4


def test_run_crowd_logs_days_that_have_pages(conn):
    client, _ = make_client({"Hello-10-24", "Hello-10-24-2"})
    lines = []
    run_crowd(conn, client, ENTRIES, DAYS, gap=0, log=lines.append)
    assert any("Hello" in line and "10-24" in line and "2" in line for line in lines)


def test_run_crowd_stops_cleanly_when_the_budget_runs_out(conn):
    # Budget for the first slug's two days only; the second slug is left for
    # the next night. Nothing raises, and what was finished is saved.
    client, _ = make_client(set(), budget=2)
    checked = run_crowd(conn, client, ENTRIES, DAYS, gap=0, log=lambda s: None)
    assert checked == 2
    rows = conn.execute("SELECT slug FROM crowd").fetchall()
    assert {r[0] for r in rows} == {"hello"}


def test_run_crowd_uses_the_gap(conn):
    client, _ = make_client({"Hello-10-24-2"})  # bare page deleted
    run_crowd(conn, client, ENTRIES[:1], [(10, 24)], gap=1, log=lambda s: None)
    assert conn.execute("SELECT highest FROM crowd").fetchone()[0] == 2


# --------------------------------------------------------------------------
# parse_args
# --------------------------------------------------------------------------


def test_parse_args_crowd_defaults():
    args = parse_args(["crowd"])
    assert args.command == "crowd"
    assert str(args.db) == "data/graphwatch.sqlite"
    assert str(args.wordlists) == "wordlists"
    assert args.days == 14
    assert args.gap == 2
    assert args.rate == 8.0
    assert args.budget is None


def test_parse_args_crowd_overrides():
    args = parse_args(
        [
            "crowd",
            "--days",
            "3",
            "--gap",
            "1",
            "--rate",
            "4",
            "--budget",
            "500",
            "--db",
            "x.sqlite",
        ]
    )
    assert (args.days, args.gap, args.rate, args.budget) == (3, 1, 4.0, 500)
    assert str(args.db) == "x.sqlite"


def test_parse_args_requires_a_command():
    with pytest.raises(SystemExit):
        parse_args([])


def test_parse_args_config_defaults_to_the_user_config_file():
    assert parse_args(["crowd"]).config == CONFIG


def test_parse_args_config_is_a_top_level_option():
    # Shared by every command, so it is typed before the command name.
    args = parse_args(["--config", "/tmp/x.env", "crowd"])
    assert str(args.config) == "/tmp/x.env"
    assert args.command == "crowd"


# --------------------------------------------------------------------------
# require_key
# --------------------------------------------------------------------------


def test_require_key_returns_the_key_bytes(tmp_path):
    cfg = tmp_path / "config.env"
    cfg.write_text("HMAC_KEY=00ff\n", encoding="utf-8")
    assert require_key(cfg) == b"\x00\xff"


def test_require_key_missing_file_exits_naming_the_path(tmp_path):
    cfg = tmp_path / "nope.env"
    with pytest.raises(SystemExit) as exc:
        require_key(cfg)
    assert str(cfg) in str(exc.value)
    assert exc.value.code != 0


def test_require_key_missing_variable_exits_naming_it(tmp_path):
    cfg = tmp_path / "config.env"
    cfg.write_text("OTHER=1\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        require_key(cfg)
    assert "HMAC_KEY" in str(exc.value)
    assert str(cfg) in str(exc.value)


def test_require_key_never_prints_the_key(tmp_path, capsys):
    cfg = tmp_path / "config.env"
    cfg.write_text("HMAC_KEY=sensitive-passphrase\n", encoding="utf-8")
    require_key(cfg)
    out, err = capsys.readouterr()
    assert "sensitive" not in out + err


# --------------------------------------------------------------------------
# make_fetch and run_sweep (issue #20)
# --------------------------------------------------------------------------

KEY = b"test-key"


class SweepSession(PathSession):
    """Like PathSession, but a FOUND body carries the requested path, so what
    the sweep stores is the page it asked for. `failing` paths get a 500 with
    an unparseable body, which the client reports as FAILED."""

    def __init__(self, existing, failing=()):
        super().__init__(existing)
        self.failing = set(failing)

    def get(self, url, **kwargs):
        path = urllib.parse.unquote(url.split("/getPage/", 1)[1].split("?", 1)[0])
        self.paths.append(path)
        if path in self.failing:
            r = Resp(b"not json")
            r.status_code = 500
            return r
        if path in self.existing:
            body = json.loads(FOUND_BODY)
            body["result"]["path"] = path
            body["result"]["title"] = f"title of {path}"
            return Resp(json.dumps(body).encode("utf-8"))
        return Resp(MISSING_BODY)


def make_sweep_client(existing, failing=(), **kwargs):
    session = SweepSession(existing, failing)
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=0, **kwargs)
    return client, session


def seed_crowd(conn, rows):
    for slug, month, day, highest in rows:
        save_day_count(conn, DayCount(slug, month, day, highest, 1, 0, []), 0.0)


@pytest.fixture
def counted(conn):
    """A crowd count of 0 for every title-day these tests sweep. run_sweep only
    walks a day that has been counted; 0 leaves the walk ending at the gap."""
    seed_crowd(conn, [(e.slug, m, d, 0) for e in ENTRIES for m, d in DAYS])
    return conn


def stored_paths(conn):
    return [r["path"] for r in conn.execute("SELECT path FROM pages ORDER BY id")]


def test_make_fetch_returns_the_whole_fetch_with_content():
    client, session = make_sweep_client({"Hello-10-24"})
    fetch = make_fetch(client)
    f = fetch("Hello-10-24")
    assert f.outcome is Outcome.FOUND
    assert f.page["path"] == "Hello-10-24"
    assert f.page["content"]
    assert fetch("Hello-10-23").outcome is Outcome.NOT_FOUND


def test_run_sweep_stores_every_page_of_every_day(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24", "Hello-10-24-2", "Povіstka-10-23"})
    stored, requests = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None
    )
    assert stored == 3
    assert stored_paths(conn) == ["Hello-10-24", "Hello-10-24-2", "Povіstka-10-23"]
    assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 3
    # gap 0: each of the 4 title-days costs its pages + 1 miss
    assert requests == 3 + 4
    assert client.requests_made == requests


def test_run_sweep_registers_titles_and_links_pages_to_them(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    row = conn.execute(
        "SELECT t.slug FROM pages p JOIN titles t ON p.title_id = t.id"
    ).fetchone()
    assert row["slug"] == "hello"


def test_run_sweep_stores_redacted_content(conn, counted):
    client, session = make_sweep_client({"Hello-10-24"})
    # make the fixture body carry a secret in the title
    orig = session.get

    def get(url, **kw):
        r = orig(url, **kw)
        if r.status_code == 200 and b'"ok": true' in r.content:
            body = json.loads(r.content)
            body["result"]["title"] = "password: hunter2"
            r.content = json.dumps(body).encode("utf-8")
        return r

    session.get = get
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    title = conn.execute("SELECT title FROM snapshots").fetchone()["title"]
    assert "hunter2" not in title
    assert "SECRET{" in title


def test_run_sweep_records_progress_per_day(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24", "Hello-10-24-2"})
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 1, None, set(), log=lambda s: None)
    assert load_progress(conn, "Hello", 10, 24) == (5, True)  # 1, 2 found; 3, 4 miss
    assert load_progress(conn, "Hello", 10, 23) == (3, True)  # 1, 2 miss
    row = conn.execute(
        "SELECT requests, failures FROM sweep_progress WHERE slug = 'hello' AND day = 24"
    ).fetchone()
    assert (row["requests"], row["failures"]) == (4, 0)


def test_run_sweep_skips_excluded_slugs_entirely(conn, counted):
    client, session = make_sweep_client({"Hello-10-24", "Povіstka-10-23"})
    stored, _ = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, {"hello"}, log=lambda s: None
    )
    assert stored == 1
    assert not any(p.startswith("Hello") for p in session.paths)
    assert load_progress(conn, "Hello", 10, 24) == (1, False)


def test_run_sweep_skips_days_already_done(conn, counted):
    client1, _ = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client1, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    client2, session2 = make_sweep_client({"Hello-10-24"})
    stored, requests = run_sweep(
        conn, client2, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None
    )
    assert (stored, requests) == (0, 0)
    assert session2.paths == []


def test_run_sweep_resumes_a_day_cut_off_by_the_budget(conn, counted):
    existing = {"Hello-10-23", "Hello-10-23-2", "Hello-10-23-3", "Hello-10-23-4"}
    # Night one: budget allows 1, 2 and the request for 3 is refused.
    client1, session1 = make_sweep_client(existing, budget=2)
    stored, _ = run_sweep(
        conn, client1, ENTRIES[:1], [(10, 23)], KEY, 0, None, set(), log=lambda s: None
    )
    assert stored == 2
    assert load_progress(conn, "Hello", 10, 23) == (3, False)
    # Night two: picks up at 3, never re-fetches 1 or 2.
    client2, session2 = make_sweep_client(existing)
    stored, _ = run_sweep(
        conn, client2, ENTRIES[:1], [(10, 23)], KEY, 0, None, set(), log=lambda s: None
    )
    assert stored == 2
    assert session2.paths == ["Hello-10-23-3", "Hello-10-23-4", "Hello-10-23-5"]
    assert load_progress(conn, "Hello", 10, 23) == (6, True)
    assert stored_paths(conn) == [
        "Hello-10-23",
        "Hello-10-23-2",
        "Hello-10-23-3",
        "Hello-10-23-4",
    ]


def test_run_sweep_budget_exceeded_is_logged_not_raised(conn, counted):
    client, _ = make_sweep_client({"Hello-10-23", "Hello-10-23-2"}, budget=1)
    lines = []
    stored, _ = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append
    )
    assert stored == 1
    assert any("budget" in line for line in lines)


def test_run_sweep_uses_expected_from_the_crowd_table(conn, counted):
    # Pages at 1 and 5; crowd says the day reaches 5. gap 0 would otherwise stop at 2.
    seed_crowd(conn, [("Hello", 10, 23, 5)])
    client, session = make_sweep_client({"Hello-10-23", "Hello-10-23-5"})
    stored, _ = run_sweep(
        conn, client, ENTRIES, [(10, 23)], KEY, 0, None, set(), log=lambda s: None
    )
    assert stored == 2
    assert "Hello-10-23-5" in session.paths


def test_run_sweep_cap_truncates_a_day(conn, counted):
    existing = {f"Hello-10-23-{n}" for n in range(2, 10)} | {"Hello-10-23"}
    seed_crowd(conn, [("Hello", 10, 23, 9)])
    client, session = make_sweep_client(existing)
    stored, _ = run_sweep(
        conn, client, ENTRIES, [(10, 23)], KEY, 2, 3, set(), log=lambda s: None
    )
    assert stored == 3
    assert load_progress(conn, "Hello", 10, 23) == (4, True)


def test_run_sweep_failed_tail_leaves_the_day_for_retry(conn, counted):
    client, _ = make_sweep_client(
        {"Hello-10-23"}, failing={"Hello-10-23-2", "Hello-10-23-3"}
    )
    lines = []
    run_sweep(conn, client, ENTRIES, [(10, 23)], KEY, 1, None, set(), log=lines.append)
    next_n, done = load_progress(conn, "Hello", 10, 23)
    assert (next_n, done) == (4, False)
    row = conn.execute("SELECT failures FROM sweep_progress").fetchone()
    assert row["failures"] == 2
    assert any("Hello" in line and "10-23" in line for line in lines)


def test_run_sweep_logs_days_with_pages_only(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24"})
    lines = []
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append)
    assert len(lines) == 1
    assert "Hello" in lines[0] and "10-24" in lines[0]


def test_run_sweep_logs_every_request(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24"})
    client.log = __import__("graphwatch.db", fromlist=["http_logger"]).http_logger(conn)
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    assert (
        conn.execute("SELECT COUNT(*) FROM http_log").fetchone()[0]
        == client.requests_made
    )


def test_run_sweep_stores_the_api_path_not_the_requested_one(conn, counted):
    client, session = make_sweep_client({"hello-10-24"})
    # The API answers for Hello-10-24 but reports its own spelling.
    orig = session.get

    def get(url, **kw):
        r = orig(url.replace("Hello-10-24", "hello-10-24"), **kw)
        return r

    session.get = get
    run_sweep(
        conn, client, ENTRIES, [(10, 24)], KEY, 0, None, set(), log=lambda s: None
    )
    assert stored_paths(conn) == ["hello-10-24"]
    # progress is keyed by the slug we swept, case-insensitively
    assert load_progress(conn, "Hello", 10, 24)[1] is True


def test_run_sweep_skips_a_title_day_that_has_no_crowd_count(conn):
    # With no count the walk would stop at the first hole of gap + 1 counters,
    # which is how 2 to 4 November lost pages. Nothing is fetched or marked done.
    client, session = make_sweep_client({"Hello-10-24", "Hello-10-24-2"})
    lines = []
    stored, requests = run_sweep(
        conn, client, ENTRIES[:1], [(10, 24)], KEY, 2, None, set(), log=lines.append
    )
    assert (stored, requests) == (0, 0)
    assert session.paths == []
    assert load_progress(conn, "Hello", 10, 24) == (1, False)
    assert len(lines) == 1
    assert "1 title-days" in lines[0] and "crowd" in lines[0]


def test_run_sweep_sweeps_the_counted_days_and_reports_the_rest(conn):
    seed_crowd(conn, [("Hello", 10, 24, 2)])
    client, session = make_sweep_client({"Hello-10-23", "Hello-10-24", "Hello-10-24-2"})
    lines = []
    stored, _ = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append
    )
    assert stored == 2
    assert stored_paths(conn) == ["Hello-10-24", "Hello-10-24-2"]
    assert not any(path.startswith("Hello-10-23") for path in session.paths)
    assert load_progress(conn, "Hello", 10, 24)[1] is True
    assert load_progress(conn, "Hello", 10, 23)[1] is False
    # Hello 10-23 and both Povіstka days have no count
    assert any("3 title-days" in line for line in lines)


def test_run_sweep_a_counted_empty_day_is_swept_and_closed(conn):
    # A count of 0 is a count: the day costs its gap probes and is marked done.
    seed_crowd(conn, [("Hello", 10, 24, 0)])
    client, session = make_sweep_client(set())
    lines = []
    _, requests = run_sweep(
        conn, client, ENTRIES[:1], [(10, 24)], KEY, 2, None, set(), log=lines.append
    )
    assert requests == 3
    assert load_progress(conn, "Hello", 10, 24) == (4, True)
    assert lines == []


def test_run_sweep_does_not_report_a_done_day_whose_count_is_gone(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client, ENTRIES[:1], [(10, 24)], KEY, 0, None, set(), log=lambda s: None)
    conn.execute("DELETE FROM crowd")
    lines = []
    client2, session2 = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client2, ENTRIES[:1], [(10, 24)], KEY, 0, None, set(), log=lines.append)
    assert session2.paths == []
    assert lines == []


def test_run_sweep_does_not_report_excluded_slugs_as_uncounted(conn):
    client, _ = make_sweep_client(set())
    lines = []
    run_sweep(conn, client, ENTRIES[:1], DAYS, KEY, 0, None, {"hello"}, log=lines.append)
    assert lines == []


# --------------------------------------------------------------------------
# main: wiring only; a budget of 0 keeps every test off the network
# --------------------------------------------------------------------------


@pytest.fixture
def workdir(tmp_path):
    (tmp_path / "wordlists").mkdir()
    (tmp_path / "wordlists" / "greetings.txt").write_text("Hello\n", encoding="utf-8")
    # main() refuses word lists that do not match SHA256SUMS (issue #10), so
    # freeze the one list by hand; sha256sum format is "digest  name".
    digest = hashlib.sha256((tmp_path / "wordlists" / "greetings.txt").read_bytes()).hexdigest()
    (tmp_path / "wordlists" / "SHA256SUMS").write_text(f"{digest}  greetings.txt\n", encoding="utf-8")
    cfg = tmp_path / "config.env"
    cfg.write_text("HMAC_KEY=00ff\n", encoding="utf-8")
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


def test_main_sweep_without_a_config_file_exits_before_touching_the_db(workdir, capsys):
    missing = workdir / "nope.env"
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(missing), "sweep", *common(workdir)])
    assert str(missing) in str(exc.value)
    assert not (workdir / "g.sqlite").exists()


def test_main_sweep_without_the_key_exits(workdir):
    (workdir / "config.env").write_text("OTHER=1\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(workdir / "config.env"), "sweep", *common(workdir)])
    assert "HMAC_KEY" in str(exc.value)


def test_main_crowd_does_not_need_the_config(workdir, capsys):
    main(
        [
            "--config",
            str(workdir / "nope.env"),
            "crowd",
            *common(workdir),
            "--days",
            "1",
        ]
    )
    out = capsys.readouterr().out
    assert "budget exceeded" in out
    assert "checked 0 title-days" in out


def test_main_crowd_takes_today_so_the_nightly_job_can_count_a_finished_day(workdir, monkeypatch):
    # Without --today, crowd counts the current, unfinished day and never
    # recounts it; the nightly job passes yesterday, the same way sweep does.
    seen = {}

    def fake_run_crowd(conn, client, entries, days, gap=2, log=print):
        seen["days"] = days
        return 0

    monkeypatch.setattr("graphwatch.cli.run_crowd", fake_run_crowd)
    main(["crowd", *common(workdir), "--days", "2", "--today", "2026-11-13"])
    assert seen["days"] == [(11, 12), (11, 13)]


def test_main_sweep_prints_the_plan_then_stops_on_the_budget(workdir, capsys):
    # The sweep only walks counted days, so count both (empty) days first.
    c = connect(workdir / "g.sqlite")
    save_day_count(c, DayCount("Hello", 10, 31, 0, 1, 0, []), 0.0)
    save_day_count(c, DayCount("Hello", 11, 1, 0, 1, 0, []), 0.0)
    c.close()
    main(
        [
            "--config",
            str(workdir / "config.env"),
            "sweep",
            *common(workdir),
            "--days",
            "2",
            "--today",
            "2026-11-01",
        ]
    )
    out = capsys.readouterr().out
    assert "2" in out.splitlines()[0]  # the window size is on the planning line
    assert "10-31" in out.splitlines()[0]  # first day of a 2-day window ending Nov 1
    assert "budget exceeded" in out
    assert "0 pages" in out.splitlines()[-1]
    assert "0 requests" in out.splitlines()[-1]


def test_main_sweep_refuses_when_no_window_fits(workdir, capsys):
    # A crowd row makes one day cost 13 requests; budget 0 fits nothing.
    c = connect(workdir / "g.sqlite")
    save_day_count(c, DayCount("Hello", 11, 1, 10, 1, 0, []), 0.0)
    c.close()
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--config",
                str(workdir / "config.env"),
                "sweep",
                *common(workdir),
                "--today",
                "2026-11-01",
            ]
        )
    assert "window" in str(exc.value)


def test_main_sweep_lets_the_crowd_table_choose_the_window(workdir, capsys):
    # Three days cost 13 each. A budget of 26 fits Nov 1 and Oct 31, not Oct 30.
    # run_sweep is replaced so no request is made; only the chosen window matters.
    c = connect(workdir / "g.sqlite")
    for d in (30, 31):
        save_day_count(c, DayCount("Hello", 10, d, 10, 1, 0, []), 0.0)
    save_day_count(c, DayCount("Hello", 11, 1, 10, 1, 0, []), 0.0)
    c.close()
    args = [
        "--db",
        str(workdir / "g.sqlite"),
        "--wordlists",
        str(workdir / "wordlists"),
    ]
    import graphwatch.cli as cli

    captured = {}
    real = cli.run_sweep

    def fake_run_sweep(conn, client, entries, days, key, gap, cap, exclude, log=print):
        captured["days"] = days
        return 0, 0

    cli.run_sweep = fake_run_sweep
    try:
        main(
            [
                "--config",
                str(workdir / "config.env"),
                "sweep",
                *args,
                "--budget",
                "26",
                "--today",
                "2026-11-01",
            ]
        )
    finally:
        cli.run_sweep = real
    assert captured["days"] == [(10, 31), (11, 1)]


def test_main_sweep_excludes_titles_above_the_count_only_threshold(workdir):
    c = connect(workdir / "g.sqlite")
    save_day_count(c, DayCount("Hello", 11, 1, 50_000, 1, 0, []), 0.0)
    c.close()
    import graphwatch.cli as cli

    captured = {}
    real = cli.run_sweep

    def fake_run_sweep(conn, client, entries, days, key, gap, cap, exclude, log=print):
        captured["exclude"] = exclude
        return 0, 0

    cli.run_sweep = fake_run_sweep
    try:
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
            ]
        )
    finally:
        cli.run_sweep = real
    assert captured["exclude"] == {"hello"}


# --------------------------------------------------------------------------
# meta: HTML metadata for selected pages (plan/page-meta-plan-2026-11-04.md)
# --------------------------------------------------------------------------

PUB_ISO = "2026-10-19T03:00:08+0000"
MOD_ISO = "2026-11-04T15:06:39+0000"
MOD2_ISO = "2026-11-05T09:00:00+0000"


def iso_ts(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


def html_body(published: str, modified: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head>"
        f'<meta property="article:published_time" content="{published}">'
        f'<meta property="article:modified_time" content="{modified}">'
        "</head><body></body></html>"
    ).encode("utf-8")


class HtmlResp:
    def __init__(self, status, body):
        self.status_code = status
        self.content = body


class HtmlSession:
    """Answers telegra.ph/<path> from `times` {path: (published, modified)};
    404 for unknown paths, 503 for paths in `failing`. Records paths."""

    def __init__(self, times, failing=()):
        self.times = dict(times)
        self.failing = set(failing)
        self.paths = []

    def get(self, url, **kwargs):
        assert url.startswith("https://telegra.ph/"), url
        path = urllib.parse.unquote(url.split("https://telegra.ph/", 1)[1])
        self.paths.append(path)
        if path in self.failing:
            return HtmlResp(503, b"<html>busy</html>")
        if path in self.times:
            return HtmlResp(200, html_body(*self.times[path]))
        return HtmlResp(404, b"<html><title>Telegraph</title></html>")


def make_meta_client(times, failing=(), **kwargs):
    session = HtmlSession(times, failing)
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=0, **kwargs)
    return client, session


def seed_pages(conn, paths):
    rows = []
    for path in paths:
        pid = upsert_page(conn, path, 0.0)
        add_snapshot(conn, pid, {"path": path, "content": []}, 0.0, KEY)
        rows.append(conn.execute("SELECT id, path FROM pages WHERE id = ?", (pid,)).fetchone())
    return rows


def meta_row(conn, path):
    return conn.execute(
        "SELECT published_at, modified_at, meta_seen_at FROM pages WHERE path = ?",
        (path,),
    ).fetchone()


def change_events(conn):
    return conn.execute(
        "SELECT page_id, detail FROM events WHERE kind = 'modified_at_changed' ORDER BY id"
    ).fetchall()


def test_run_meta_fetches_each_selected_page_once(conn):
    pages = seed_pages(conn, ["Hello-10-19-130", "Hello-10-19-143"])
    client, session = make_meta_client(
        {"Hello-10-19-130": (PUB_ISO, MOD_ISO), "Hello-10-19-143": (PUB_ISO, MOD_ISO)}
    )
    counts = run_meta(conn, client, pages, log=lambda s: None)
    assert session.paths == ["Hello-10-19-130", "Hello-10-19-143"]
    assert client.requests_made == 2
    assert counts["fetched"] == 2


def test_run_meta_stores_the_timestamps(conn):
    pages = seed_pages(conn, ["Hello-10-19-130"])
    client, _ = make_meta_client({"Hello-10-19-130": (PUB_ISO, MOD_ISO)})
    run_meta(conn, client, pages, log=lambda s: None)
    row = meta_row(conn, "Hello-10-19-130")
    assert row["published_at"] == iso_ts(PUB_ISO)
    assert row["modified_at"] == iso_ts(MOD_ISO)
    assert row["meta_seen_at"] is not None


def test_run_meta_first_fetch_is_not_a_change(conn):
    pages = seed_pages(conn, ["Hello-10-19-130"])
    client, _ = make_meta_client({"Hello-10-19-130": (PUB_ISO, MOD_ISO)})
    counts = run_meta(conn, client, pages, log=lambda s: None)
    assert counts["changed"] == 0
    assert change_events(conn) == []


def test_run_meta_counts_and_logs_a_changed_page(conn):
    pages = seed_pages(conn, ["Hello-10-19-130", "Hello-10-19-143"])
    client, session = make_meta_client(
        {"Hello-10-19-130": (PUB_ISO, MOD_ISO), "Hello-10-19-143": (PUB_ISO, MOD_ISO)}
    )
    run_meta(conn, client, pages, log=lambda s: None)
    session.times["Hello-10-19-143"] = (PUB_ISO, MOD2_ISO)  # the actor edits one page
    lines = []
    counts = run_meta(conn, client, pages, log=lines.append)
    assert counts == {"fetched": 2, "changed": 1, "not_found": 0, "failed": 0}
    assert len(change_events(conn)) == 1
    assert change_events(conn)[0]["page_id"] == pages[1]["id"]
    assert len(lines) == 1
    assert "Hello-10-19-143" in lines[0]
    assert "2026-11-05T09:00:00" in lines[0]
    assert "Hello-10-19-130" not in lines[0]


def test_run_meta_not_found_is_counted_and_stores_nothing(conn):
    pages = seed_pages(conn, ["Hello-10-19-130", "zz-01-01-99999"])
    client, _ = make_meta_client({"Hello-10-19-130": (PUB_ISO, MOD_ISO)})
    counts = run_meta(conn, client, pages, log=lambda s: None)
    assert counts["fetched"] == 1
    assert counts["not_found"] == 1
    assert meta_row(conn, "zz-01-01-99999")["meta_seen_at"] is None


def test_run_meta_failed_is_counted_logged_and_does_not_stop_the_run(conn):
    pages = seed_pages(conn, ["Hello-10-19-130", "Hello-10-19-143"])
    client, _ = make_meta_client(
        {"Hello-10-19-143": (PUB_ISO, MOD_ISO)}, failing={"Hello-10-19-130"}
    )
    lines = []
    counts = run_meta(conn, client, pages, log=lines.append)
    assert counts["failed"] == 1
    assert counts["fetched"] == 1
    assert meta_row(conn, "Hello-10-19-143")["modified_at"] == iso_ts(MOD_ISO)
    assert any("Hello-10-19-130" in line for line in lines)


def test_run_meta_budget_exceeded_is_logged_not_raised(conn):
    pages = seed_pages(conn, ["a-01-01", "b-01-01", "c-01-01"])
    client, session = make_meta_client(
        {p["path"]: (PUB_ISO, MOD_ISO) for p in pages}, budget=2
    )
    lines = []
    counts = run_meta(conn, client, pages, log=lines.append)
    assert session.paths == ["a-01-01", "b-01-01"]
    assert counts["fetched"] == 2
    assert any("budget" in line for line in lines)


def test_run_meta_empty_selection_makes_no_requests(conn):
    client, session = make_meta_client({})
    counts = run_meta(conn, client, [], log=lambda s: None)
    assert session.paths == []
    assert counts == {"fetched": 0, "changed": 0, "not_found": 0, "failed": 0}


def test_run_meta_logs_html_requests_with_the_prefix(conn):
    from graphwatch.db import http_logger

    pages = seed_pages(conn, ["Hello-10-19-130"])
    client, _ = make_meta_client(
        {"Hello-10-19-130": (PUB_ISO, MOD_ISO)}, log=http_logger(conn)
    )
    run_meta(conn, client, pages, log=lambda s: None)
    rows = conn.execute("SELECT path FROM http_log").fetchall()
    assert [r["path"] for r in rows] == ["html:Hello-10-19-130"]


# parse_args and main for meta


def test_parse_args_meta_defaults():
    args = parse_args(["meta", "--stale", "24"])
    assert args.command == "meta"
    assert args.stale == 24.0
    assert args.limit == 5000
    assert args.budget == 230000
    assert args.rate == 8.0
    assert args.db == Path("data/graphwatch.sqlite")


def test_parse_args_meta_overrides():
    args = parse_args(
        ["meta", "--stale", "0", "--limit", "500", "--budget", "27", "--rate", "2"]
    )
    assert (args.stale, args.limit, args.budget, args.rate) == (0.0, 500, 27, 2.0)


def test_parse_args_meta_requires_stale():
    with pytest.raises(SystemExit):
        parse_args(["meta"])


def test_parse_args_meta_has_no_wordlists_option():
    with pytest.raises(SystemExit):
        parse_args(["meta", "--stale", "24", "--wordlists", "w"])


def test_main_meta_does_not_need_the_config_or_wordlists(workdir, capsys):
    # No redaction happens on the HTML path, so no key; and no titles are
    # swept, so no wordlists. A budget of 0 keeps it off the network.
    main(
        [
            "--config",
            str(workdir / "nope.env"),
            "meta",
            "--db",
            str(workdir / "g.sqlite"),
            "--budget",
            "0",
            "--stale",
            "0",
        ]
    )
    out = capsys.readouterr().out.lower()
    assert "0 fetched" in out or "fetched 0" in out


def test_main_meta_stale_selects_from_the_database(workdir, capsys):
    c = connect(workdir / "g.sqlite")
    upsert_page(c, "Hello-10-19-130", 0.0)
    upsert_page(c, "Hello-10-19-143", 0.0)
    c.close()
    main(["meta", "--db", str(workdir / "g.sqlite"), "--budget", "0", "--stale", "24"])
    out = capsys.readouterr().out
    assert "budget exceeded" in out
    assert "2 selected" in out or "selected 2" in out


def test_main_meta_limit_caps_the_selection(workdir, capsys):
    c = connect(workdir / "g.sqlite")
    for i in range(3):
        upsert_page(c, f"p{i}-01-01", 0.0)
    c.close()
    main(
        [
            "meta",
            "--db",
            str(workdir / "g.sqlite"),
            "--budget",
            "0",
            "--stale",
            "24",
            "--limit",
            "2",
        ]
    )
    out = capsys.readouterr().out
    assert "2 selected" in out or "selected 2" in out


# --------------------------------------------------------------------------
# classify (issue #29): run_classify, run_explain, the command
# --------------------------------------------------------------------------

T0 = 1_700_000_000.0
KEY = b"test-key"
API_SAMPLE = "Hello,+world!"
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"
SQUATTER_BODY = (
    "https://t.me/+YztOEovieQIzZjY8 exploits, malware, RATs, steallers and other "
    "stuff https://t.me/+YztOEovieQIzZjY8 https://t.me/+YztOEovieQIzZjY8"
)


def put(conn, path, title, description="", body="", held_out=False, ts=T0):
    """Store one synthetic page; returns its page id."""
    page_id = upsert_page(conn, path, ts, held_out=held_out)
    page = {"title": title, "description": description, "content": [body]}
    add_snapshot(conn, page_id, page, ts, KEY)
    return page_id


def put_fixture(conn, path, name, held_out=False):
    page_id = upsert_page(conn, path, T0, held_out=held_out)
    page = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    add_snapshot(conn, page_id, page["result"], T0, KEY)
    return page_id


def quiet(_line):
    pass


def score_of(conn, path):
    sql = """
    SELECT sc.score, sc.flagged FROM scores sc JOIN pages p ON p.id = sc.page_id
    WHERE p.path = ? ORDER BY sc.snapshot_id DESC LIMIT 1
    """
    return tuple(conn.execute(sql, (path,)).fetchone())


RESOLVER_RULES = {r.name for r in RULES if r.category == "resolver"}
COMPUTED_RULES = {r.name for r in RULES if r.where == "computed"}


def all_hit_names(conn, path):
    sql = """
    SELECT h.rule FROM hits h JOIN scores sc ON sc.snapshot_id = h.snapshot_id
    JOIN pages p ON p.id = sc.page_id WHERE p.path = ? ORDER BY h.id
    """
    return [r["rule"] for r in conn.execute(sql, (path,))]


def hit_names(conn, path):
    """The resolver rules stored for a page; the category rules are tested below."""
    return [name for name in all_hit_names(conn, path) if name in RESOLVER_RULES]


@pytest.fixture
def swept(conn):
    """A small sweep: both actor shapes, benign pages, one squatter body."""
    put_fixture(conn, "Hello-10-17-154", "Hello-10-17-154")
    put(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    put_fixture(conn, "Hello-10-17-5", "Hello-10-17-5")
    put_fixture(conn, "Test-10-16", "Test-10-16")
    put(conn, "Hello-10-17-7", "Hello", API_SAMPLE, API_SAMPLE)
    for title in ("Cobalt-Strike", "Mimikatz", "Stealer"):
        put(conn, f"{title}-10-17", title, "", SQUATTER_BODY)
    return conn


def test_run_classify_scores_every_page_once(swept):
    counts = run_classify(swept, log=quiet)
    assert counts["pages"] == 8
    assert swept.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 8


def test_run_classify_flags_both_actor_shapes(swept):
    run_classify(swept, log=quiet)
    assert score_of(swept, "Hello-10-17-154")[1] == 1
    assert score_of(swept, "Hello-10-17-9") == (6, 1)


def test_run_classify_does_not_flag_the_benign_pages(swept):
    counts = run_classify(swept, log=quiet)
    for path in ("Hello-10-17-5", "Test-10-16", "Hello-10-17-7"):
        assert score_of(swept, path)[1] == 0, path
    assert counts["flagged"] == 2


def test_run_classify_counts_an_api_test_page_as_a_near_miss(swept):
    counts = run_classify(swept, log=quiet)
    assert score_of(swept, "Hello-10-17-7") == (1, 0)
    assert counts["near_miss"] >= 1


def test_run_classify_penalises_one_body_under_three_titles(swept):
    run_classify(swept, log=quiet)
    for title in ("Cobalt-Strike", "Mimikatz", "Stealer"):
        assert hit_names(swept, f"{title}-10-17") == ["telegram_link", "templated_body"]
        assert score_of(swept, f"{title}-10-17") == (-3, 0)


def test_run_classify_does_not_penalise_a_body_under_two_titles(conn):
    put(conn, "Alpha-10-17", "Alpha", "", SQUATTER_BODY)
    put(conn, "Beta-10-17", "Beta", "", SQUATTER_BODY)
    run_classify(conn, log=quiet)
    assert hit_names(conn, "Alpha-10-17") == ["telegram_link"]


def test_run_classify_does_not_penalise_the_actor_for_the_shared_sample_body(conn):
    # "Hello,+world!" sits under many titles; it is too short to be a template.
    put(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    for title in ("Hello", "title", "Test"):
        put(conn, f"{title}-10-17", title, API_SAMPLE, API_SAMPLE)
    run_classify(conn, log=quiet)
    assert "templated_body" not in hit_names(conn, "Hello-10-17-9")
    assert score_of(conn, "Hello-10-17-9") == (6, 1)


def test_run_classify_stores_the_body_hash_for_long_bodies_only(swept):
    run_classify(swept, log=quiet)
    sql = """
    SELECT sc.body_sha256 FROM scores sc JOIN pages p ON p.id = sc.page_id
    WHERE p.path = ?
    """
    squatter = swept.execute(sql, ("Mimikatz-10-17",)).fetchone()[0]
    assert squatter == hashlib.sha256(SQUATTER_BODY.encode("utf-8")).hexdigest()
    assert swept.execute(sql, ("Hello-10-17-7",)).fetchone()[0] is None


def test_run_classify_stores_evidence_with_each_hit(swept):
    run_classify(swept, log=quiet)
    sql = """
    SELECT h.rule, h.weight, h.evidence, h.matches FROM hits h
    JOIN scores sc ON sc.snapshot_id = h.snapshot_id
    JOIN pages p ON p.id = sc.page_id WHERE p.path = ? ORDER BY h.id
    """
    rows = [tuple(r) for r in swept.execute(sql, ("Hello-10-17-9",))]
    assert [row for row in rows if row[0] in RESOLVER_RULES] == [
        ("userinfo_spoof", 5, "www.tenable.com@agfc.harper18.workers.dev", 1),
        ("api_sample_body", 1, API_SAMPLE, 1),
    ]


def test_run_classify_stores_how_often_each_rule_matched(swept):
    # The squatter body carries the same t.me link three times.
    run_classify(swept, log=quiet)
    sql = """
    SELECT h.rule, h.matches FROM hits h
    JOIN scores sc ON sc.snapshot_id = h.snapshot_id
    JOIN pages p ON p.id = sc.page_id WHERE p.path = ? ORDER BY h.id
    """
    rows = [tuple(r) for r in swept.execute(sql, ("Mimikatz-10-17",))]
    assert [row for row in rows if row[0] in RESOLVER_RULES] == [
        ("telegram_link", 3),
        ("templated_body", 1),
    ]
    assert score_of(swept, "Mimikatz-10-17") == (-3, 0)  # counted, not scored


def test_run_classify_stores_a_hit_for_every_rule_that_fired(swept):
    # Positive or negative, weak or decisive, flagged page or not: every rule
    # that fired on a page has its row in hits.
    run_classify(swept, log=quiet)
    checked = 0
    for row in latest_snapshots(swept).fetchall():
        fired = apply_rules(row["title"], row["description"], row["text"])
        stored = [n for n in all_hit_names(swept, row["path"]) if n not in COMPUTED_RULES]
        assert stored == [hit.rule.name for hit in fired], row["path"]
        checked += len(fired)
    assert checked >= 10
    negative = swept.execute("SELECT COUNT(*) FROM hits WHERE weight < 0").fetchone()[0]
    assert negative >= 6  # three squatter pages, two penalties each


def test_run_classify_scores_are_the_sum_of_their_stored_hits(swept):
    run_classify(swept, log=quiet)
    # The score is the resolver score, so only the resolver rules' hits add up to it.
    marks = ", ".join("?" for _ in RESOLVER_RULES)
    sql = f"""
    SELECT sc.score, COALESCE(SUM(h.weight), 0) AS total
    FROM scores sc LEFT JOIN hits h
        ON h.snapshot_id = sc.snapshot_id AND h.rule IN ({marks})
    GROUP BY sc.snapshot_id
    """
    rows = swept.execute(sql, tuple(RESOLVER_RULES)).fetchall()
    assert len(rows) == 8
    assert all(row["score"] == row["total"] for row in rows)


def test_run_classify_twice_replaces_rather_than_adds(swept):
    run_classify(swept, log=quiet)
    hits = swept.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
    run_classify(swept, log=quiet)
    assert swept.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 8
    assert swept.execute("SELECT COUNT(*) FROM hits").fetchone()[0] == hits


def test_run_classify_threshold_is_an_argument(swept):
    counts = run_classify(swept, threshold=1, log=quiet)
    assert score_of(swept, "Hello-10-17-7") == (1, 1)
    assert counts["flagged"] == 3
    assert counts["near_miss"] == 0


def test_run_classify_scores_the_newest_snapshot_of_an_edited_page(conn):
    page_id = put(conn, "Hello-10-17-9", "Hello", "", "nothing here")
    page = {"title": SPOOF_TITLE, "description": API_SAMPLE, "content": [API_SAMPLE]}
    add_snapshot(conn, page_id, page, T0 + 60, KEY)
    counts = run_classify(conn, log=quiet)
    assert counts["pages"] == 1
    assert score_of(conn, "Hello-10-17-9") == (6, 1)


def test_run_classify_counts_held_out_pages_apart_from_the_sweep(swept):
    # Held-out rows here are synthetic: real held-out content is never a test input.
    put(swept, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    put(swept, "Known-01-03", "Hello", "", "nothing here", held_out=True)
    counts = run_classify(swept, log=quiet)
    assert (counts["held_out"], counts["held_out_flagged"]) == (2, 1)
    assert counts["pages"] == 8
    assert counts["flagged"] == 2
    assert sum(counts["scores"].values()) == 8


def test_run_classify_logs_recall_as_counts_and_never_names_a_held_out_page(swept):
    put(swept, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    put(swept, "Known-01-03", "Hello", "", "nothing here", held_out=True)
    lines = []
    run_classify(swept, log=lines.append)
    out = "\n".join(lines)
    assert "held-out: 1/2 flagged" in out
    assert "Known-01" not in out
    assert "tenable" not in out


def test_run_classify_logs_the_sweep_totals(swept):
    lines = []
    run_classify(swept, log=lines.append)
    assert "classified 8 pages" in lines[0]
    assert "2 flagged" in lines[0]


def test_run_classify_scores_distribution_covers_the_sweep(swept):
    counts = run_classify(swept, log=quiet)
    assert counts["scores"][-3] == 3
    assert counts["scores"][6] == 1


def test_run_classify_on_an_empty_database(conn):
    counts = run_classify(conn, log=quiet)
    assert counts["pages"] == 0
    assert counts["held_out"] == 0


def test_run_classify_commits_everything_across_batches(tmp_path, monkeypatch):
    monkeypatch.setattr("graphwatch.cli.CLASSIFY_BATCH", 2)
    writer = connect(tmp_path / "g.sqlite")
    for i in range(5):
        put(writer, f"Hello-10-17-{i + 1}", "Hello", "", f"note {i}")
    run_classify(writer, log=quiet)
    reader = connect(tmp_path / "g.sqlite")  # a second connection sees commits only
    assert reader.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 5
    reader.close()
    writer.close()


def test_run_classify_writes_nothing_to_the_http_log(swept):
    run_classify(swept, log=quiet)
    assert swept.execute("SELECT COUNT(*) FROM http_log").fetchone()[0] == 0


def test_run_explain_prints_the_score_and_one_line_per_hit(swept):
    run_classify(swept, log=quiet)
    lines = []
    assert run_explain(swept, "Hello-10-17-9", log=lines.append) is True
    assert lines[0] == "Hello-10-17-9: score 6, flagged"
    assert SPOOF_TITLE in lines[1]
    spoof = next(line for line in lines if "+5 userinfo_spoof" in line)
    assert "www.tenable.com@agfc.harper18.workers.dev" in spoof
    assert any("+1 api_sample_body" in line for line in lines)


def test_run_explain_shows_negative_weights_signed(swept):
    run_classify(swept, log=quiet)
    lines = []
    run_explain(swept, "Mimikatz-10-17", log=lines.append)
    assert lines[0] == "Mimikatz-10-17: score -3, not flagged"
    assert any("-2 templated_body" in line for line in lines)


def test_run_explain_shows_how_often_a_rule_matched(swept):
    run_classify(swept, log=quiet)
    lines = []
    run_explain(swept, "Mimikatz-10-17", log=lines.append)
    assert any(line.endswith("t.me/ x3") for line in lines)
    assert not any(line.endswith("x1") for line in lines)


def test_run_explain_withholds_evidence_for_a_held_out_page(swept):
    put(swept, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    run_classify(swept, log=quiet)
    lines = []
    assert run_explain(swept, "Known-01-02", log=lines.append) is True
    out = "\n".join(lines)
    assert "Known-01-02: score 6, flagged" in out
    assert "withheld" in out
    assert "tenable" not in out
    assert "userinfo_spoof" not in out


def test_run_explain_says_so_when_there_is_no_score(swept):
    lines = []
    assert run_explain(swept, "Hello-10-17-9", log=lines.append) is False
    assert "run classify first" in lines[0]
    assert run_explain(swept, "Nope-01-01", log=lines.append) is False


def test_parse_args_classify_defaults():
    args = parse_args(["classify"])
    assert args.command == "classify"
    assert args.threshold == 4
    assert args.explain is None
    assert args.db == Path("data/graphwatch.sqlite")


def test_parse_args_classify_options():
    args = parse_args(["classify", "--threshold", "6", "--explain", "Hello-10-17-9"])
    assert args.threshold == 6
    assert args.explain == "Hello-10-17-9"


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("classify must not build a client")

    monkeypatch.setattr("graphwatch.cli.TelegraphClient", refuse)


def test_main_classify_needs_no_client_config_or_wordlists(tmp_path, capsys, no_network):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    put(c, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    put(c, "Hello-10-17-7", "Hello", API_SAMPLE, API_SAMPLE)
    c.close()
    main(["--config", str(tmp_path / "missing.env"), "classify", "--db", str(db)])
    out = capsys.readouterr().out
    assert "classified 2 pages" in out
    assert "1 flagged" in out
    assert "held-out: 0/0 flagged" in out
    assert "score +6: 1" in out
    assert "score +1: 1" in out


def test_main_classify_threshold_option(tmp_path, capsys, no_network):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    put(c, "Hello-10-17-7", "Hello", API_SAMPLE, API_SAMPLE)
    c.close()
    main(["classify", "--db", str(db), "--threshold", "1"])
    assert "1 flagged" in capsys.readouterr().out


def test_main_classify_explain_reads_the_stored_result(tmp_path, capsys, no_network):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    put(c, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    c.close()
    main(["classify", "--db", str(db)])
    capsys.readouterr()
    main(["classify", "--db", str(db), "--explain", "Hello-10-17-9"])
    out = capsys.readouterr().out
    assert "Hello-10-17-9: score 6, flagged" in out
    assert "+5 userinfo_spoof" in out
    assert "classified" not in out  # explain does not rescore


def test_run_explain_lists_the_indicators_of_a_flagged_page(swept):
    run_classify(swept, log=quiet)
    lines = []
    run_explain(swept, "Hello-10-17-9", log=lines.append)
    assert "  decoy www.tenable.com (title)" in lines
    assert "  host  agfc.harper18.workers.dev (title)" in lines


def test_run_explain_lists_no_indicators_for_an_unflagged_page(swept):
    run_classify(swept, log=quiet)
    lines = []
    run_explain(swept, "Mimikatz-10-17", log=lines.append)
    assert not any(line.startswith("  host") for line in lines)


def test_run_explain_lists_no_indicators_for_a_held_out_page(swept):
    put(swept, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    run_classify(swept, log=quiet)
    lines = []
    run_explain(swept, "Known-01-02", log=lines.append)
    assert not any("workers.dev" in line for line in lines)


# --------------------------------------------------------------------------
# classify by category: labels, the per-category summary, --explain
# (plan/classification-plan-2026-11-15.md)
# --------------------------------------------------------------------------

HASHED = "SECRET{" + "ab" * 32 + "}"
COMBO_BODY = "\n".join(f"user{n}@mail.example.com:hunter{n}pass" for n in range(4))
PROXY_BODY = "fresh today:\n8.8.8.8:1080\n1.1.1.1:3128\n9.9.9.9:8080"
PLAIN_BODY = "We met on Tuesday and agreed to meet again next week."


def labels_of(conn, path):
    """(category, score, assigned, is_primary) rows for a page's newest snapshot."""
    sql = """
    SELECT l.category, l.score, l.assigned, l.is_primary FROM labels l
    JOIN pages p ON p.id = l.page_id WHERE p.path = ? ORDER BY l.rowid
    """
    return [tuple(r) for r in conn.execute(sql, (path,))]


def assigned_labels(conn, path):
    return [row[0] for row in labels_of(conn, path) if row[2]]


def primary_of(conn, path):
    primaries = [row[0] for row in labels_of(conn, path) if row[3]]
    assert len(primaries) <= 1
    return primaries[0] if primaries else None


@pytest.fixture
def mixed(swept):
    """The small sweep plus one page for each of three more categories and a plain one."""
    put(swept, "Accounts-10-17", "Accounts", "", COMBO_BODY)
    put(swept, "Proxy-10-17", "Proxy", "", PROXY_BODY)
    put(swept, "Notes-10-17", "Notes", "", PLAIN_BODY)
    return swept


def test_the_combo_body_is_stored_hashed_before_the_rules_see_it(mixed):
    text = mixed.execute(
        "SELECT s.text FROM snapshots s JOIN pages p ON p.id = s.page_id WHERE p.path = ?",
        ("Accounts-10-17",),
    ).fetchone()[0]
    assert "hunter0pass" not in text
    assert text.count("SECRET{") == 4


def test_run_classify_labels_each_page_with_its_categories(mixed):
    run_classify(mixed, log=quiet)
    assert assigned_labels(mixed, "Accounts-10-17") == ["leaked_credentials"]
    assert assigned_labels(mixed, "Proxy-10-17") == ["proxy_list"]
    assert assigned_labels(mixed, "Mimikatz-10-17") == ["template_spam"]
    assert assigned_labels(mixed, "Notes-10-17") == []


def test_run_classify_marks_one_primary_label_per_labelled_page(mixed):
    run_classify(mixed, log=quiet)
    # The spoof page is a resolver, a pointer (its tunnel host) and a placeholder.
    assert assigned_labels(mixed, "Hello-10-17-9") == ["resolver", "pointer", "placeholder"]
    assert primary_of(mixed, "Hello-10-17-9") == "resolver"
    assert primary_of(mixed, "Accounts-10-17") == "leaked_credentials"
    assert primary_of(mixed, "Notes-10-17") is None
    two_primaries = mixed.execute(
        "SELECT COUNT(*) FROM (SELECT snapshot_id FROM labels GROUP BY snapshot_id "
        "HAVING SUM(is_primary) > 1)"
    ).fetchone()[0]
    assert two_primaries == 0


def test_the_primary_label_is_always_an_assigned_one(mixed):
    run_classify(mixed, log=quiet)
    bad = mixed.execute(
        "SELECT COUNT(*) FROM labels WHERE is_primary = 1 AND assigned = 0"
    ).fetchone()[0]
    assert bad == 0


def test_run_classify_stores_near_misses_and_no_zero_scores(mixed):
    run_classify(mixed, log=quiet)
    # The squatter advert: an invite link is +2 towards telegram_funnel.
    rows = {row[0]: row for row in labels_of(mixed, "Mimikatz-10-17")}
    assert rows["telegram_funnel"][1:] == (2, 0, 0)
    assert rows["resolver"][1:] == (-3, 0, 0)
    assert mixed.execute("SELECT COUNT(*) FROM labels WHERE score = 0").fetchone()[0] == 0
    assert labels_of(mixed, "Notes-10-17") == []


def test_the_resolver_label_row_agrees_with_the_scores_table(mixed):
    run_classify(mixed, log=quiet)
    sql = """
    SELECT sc.score, sc.flagged, l.score AS label_score, l.assigned
    FROM scores sc JOIN labels l ON l.snapshot_id = sc.snapshot_id
    WHERE l.category = 'resolver'
    """
    rows = mixed.execute(sql).fetchall()
    assert len(rows) >= 5
    for row in rows:
        assert row["score"] == row["label_score"]
        assert row["flagged"] == row["assigned"]


def test_the_categories_do_not_move_the_resolver_verdict(mixed):
    counts = run_classify(mixed, log=quiet)
    assert counts["flagged"] == 2
    assert score_of(mixed, "Hello-10-17-9") == (6, 1)
    # A combo list scores on its email address and nothing else, as before.
    assert score_of(mixed, "Accounts-10-17") == (1, 0)
    assert score_of(mixed, "Mimikatz-10-17") == (-3, 0)


def test_run_classify_twice_replaces_the_labels(mixed):
    run_classify(mixed, log=quiet)
    before = mixed.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
    run_classify(mixed, log=quiet)
    assert mixed.execute("SELECT COUNT(*) FROM labels").fetchone()[0] == before


def test_the_threshold_argument_applies_to_every_category(mixed):
    run_classify(mixed, threshold=2, log=quiet)
    assert "telegram_funnel" in assigned_labels(mixed, "Mimikatz-10-17")
    run_classify(mixed, threshold=5, log=quiet)
    assert assigned_labels(mixed, "Mimikatz-10-17") == []


def test_run_classify_counts_labels_per_category(mixed):
    counts = run_classify(mixed, log=quiet)
    assert counts["labelled"]["resolver"] == 2
    assert counts["labelled"]["template_spam"] == 3
    assert counts["labelled"]["leaked_credentials"] == 1
    assert counts["labelled"]["proxy_list"] == 1
    assert counts["primary"]["template_spam"] == 3
    assert counts["category_near_miss"]["telegram_funnel"] == 3


def test_every_page_is_counted_once_as_a_primary_label_or_as_unlabelled(mixed):
    counts = run_classify(mixed, log=quiet)
    assert sum(counts["primary"].values()) + counts["unlabelled"] == counts["pages"]
    assert counts["unlabelled"] >= 1  # Notes-10-17 at least


def test_a_labelled_page_is_not_also_a_near_miss_of_that_category(mixed):
    counts = run_classify(mixed, log=quiet)
    assert counts["category_near_miss"]["template_spam"] == 0
    assert counts["category_near_miss"]["leaked_credentials"] == 0


def test_run_classify_logs_one_line_per_category_after_the_summary(mixed):
    lines = []
    run_classify(mixed, log=lines.append)
    assert "classified 11 pages" in lines[0]
    assert lines[1].startswith("held-out:")
    category_lines = lines[2:16]
    assert [line.split()[0] for line in category_lines] == [
        "resolver",
        "template_spam",
        "pointer",
        "leaked_credentials",
        "proxy_list",
        "malware_delivery",
        "fraud_market",
        "crypto_lure",
        "phishing",
        "doxx",
        "telegram_funnel",
        "seo_spam",
        "placeholder",
        "prose",
    ]
    for line in category_lines:
        assert "labelled" in line and "primary" in line and "near misses" in line


def test_the_category_lines_carry_the_counts(mixed):
    lines = []
    counts = run_classify(mixed, log=lines.append)
    line = next(l for l in lines if l.split()[0] == "template_spam")
    assert line.split() == [
        "template_spam", "labelled", "3,", "primary", "3,", "near", "misses", "0",
    ]
    line = next(l for l in lines if l.split()[0] == "telegram_funnel")
    assert line.split()[-1] == str(counts["category_near_miss"]["telegram_funnel"])


def test_run_classify_reports_the_unlabelled_share(mixed):
    lines = []
    counts = run_classify(mixed, log=lines.append)
    last = lines[-1]
    assert last.split()[0] == "unlabelled"
    assert f"{counts['unlabelled']:,}" in last
    assert f"({counts['unlabelled'] / counts['pages']:.1%} of pages)" in last


def test_the_unlabelled_share_of_an_empty_database_is_zero(conn):
    lines = []
    run_classify(conn, log=lines.append)
    assert "(0.0% of pages)" in lines[-1]


def test_held_out_pages_are_left_out_of_every_category_count(mixed):
    before = run_classify(mixed, log=quiet)
    put(mixed, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    put(mixed, "Known-01-03", "Accounts", "", COMBO_BODY, held_out=True)
    lines = []
    after = run_classify(mixed, log=lines.append)
    for name in ("labelled", "primary", "category_near_miss"):
        assert after[name] == before[name], name
    assert after["unlabelled"] == before["unlabelled"]
    assert after["held_out"] == 2
    out = "\n".join(lines)
    assert "held-out: 1/2 flagged" in out
    assert "Known-01" not in out


def test_run_classify_with_categories_still_writes_nothing_to_the_http_log(mixed):
    run_classify(mixed, log=quiet)
    assert mixed.execute("SELECT COUNT(*) FROM http_log").fetchone()[0] == 0


# --- --explain ---


def explain(conn, path) -> list[str]:
    lines = []
    assert run_explain(conn, path, log=lines.append) is True
    return lines


def test_run_explain_prints_the_labels_with_the_primary_marked(mixed):
    run_classify(mixed, log=quiet)
    lines = explain(mixed, "Hello-10-17-9")
    assert lines[2] == "  labels: resolver (primary), pointer, placeholder"


def test_run_explain_says_none_for_a_page_with_no_label(mixed):
    run_classify(mixed, log=quiet)
    lines = explain(mixed, "Notes-10-17")
    assert lines[0] == "Notes-10-17: score 0, not flagged"
    assert lines[2] == "  labels: none"
    assert len(lines) == 3


def test_run_explain_groups_the_hits_by_category_in_category_order(mixed):
    run_classify(mixed, log=quiet)
    lines = explain(mixed, "Hello-10-17-9")
    headings = [line for line in lines if line.startswith("  ") and not line.startswith("   ")]
    assert headings[2:5] == ["  resolver +6", "  pointer +4", "  placeholder +4"]
    resolver_at = lines.index("  resolver +6")
    pointer_at = lines.index("  pointer +4")
    spoof_at = next(i for i, line in enumerate(lines) if "+5 userinfo_spoof" in line)
    tunnel_at = next(i for i, line in enumerate(lines) if "+3 tunnel_host" in line)
    assert resolver_at < spoof_at < pointer_at < tunnel_at


def test_run_explain_shows_a_near_miss_category_with_its_score(mixed):
    run_classify(mixed, log=quiet)
    lines = explain(mixed, "Mimikatz-10-17")
    assert "  resolver -3" in lines
    assert "  template_spam +4" in lines
    assert "  telegram_funnel +2" in lines
    assert lines[2] == "  labels: template_spam (primary)"


def test_run_explain_shows_the_evidence_of_a_category_hit(mixed):
    run_classify(mixed, log=quiet)
    lines = explain(mixed, "Proxy-10-17")
    line = next(l for l in lines if "ip_port_list" in l)
    assert line.strip().startswith("+4 ip_port_list")
    assert line.endswith("8.8.8.8:1080 x3")


def test_run_explain_never_prints_a_clear_password(mixed):
    run_classify(mixed, log=quiet)
    out = "\n".join(explain(mixed, "Accounts-10-17"))
    assert "combo_lines" in out
    assert "hunter" not in out


def test_run_explain_lists_a_hit_of_a_rule_no_longer_in_the_table_as_retired(mixed):
    run_classify(mixed, log=quiet)
    snapshot_id = mixed.execute(
        "SELECT sc.snapshot_id FROM scores sc JOIN pages p ON p.id = sc.page_id WHERE p.path = ?",
        ("Notes-10-17",),
    ).fetchone()[0]
    mixed.execute(
        "INSERT INTO hits (snapshot_id, rule, weight, evidence, matches) VALUES (?, ?, ?, ?, ?)",
        (snapshot_id, "old_rule", 2, "something", 1),
    )
    lines = explain(mixed, "Notes-10-17")
    assert lines[-2] == "  retired rule"
    assert lines[-1].strip() == "+2 old_rule               something"


def test_run_explain_shows_only_the_resolver_score_of_a_held_out_page(mixed):
    # Synthetic held-out rows: one resolver shape and one combo list.
    put(mixed, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    put(mixed, "Known-01-03", "Accounts", "", COMBO_BODY, held_out=True)
    run_classify(mixed, log=quiet)
    for path, first in (
        ("Known-01-02", "Known-01-02: score 6, flagged"),
        ("Known-01-03", "Known-01-03: score 1, not flagged"),
    ):
        lines = explain(mixed, path)
        assert lines == [first, "held-out page: evidence withheld"]


def test_run_explain_names_no_label_or_category_for_a_held_out_page(mixed):
    put(mixed, "Known-01-03", "Accounts", "", COMBO_BODY, held_out=True)
    run_classify(mixed, log=quiet)
    out = "\n".join(explain(mixed, "Known-01-03"))
    for word in ("labels", "leaked_credentials", "combo_lines", "example.com"):
        assert word not in out


def test_main_classify_prints_the_category_lines(tmp_path, capsys, no_network):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    put(c, "Proxy-10-17", "Proxy", "", PROXY_BODY)
    put(c, "Notes-10-17", "Notes", "", PLAIN_BODY)
    c.close()
    main(["--config", str(tmp_path / "missing.env"), "classify", "--db", str(db)])
    out = capsys.readouterr().out
    assert "classified 2 pages" in out
    proxy = next(line for line in out.splitlines() if line.split()[:1] == ["proxy_list"])
    assert proxy.split()[2] == "1,"
    assert "unlabelled" in out
    assert "(50.0% of pages)" in out


def test_main_classify_explain_prints_the_labels(tmp_path, capsys, no_network):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    put(c, "Proxy-10-17", "Proxy", "", PROXY_BODY)
    c.close()
    main(["classify", "--db", str(db)])
    capsys.readouterr()
    main(["classify", "--db", str(db), "--explain", "Proxy-10-17"])
    out = capsys.readouterr().out
    assert "labels: proxy_list (primary)" in out
    assert "proxy_list +5" in out


# --- the command ---


def resweep_argv(workdir, *extra):
    return [
        "--config",
        str(workdir / "config.env"),
        "sweep",
        "--db",
        str(workdir / "g.sqlite"),
        "--wordlists",
        str(workdir / "no-such-directory"),
        "--budget",
        "0",
        "--resweep",
        *extra,
    ]


# --- the command ---


@pytest.fixture
def no_feed_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("this command must not build a feed client")

    monkeypatch.setattr("graphwatch.cli.FeedClient", refuse)


def enrich_argv(workdir, *extra):
    return ["--config", str(workdir / "config.env"), "enrich", "--db", str(workdir / "g.sqlite"), *extra]


# --- a flag from an old rule table does not outlive the rule ---


def test_run_classify_rescores_the_older_snapshots_of_a_flagged_page(conn):
    page_id = put(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    add_snapshot(conn, page_id, {"title": "plain", "description": "", "content": ["nothing here at all, really"]}, T0 + 60, KEY)
    old_snapshot = conn.execute("SELECT MIN(id) FROM snapshots").fetchone()[0]
    # The old snapshot's score as some earlier rule table left it: wrong, and flagged.
    save_score(conn, old_snapshot, page_id, 99, True, None, [("old_rule", 99, "x", 1)], T0)
    conn.commit()
    counts = run_classify(conn, log=quiet)
    row = conn.execute("SELECT score, flagged FROM scores WHERE snapshot_id = ?", (old_snapshot,)).fetchone()
    assert tuple(row) == (6, 1)  # the spoof, scored by today's table
    assert counts["rescored"] == 1
    assert counts["pages"] == 1  # still one page, counted by its newest snapshot
    assert counts["flagged"] == 0


def test_pages_never_flagged_are_not_rescored(swept):
    put(swept, "Notes-10-17", "Notes", "", "first version of some notes")
    page_id = swept.execute("SELECT id FROM pages WHERE path = 'Notes-10-17'").fetchone()[0]
    add_snapshot(swept, page_id, {"title": "Notes", "description": "", "content": ["second version of the notes"]}, T0 + 60, KEY)
    counts = run_classify(swept, log=quiet)
    assert counts["rescored"] == 0


# --- the rules read link targets (decided 22 November) ---


def put_linked(conn, path, title, text, href):
    page_id = upsert_page(conn, path, T0)
    page = {"title": title, "description": text[:100], "content": [{"tag": "p", "children": [text, {"tag": "a", "attrs": {"href": href}, "children": ["Download here"]}]}]}
    add_snapshot(conn, page_id, page, T0, KEY)
    return page_id


def test_run_classify_sees_the_address_behind_a_link(conn):
    put_linked(conn, "Game-10-17", "Game", "Free game, full version. ", "https://files.example.com/setup.exe")
    run_classify(conn, log=quiet)
    assert "executable_link" in all_hit_names(conn, "Game-10-17")
    assert assigned_labels(conn, "Game-10-17") == ["malware_delivery"]


def test_run_classify_does_not_file_a_lure_with_a_hidden_link_as_prose(conn):
    put_linked(conn, "Story-10-17", "Story", "word " * 700, "https://files.example.com/book.zip")
    put(conn, "Essay-10-17", "Essay", "", "word " * 700)
    run_classify(conn, log=quiet)
    assert "prose" not in assigned_labels(conn, "Story-10-17")
    assert assigned_labels(conn, "Essay-10-17") == ["prose"]


def test_a_hidden_link_does_not_move_the_resolver_score(conn):
    put_linked(conn, "Notes-10-17", "Notes", "see the docs. ", "https://www.tenable.com@agfc.harper18.workers.dev/")
    run_classify(conn, log=quiet)
    assert score_of(conn, "Notes-10-17") == (0, 0)


def test_the_evidence_of_a_hit_on_a_link_target_is_redacted(conn):
    put_linked(conn, "Katya-10-17", "Katya", "write to me. ", "https://m.dating.example.com/autologin/?key=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d")
    run_classify(conn, log=quiet)
    evidence = [r[0] for r in conn.execute("SELECT evidence FROM hits WHERE rule = 'autologin_link'")]
    assert len(evidence) == 1
    assert "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d" not in evidence[0]
    assert "SECRET{" in evidence[0]


# --- what the third review of 22 November found ---


def nested(depth: int) -> dict:
    node = "deep"
    for _ in range(depth):
        node = {"tag": "b", "children": [node]}
    return node


def test_redact_page_really_does_overflow_on_a_very_deep_page():
    # The premise of the test above and the one below.
    from graphwatch.redact import redact_page

    with pytest.raises(RecursionError):
        redact_page({"content": [nested(3000)]}, KEY)
