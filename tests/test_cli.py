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
    run_enrich,
    run_explain,
    run_meta,
    run_resweep,
    run_sweep,
)
from graphwatch.config import CONFIG
from graphwatch.crowd import DayCount, save_day_count
from graphwatch.enrich import novelty, novelty_rows
from graphwatch.db import (
    add_snapshot,
    connect,
    http_logger,
    latest_snapshots,
    load_progress,
    resweep_paths,
    save_lookup,
    save_score,
    upsert_indicator,
    upsert_page,
)
from graphwatch.feeds import FeedClient
from graphwatch.rules import RULES, apply_rules
from graphwatch.slugify import Entry
from graphwatch.telegraph import BudgetExceeded, Outcome, TelegraphClient

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


# --------------------------------------------------------------------------
# re-sweep (issue #37): run_resweep and sweep --resweep
# (plan/resweep-plan-2026-11-04.md)
# --------------------------------------------------------------------------

HOUR = 3600.0


class ResweepSession:
    """Serves the page stored under each path in `pages`; a test edits that
    dict to rotate or delete a page between two runs. `failing` paths get a
    500 with an unparseable body, which the client reports as FAILED."""

    def __init__(self, pages, failing=()):
        self.pages = pages
        self.failing = set(failing)
        self.paths = []

    def get(self, url, **kwargs):
        path = urllib.parse.unquote(url.split("/getPage/", 1)[1].split("?", 1)[0])
        self.paths.append(path)
        if path in self.failing:
            r = Resp(b"not json")
            r.status_code = 500
            return r
        if path not in self.pages:
            return Resp(MISSING_BODY)
        result = {"path": path, **self.pages[path]}
        return Resp(json.dumps({"ok": True, "result": result}).encode("utf-8"))


def live_page(title, body="Hello,+world!", views=1) -> dict:
    return {"title": title, "description": body, "views": views, "content": [body]}


def make_resweep_client(pages, failing=(), **kwargs):
    session = ResweepSession(pages, failing)
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=0, **kwargs)
    return client, session


# What Telegraph serves at the start of each test, and what was stored a day ago.
LIVE = {
    "Hello-10-17-1": live_page("8.8.8.8 first"),
    "Hello-10-17-2": live_page("second"),
    "Hello-10-17-3": live_page("third"),
}


@pytest.fixture
def stored(conn):
    """Three pages as a sweep stored them at T0, long before any cutoff used here."""
    for path, page in LIVE.items():
        page_id = upsert_page(conn, path, T0)
        add_snapshot(conn, page_id, {"path": path, **page}, T0, KEY)
    return conn


def everything(conn):
    """The whole work list: every stored page not marked gone."""
    return resweep_paths(conn, time.time() + HOUR)


def kinds(conn, path):
    sql = """
    SELECT e.kind FROM events e JOIN pages p ON p.id = e.page_id
    WHERE p.path = ? ORDER BY e.id
    """
    return [r["kind"] for r in conn.execute(sql, (path,))]


def snapshots_of(conn, path):
    sql = """
    SELECT s.title, s.views FROM snapshots s JOIN pages p ON p.id = s.page_id
    WHERE p.path = ? ORDER BY s.id
    """
    return [tuple(r) for r in conn.execute(sql, (path,))]


def last_seen(conn, path):
    return conn.execute("SELECT last_seen FROM pages WHERE path = ?", (path,)).fetchone()[0]


def views_of(conn, path):
    sql = """
    SELECT v.views FROM views v JOIN pages p ON p.id = v.page_id
    WHERE p.path = ? ORDER BY v.fetched_at
    """
    return [r["views"] for r in conn.execute(sql, (path,))]


def test_run_resweep_fetches_each_listed_page_once(stored):
    client, session = make_resweep_client(dict(LIVE))
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert sorted(session.paths) == sorted(LIVE)
    assert counts == {"refreshed": 3, "changed": 0, "gone": 0, "failed": 0}


def test_run_resweep_moves_last_seen_and_stores_no_snapshot_of_an_unchanged_page(stored):
    # Decided 22 November: a page polled every ten minutes would otherwise
    # add 144 identical rows a day.
    client, _ = make_resweep_client(dict(LIVE))
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert len(snapshots_of(stored, "Hello-10-17-2")) == 1
    assert last_seen(stored, "Hello-10-17-2") > T0


def test_run_resweep_an_unchanged_page_writes_no_event_and_logs_nothing(stored):
    client, _ = make_resweep_client(dict(LIVE))
    lines = []
    run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert lines == []
    for path in LIVE:
        assert kinds(stored, path) == ["discovered"]


def test_run_resweep_a_view_count_tick_is_not_a_change(stored):
    live = {**LIVE, "Hello-10-17-2": live_page("second", views=40)}
    client, _ = make_resweep_client(live)
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts["changed"] == 0
    assert snapshots_of(stored, "Hello-10-17-2") == [("second", 1)]
    assert views_of(stored, "Hello-10-17-2") == [40]


def test_run_resweep_reports_a_rotation_as_one_content_changed_event(stored):
    # The actor's shape: the same page, a new address in the title.
    live = {**LIVE, "Hello-10-17-1": live_page("9.9.9.9 first")}
    client, _ = make_resweep_client(live)
    lines = []
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert counts == {"refreshed": 3, "changed": 1, "gone": 0, "failed": 0}
    assert lines == ["Hello-10-17-1: content changed"]
    assert kinds(stored, "Hello-10-17-1") == ["discovered", "content_changed"]
    assert [title for title, _ in snapshots_of(stored, "Hello-10-17-1")] == [
        "8.8.8.8 first",
        "9.9.9.9 first",
    ]


def test_run_resweep_the_change_event_carries_the_fetch_time(stored):
    live = {**LIVE, "Hello-10-17-1": live_page("9.9.9.9 first")}
    client, _ = make_resweep_client(live)
    before = time.time()
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    ts = stored.execute("SELECT ts FROM events WHERE kind = 'content_changed'").fetchone()[0]
    assert before <= ts <= time.time()
    assert ts == last_seen(stored, "Hello-10-17-1")


def test_run_resweep_a_second_run_does_not_report_the_same_rotation_again(stored):
    live = {**LIVE, "Hello-10-17-1": live_page("9.9.9.9 first")}
    client, _ = make_resweep_client(live)
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts["changed"] == 0
    assert kinds(stored, "Hello-10-17-1").count("content_changed") == 1


def test_run_resweep_marks_a_deleted_page_gone(stored):
    live = {path: page for path, page in LIVE.items() if path != "Hello-10-17-2"}
    client, _ = make_resweep_client(live)
    lines = []
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert counts == {"refreshed": 2, "changed": 0, "gone": 1, "failed": 0}
    assert lines == ["Hello-10-17-2: gone"]
    assert kinds(stored, "Hello-10-17-2") == ["discovered", "gone"]


def test_run_resweep_a_gone_page_keeps_its_snapshot_and_last_seen(stored):
    live = {path: page for path, page in LIVE.items() if path != "Hello-10-17-2"}
    client, _ = make_resweep_client(live)
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert snapshots_of(stored, "Hello-10-17-2") == [("second", 1)]
    assert last_seen(stored, "Hello-10-17-2") == T0


def test_run_resweep_does_not_ask_for_a_gone_page_again(stored):
    live = {path: page for path, page in LIVE.items() if path != "Hello-10-17-2"}
    client, session = make_resweep_client(live)
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    session.paths.clear()
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert "Hello-10-17-2" not in session.paths
    assert kinds(stored, "Hello-10-17-2").count("gone") == 1


def test_run_resweep_a_failed_fetch_changes_nothing(stored):
    client, _ = make_resweep_client(dict(LIVE), failing={"Hello-10-17-2"})
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts == {"refreshed": 2, "changed": 0, "gone": 0, "failed": 1}
    assert last_seen(stored, "Hello-10-17-2") == T0
    assert kinds(stored, "Hello-10-17-2") == ["discovered"]
    assert len(snapshots_of(stored, "Hello-10-17-2")) == 1


def test_run_resweep_a_failed_page_is_first_in_line_next_time(stored):
    client, _ = make_resweep_client(dict(LIVE), failing={"Hello-10-17-2"})
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert everything(stored)[0]["path"] == "Hello-10-17-2"


def test_run_resweep_a_failure_is_never_taken_for_a_deletion(stored):
    client, _ = make_resweep_client(dict(LIVE), failing=set(LIVE))
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts["gone"] == 0
    assert stored.execute("SELECT COUNT(*) FROM events WHERE kind = 'gone'").fetchone()[0] == 0


def test_run_resweep_budget_exceeded_is_logged_not_raised(stored):
    client, session = make_resweep_client(dict(LIVE), budget=2)
    lines = []
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert counts["refreshed"] == 2
    assert lines[-1] == "budget exceeded"
    assert len(session.paths) == 2


def test_run_resweep_after_a_budget_stop_the_list_is_the_unfetched_tail(stored):
    cutoff = time.time() - 1
    client, session = make_resweep_client(dict(LIVE), budget=2)
    run_resweep(stored, client, resweep_paths(stored, cutoff), KEY, log=quiet)
    left = [row["path"] for row in resweep_paths(stored, cutoff)]
    assert left == sorted(set(LIVE) - set(session.paths))
    assert len(left) == 1


def test_run_resweep_an_empty_list_makes_no_requests(conn):
    client, session = make_resweep_client({})
    counts = run_resweep(conn, client, [], KEY, log=quiet)
    assert counts == {"refreshed": 0, "changed": 0, "gone": 0, "failed": 0}
    assert session.paths == []


def test_run_resweep_stores_redacted_content(stored):
    live = {**LIVE, "Hello-10-17-3": live_page("third", "password: hunter2")}
    client, _ = make_resweep_client(live)
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    text = stored.execute(
        "SELECT s.text FROM snapshots s JOIN pages p ON p.id = s.page_id "
        "WHERE p.path = ? ORDER BY s.id DESC LIMIT 1",
        ("Hello-10-17-3",),
    ).fetchone()[0]
    assert "hunter2" not in text
    assert "SECRET{" in text


def test_run_resweep_logs_every_request(stored):
    client, _ = make_resweep_client(dict(LIVE), log=http_logger(stored))
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert stored.execute("SELECT COUNT(*) FROM http_log").fetchone()[0] == 3


def test_run_resweep_keeps_the_held_out_mark(conn):
    page_id = upsert_page(conn, "Known-01-02", T0, held_out=True)
    add_snapshot(conn, page_id, live_page("known"), T0, KEY)
    client, _ = make_resweep_client({"Known-01-02": live_page("known")})
    run_resweep(conn, client, everything(conn), KEY, log=quiet)
    assert conn.execute("SELECT held_out FROM pages WHERE id = ?", (page_id,)).fetchone()[0] == 1


def test_a_flagged_repoll_fetches_only_the_flagged_pages(stored):
    run_classify(stored, log=quiet)  # the title with a public IP flags
    assert score_of(stored, "Hello-10-17-1")[1] == 1
    pages = resweep_paths(stored, time.time() + HOUR, flagged=True)
    client, session = make_resweep_client(dict(LIVE))
    run_resweep(stored, client, pages, KEY, log=quiet)
    assert session.paths == ["Hello-10-17-1"]


# --- the command ---


def test_parse_args_resweep_defaults():
    args = parse_args(["sweep"])
    assert args.resweep is False
    assert args.older_than == 20.0
    assert args.flagged is False
    assert args.match is None


def test_parse_args_resweep_options():
    args = parse_args(
        ["sweep", "--resweep", "--older-than", "0", "--flagged", "--match", "8.8.8.8", "--days", "31"]
    )
    assert args.resweep is True
    assert args.older_than == 0.0
    assert args.flagged is True
    assert args.match == "8.8.8.8"
    assert args.days == 31


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


@pytest.fixture
def stored_file(workdir):
    """The three stored pages in a database file, the first one flagged."""
    c = connect(workdir / "g.sqlite")
    for path, page in LIVE.items():
        page_id = upsert_page(c, path, T0)
        add_snapshot(c, page_id, {"path": path, **page}, T0, KEY)
    run_classify(c, log=quiet)
    c.close()
    return workdir


def test_main_resweep_prints_the_header_and_the_summary(stored_file, capsys):
    main(resweep_argv(stored_file))
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "Resweep: all days, Pages: 3, Older than: 20h, Budget: 0"
    assert lines[1] == "budget exceeded"
    assert lines[2].startswith("refreshed 0 pages, 0 changed, 0 gone, 0 failed, 0 requests, ")


def test_main_resweep_needs_no_word_lists(stored_file, capsys):
    # The wordlists directory in resweep_argv does not exist.
    main(resweep_argv(stored_file))
    assert "Resweep:" in capsys.readouterr().out


def test_main_resweep_needs_the_key(stored_file):
    argv = resweep_argv(stored_file)
    argv[1] = str(stored_file / "nope.env")
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert "nope.env" in str(exc.value)


def test_main_resweep_flagged_counts_only_the_flagged_pages(stored_file, capsys):
    main(resweep_argv(stored_file, "--flagged"))
    assert "Pages: 1," in capsys.readouterr().out.splitlines()[0]


def test_main_resweep_match_narrows_the_list(stored_file, capsys):
    main(resweep_argv(stored_file, "--match", "second"))
    assert "Pages: 1," in capsys.readouterr().out.splitlines()[0]
    main(resweep_argv(stored_file, "--match", "no such text anywhere"))
    assert "Pages: 0," in capsys.readouterr().out.splitlines()[0]


def test_main_resweep_days_names_the_window(stored_file, capsys):
    main(resweep_argv(stored_file, "--days", "2", "--today", "2026-10-18"))
    first = capsys.readouterr().out.splitlines()[0]
    assert first == (
        "Resweep: 2 days, From: 10-17 to 10-18, Pages: 3, Older than: 20h, Budget: 0"
    )
    main(resweep_argv(stored_file, "--days", "2", "--today", "2026-11-18"))
    assert "Pages: 0," in capsys.readouterr().out.splitlines()[0]


def test_main_resweep_older_than_leaves_out_pages_seen_since(stored_file, capsys):
    c = connect(stored_file / "g.sqlite")
    upsert_page(c, "Hello-10-17-2", time.time())  # seen a moment ago
    c.close()
    main(resweep_argv(stored_file))
    assert "Pages: 2," in capsys.readouterr().out.splitlines()[0]
    main(resweep_argv(stored_file, "--older-than", "0"))
    assert "Pages: 3," in capsys.readouterr().out.splitlines()[0]


def test_main_resweep_hands_the_work_list_to_run_resweep(stored_file, monkeypatch, capsys):
    seen = {}

    def fake_run_resweep(conn, client, pages, key, log=print):
        seen["paths"] = [row["path"] for row in pages]
        seen["key"] = key
        return {"refreshed": 1, "changed": 1, "gone": 0, "failed": 0}

    monkeypatch.setattr("graphwatch.cli.run_resweep", fake_run_resweep)
    main(resweep_argv(stored_file, "--flagged"))
    assert seen == {"paths": ["Hello-10-17-1"], "key": b"\x00\xff"}
    assert "refreshed 1 pages, 1 changed, 0 gone, 0 failed" in capsys.readouterr().out


def test_main_sweep_without_the_flag_does_not_resweep(workdir, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise AssertionError("an ordinary sweep must not re-sweep")

    monkeypatch.setattr("graphwatch.cli.run_resweep", refuse)
    main(["--config", str(workdir / "config.env"), "sweep", *common(workdir), "--days", "1"])
    assert "Resweep" not in capsys.readouterr().out


# --------------------------------------------------------------------------
# enrich (issues #38 and #39): run_enrich, the command, the novelty table
# (plan/enrichment-plan-2026-11-22.md)
# --------------------------------------------------------------------------

FEED_KEYS = {
    "threatfox": "abuse-key-made-up",
    "urlhaus": "abuse-key-made-up",
    "otx": "otx-key-made-up",
    "virustotal": "vt-key-made-up",
}
FEED_HOST = {
    "threatfox": "threatfox-api.abuse.ch",
    "urlhaus": "urlhaus-api.abuse.ch",
    "otx": "otx.alienvault.com",
    "virustotal": "www.virustotal.com",
}


def feed_miss(feed) -> bytes:
    answers = {
        "threatfox": {"query_status": "no_result"},
        "urlhaus": {"query_status": "no_results"},
        "otx": {"pulse_info": {"count": 0}},
        "virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 9}}}},
    }
    return json.dumps(answers[feed]).encode("utf-8")


def feed_hit(feed, value) -> bytes:
    answers = {
        "threatfox": {"query_status": "ok", "data": [{"ioc": f"{value}:443", "malware_printable": "Made-up RAT"}]},
        "urlhaus": {"query_status": "ok", "url_count": "2"},
        "otx": {"pulse_info": {"count": 3}},
        "virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 4}}}},
    }
    return json.dumps(answers[feed]).encode("utf-8")


class FeedResp:
    def __init__(self, status, content):
        self.status_code = status
        self.content = content


class EnrichSession:
    """Answers every feed with a miss, except a hit for the (feed, value)
    pairs in `known` and the given status for the feeds in `broken`."""

    def __init__(self, known=(), broken=None):
        self.known = set(known)
        self.broken = dict(broken or {})
        self.calls = []

    def request(self, method, url, **kwargs):
        feed = next(name for name, host in FEED_HOST.items() if host in url)
        sent = json.dumps([url, kwargs.get("json"), kwargs.get("data")])
        self.calls.append((feed, sent))
        if feed in self.broken:
            return FeedResp(self.broken[feed], b"{}")
        for known_feed, value in self.known:
            if known_feed == feed and value in sent:
                return FeedResp(200, feed_hit(feed, value))
        return FeedResp(200, feed_miss(feed))

    def asked(self, feed) -> int:
        return sum(1 for name, _sent in self.calls if name == feed)


def make_feed_client(known=(), broken=None, keys=FEED_KEYS, **kwargs):
    session = EnrichSession(known, broken)
    client = FeedClient(keys, session=session, sleep=lambda s: None, **kwargs)
    return client, session


@pytest.fixture
def indicators(conn):
    """Two stored indicators, an address and a host, with nothing looked up yet."""
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 4)
    upsert_indicator(conn, "ip", "9.9.9.9", "pages", T0 + 60, T0 + 60, 1)
    return conn


def stored_lookups(conn):
    sql = """
    SELECT i.value, l.feed, l.verdict FROM feed_lookups l
    JOIN indicators i ON i.id = l.indicator_id ORDER BY i.value, l.feed
    """
    return [tuple(r) for r in conn.execute(sql)]


def test_run_enrich_asks_every_feed_about_every_indicator(indicators):
    client, session = make_feed_client()
    counts = run_enrich(indicators, client, log=quiet)
    assert counts == {"looked_up": 8, "cached": 0, "known": 0, "unknown": 8, "failed": 0}
    assert {feed: session.asked(feed) for feed in FEED_KEYS} == dict.fromkeys(FEED_KEYS, 2)
    assert len(stored_lookups(indicators)) == 8


def test_run_enrich_stores_and_logs_a_known_indicator(indicators):
    client, _ = make_feed_client(known={("threatfox", "8.8.8.8"), ("otx", "8.8.8.8")})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert (counts["known"], counts["unknown"]) == (2, 6)
    assert ("8.8.8.8", "threatfox", "KNOWN") in stored_lookups(indicators)
    assert ("9.9.9.9", "threatfox", "UNKNOWN") in stored_lookups(indicators)
    assert lines == [
        "8.8.8.8: known to threatfox (1 IOCs, Made-up RAT)",
        "8.8.8.8: known to otx (3 pulses)",
    ]


def test_run_enrich_does_not_ask_again_for_a_stored_answer(indicators):
    client, session = make_feed_client()
    run_enrich(indicators, client, log=quiet)
    session.calls.clear()
    counts = run_enrich(indicators, client, log=quiet)
    assert session.calls == []
    assert counts == {"looked_up": 0, "cached": 8, "known": 0, "unknown": 0, "failed": 0}


def test_run_enrich_keeps_the_answer_and_the_day_it_was_given(indicators):
    # Novelty is measured on the day the indicator was found.
    client, _ = make_feed_client()
    run_enrich(indicators, client, log=quiet)
    before = [tuple(r) for r in indicators.execute("SELECT * FROM feed_lookups ORDER BY rowid")]
    later, _ = make_feed_client(known={("threatfox", "8.8.8.8")})
    run_enrich(indicators, later, log=quiet)
    assert [tuple(r) for r in indicators.execute("SELECT * FROM feed_lookups ORDER BY rowid")] == before


def test_run_enrich_refresh_asks_again_and_replaces_the_answer(indicators):
    client, _ = make_feed_client()
    run_enrich(indicators, client, log=quiet)
    later, session = make_feed_client(known={("threatfox", "8.8.8.8")})
    counts = run_enrich(indicators, later, refresh=True, log=quiet)
    assert counts["looked_up"] == 8
    assert len(session.calls) == 8
    assert ("8.8.8.8", "threatfox", "KNOWN") in stored_lookups(indicators)
    assert len(stored_lookups(indicators)) == 8


def test_run_enrich_only_asks_the_feeds_it_has_a_key_for(indicators):
    client, session = make_feed_client(keys={"threatfox": "a", "otx": "o"})
    counts = run_enrich(indicators, client, log=quiet)
    assert counts["looked_up"] == 4
    assert {feed for feed, _sent in session.calls} == {"threatfox", "otx"}


def test_run_enrich_a_feed_added_later_is_asked_about_the_old_indicators(indicators):
    first, _ = make_feed_client(keys={"threatfox": "a", "otx": "o"})
    run_enrich(indicators, first, log=quiet)
    full, session = make_feed_client()
    counts = run_enrich(indicators, full, log=quiet)
    assert (counts["looked_up"], counts["cached"]) == (4, 4)
    assert {feed for feed, _sent in session.calls} == {"urlhaus", "virustotal"}


def test_run_enrich_a_failed_lookup_stores_nothing_and_is_tried_again(indicators):
    client, _ = make_feed_client(broken={"urlhaus": 500})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert (counts["failed"], counts["unknown"]) == (2, 6)
    assert not any(feed == "urlhaus" for _value, feed, _verdict in stored_lookups(indicators))
    assert sum(line.startswith("urlhaus ") for line in lines) == 2
    mended, session = make_feed_client()
    counts = run_enrich(indicators, mended, log=quiet)
    assert (counts["looked_up"], counts["cached"]) == (2, 6)
    assert session.asked("urlhaus") == 2


def test_run_enrich_a_failure_never_becomes_a_verdict(indicators):
    client, _ = make_feed_client(broken=dict.fromkeys(FEED_KEYS, 500))
    run_enrich(indicators, client, log=quiet)
    assert stored_lookups(indicators) == []
    verdicts = {row["value"]: novelty({f: v for f, (v, _d) in row["lookups"].items()})
                for row in novelty_rows(indicators)}
    assert set(verdicts.values()) == {"unchecked"}


def test_run_enrich_leaves_a_feed_alone_once_its_quota_is_spent(indicators):
    client, session = make_feed_client(broken={"virustotal": 429})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert session.asked("virustotal") == 1  # not once per indicator
    assert lines == ["virustotal: quota spent, left for the next run"]
    assert counts["failed"] == 1
    assert session.asked("threatfox") == 2  # the other feeds carry on


def test_run_enrich_budget_exceeded_is_logged_and_what_was_asked_is_kept(indicators):
    client, session = make_feed_client(budget=3)
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines[-1] == "budget exceeded"
    assert counts["looked_up"] == 3
    assert len(stored_lookups(indicators)) == 3
    rest, session = make_feed_client()
    counts = run_enrich(indicators, rest, log=quiet)
    assert (counts["looked_up"], counts["cached"]) == (5, 3)


def test_run_enrich_with_no_indicators_makes_no_request(conn):
    client, session = make_feed_client()
    counts = run_enrich(conn, client, log=quiet)
    assert session.calls == []
    assert counts["looked_up"] == 0


def test_run_enrich_logs_every_request_and_no_key(indicators):
    client, _ = make_feed_client(log=http_logger(indicators))
    run_enrich(indicators, client, log=quiet)
    rows = [tuple(r) for r in indicators.execute("SELECT path, outcome, error FROM http_log")]
    assert len(rows) == 8
    assert ("threatfox:8.8.8.8", "UNKNOWN", None) in rows
    for key in set(FEED_KEYS.values()):
        assert key not in json.dumps(rows)


# --- the command ---


def test_parse_args_enrich_defaults():
    args = parse_args(["enrich"])
    assert args.command == "enrich"
    assert args.db == Path("data/graphwatch.sqlite")
    assert (args.file, args.refresh, args.budget, args.table) == (None, False, None, False)


def test_parse_args_enrich_options():
    args = parse_args(["enrich", "--file", "x.tsv", "--refresh", "--budget", "40", "--table"])
    assert (args.file, args.refresh, args.budget, args.table) == (Path("x.tsv"), True, 40, True)


@pytest.fixture
def no_feed_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("this command must not build a feed client")

    monkeypatch.setattr("graphwatch.cli.FeedClient", refuse)


def test_main_enrich_table_prints_the_stored_table_and_makes_no_request(tmp_path, capsys, no_feed_network):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    indicator_id = upsert_indicator(c, "ip", "8.8.8.8", "pages", T0, T0, 4)
    save_lookup(c, indicator_id, "threatfox", "UNKNOWN", None, T0)
    save_lookup(c, indicator_id, "otx", "UNKNOWN", None, T0)
    c.close()
    main(["--config", str(tmp_path / "missing.env"), "enrich", "--db", str(db), "--table"])
    out = capsys.readouterr().out
    assert out.startswith("| Indicator | Kind | First seen | Pages | ThreatFox |")
    assert "| `8.8.8[.]8` | ip |" in out
    assert "1 indicators: 1 novel, 0 known, 0 unchecked." in out
    assert "8.8.8.8" not in out


def test_main_enrich_without_a_config_file_exits_naming_the_path(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(tmp_path / "missing.env"), "enrich", "--db", str(tmp_path / "g.sqlite")])
    assert "missing.env" in str(exc.value)


def test_main_enrich_without_any_feed_key_exits_naming_the_keys(tmp_path, no_feed_network):
    config = tmp_path / "config.env"
    config.write_text("HMAC_KEY=00ff\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "enrich", "--db", str(tmp_path / "g.sqlite")])
    for name in ("ABUSE_CH_KEY", "OTX_KEY", "VT_KEY"):
        assert name in str(exc.value)
    assert "00ff" not in str(exc.value)


@pytest.fixture
def enrich_workdir(tmp_path, monkeypatch):
    """A database with one flagged spoof page, a config with two feed keys, and
    main's FeedClient swapped for one on a fake session."""
    db = tmp_path / "g.sqlite"
    c = connect(db)
    put(c, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    run_classify(c, log=quiet)
    c.close()
    config = tmp_path / "config.env"
    config.write_text("ABUSE_CH_KEY=abuse-key-made-up\nOTX_KEY=otx-key-made-up\n", encoding="utf-8")
    session = EnrichSession()

    def fake_client(keys, **kwargs):
        return FeedClient(keys, session=session, sleep=lambda s: None, **kwargs)

    monkeypatch.setattr("graphwatch.cli.FeedClient", fake_client)
    return tmp_path, session


def enrich_argv(workdir, *extra):
    return ["--config", str(workdir / "config.env"), "enrich", "--db", str(workdir / "g.sqlite"), *extra]


def test_main_enrich_looks_up_the_flagged_pages_indicators(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir))
    out = capsys.readouterr().out
    assert "1 indicators from flagged pages, 0 from the file, feeds: threatfox, urlhaus, otx" in out
    assert "no key for virustotal (VT_KEY), skipped" in out
    assert "looked up 3, cached 0, known 0, unknown 3, failed 0, 4 requests" in out
    assert "1 indicators: 1 novel, 0 known, 0 unchecked" in out
    sent = " ".join(sent for _feed, sent in session.calls)
    assert "agfc.harper18.workers.dev" in sent
    assert "tenable" not in sent  # the decoy is never looked up


def test_main_enrich_never_prints_a_key(enrich_workdir, capsys):
    workdir, _session = enrich_workdir
    main(enrich_argv(workdir))
    captured = capsys.readouterr()
    assert "made-up" not in captured.out + captured.err


def test_main_enrich_a_second_run_asks_nothing(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir))
    session.calls.clear()
    main(enrich_argv(workdir))
    assert session.calls == []
    assert "looked up 0, cached 3" in capsys.readouterr().out


def test_main_enrich_file_adds_its_indicators_and_skips_its_decoys(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    listed = workdir / "indicators-2026-11-22.tsv"
    listed.write_text(
        "kind\tvalue\tset\n"
        "host\tprobe-only.trycloudflare.com\tactor\n"
        "host\tagfc.harper18.workers.dev\tactor\n"
        "decoy\twww.juniper.net\tactor\n",
        encoding="utf-8",
    )
    main(enrich_argv(workdir, "--file", str(listed)))
    out = capsys.readouterr().out
    assert "1 rows of indicators-2026-11-22.tsv are not an ip, host or url, skipped" in out
    assert "1 indicators from flagged pages, 2 from the file" in out
    assert "2 indicators: 2 novel" in out
    sent = " ".join(sent for _feed, sent in session.calls)
    assert "probe-only.trycloudflare.com" in sent
    assert "juniper" not in sent
    c = connect(workdir / "g.sqlite")
    sources = {r["value"]: r["source"] for r in c.execute("SELECT value, source FROM indicators")}
    c.close()
    assert sources == {
        "agfc.harper18.workers.dev": "pages",
        "probe-only.trycloudflare.com": "indicators-2026-11-22.tsv",
    }


def test_main_enrich_then_table_reads_what_the_run_stored(enrich_workdir, capsys):
    workdir, _session = enrich_workdir
    main(enrich_argv(workdir))
    capsys.readouterr()
    main(enrich_argv(workdir, "--table"))
    out = capsys.readouterr().out
    assert "| `agfc.harper18.workers[.]dev` | host |" in out
    assert "| - | - | - | not checked | novel |" in out


def test_main_enrich_builds_no_telegraph_client(enrich_workdir, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise AssertionError("enrich must not build a Telegraph client")

    monkeypatch.setattr("graphwatch.cli.TelegraphClient", refuse)
    workdir, _session = enrich_workdir
    main(enrich_argv(workdir))
    assert "looked up 3" in capsys.readouterr().out


# --- the re-poll every ten minutes, and what the review of 22 November found ---


def test_a_hundred_polls_of_an_unchanged_page_add_no_snapshot(stored):
    client, _ = make_resweep_client(dict(LIVE))
    for _ in range(100):
        run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert stored.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 3
    assert stored.execute("SELECT COUNT(*) FROM events WHERE kind != 'discovered'").fetchone()[0] == 0
    assert len(views_of(stored, "Hello-10-17-1")) == 100


def test_a_rotation_between_two_polls_is_one_snapshot_and_one_event(stored):
    live = dict(LIVE)
    client, _ = make_resweep_client(live)
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    live["Hello-10-17-1"] = live_page("9.9.9.9 first")
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts["changed"] == 1
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert [title for title, _ in snapshots_of(stored, "Hello-10-17-1")] == ["8.8.8.8 first", "9.9.9.9 first"]
    assert kinds(stored, "Hello-10-17-1") == ["discovered", "content_changed"]


def test_a_page_that_changes_back_is_a_second_change(stored):
    live = dict(LIVE)
    client, _ = make_resweep_client(live)
    live["Hello-10-17-1"] = live_page("9.9.9.9 first")
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    live["Hello-10-17-1"] = live_page("8.8.8.8 first")
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts["changed"] == 1
    assert kinds(stored, "Hello-10-17-1").count("content_changed") == 2


class RespellingSession(ResweepSession):
    """Answers with the path in upper case, as Telegraph does when the stored
    spelling differs from its own."""

    def get(self, url, **kwargs):
        resp = super().get(url, **kwargs)
        body = json.loads(resp.content)
        if body.get("ok"):
            body["result"]["path"] = body["result"]["path"].upper()
            resp.content = json.dumps(body).encode("utf-8")
        return resp


def test_run_resweep_refreshes_the_row_it_asked_for_when_telegraph_respells_the_path(conn):
    page_id = upsert_page(conn, "mark-01-20-5", T0, held_out=True)
    add_snapshot(conn, page_id, live_page("known"), T0, KEY)
    session = RespellingSession({"mark-01-20-5": live_page("known")})
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=0)
    run_resweep(conn, client, everything(conn), KEY, log=quiet)
    rows = [tuple(r) for r in conn.execute("SELECT path, held_out FROM pages")]
    assert rows == [("mark-01-20-5", 1)]  # no second row, and still held out
    assert last_seen(conn, "mark-01-20-5") > T0
    cutoff = time.time() - 1
    assert [r["path"] for r in resweep_paths(conn, cutoff)] == []


def test_main_sweep_refuses_a_window_of_no_days(workdir):
    for argv in (["--days", "0"], ["--days", "-3"], ["--resweep", "--days", "0"]):
        with pytest.raises(SystemExit) as exc:
            main(["--config", str(workdir / "config.env"), "sweep", *common(workdir), *argv])
        assert "--days" in str(exc.value)


def test_main_resweep_older_than_zero_takes_every_page_every_time(stored_file, capsys):
    # The ten-minute cron line: sweep --resweep --flagged --older-than 0
    c = connect(stored_file / "g.sqlite")
    for path in LIVE:
        c.execute("UPDATE pages SET last_seen = ? WHERE path = ?", (time.time() - 5, path))
    c.commit()
    c.close()
    main(resweep_argv(stored_file, "--older-than", "0", "--flagged"))
    assert "Pages: 1, Older than: 0h" in capsys.readouterr().out.splitlines()[0]


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


def test_a_stale_flag_on_an_older_snapshot_is_cleared(conn):
    # The false positives of 22 November: flagged once, and a re-poll has since added a snapshot.
    page_id = put(conn, "PayPal-10-31-12", "PayPal", "", "cfihelp.ua@gmail.com write to us")
    add_snapshot(conn, page_id, {"title": "PayPal", "description": "", "content": ["edited text, nothing to see"]}, T0 + 60, KEY)
    old_snapshot = conn.execute("SELECT MIN(id) FROM snapshots").fetchone()[0]
    save_score(conn, old_snapshot, page_id, 5, True, None, [("userinfo_spoof", 5, "cfihelp.ua@gmail.com", 1)], T0)
    conn.commit()
    assert [r["path"] for r in resweep_paths(conn, time.time() + HOUR, flagged=True)] == ["PayPal-10-31-12"]
    run_classify(conn, log=quiet)
    assert resweep_paths(conn, time.time() + HOUR, flagged=True) == []
    assert conn.execute("SELECT COUNT(*) FROM scores WHERE flagged = 1").fetchone()[0] == 0


def test_an_actor_page_stays_on_the_flagged_list_after_it_is_edited_to_nothing(conn):
    page_id = put(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    run_classify(conn, log=quiet)
    add_snapshot(conn, page_id, {"title": "gone quiet", "description": "", "content": ["nothing here at all, really"]}, T0 + 60, KEY)
    run_classify(conn, log=quiet)
    assert [r["path"] for r in resweep_paths(conn, time.time() + HOUR, flagged=True)] == ["Hello-10-17-9"]


def test_pages_never_flagged_are_not_rescored(swept):
    put(swept, "Notes-10-17", "Notes", "", "first version of some notes")
    page_id = swept.execute("SELECT id FROM pages WHERE path = 'Notes-10-17'").fetchone()[0]
    add_snapshot(swept, page_id, {"title": "Notes", "description": "", "content": ["second version of the notes"]}, T0 + 60, KEY)
    counts = run_classify(swept, log=quiet)
    assert counts["rescored"] == 0


# --- enrich drops what no flagged page holds any more ---


def test_main_enrich_drops_an_indicator_whose_page_is_no_longer_flagged(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir))
    c = connect(workdir / "g.sqlite")
    c.execute("UPDATE scores SET flagged = 0")  # as after a rule fix and a classify rerun
    c.commit()
    c.close()
    capsys.readouterr()
    main(enrich_argv(workdir))
    out = capsys.readouterr().out
    assert "1 indicators are on no flagged page any more, dropped" in out
    assert "0 indicators: 0 novel" in out
    c = connect(workdir / "g.sqlite")
    assert c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM feed_lookups").fetchone()[0] == 0
    c.close()


def test_main_enrich_keeps_a_file_indicator_between_runs(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    listed = workdir / "indicators.tsv"
    listed.write_text("kind\tvalue\nhost\tprobe-only.trycloudflare.com\n", encoding="utf-8")
    main(enrich_argv(workdir, "--file", str(listed)))
    main(enrich_argv(workdir))  # the file is not passed this time
    out = capsys.readouterr().out
    assert "dropped" not in out
    c = connect(workdir / "g.sqlite")
    assert c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 2
    c.close()


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


# --- classify and the ten-minute re-poll on one file (second review, 22 November) ---


def test_run_classify_holds_nothing_open_between_reading_a_batch_and_writing_it(tmp_path, monkeypatch):
    # The re-poll writes to the same file every ten minutes. Classify used to
    # write with its own read cursor still open; SQLite then fails the write
    # at once with "database is locked" if another process wrote in between,
    # whatever the timeout. Here another connection writes at the start of
    # every batch's write-out, as the re-poll would between two batches.
    import sqlite3

    import graphwatch.cli as cli

    monkeypatch.setattr("graphwatch.cli.CLASSIFY_BATCH", 2)
    db = tmp_path / "g.sqlite"
    writer = connect(db)
    for n in range(1, 6):
        put(writer, f"Hello-10-17-{n}", "Hello", "", f"note {n}")
    real_save_score = cli.save_score
    intrusions = []

    def save_score_after_an_intrusion(conn, *args, **kwargs):
        if not conn.in_transaction:
            other = sqlite3.connect(str(db), timeout=1)
            other.execute("INSERT INTO events (ts, kind) VALUES (?, ?)", (T0, "repoll"))
            other.commit()
            other.close()
            intrusions.append(True)
        return real_save_score(conn, *args, **kwargs)

    monkeypatch.setattr("graphwatch.cli.save_score", save_score_after_an_intrusion)
    counts = run_classify(writer, log=quiet)
    assert counts["pages"] == 5
    assert len(intrusions) == 3  # batches of 2, 2 and 1
    assert writer.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 5
    assert writer.execute("SELECT COUNT(*) FROM events WHERE kind = 'repoll'").fetchone()[0] == 3
    writer.close()


def test_run_classify_commits_each_batch_before_it_reads_the_next(tmp_path, monkeypatch):
    import graphwatch.cli as cli

    monkeypatch.setattr("graphwatch.cli.CLASSIFY_BATCH", 2)
    db = tmp_path / "g.sqlite"
    writer = connect(db)
    for n in range(1, 6):
        put(writer, f"Hello-10-17-{n}", "Hello", "", f"note {n}")
    real = cli.latest_snapshots
    open_transactions = []

    def watching(conn, *args, **kwargs):
        open_transactions.append(conn.in_transaction)
        return real(conn, *args, **kwargs)

    monkeypatch.setattr("graphwatch.cli.latest_snapshots", watching)
    run_classify(writer, log=quiet)
    assert open_transactions and not any(open_transactions)
    writer.close()


def test_run_classify_gives_the_same_result_whatever_the_batch_size(conn, monkeypatch):
    put_fixture(conn, "Hello-10-17-154", "Hello-10-17-154")
    put(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    for title in ("Cobalt-Strike", "Mimikatz", "Stealer"):
        put(conn, f"{title}-10-17", title, "", SQUATTER_BODY)
    put(conn, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)

    def stored():
        scores = [tuple(r) for r in conn.execute("SELECT snapshot_id, score, flagged FROM scores ORDER BY snapshot_id")]
        labels = [tuple(r) for r in conn.execute("SELECT snapshot_id, category, score, assigned, is_primary FROM labels ORDER BY snapshot_id, category")]
        return scores, labels

    monkeypatch.setattr("graphwatch.cli.CLASSIFY_BATCH", 1000)
    whole = dict(run_classify(conn, log=quiet))
    whole_rows = stored()
    monkeypatch.setattr("graphwatch.cli.CLASSIFY_BATCH", 1)
    one_by_one = dict(run_classify(conn, log=quiet))
    assert one_by_one == whole
    assert stored() == whole_rows


# --- what the third review of 22 November found ---


def nested(depth: int) -> dict:
    node = "deep"
    for _ in range(depth):
        node = {"tag": "b", "children": [node]}
    return node


def test_run_sweep_moves_past_a_page_nested_too_deep_to_redact(conn, counted, monkeypatch):
    # One such page would otherwise stop the sweep at the same counter every night.
    import graphwatch.cli as cli

    real = cli.store_fetch

    def store_or_overflow(conn, fetch, ts, key, **kwargs):
        if fetch.page["path"] == "Hello-10-24":
            raise RecursionError("maximum recursion depth exceeded")
        return real(conn, fetch, ts, key, **kwargs)

    monkeypatch.setattr("graphwatch.cli.store_fetch", store_or_overflow)
    client, _ = make_sweep_client({"Hello-10-24", "Hello-10-24-2"})
    lines = []
    stored, _requests = run_sweep(conn, client, ENTRIES, DAYS, KEY, 2, None, set(), log=lines.append)
    assert stored == 1
    assert stored_paths(conn) == ["Hello-10-24-2"]
    assert "Hello-10-24: nested too deep to redact, not stored" in lines
    assert load_progress(conn, "Hello", 10, 24)[1] is True  # the day is closed, not stuck


def test_redact_page_really_does_overflow_on_a_very_deep_page():
    # The premise of the test above and the one below.
    from graphwatch.redact import redact_page

    with pytest.raises(RecursionError):
        redact_page({"content": [nested(3000)]}, KEY)


def test_run_resweep_counts_a_page_nested_too_deep_as_failed_and_goes_on(stored):
    live = {**LIVE, "Hello-10-17-1": {"title": "t", "description": "", "views": 1, "content": [nested(3000)]}}
    client, _ = make_resweep_client(live)
    lines = []
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert counts == {"refreshed": 2, "changed": 0, "gone": 0, "failed": 1}
    assert lines == ["Hello-10-17-1: nested too deep to redact, not stored"]
    assert last_seen(stored, "Hello-10-17-1") == T0
    assert len(snapshots_of(stored, "Hello-10-17-1")) == 1


def test_main_enrich_gives_a_file_indicator_back_to_the_file_when_no_page_holds_it(enrich_workdir, capsys):
    workdir, _session = enrich_workdir
    listed = workdir / "indicators.tsv"
    listed.write_text("kind\tvalue\nhost\tagfc.harper18.workers.dev\n", encoding="utf-8")
    main(enrich_argv(workdir, "--file", str(listed)))
    c = connect(workdir / "g.sqlite")
    assert c.execute("SELECT source, pages FROM indicators").fetchone()[:] == ("pages", 1)
    c.execute("UPDATE scores SET flagged = 0")  # as after a rule fix and a classify rerun
    c.commit()
    c.close()
    capsys.readouterr()
    main(enrich_argv(workdir, "--file", str(listed)))
    out = capsys.readouterr().out
    assert "dropped" not in out
    c = connect(workdir / "g.sqlite")
    row = c.execute("SELECT source, first_seen, last_seen, pages FROM indicators").fetchone()
    assert tuple(row) == ("indicators.tsv", None, None, 0)
    assert c.execute("SELECT COUNT(*) FROM feed_lookups").fetchone()[0] == 3  # its answers are kept
    c.close()
