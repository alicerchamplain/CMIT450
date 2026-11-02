"""Tests for graphwatch.cli, the runner.

The runner is split so the wiring can be tested without the network: main()
parses arguments and builds real objects; run_crowd() takes those objects and
does the work. Here run_crowd gets a client whose session answers from a set
of existing paths.
"""

import json
import urllib.parse
from pathlib import Path

import pytest

from graphwatch.cli import (
    main,
    make_fetch,
    make_probe,
    parse_args,
    require_key,
    run_crowd,
    run_sweep,
)
from graphwatch.config import CONFIG
from graphwatch.crowd import save_day_count, DayCount
from graphwatch.db import connect, load_progress
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


def test_run_sweep_stores_every_page_of_every_day(conn):
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


def test_run_sweep_registers_titles_and_links_pages_to_them(conn):
    client, _ = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    row = conn.execute(
        "SELECT t.slug FROM pages p JOIN titles t ON p.title_id = t.id"
    ).fetchone()
    assert row["slug"] == "hello"


def test_run_sweep_stores_redacted_content(conn):
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


def test_run_sweep_records_progress_per_day(conn):
    client, _ = make_sweep_client({"Hello-10-24", "Hello-10-24-2"})
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 1, None, set(), log=lambda s: None)
    assert load_progress(conn, "Hello", 10, 24) == (5, True)  # 1, 2 found; 3, 4 miss
    assert load_progress(conn, "Hello", 10, 23) == (3, True)  # 1, 2 miss
    row = conn.execute(
        "SELECT requests, failures FROM sweep_progress WHERE slug = 'hello' AND day = 24"
    ).fetchone()
    assert (row["requests"], row["failures"]) == (4, 0)


def test_run_sweep_skips_excluded_slugs_entirely(conn):
    client, session = make_sweep_client({"Hello-10-24", "Povіstka-10-23"})
    stored, _ = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, {"hello"}, log=lambda s: None
    )
    assert stored == 1
    assert not any(p.startswith("Hello") for p in session.paths)
    assert load_progress(conn, "Hello", 10, 24) == (1, False)


def test_run_sweep_skips_days_already_done(conn):
    client1, _ = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client1, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    client2, session2 = make_sweep_client({"Hello-10-24"})
    stored, requests = run_sweep(
        conn, client2, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None
    )
    assert (stored, requests) == (0, 0)
    assert session2.paths == []


def test_run_sweep_resumes_a_day_cut_off_by_the_budget(conn):
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


def test_run_sweep_budget_exceeded_is_logged_not_raised(conn):
    client, _ = make_sweep_client({"Hello-10-23", "Hello-10-23-2"}, budget=1)
    lines = []
    stored, _ = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append
    )
    assert stored == 1
    assert any("budget" in line for line in lines)


def test_run_sweep_uses_expected_from_the_crowd_table(conn):
    # Pages at 1 and 5; crowd says the day reaches 5. gap 0 would otherwise stop at 2.
    seed_crowd(conn, [("Hello", 10, 23, 5)])
    client, session = make_sweep_client({"Hello-10-23", "Hello-10-23-5"})
    stored, _ = run_sweep(
        conn, client, ENTRIES, [(10, 23)], KEY, 0, None, set(), log=lambda s: None
    )
    assert stored == 2
    assert "Hello-10-23-5" in session.paths


def test_run_sweep_cap_truncates_a_day(conn):
    existing = {f"Hello-10-23-{n}" for n in range(2, 10)} | {"Hello-10-23"}
    seed_crowd(conn, [("Hello", 10, 23, 9)])
    client, session = make_sweep_client(existing)
    stored, _ = run_sweep(
        conn, client, ENTRIES, [(10, 23)], KEY, 2, 3, set(), log=lambda s: None
    )
    assert stored == 3
    assert load_progress(conn, "Hello", 10, 23) == (4, True)


def test_run_sweep_failed_tail_leaves_the_day_for_retry(conn):
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


def test_run_sweep_logs_days_with_pages_only(conn):
    client, _ = make_sweep_client({"Hello-10-24"})
    lines = []
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append)
    assert len(lines) == 1
    assert "Hello" in lines[0] and "10-24" in lines[0]


def test_run_sweep_logs_every_request(conn):
    client, _ = make_sweep_client({"Hello-10-24"})
    client.log = __import__("graphwatch.db", fromlist=["http_logger"]).http_logger(conn)
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    assert (
        conn.execute("SELECT COUNT(*) FROM http_log").fetchone()[0]
        == client.requests_made
    )


def test_run_sweep_stores_the_api_path_not_the_requested_one(conn):
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


# --------------------------------------------------------------------------
# main: wiring only; a budget of 0 keeps every test off the network
# --------------------------------------------------------------------------


@pytest.fixture
def workdir(tmp_path):
    (tmp_path / "wordlists").mkdir()
    (tmp_path / "wordlists" / "greetings.txt").write_text("Hello\n", encoding="utf-8")
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


def test_main_sweep_prints_the_plan_then_stops_on_the_budget(workdir, capsys):
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
