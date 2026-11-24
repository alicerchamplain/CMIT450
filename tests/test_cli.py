"""Tests for graphwatch.cli, the runner.

The runner is split so the wiring can be tested without the network: main()
parses arguments and builds real objects; the run_* functions take those
objects and do the work. Here each run_* gets a client whose session answers
from what the test gives it, and main() gets a budget of 0 or a client on a
fake session.
"""

import hashlib
import json
import random
import re
import runpy
import time
import urllib.parse
import warnings
from datetime import date, datetime
from pathlib import Path

import threading

import pytest
import requests

from graphwatch.cli import (
    CLASSIFY_WORKERS,
    classify_counts,
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
from graphwatch.classify import Scorer, _start_worker
from graphwatch.config import CONFIG
from graphwatch.crowd import DayCount, save_day_count
from graphwatch.db import (
    add_snapshot,
    classify_mark,
    http_logger,
    connect,
    load_progress,
    resweep_paths,
    save_lookup,
    save_score,
    set_classify_mark,
    store_meta,
    upsert_indicator,
    upsert_page,
)
from graphwatch.feeds import FeedClient
from graphwatch.redact import hash_secret
from graphwatch.rules import CATEGORIES, RULES
from graphwatch.slugify import Entry
from graphwatch.telegraph import Outcome, TelegraphClient, build_path

FIXTURES = Path(__file__).resolve().parents[1] / "plan" / "fixtures"
FOUND_BODY = (FIXTURES / "Vizit-12-28.json").read_bytes()
MISSING_BODY = (FIXTURES / "not-found.json").read_bytes()

# The run time a summary line ends with. A run here takes no time; a number
# of ten digits would be a sum of two clock readings, not their difference.
SECONDS = r"\d{1,2}s"


class Resp:
    def __init__(self, body):
        self.status_code = 200
        self.content = body


class PathSession:
    """Answers FOUND for paths in `existing`, NOT_FOUND otherwise; records
    the paths asked for and the whole URLs."""

    def __init__(self, existing):
        self.existing = set(existing)
        self.paths = []
        self.urls = []

    def get(self, url, **kwargs):
        path = urllib.parse.unquote(url.split("/getPage/", 1)[1].split("?", 1)[0])
        self.paths.append(path)
        self.urls.append(url)
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


def test_make_probe_returns_the_outcome_only_and_asks_without_content():
    client, session = make_client({"Hello-10-24"})
    probe = make_probe(client)
    assert probe("Hello-10-24") is Outcome.FOUND
    assert probe("Hello-10-23") is Outcome.NOT_FOUND
    # the crowd check must not pull page bodies
    assert [url.split("?", 1)[1] for url in session.urls] == ["return_content=false"] * 2


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


def test_run_crowd_logs_the_days_that_have_pages_and_no_others(conn):
    client, _ = make_client({"Hello-10-24", "Hello-10-24-2"})
    lines = []
    run_crowd(conn, client, ENTRIES, DAYS, gap=0, log=lines.append)
    # counters 1 and 2 found, then 4 and 3 missing
    assert lines == ["Hello 10-24: 2 pages, 4 requests"]


def test_run_crowd_stops_cleanly_when_the_budget_runs_out(conn):
    # Budget for the first slug's two days only; the second slug is left for
    # the next night. Nothing raises, and what was finished is saved.
    client, _ = make_client(set(), budget=2)
    lines = []
    checked = run_crowd(conn, client, ENTRIES, DAYS, gap=0, log=lines.append)
    assert checked == 2
    rows = conn.execute("SELECT slug FROM crowd").fetchall()
    assert {r[0] for r in rows} == {"hello"}
    assert lines == ["budget exceeded"]


def test_run_crowd_uses_the_gap(conn):
    client, _ = make_client({"Hello-10-24-2"})  # bare page deleted
    run_crowd(conn, client, ENTRIES[:1], [(10, 24)], gap=1, log=lambda s: None)
    assert conn.execute("SELECT highest FROM crowd").fetchone()[0] == 2


# --------------------------------------------------------------------------
# parse_args
# --------------------------------------------------------------------------

DB = Path("data/graphwatch.sqlite")
LISTS = Path("wordlists")


@pytest.mark.parametrize(
    "argv, options",
    [
        (
            ["crowd"],
            dict(
                db=DB, wordlists=LISTS, days=14, gap=2, rate=8.0, budget=None, today=None, unfrozen=False,
                workers=4,
            ),
        ),
        (
            ["sweep"],
            dict(
                db=DB, wordlists=LISTS, days=None, gap=2, rate=8.0, budget=230000, cap=None,
                count_only_above=700, today=None, unfrozen=False,
                resweep=False, older_than=20.0, flagged=False, match=None, workers=4,
            ),
        ),
        (["meta", "--stale", "24"], dict(db=DB, rate=8.0, budget=230000, limit=5000, stale=24.0, workers=4)),
        (["freeze"], dict(wordlists=LISTS)),
        (["classify"], dict(db=DB, threshold=4, explain=None, workers=CLASSIFY_WORKERS, full=False)),
        (["enrich"], dict(db=DB, file=None, refresh=False, budget=None, table=False, recheck_days=14.0)),
    ],
)
def test_parse_args_defaults(argv, options):
    # The whole namespace: a command that gains an option gains a line here,
    # and no command has an option that is not written down.
    assert vars(parse_args(argv)) == {"config": CONFIG, "command": argv[0], **options}


@pytest.mark.parametrize(
    "argv, options",
    [
        # --config is shared by every command, so it is typed before the command name
        (["--config", "/tmp/x.env", "crowd"], dict(config=Path("/tmp/x.env"), command="crowd")),
        (
            ["crowd", "--db", "x.sqlite", "--wordlists", "w", "--days", "3", "--gap", "1",
             "--rate", "4", "--budget", "500", "--today", "2026-11-13", "--unfrozen"],
            dict(db=Path("x.sqlite"), wordlists=Path("w"), days=3, gap=1, rate=4.0, budget=500,
                 today=date(2026, 11, 13), unfrozen=True),
        ),
        (
            ["sweep", "--db", "x.sqlite", "--wordlists", "w", "--days", "31", "--gap", "1",
             "--rate", "2", "--budget", "9", "--cap", "200", "--count-only-above", "50",
             "--today", "2026-11-04", "--unfrozen",
             "--resweep", "--older-than", "0", "--flagged", "--match", "8.8.8.8"],
            dict(db=Path("x.sqlite"), wordlists=Path("w"), days=31, gap=1, rate=2.0, budget=9,
                 cap=200, count_only_above=50, today=date(2026, 11, 4), unfrozen=True,
                 resweep=True, older_than=0.0, flagged=True, match="8.8.8.8"),
        ),
        (
            ["meta", "--db", "x.sqlite", "--stale", "0", "--limit", "500", "--budget", "27", "--rate", "2"],
            dict(db=Path("x.sqlite"), stale=0.0, limit=500, budget=27, rate=2.0),
        ),
        (["freeze", "--wordlists", "w"], dict(wordlists=Path("w"))),
        (
            ["classify", "--db", "x.sqlite", "--threshold", "6", "--explain", "Hello-10-17-9"],
            dict(db=Path("x.sqlite"), threshold=6, explain="Hello-10-17-9"),
        ),
        (
            ["enrich", "--db", "x.sqlite", "--file", "x.tsv", "--refresh", "--budget", "40", "--table"],
            dict(db=Path("x.sqlite"), file=Path("x.tsv"), refresh=True, budget=40, table=True),
        ),
    ],
)
def test_parse_args_reads_every_option(argv, options):
    args = vars(parse_args(argv))
    assert {name: args[name] for name in options} == options


@pytest.mark.parametrize("argv", [[], ["meta"]])
def test_parse_args_requires_a_command_and_meta_requires_stale(argv):
    with pytest.raises(SystemExit):
        parse_args(argv)


# --------------------------------------------------------------------------
# require_key
# --------------------------------------------------------------------------


# The key every config file in this module holds: 32 bytes, the shortest
# hmac_key accepts, written as hex the way secrets.token_hex(32) gives it
CONFIG_KEY = b"\x00\xff" * 16
CONFIG_LINE = "HMAC_KEY=" + "00ff" * 16 + "\n"


def test_require_key_returns_the_key_bytes_and_prints_nothing(tmp_path, capsys):
    cfg = tmp_path / "config.env"
    cfg.write_text(CONFIG_LINE, encoding="utf-8")
    assert require_key(cfg) == CONFIG_KEY
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "content, message",
    [
        (None, "Config file not found: {}"),
        ("OTHER=1\n", "HMAC_KEY not set in {}"),
        ("HMAC_KEY=\n", "HMAC_KEY is shorter than 32 bytes: {}"),
        ("HMAC_KEY=" + "00ff" * 15 + "00\n", "HMAC_KEY is shorter than 32 bytes: {}"),  # 31 bytes
    ],
)
def test_require_key_exits_naming_the_file_and_what_is_wrong_with_it(tmp_path, content, message):
    cfg = tmp_path / "config.env"
    if content is not None:
        cfg.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        require_key(cfg)
    assert str(exc.value) == message.format(cfg)


# --------------------------------------------------------------------------
# make_fetch and run_sweep (issue #20)
# --------------------------------------------------------------------------

KEY = b"test-key"


class SweepSession(PathSession):
    """Like PathSession, but a FOUND body carries the requested path, so what
    the sweep stores is the page it asked for. `overrides` replaces fields of
    one path's page. `failing` paths get a 500 with an unparseable body, which
    the client reports as FAILED."""

    def __init__(self, existing, failing=(), overrides=None):
        super().__init__(existing)
        self.failing = set(failing)
        self.overrides = dict(overrides or {})

    def get(self, url, **kwargs):
        path = urllib.parse.unquote(url.split("/getPage/", 1)[1].split("?", 1)[0])
        self.paths.append(path)
        self.urls.append(url)
        if path in self.failing:
            r = Resp(b"not json")
            r.status_code = 500
            return r
        if path in self.existing:
            body = json.loads(FOUND_BODY)
            body["result"]["path"] = path
            body["result"]["title"] = f"title of {path}"
            body["result"].update(self.overrides.get(path, {}))
            return Resp(json.dumps(body).encode("utf-8"))
        return Resp(MISSING_BODY)


def make_sweep_client(existing, failing=(), overrides=None, **kwargs):
    session = SweepSession(existing, failing, overrides)
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


def nested(depth: int) -> dict:
    node = "deep"
    for _ in range(depth):
        node = {"tag": "b", "children": [node]}
    return node


def test_make_fetch_returns_the_whole_fetch_and_asks_for_the_content():
    client, session = make_sweep_client({"Hello-10-24"})
    fetch = make_fetch(client)
    f = fetch("Hello-10-24")
    assert f.outcome is Outcome.FOUND
    assert f.page["path"] == "Hello-10-24"
    assert f.page["content"]
    assert fetch("Hello-10-23").outcome is Outcome.NOT_FOUND
    assert session.urls[0].endswith("?return_content=true")


def test_run_sweep_stores_every_page_of_every_day(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24", "Hello-10-24-2", "Povіstka-10-23"})
    lines = []
    stored, requests = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append
    )
    assert stored == 3
    assert stored_paths(conn) == ["Hello-10-24", "Hello-10-24-2", "Povіstka-10-23"]
    assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 3
    # gap 0: each of the 4 title-days costs its pages + 1 miss
    assert requests == 3 + 4
    assert client.requests_made == requests
    # one line for each day that had pages, none for the two that had none
    assert lines == ["Hello 10-24: 2 pages, 3 requests", "Povіstka 10-23: 1 pages, 2 requests"]


def test_run_sweep_registers_titles_and_links_pages_to_them(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    row = conn.execute(
        "SELECT t.slug FROM pages p JOIN titles t ON p.title_id = t.id"
    ).fetchone()
    assert row["slug"] == "hello"


def test_run_sweep_stores_redacted_content(conn, counted):
    client, _ = make_sweep_client(
        {"Hello-10-24"}, overrides={"Hello-10-24": {"title": "password: hunter2"}}
    )
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    title = conn.execute("SELECT title FROM snapshots").fetchone()["title"]
    assert "hunter2" not in title
    assert hash_secret("hunter2", KEY) in title  # hashed, and with the key the sweep was given


def test_run_sweep_records_progress_per_day(conn, counted):
    client, _ = make_sweep_client({"Hello-10-24", "Hello-10-24-2"})
    run_sweep(conn, client, ENTRIES, DAYS, KEY, 1, None, set(), log=lambda s: None)
    assert load_progress(conn, "Hello", 10, 24) == (5, True)  # 1, 2 found; 3, 4 miss
    assert load_progress(conn, "Hello", 10, 23) == (3, True)  # 1, 2 miss
    row = conn.execute(
        "SELECT requests, failures FROM sweep_progress WHERE slug = 'hello' AND day = 24"
    ).fetchone()
    assert (row["requests"], row["failures"]) == (4, 0)


def test_run_sweep_skips_excluded_slugs_entirely(conn):
    # Hello is counted on the 24th and not on the 23rd: an excluded title is not
    # fetched where it has a count and not reported where it has none
    seed_crowd(conn, [("Povіstka", m, d, 0) for m, d in DAYS] + [("Hello", 10, 24, 0)])
    client, session = make_sweep_client({"Hello-10-24", "Povіstka-10-23"})
    lines = []
    stored, _ = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, {"hello"}, log=lines.append
    )
    assert stored == 1
    assert not any(p.startswith("Hello") for p in session.paths)
    assert load_progress(conn, "Hello", 10, 24) == (1, False)
    assert lines == ["Povіstka 10-23: 1 pages, 2 requests"]


def test_run_sweep_skips_days_already_done_even_when_their_count_is_gone(conn, counted):
    client1, _ = make_sweep_client({"Hello-10-24"})
    run_sweep(conn, client1, ENTRIES, DAYS, KEY, 0, None, set(), log=lambda s: None)
    # the 24th keeps its count and the 23rd loses it: neither is fetched again
    conn.execute("DELETE FROM crowd WHERE day = 23")
    client2, session2 = make_sweep_client({"Hello-10-24"})
    lines = []
    stored, requests = run_sweep(
        conn, client2, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append
    )
    assert (stored, requests) == (0, 0)
    assert session2.paths == []
    assert lines == []  # a done day is not reported as uncounted


# Cut after the bare page, and after a numbered one: the page just stored
# names the counter to pick up at, and the bare page has no number in its path.
@pytest.mark.parametrize("budget", [1, 2])
def test_run_sweep_resumes_a_day_cut_off_by_the_budget(conn, counted, budget):
    existing = {"Hello-10-23", "Hello-10-23-2", "Hello-10-23-3", "Hello-10-23-4"}
    # Night one: the budget runs out and the next request is refused.
    client1, _ = make_sweep_client(existing, budget=budget)
    lines = []
    stored, _ = run_sweep(
        conn, client1, ENTRIES[:1], [(10, 23)], KEY, 0, None, set(), log=lines.append
    )
    assert stored == budget
    assert lines == ["budget exceeded"]
    assert load_progress(conn, "Hello", 10, 23) == (budget + 1, False)
    # Night two: picks up at the next counter, never re-fetches what is stored.
    client2, session2 = make_sweep_client(existing)
    stored, _ = run_sweep(
        conn, client2, ENTRIES[:1], [(10, 23)], KEY, 0, None, set(), log=lambda s: None
    )
    assert stored == 4 - budget
    assert session2.paths == [f"Hello-10-23-{n}" for n in range(budget + 1, 6)]
    assert load_progress(conn, "Hello", 10, 23) == (6, True)
    assert stored_paths(conn) == [
        "Hello-10-23",
        "Hello-10-23-2",
        "Hello-10-23-3",
        "Hello-10-23-4",
    ]


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
    run_sweep(conn, client, ENTRIES[:1], [(10, 23)], KEY, 1, None, set(), log=lines.append)
    # left open at the first counter that failed, so the retry asks for it again
    assert load_progress(conn, "Hello", 10, 23) == (2, False)
    row = conn.execute("SELECT failures FROM sweep_progress").fetchone()
    assert row["failures"] == 2
    assert lines == ["Hello 10-23: 1 pages, 3 requests"]
    # The next night Telegraph answers: the two pages behind the failures are stored
    mended, session = make_sweep_client({"Hello-10-23", "Hello-10-23-2", "Hello-10-23-3"})
    stored, _ = run_sweep(conn, mended, ENTRIES[:1], [(10, 23)], KEY, 1, None, set(), log=quiet)
    assert (stored, session.paths[0]) == (2, "Hello-10-23-2")
    assert stored_paths(conn) == ["Hello-10-23", "Hello-10-23-2", "Hello-10-23-3"]
    assert load_progress(conn, "Hello", 10, 23) == (6, True)


def test_run_sweep_stores_the_api_path_not_the_requested_one(conn, counted):
    # The API answers for Hello-10-24 but reports its own spelling.
    client, _ = make_sweep_client(
        {"Hello-10-24"}, overrides={"Hello-10-24": {"path": "hello-10-24"}}
    )
    run_sweep(
        conn, client, ENTRIES, [(10, 24)], KEY, 0, None, set(), log=lambda s: None
    )
    assert stored_paths(conn) == ["hello-10-24"]
    # progress is keyed by the slug we swept, case-insensitively
    assert load_progress(conn, "Hello", 10, 24) == (3, True)


def test_run_sweep_sweeps_the_counted_days_and_reports_the_rest(conn):
    # With no count the walk would stop at the first hole of gap + 1 counters,
    # which is how 2 to 4 November lost pages. An uncounted day is not fetched
    # and not marked done.
    seed_crowd(conn, [("Hello", 10, 24, 2)])
    client, session = make_sweep_client({"Hello-10-23", "Hello-10-24", "Hello-10-24-2"})
    lines = []
    stored, _ = run_sweep(
        conn, client, ENTRIES, DAYS, KEY, 0, None, set(), log=lines.append
    )
    assert stored == 2
    assert stored_paths(conn) == ["Hello-10-24", "Hello-10-24-2"]
    assert session.paths == ["Hello-10-24", "Hello-10-24-2", "Hello-10-24-3"]
    assert load_progress(conn, "Hello", 10, 24) == (4, True)
    assert load_progress(conn, "Hello", 10, 23) == (1, False)
    # Hello 10-23 and both Povіstka days have no count
    assert lines == [
        "Hello 10-24: 2 pages, 3 requests",
        "skipped 3 title-days with no crowd count; run crowd for those days, then sweep again",
    ]


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


def test_run_sweep_moves_past_a_page_nested_too_deep_to_redact(conn, counted):
    # One such page would otherwise stop the sweep at the same counter every night.
    client, _ = make_sweep_client(
        {"Hello-10-24", "Hello-10-24-2"}, overrides={"Hello-10-24": {"content": [nested(3000)]}}
    )
    lines = []
    try:
        stored, _requests = run_sweep(conn, client, ENTRIES, DAYS, KEY, 2, None, set(), log=lines.append)
    except RecursionError:
        stored = None  # caught here: pytest takes over a minute to report a traceback this deep
    assert stored == 1
    # Only the snapshots are looked at. The page's row is written before the overflow
    # and stays; whether it should is an open question, so it is asserted neither way.
    snapshots = conn.execute(
        "SELECT p.path FROM snapshots s JOIN pages p ON p.id = s.page_id"
    ).fetchall()
    assert [r["path"] for r in snapshots] == ["Hello-10-24-2"]
    assert "Hello-10-24: nested too deep to redact, not stored" in lines
    assert load_progress(conn, "Hello", 10, 24) == (6, True)  # the day is closed, not stuck


# --------------------------------------------------------------------------
# main: wiring only; a budget of 0 or a fake session keeps every test off the network
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
    cfg.write_text(CONFIG_LINE, encoding="utf-8")
    return tmp_path


def common(workdir, budget="0"):
    return [
        "--db",
        str(workdir / "g.sqlite"),
        "--wordlists",
        str(workdir / "wordlists"),
        "--budget",
        budget,
    ]


def sweep_argv(workdir, *extra, budget="0"):
    return ["--config", str(workdir / "config.env"), "sweep", *common(workdir, budget), *extra]


@pytest.fixture
def offline(monkeypatch):
    """main's TelegraphClient on a session that finds no page. What main built
    the client with, and the session, are in the dict."""
    built = {}

    def build(**kwargs):
        built.update(kwargs, session=PathSession(set()))
        return TelegraphClient(session=built["session"], sleep=lambda s: None, retries=0, **kwargs)

    monkeypatch.setattr("graphwatch.cli.TelegraphClient", build)
    return built


@pytest.fixture
def sweep_call(monkeypatch):
    """Replaces run_sweep, so main makes no request; what main handed it is in the dict."""
    seen = {}

    def fake_run_sweep(conn, client, entries, days, key, gap, cap, exclude, log=print):
        seen.update(slugs=[e.slug for e in entries], days=days, key=key, gap=gap, cap=cap, exclude=exclude)
        return 0, 0

    monkeypatch.setattr("graphwatch.cli.run_sweep", fake_run_sweep)
    return seen


def test_python_m_graphwatch_cli_runs_main_on_the_command_line(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.txt").write_text("Hello\n", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["graphwatch", "freeze", "--wordlists", str(tmp_path)])
    with warnings.catch_warnings():
        # runpy warns that the module was imported already, which this file did
        warnings.simplefilter("ignore", RuntimeWarning)
        runpy.run_module("graphwatch.cli", run_name="__main__")
    assert (tmp_path / "SHA256SUMS").exists()
    assert "1 titles in 1 lists" in capsys.readouterr().out


@pytest.mark.parametrize(
    "content, options, message",
    [
        (None, [], "Config file not found: {}"),
        ("OTHER=1\n", [], "HMAC_KEY not set in {}"),
        ("HMAC_KEY=short\n", [], "HMAC_KEY is shorter than 32 bytes: {}"),
        # a re-sweep hashes what it fetches, so it needs the key as well
        (None, ["--resweep"], "Config file not found: {}"),
    ],
)
def test_main_sweep_without_the_key_exits_before_touching_the_db(workdir, content, options, message):
    cfg = workdir / "other.env"
    if content is not None:
        cfg.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(cfg), "sweep", *common(workdir), *options])
    assert str(exc.value) == message.format(cfg)
    assert not (workdir / "g.sqlite").exists()


def test_main_crowd_needs_no_config_and_builds_its_client_from_the_options(workdir, offline, capsys):
    main(
        ["--config", str(workdir / "nope.env"), "crowd", *common(workdir, budget="5"),
         "--days", "1", "--today", "2026-11-01", "--gap", "1", "--rate", "4"]
    )
    assert (offline["rate_per_s"], offline["budget"]) == (4.0, 5)
    # gap 1: the bare page and one more, and the day is empty
    assert offline["session"].paths == ["Hello-11-01", "Hello-11-01-2"]
    assert re.fullmatch(rf"checked 1 title-days, 2 requests, {SECONDS}\n", capsys.readouterr().out)
    c = connect(workdir / "g.sqlite")
    assert c.execute("SELECT COUNT(*) FROM http_log").fetchone()[0] == 2  # every request is logged
    c.close()


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
    seed_crowd(c, [("Hello", 10, 31, 0), ("Hello", 11, 1, 0)])
    c.close()
    main(sweep_argv(workdir, "--days", "2", "--today", "2026-11-01"))
    plan, stop, summary = capsys.readouterr().out.splitlines()
    assert plan == "Window Size: 2, From: 10-31 to 11-01, Estimated Requests: 6, Budget: 0, Count Only 0"
    assert stop == "budget exceeded"
    assert re.fullmatch(rf"Stored 0 pages, 0 requests, 0\.0/s, {SECONDS}", summary)


def test_main_sweep_refuses_when_no_window_fits(workdir):
    # A crowd row makes one day cost 13 requests; budget 0 fits nothing.
    c = connect(workdir / "g.sqlite")
    seed_crowd(c, [("Hello", 11, 1, 10)])
    c.close()
    with pytest.raises(SystemExit) as exc:
        main(sweep_argv(workdir, "--today", "2026-11-01"))
    assert "window" in str(exc.value)


@pytest.mark.parametrize(
    "options, budget, estimate",
    [
        # Three days of 10 pages cost 13 each with the default gap of 2 and no cap.
        # A budget of 26 fits Nov 1 and Oct 31, not Oct 30.
        ([], 26, 26),
        # With no gap and a cap of 4 pages a day costs 5: two days fit 12, three do not.
        (["--gap", "0", "--cap", "4"], 12, 10),
    ],
)
def test_main_sweep_lets_the_crowd_table_choose_the_window(workdir, sweep_call, capsys, options, budget, estimate):
    # A title that is only counted costs nothing, however many pages it has.
    c = connect(workdir / "g.sqlite")
    seed_crowd(c, [("Hello", 10, 30, 10), ("Hello", 10, 31, 10), ("Hello", 11, 1, 10)])
    seed_crowd(c, [("Busy", 11, 1, 50_000)])
    c.close()
    main(sweep_argv(workdir, "--today", "2026-11-01", *options, budget=str(budget)))
    assert sweep_call["days"] == [(10, 31), (11, 1)]
    assert capsys.readouterr().out.splitlines()[0] == (
        f"Window Size: 2, From: 10-31 to 11-01, Estimated Requests: {estimate}, Budget: {budget}, Count Only 1"
    )


@pytest.mark.parametrize(
    "highest, option, excluded",
    [
        (50_000, [], {"hello"}),
        (10, [], set()),
        (10, ["--count-only-above", "10"], {"hello"}),
    ],
)
def test_main_sweep_excludes_titles_above_the_count_only_threshold(
    workdir, sweep_call, highest, option, excluded
):
    c = connect(workdir / "g.sqlite")
    seed_crowd(c, [("Hello", 11, 1, highest)])
    c.close()
    main(sweep_argv(workdir, "--days", "1", "--today", "2026-11-01", *option))
    assert sweep_call["exclude"] == excluded


def test_main_sweep_hands_run_sweep_the_word_list_the_key_and_its_options(workdir, sweep_call):
    main(sweep_argv(workdir, "--days", "1", "--today", "2026-11-01", "--gap", "1", "--cap", "200"))
    assert sweep_call == {
        "slugs": ["Hello"],
        "days": [(11, 1)],
        "key": CONFIG_KEY,
        "gap": 1,
        "cap": 200,
        "exclude": set(),
    }


def test_main_sweep_without_the_flag_does_not_resweep(workdir, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise AssertionError("an ordinary sweep must not re-sweep")

    monkeypatch.setattr("graphwatch.cli.run_resweep", refuse)
    main(sweep_argv(workdir, "--days", "1"))
    assert "Resweep" not in capsys.readouterr().out


@pytest.mark.parametrize("days", [["--days", "0"], ["--days", "-3"], ["--resweep", "--days", "0"]])
def test_main_sweep_refuses_a_window_of_no_days(workdir, days):
    with pytest.raises(SystemExit) as exc:
        main(sweep_argv(workdir, *days))
    assert "--days" in str(exc.value)


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


def test_run_meta_fetches_each_selected_page_once_and_stores_its_timestamps(conn):
    pages = seed_pages(conn, ["Hello-10-19-130", "Hello-10-19-143"])
    client, session = make_meta_client(
        {"Hello-10-19-130": (PUB_ISO, MOD_ISO), "Hello-10-19-143": (PUB_ISO, MOD_ISO)}
    )
    before = time.time()
    counts = run_meta(conn, client, pages, log=lambda s: None)
    assert session.paths == ["Hello-10-19-130", "Hello-10-19-143"]
    assert client.requests_made == 2
    # a first fetch is not a change
    assert counts == {"fetched": 2, "changed": 0, "not_found": 0, "failed": 0}
    assert change_events(conn) == []
    row = meta_row(conn, "Hello-10-19-130")
    assert row["published_at"] == iso_ts(PUB_ISO)
    assert row["modified_at"] == iso_ts(MOD_ISO)
    assert before <= row["meta_seen_at"] <= time.time()


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
    assert [event["page_id"] for event in change_events(conn)] == [pages[1]["id"]]
    assert lines == ["Hello-10-19-143: modified_at changed to 2026-11-05T09:00:00+00:00"]


def test_run_meta_not_found_is_counted_stores_nothing_and_does_not_stop_the_run(conn):
    pages = seed_pages(conn, ["zz-01-01-99999", "Hello-10-19-130"])
    client, _ = make_meta_client({"Hello-10-19-130": (PUB_ISO, MOD_ISO)})
    counts = run_meta(conn, client, pages, log=lambda s: None)
    assert counts == {"fetched": 1, "changed": 0, "not_found": 1, "failed": 0}
    assert meta_row(conn, "zz-01-01-99999")["meta_seen_at"] is None


def test_run_meta_failed_is_counted_logged_and_does_not_stop_the_run(conn):
    pages = seed_pages(conn, ["Hello-10-19-130", "Hello-10-19-143"])
    client, _ = make_meta_client(
        {"Hello-10-19-143": (PUB_ISO, MOD_ISO)}, failing={"Hello-10-19-130"}
    )
    lines = []
    counts = run_meta(conn, client, pages, log=lines.append)
    assert counts == {"fetched": 1, "changed": 0, "not_found": 0, "failed": 1}
    assert meta_row(conn, "Hello-10-19-130")["meta_seen_at"] is None
    assert meta_row(conn, "Hello-10-19-143")["modified_at"] == iso_ts(MOD_ISO)
    assert lines == ["Hello-10-19-130: FAILED: 503"]


def test_run_meta_budget_exceeded_is_logged_not_raised(conn):
    pages = seed_pages(conn, ["a-01-01", "b-01-01", "c-01-01"])
    client, session = make_meta_client(
        {p["path"]: (PUB_ISO, MOD_ISO) for p in pages}, budget=2
    )
    lines = []
    counts = run_meta(conn, client, pages, log=lines.append)
    assert session.paths == ["a-01-01", "b-01-01"]
    assert counts["fetched"] == 2
    assert lines == ["budget exceeded"]


def meta_argv(workdir, *extra):
    # No redaction happens on the HTML path, so no key; and no titles are
    # swept, so no wordlists. A budget of 0 keeps it off the network.
    return ["--config", str(workdir / "nope.env"), "meta", "--db", str(workdir / "g.sqlite"),
            "--budget", "0", *extra]


def test_main_meta_does_not_need_the_config_or_wordlists(workdir, capsys):
    main(meta_argv(workdir, "--stale", "0"))
    selected, summary = capsys.readouterr().out.splitlines()
    assert selected == "0 selected"
    assert re.fullmatch(
        rf"Fetched 0, changed 0, not found 0, failed 0, 0 requests, 0\.0/s, {SECONDS}", summary
    )


@pytest.mark.parametrize(
    "options, selected",
    [
        (["--stale", "24"], 2),  # the page seen a moment ago is not stale yet
        (["--stale", "0"], 3),
        (["--stale", "0", "--limit", "2"], 2),
    ],
)
def test_main_meta_selects_the_stale_pages_up_to_the_limit(workdir, capsys, options, selected):
    c = connect(workdir / "g.sqlite")
    ids = [upsert_page(c, f"Hello-10-19-{n}", 0.0) for n in (1, 2, 3)]
    seen = {"published_at": iso_ts(PUB_ISO), "modified_at": iso_ts(MOD_ISO)}
    store_meta(c, ids[2], seen, time.time())
    c.close()
    main(meta_argv(workdir, *options))
    assert capsys.readouterr().out.splitlines()[:2] == [f"{selected} selected", "budget exceeded"]


# --------------------------------------------------------------------------
# classify (issue #29): run_classify, run_explain, the command
# --------------------------------------------------------------------------

T0 = 1_700_000_000.0
API_SAMPLE = "Hello,+world!"
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"
SQUATTER_BODY = (
    "https://t.me/+YztOEovieQIzZjY8 exploits, malware, RATs, steallers and other "
    "stuff https://t.me/+YztOEovieQIzZjY8 https://t.me/+YztOEovieQIzZjY8"
)
COMBO_BODY = "\n".join(f"user{n}@mail.example.com:hunter{n}pass" for n in range(4))
PROXY_BODY = "fresh today:\n8.8.8.8:1080\n1.1.1.1:3128\n9.9.9.9:8080"
PLAIN_BODY = "We met on Tuesday and agreed to meet again next week."
HOUR = 3600.0


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


def put_linked(conn, path, title, text, href):
    """Store a page whose text ends in a link: the address is in the href, not in the text."""
    page_id = upsert_page(conn, path, T0)
    link = {"tag": "a", "attrs": {"href": href}, "children": ["Download here"]}
    page = {"title": title, "description": text[:100], "content": [{"tag": "p", "children": [text, link]}]}
    add_snapshot(conn, page_id, page, T0, KEY)
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


def resolver_hits(conn, path):
    """(rule, weight, evidence, matches) of the resolver rules stored for a page, in
    stored order; the category rules are tested through the labels below."""
    sql = """
    SELECT h.rule, h.weight, h.evidence, h.matches FROM hits h
    JOIN scores sc ON sc.snapshot_id = h.snapshot_id
    JOIN pages p ON p.id = sc.page_id WHERE p.path = ? ORDER BY h.id
    """
    return [tuple(r) for r in conn.execute(sql, (path,)) if r["rule"] in RESOLVER_RULES]


def labels_of(conn, path):
    """(category, score, assigned, is_primary) rows for a page's newest snapshot."""
    sql = """
    SELECT l.category, l.score, l.assigned, l.is_primary FROM labels l
    JOIN pages p ON p.id = l.page_id WHERE p.path = ? ORDER BY l.rowid
    """
    return [tuple(r) for r in conn.execute(sql, (path,))]


def assigned_labels(conn, path):
    return [row[0] for row in labels_of(conn, path) if row[2]]


def evidence_of(conn, rule):
    return [r["evidence"] for r in conn.execute("SELECT evidence FROM hits WHERE rule = ?", (rule,))]


def explain(conn, path) -> list[str]:
    lines = []
    assert run_explain(conn, path, log=lines.append) is True
    return lines


def flagged_list(conn):
    """The paths a flagged re-poll would fetch."""
    return [r["path"] for r in resweep_paths(conn, time.time() + HOUR, flagged=True)]


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


@pytest.fixture
def mixed(swept):
    """The small sweep plus one page for each of two more categories and a plain one."""
    put(swept, "Accounts-10-17", "Accounts", "", COMBO_BODY)
    put(swept, "Proxy-10-17", "Proxy", "", PROXY_BODY)
    put(swept, "Notes-10-17", "Notes", "", PLAIN_BODY)
    return swept


def test_run_classify_stores_one_resolver_verdict_for_every_page(swept):
    run_classify(swept, log=quiet)
    assert swept.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 8
    assert {path: score_of(swept, path)[1] for path in stored_paths(swept)} == {
        "Hello-10-17-154": 1,  # the pointer shape, as recorded
        "Hello-10-17-9": 1,  # the spoof shape
        "Hello-10-17-5": 0,
        "Test-10-16": 0,
        "Hello-10-17-7": 0,
        "Cobalt-Strike-10-17": 0,
        "Mimikatz-10-17": 0,
        "Stealer-10-17": 0,
    }


def test_run_classify_counts_the_sweep_by_resolver_score(swept):
    counts = run_classify(swept, log=quiet)
    assert (counts["pages"], counts["flagged"], counts["rescored"]) == (8, 2, 0)
    assert (counts["held_out"], counts["held_out_flagged"]) == (0, 0)
    # The API test page at +1 is the one near miss; a page at 0 or below is not one.
    assert score_of(swept, "Hello-10-17-7") == (1, 0)
    assert counts["near_miss"] == 1
    scores = dict(counts["scores"])
    assert scores.pop(score_of(swept, "Hello-10-17-154")[0]) == 1  # the recorded page, whatever it scores
    assert scores == {6: 1, 1: 1, 0: 2, -3: 3}


def test_run_classify_penalises_one_body_under_three_titles_and_stores_its_hash(swept):
    run_classify(swept, log=quiet)
    sql = """
    SELECT sc.body_sha256 FROM scores sc JOIN pages p ON p.id = sc.page_id
    WHERE p.path = ?
    """
    for title in ("Cobalt-Strike", "Mimikatz", "Stealer"):
        assert [hit[0] for hit in resolver_hits(swept, f"{title}-10-17")] == ["telegram_link", "templated_body"]
        assert score_of(swept, f"{title}-10-17") == (-3, 0)
        digest = swept.execute(sql, (f"{title}-10-17",)).fetchone()[0]
        assert digest == hashlib.sha256(SQUATTER_BODY.encode("utf-8")).hexdigest()
    # a body too short to be a template has no hash
    assert swept.execute(sql, ("Hello-10-17-7",)).fetchone()[0] is None


def test_run_classify_does_not_penalise_one_title_that_posts_a_body_three_times(conn):
    # A template is one body under several titles; pages are not titles.
    for n in (1, 2, 3):
        put(conn, f"Alpha-10-17-{n}", "Alpha", "", SQUATTER_BODY)
    put(conn, "Beta-10-17", "Beta", "", SQUATTER_BODY)
    run_classify(conn, log=quiet)
    assert [hit[0] for hit in resolver_hits(conn, "Alpha-10-17-2")] == ["telegram_link"]


def test_run_classify_does_not_penalise_the_actor_for_the_shared_sample_body(conn):
    # "Hello,+world!" sits under many titles; it is too short to be a template.
    put(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    for title in ("Hello", "title", "Test"):
        put(conn, f"{title}-10-17", title, API_SAMPLE, API_SAMPLE)
    run_classify(conn, log=quiet)
    assert resolver_hits(conn, "Hello-10-17-9") == [
        ("userinfo_spoof", 5, "www.tenable.com@agfc.harper18.workers.dev", 1),
        ("api_sample_body", 1, API_SAMPLE, 1),
    ]
    assert score_of(conn, "Hello-10-17-9") == (6, 1)


def test_run_classify_stores_each_hit_with_its_weight_evidence_and_match_count(swept):
    run_classify(swept, log=quiet)
    # The squatter body carries the same t.me link three times: counted, not scored three times.
    assert resolver_hits(swept, "Mimikatz-10-17") == [
        ("telegram_link", -1, "t.me/", 3),
        ("templated_body", -2, "body " + hashlib.sha256(SQUATTER_BODY.encode("utf-8")).hexdigest()[:12], 1),
    ]


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


def test_run_classify_on_an_empty_database(conn):
    lines = []
    counts = run_classify(conn, log=lines.append)
    assert (counts["pages"], counts["held_out"]) == (0, 0)
    assert lines[0] == "classified 0 pages at threshold 4: 0 flagged, 0 near misses, 0 templated bodies"
    assert lines[-2].split() == ["unlabelled", "0", "(0.0%", "of", "pages)"]
    assert lines[-1] == "scored every page: 0 snapshots, and 0 older ones again"


# --- labels (plan/classification-plan-2026-11-15.md) ---


def test_run_classify_stores_a_label_row_for_every_category_that_scored(mixed):
    counts = run_classify(mixed, log=quiet)
    expected = {
        # a resolver, a pointer (its tunnel host) and a placeholder: one primary, the first in order
        "Hello-10-17-9": [("resolver", 6, 1, 1), ("pointer", 4, 1, 0), ("placeholder", 4, 1, 0)],
        # a near miss is a row that is not assigned, and so is a score below zero
        "Mimikatz-10-17": [
            ("resolver", -3, 0, 0),
            ("template_spam", 4, 1, 1),
            ("fraud_market", 2, 0, 0),
            ("telegram_funnel", 2, 0, 0),
        ],
        "Accounts-10-17": [("resolver", 1, 0, 0), ("leaked_credentials", 4, 1, 1)],
        "Proxy-10-17": [("resolver", 1, 0, 0), ("pointer", 3, 0, 0), ("proxy_list", 5, 1, 1)],
        "Notes-10-17": [],
    }
    assert {path: labels_of(mixed, path) for path in expected} == expected
    # The resolver row is the scores table's verdict: the categories did not move it.
    for path, rows in expected.items():
        resolver = rows[0][1:3] if rows else (0, 0)
        assert score_of(mixed, path) == resolver, path
    assert counts["flagged"] == 2


def test_the_primary_label_is_the_first_in_category_order_not_the_highest_score(conn):
    # One proxy list under three titles: template_spam at +4 comes before proxy_list at +5
    for title in ("Alpha", "Beta", "Gamma"):
        put(conn, f"{title}-10-17", title, "", PROXY_BODY)
    run_classify(conn, log=quiet)
    assigned = [row for row in labels_of(conn, "Alpha-10-17") if row[2]]
    assert assigned == [("template_spam", 4, 1, 1), ("proxy_list", 5, 1, 0)]


def test_a_category_whose_hits_cancel_out_is_no_label_row_and_no_near_miss(conn):
    # +1 for the address and -1 for the t.me link: the resolver rules fired and sum to 0
    put(conn, "Contact-10-17", "Contact", "", "write to someone@example.com or see https://t.me/somechannel for more")
    counts = run_classify(conn, log=quiet)
    assert [hit[:2] for hit in resolver_hits(conn, "Contact-10-17")] == [("email_address", 1), ("telegram_link", -1)]
    assert labels_of(conn, "Contact-10-17") == []
    assert counts["category_near_miss"]["resolver"] == 0
    assert (counts["near_miss"], counts["unlabelled"]) == (0, 1)
    assert explain(conn, "Contact-10-17")[3] == "  resolver +0"


def test_run_classify_counts_labels_primaries_and_near_misses_per_category(mixed):
    counts = run_classify(mixed, log=quiet)
    for category, expected in {
        "resolver": (2, 2, 3),  # three pages at +1 are its near misses
        "template_spam": (3, 3, 0),  # a labelled page is not also a near miss
        "leaked_credentials": (1, 1, 0),
        "proxy_list": (1, 1, 0),
        "placeholder": (3, 1, 0),  # a label on three pages, the primary one on one
        "telegram_funnel": (0, 0, 3),  # the advert's invite link
    }.items():
        got = (counts["labelled"][category], counts["primary"][category], counts["category_near_miss"][category])
        assert got == expected, category
    # every page is counted once: under its primary label, or as unlabelled
    assert counts["unlabelled"] == 3
    assert sum(counts["primary"].values()) + counts["unlabelled"] == counts["pages"] == 11


def test_run_classify_logs_the_totals_then_one_line_per_category_then_the_unlabelled_share(mixed):
    lines = []
    counts = run_classify(mixed, log=lines.append)
    assert lines[0] == "classified 11 pages at threshold 4: 2 flagged, 3 near misses, 1 templated bodies"
    assert lines[1] == "held-out: 0/0 flagged"
    assert len(lines) == 2 + len(CATEGORIES) + 2
    for category, line in zip(CATEGORIES, lines[2:-2]):
        assert line.split() == [
            category,
            "labelled", f"{counts['labelled'][category]},",
            "primary", f"{counts['primary'][category]},",
            "near", "misses", f"{counts['category_near_miss'][category]}",
        ]
    assert lines[3].split() == ["template_spam", "labelled", "3,", "primary", "3,", "near", "misses", "0"]
    assert lines[-2].split() == ["unlabelled", "3", "(27.3%", "of", "pages)"]
    assert lines[-1] == "scored every page: 11 snapshots, and 0 older ones again"


def tables_of(conn):
    """Everything classify stores, row for row. When a row was written and the
    ids of the hits are left out: they say that a row was written again, not
    what it holds."""
    scores = "SELECT snapshot_id, page_id, score, flagged, body_sha256 FROM scores ORDER BY snapshot_id"
    hits = "SELECT snapshot_id, rule, weight, evidence, matches FROM hits ORDER BY snapshot_id, id"
    labels = "SELECT snapshot_id, page_id, category, score, assigned, is_primary FROM labels ORDER BY snapshot_id, category"
    return [[tuple(row) for row in conn.execute(sql)] for sql in (scores, hits, labels)]


def written(conn):
    """When each score was written and the id of every hit: a snapshot that was
    scored again has a new time and new hit ids."""
    times = {r[0]: r[1] for r in conn.execute("SELECT snapshot_id, classified_at FROM scores")}
    return times, [r[0] for r in conn.execute("SELECT id FROM hits ORDER BY id")]


def page_id_of(conn, path):
    return conn.execute("SELECT id FROM pages WHERE path = ?", (path,)).fetchone()[0]


def snapshots_of_page(conn, path, scored=False):
    sql = "SELECT s.id FROM snapshots s JOIN pages p ON p.id = s.page_id WHERE p.path = ?"
    if scored:
        sql += " AND s.id IN (SELECT snapshot_id FROM scores)"
    return [r[0] for r in conn.execute(sql + " ORDER BY s.id", (path,))]


# What a run did, as opposed to what the table holds afterwards
RUN_KEYS = ("full", "scored", "rescored")


def test_an_ordinary_night_scores_the_new_and_the_changed_snapshots_and_writes_no_other_row(mixed):
    first = run_classify(mixed, log=quiet)
    assert [first[key] for key in RUN_KEYS] == [True, 11, 0]
    stored, rows = tables_of(mixed), written(mixed)
    assert [len(table) for table in stored][0] == 11
    # A night with nothing new: nothing is scored and no row is written, and
    # the counts are still of every page
    lines = []
    second = run_classify(mixed, log=lines.append)
    assert second == {**first, "full": False, "scored": 0}
    assert (tables_of(mixed), written(mixed)) == (stored, rows)
    assert lines[0] == "classified 11 pages at threshold 4: 2 flagged, 3 near misses, 1 templated bodies"
    assert lines[-1] == "scored 0 new or changed snapshots, and 0 older ones again; every other page kept its score"
    # The sweep stores a page, and the re-poll finds an old one changed twice
    put(mixed, "Notes-10-18", "Notes", "", PLAIN_BODY)
    notes = page_id_of(mixed, "Notes-10-17")
    for minute, body in enumerate(("an edit nobody scored", PROXY_BODY), start=1):
        add_snapshot(mixed, notes, {"title": "Notes", "description": "", "content": [body]}, T0 + 60 * minute, KEY)
    third = run_classify(mixed, log=quiet)
    assert [third[key] for key in RUN_KEYS] == [False, 2, 0]
    assert (third["pages"], third["labelled"]["proxy_list"]) == (12, first["labelled"]["proxy_list"] + 1)
    # Only a page's newest snapshot is scored: the edit in between never is
    first_snapshot, _between, newest = snapshots_of_page(mixed, "Notes-10-17")
    assert snapshots_of_page(mixed, "Notes-10-17", scored=True) == [first_snapshot, newest]
    # and the eleven rows of the first night are the rows written that night
    times, _hit_ids = written(mixed)
    assert {snapshot: times[snapshot] for snapshot in rows[0]} == rows[0]
    assert len(times) == 13
    # The re-poll stores a flagged page's edit while classify is still
    # running: the page is counted by the snapshot that was scored, not dropped
    spoof = page_id_of(mixed, "Hello-10-17-9")
    add_snapshot(mixed, spoof, {"title": "Hello", "description": "", "content": ["rotated"]}, T0 + 600, KEY)
    counts = classify_counts(mixed, 4)
    assert (counts["pages"], counts["flagged"]) == (third["pages"], third["flagged"]) == (12, 2)
    assert counts["labelled"] == third["labelled"]


# Bodies long enough to be hashed. The first is flagged for its /! marker
# until it is a template, which takes two points off; under the spoof title
# any of them is flagged, and the penalty takes that flag too.
MARKER_BODY = "the key for this month is at /!bucket-of-the-month, fetch it from there as usual"
NIGHT_BODIES = (MARKER_BODY, PLAIN_BODY, PROXY_BODY + " and a few more words", SQUATTER_BODY, "short")
NIGHT_TITLES = ("Hello", "Notes", "Proxy", "Accounts", SPOOF_TITLE)


def test_ordinary_nights_store_what_scoring_every_page_each_night_would():
    # Two databases get the same pages and the same edits. One scores every
    # page every night (full=True); the other only what an ordinary night
    # scores. They must hold the same rows after every night, whatever the
    # batch size.
    did = {"scored": 0, "rescored": 0, "every_page": 0}
    for seed in range(8):
        rng = random.Random(seed)
        every_night, ordinary = connect(":memory:"), connect(":memory:")
        paths = []
        clock = T0
        for night in range(7):
            edits = []
            for _ in range(rng.randint(1, 5)):
                if paths and rng.random() < 0.5:
                    # a re-poll finds a page changed, sometimes twice before classify runs
                    path = rng.choice(paths)
                    edits += [(path, rng.choice(NIGHT_TITLES), rng.choice(NIGHT_BODIES)) for _ in range(rng.randint(1, 2))]
                else:
                    paths.append(f"Page-10-{10 + night}-{len(paths) + 1}")
                    edits.append((paths[-1], rng.choice(NIGHT_TITLES), rng.choice(NIGHT_BODIES)))
            for conn in (every_night, ordinary):
                ts = clock
                for path, title, body in edits:
                    ts += 60
                    page_id = upsert_page(conn, path, ts)
                    add_snapshot(conn, page_id, {"title": title, "description": "", "content": [body]}, ts, KEY)
            clock += 86_400
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr("graphwatch.cli.CLASSIFY_BATCH", (1000, 1, 3)[seed % 3])
                all_pages = run_classify(every_night, log=quiet, full=True)
                some = run_classify(ordinary, log=quiet)
            where = (seed, night)
            assert tables_of(ordinary) == tables_of(every_night), where
            assert flagged_list(ordinary) == flagged_list(every_night), where
            assert {k: v for k, v in some.items() if k not in RUN_KEYS} == {k: v for k, v in all_pages.items() if k not in RUN_KEYS}, where
            assert some["full"] is (night == 0), where
            if night:
                did["scored"] += some["scored"]
                did["rescored"] += some["rescored"]
                did["every_page"] += all_pages["scored"] + all_pages["rescored"]
    # The nights did happen as described: templates came and went under
    # flagged pages, and the ordinary nights scored a fraction of the pages
    assert did["rescored"] > 0
    assert 0 < did["scored"] + did["rescored"] < did["every_page"] / 2


@pytest.mark.parametrize(
    "why",
    ["the threshold", "the code", "the mark was cleared", "it was asked for", "a run was cut short", "the mark was cleared under a run"],
)
def test_every_page_is_scored_again_when_the_stored_scores_may_be_out_of_date(mixed, monkeypatch, why):
    import graphwatch.cli as cli

    run_classify(mixed, log=quiet)
    assert run_classify(mixed, log=quiet)["full"] is False
    options = {}
    real_save_labels, calls = cli.save_labels, []
    if why == "the mark was cleared under a run":
        # reredact rewrites snapshots while a run is scoring every page, some
        # of them scored already: that run must not end by calling itself complete

        # The same holds when a second run started meanwhile and put its own token there.
        for left_by_the_other in (None, "running:the token of another run"):

            def replace_at_the_third(*args, **kwargs):
                calls.append(args)
                if len(calls) == 3:
                    set_classify_mark(mixed, left_by_the_other)
                return real_save_labels(*args, **kwargs)

            calls.clear()
            monkeypatch.setattr(cli, "save_labels", replace_at_the_third)
            lines = []
            assert run_classify(mixed, log=lines.append, full=True)["full"] is True
            assert "the mark was cleared while classify ran: the next run scores every page again" in lines
            assert classify_mark(mixed) == left_by_the_other
        monkeypatch.setattr(cli, "save_labels", real_save_labels)
    if why == "the threshold":
        options = {"threshold": 3}
    elif why == "the code":
        monkeypatch.setattr(cli, "fingerprint", lambda threshold: f"other rules at {threshold}")
    elif why == "the mark was cleared":
        # what reredact does when it rewrites a snapshot (test_reredact.py)
        set_classify_mark(mixed, None)
        mixed.commit()
    elif why == "a run was cut short":

        def stop_at_the_third(*args, **kwargs):
            calls.append(args)
            if len(calls) == 3:
                raise KeyboardInterrupt
            return real_save_labels(*args, **kwargs)

        monkeypatch.setattr(cli, "save_labels", stop_at_the_third)
        with pytest.raises(KeyboardInterrupt):
            run_classify(mixed, log=quiet, full=True)
        mixed.rollback()
        # what is left in the mark's place is that run's token, and no fingerprint
        assert classify_mark(mixed).startswith("running:")
        monkeypatch.setattr(cli, "save_labels", real_save_labels)
    lines = []
    counts = run_classify(mixed, log=lines.append, full=(why == "it was asked for"), **options)
    assert [counts[key] for key in RUN_KEYS] == [True, 11, 0]
    assert lines[-1] == "scored every page: 11 snapshots, and 0 older ones again"
    assert classify_mark(mixed) == cli.fingerprint(options.get("threshold", 4))
    # and the night after that is an ordinary one again
    assert run_classify(mixed, log=quiet, **options)["full"] is False


def test_a_body_that_becomes_a_template_or_stops_being_one_is_scored_again_wherever_it_is_stored(conn):
    # Night 1: the marker page is flagged, and one other title shares its body
    watched = put(conn, "Hello-10-17-1", "Hello", "", MARKER_BODY)
    put(conn, "Notes-10-17", "Notes", "", MARKER_BODY)
    run_classify(conn, log=quiet)
    assert flagged_list(conn) == ["Hello-10-17-1", "Notes-10-17"]
    # The re-poll finds the watched page edited to plain text: its flag is on
    # an older snapshot now. Two more titles take up the body, three with Notes.
    add_snapshot(conn, watched, {"title": "Hello", "description": "", "content": ["nothing here at all, really"]}, T0 + 60, KEY)
    put(conn, "Proxy-10-18", "Proxy", "", MARKER_BODY)
    last = put(conn, "Accounts-10-18", "Accounts", "", MARKER_BODY)
    counts = run_classify(conn, log=quiet)
    # scored: the edit and the two new pages, and Notes, which did not change
    # and whose body is a template tonight; and the older flagged snapshot
    assert [counts[key] for key in RUN_KEYS] == [False, 4, 1]
    assert counts["templated"] == 1
    assert flagged_list(conn) == []
    assert assigned_labels(conn, "Notes-10-17") == ["template_spam"]
    # One of the three is edited, and the body is two titles' again. Both of
    # them get their flag back, and so does the older snapshot that lost it
    # to the penalty: until 24 November that row was never scored again, and
    # the page was off the re-poll's list for good. The edited page's own
    # older snapshot holds the penalty too, and is judged the same way.
    add_snapshot(conn, last, {"title": "Accounts", "description": "", "content": ["nothing here either, honestly"]}, T0 + 120, KEY)
    counts = run_classify(conn, log=quiet)
    assert [counts[key] for key in RUN_KEYS] == [False, 3, 2]
    assert counts["templated"] == 0
    assert sorted(flagged_list(conn)) == ["Accounts-10-18", "Hello-10-17-1", "Notes-10-17", "Proxy-10-18"]
    assert assigned_labels(conn, "Notes-10-17") == ["resolver"]
    # nothing is left to do: the night after scores nothing
    counts = run_classify(conn, log=quiet)
    assert [counts[key] for key in RUN_KEYS] == [False, 0, 0]


def test_two_worker_processes_store_what_one_process_does(monkeypatch):
    # The workers are real processes here, started the way they are on the
    # VPS. The threshold is not the default, so a worker that ignored the one
    # it was started with would store other rows.
    import graphwatch.classify as classify

    monkeypatch.setattr(classify, "POOL_MIN_ROWS", 1)
    real_score_snapshot, in_this_process = classify.score_snapshot, []

    def counted(item, *args):
        in_this_process[-1] += 1
        return real_score_snapshot(item, *args)

    monkeypatch.setattr(classify, "score_snapshot", counted)
    stored = []
    for workers in (1, 2):
        in_this_process.append(0)
        conn = connect(":memory:")
        put_fixture(conn, "Hello-10-17-154", "Hello-10-17-154")
        put(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
        put_linked(conn, "Katya-10-17", "Katya", "write to me. ", "https://files.example.com/setup.exe")
        for title in ("Cobalt-Strike", "Mimikatz", "Stealer"):
            put(conn, f"{title}-10-17", title, "", SQUATTER_BODY)
        counts = run_classify(conn, threshold=5, log=quiet, workers=workers)
        stored.append((tables_of(conn), counts))
    assert stored[0] == stored[1]
    assert stored[0][1]["scored"] == 6
    # with two workers this process scored nothing itself
    assert in_this_process == [6, 0]
    monkeypatch.undo()
    # A batch too small to be worth it starts no worker, and there is never less than one scorer
    with Scorer([], 4, workers=2) as small:
        assert len(small.score([(1, 1, "t", "", "t\n\nx", "[]")])) == 1
        assert small._pool is None
    assert Scorer([], 4, workers=0).workers == 1
    # A worker that loaded other scoring code than its parent refuses to start
    with pytest.raises(RuntimeError, match="other scoring code"):
        _start_worker(frozenset(), 4, "the fingerprint of other code")
    _start_worker(frozenset(), 4, classify.fingerprint(4))


def test_the_threshold_is_an_argument_for_the_verdict_and_for_every_category(mixed):
    counts = run_classify(mixed, threshold=1, log=quiet)
    assert score_of(mixed, "Hello-10-17-7") == (1, 1)  # at the threshold is flagged
    assert (counts["flagged"], counts["near_miss"]) == (5, 0)
    run_classify(mixed, threshold=2, log=quiet)
    assert "telegram_funnel" in assigned_labels(mixed, "Mimikatz-10-17")
    run_classify(mixed, threshold=5, log=quiet)
    assert assigned_labels(mixed, "Mimikatz-10-17") == []


def test_held_out_pages_change_no_count_but_their_own_and_are_never_named(mixed):
    # Held-out rows here are synthetic: real held-out content is never a test input.
    before = run_classify(mixed, log=quiet)
    put(mixed, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    put(mixed, "Known-01-03", "Hello", "", "nothing here", held_out=True)
    put(mixed, "Known-01-04", "Accounts", "", COMBO_BODY, held_out=True)
    upsert_page(mixed, "Known-01-05", T0, held_out=True)  # on the list and never fetched: no snapshot
    lines = []
    after = run_classify(mixed, log=lines.append)
    assert after == {**before, "held_out": 3, "held_out_flagged": 1, "full": False, "scored": 3}
    # Recall is logged as counts: which held-out pages missed is never printed.
    assert lines[1] == "held-out: 1/3 flagged"
    out = "\n".join(lines)
    assert "Known-01" not in out
    assert "tenable" not in out


# --- the rules read link targets (decided 22 November) ---


def test_run_classify_sees_the_address_behind_a_link(conn):
    put_linked(conn, "Game-10-17", "Game", "Free game, full version. ", "https://files.example.com/setup.exe")
    run_classify(conn, log=quiet)
    assert evidence_of(conn, "executable_link") == ["https://files.example.com/setup.exe"]
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
    evidence = evidence_of(conn, "autologin_link")
    assert len(evidence) == 1
    assert "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d" not in evidence[0]
    assert "SECRET{" in evidence[0]


# --- a flag from an old rule table does not outlive the rule ---


def with_an_older_flagged_snapshot(conn, path, title, description, body, old_score):
    """A page whose first snapshot holds a flagged score from some earlier rule
    table, and which has since been edited to plain text. Returns the old snapshot's id."""
    page_id = put(conn, path, title, description, body)
    page = {"title": "plain", "description": "", "content": ["nothing here at all, really"]}
    add_snapshot(conn, page_id, page, T0 + 60, KEY)
    old_snapshot = conn.execute("SELECT MIN(id) FROM snapshots WHERE page_id = ?", (page_id,)).fetchone()[0]
    save_score(conn, old_snapshot, page_id, old_score, True, None, [("old_rule", old_score, "x", 1)], T0)
    conn.commit()
    return old_snapshot


def test_run_classify_rescores_the_older_snapshots_of_a_flagged_page(conn):
    old_snapshot = with_an_older_flagged_snapshot(conn, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, 99)
    counts = run_classify(conn, log=quiet)
    row = conn.execute("SELECT score, flagged FROM scores WHERE snapshot_id = ?", (old_snapshot,)).fetchone()
    assert tuple(row) == (6, 1)  # the spoof, scored by today's table
    assert counts["rescored"] == 1
    assert counts["pages"] == 1  # still one page, counted by its newest snapshot
    assert counts["flagged"] == 0
    # and labelled by it: the older snapshot's resolver label is not counted
    assert (counts["labelled"]["resolver"], counts["unlabelled"]) == (0, 1)
    # the actor edits pages in place: once a resolver, still one to watch
    assert flagged_list(conn) == ["Hello-10-17-9"]
    # A run by hand at a higher threshold takes that flag off. The next
    # run at 4 gives it back: until 24 November it was gone for good.
    run_classify(conn, threshold=7, log=quiet)
    assert flagged_list(conn) == []
    counts = run_classify(conn, log=quiet)
    assert (counts["full"], counts["rescored"]) == (True, 1)
    assert flagged_list(conn) == ["Hello-10-17-9"]


def test_a_stale_flag_on_an_older_snapshot_is_cleared(conn, monkeypatch):
    # The false positives of 22 November: flagged once, and a re-poll has since added a snapshot.
    import graphwatch.cli as cli

    old_snapshot = with_an_older_flagged_snapshot(conn, "PayPal-10-31-12", "PayPal", "", "example.ua@gmail.com write to us", 5)
    assert flagged_list(conn) == ["PayPal-10-31-12"]
    # A run that is stopped while it scores the older snapshots is not a
    # complete one: the run after it scores every page, and clears the flag
    real_save_labels = cli.save_labels

    def stop_at_the_older_snapshot(conn_, snapshot_id, *args):
        if snapshot_id == old_snapshot:
            raise KeyboardInterrupt
        return real_save_labels(conn_, snapshot_id, *args)

    monkeypatch.setattr(cli, "save_labels", stop_at_the_older_snapshot)
    with pytest.raises(KeyboardInterrupt):
        run_classify(conn, log=quiet)
    conn.rollback()
    monkeypatch.undo()
    assert flagged_list(conn) == ["PayPal-10-31-12"]
    assert run_classify(conn, log=quiet)["full"] is True
    assert flagged_list(conn) == []
    assert conn.execute("SELECT COUNT(*) FROM scores WHERE flagged = 1").fetchone()[0] == 0


# --- classify and the ten-minute re-poll on one file (second review, 22 November) ---


def test_run_classify_commits_every_batch_and_the_rescored_snapshots(tmp_path, monkeypatch):
    monkeypatch.setattr("graphwatch.cli.CLASSIFY_BATCH", 2)
    writer = connect(tmp_path / "g.sqlite")
    for n in range(1, 6):
        put(writer, f"Hello-10-17-{n}", "Hello", "", f"note {n}")
    old_snapshot = with_an_older_flagged_snapshot(writer, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, 99)
    run_classify(writer, log=quiet)
    reader = connect(tmp_path / "g.sqlite")  # a second connection sees commits only
    assert reader.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 7
    assert reader.execute("SELECT COUNT(*) FROM labels").fetchone()[0] > 0
    assert reader.execute("SELECT score FROM scores WHERE snapshot_id = ?", (old_snapshot,)).fetchone()[0] == 6
    reader.close()
    writer.close()


def test_run_classify_holds_nothing_open_between_reading_a_batch_and_writing_it(tmp_path, monkeypatch):
    # The re-poll writes to the same file every ten minutes. Classify used to
    # write with its own read cursor still open; SQLite then fails the write
    # at once with "database is locked" if another process wrote in between,
    # whatever the timeout. Here another connection writes at the start of
    # every batch's write-out, as the re-poll would between two batches. A
    # batch that was not committed before the next was read would still be an
    # open transaction there, and the intrusion would not be made.
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


# --- --explain ---


def test_run_explain_of_a_flagged_page_lists_its_labels_its_hits_by_category_and_its_indicators(mixed):
    run_classify(mixed, log=quiet)
    lines = explain(mixed, "Hello-10-17-9")
    assert lines[:6] == [
        "Hello-10-17-9: score 6, flagged",
        "  title: www.tenable.com@agfc.harper18.workers.dev/",
        "  labels: resolver (primary), pointer, placeholder",
        "  resolver +6",
        "    +5 userinfo_spoof         www.tenable.com@agfc.harper18.workers.dev",
        "    +1 api_sample_body        Hello,+world!",
    ]
    # the categories come in category order, each with its score and its own hits under it
    headings = [line for line in lines[3:] if not line.startswith("    ")]
    assert headings[:3] == ["  resolver +6", "  pointer +4", "  placeholder +4"]
    tunnel_at = next(i for i, line in enumerate(lines) if "+3 tunnel_host" in line)
    assert lines.index("  pointer +4") < tunnel_at < lines.index("  placeholder +4")
    assert lines[-2:] == [
        "  decoy www.tenable.com (title)",
        "  host  agfc.harper18.workers.dev (title)",
    ]


def test_run_explain_of_an_unflagged_page_shows_signed_weights_near_misses_and_no_indicators(mixed):
    run_classify(mixed, log=quiet)
    lines = explain(mixed, "Mimikatz-10-17")
    assert lines[:6] == [
        "Mimikatz-10-17: score -3, not flagged",
        "  title: Mimikatz",
        "  labels: template_spam (primary)",
        "  resolver -3",
        # a rule that matched more than once says how often
        "    -1 telegram_link          t.me/ x3",
        "    -2 templated_body         body " + hashlib.sha256(SQUATTER_BODY.encode("utf-8")).hexdigest()[:12],
    ]
    assert "  template_spam +4" in lines
    assert "  telegram_funnel +2" in lines  # a near miss is shown with its score
    assert lines[-1] == "    +2 telegram_invite        t.me/+YztOEovieQIzZjY8 x3"  # no indicators follow


def test_run_explain_says_how_often_only_for_a_rule_that_matched_more_than_once(conn):
    link = "https://t.me/+YztOEovieQIzZjY8"
    put(conn, "Once-10-17", "Once", "", f"{link} is where the rest of it is posted, come and see")
    put(conn, "Twice-10-17", "Twice", "", f"{link} and again {link} is where the rest of it is posted")
    run_classify(conn, log=quiet)
    assert "    -1 telegram_link          t.me/" in explain(conn, "Once-10-17")
    assert "    -1 telegram_link          t.me/ x2" in explain(conn, "Twice-10-17")


def test_run_explain_says_none_for_a_page_with_no_label(mixed):
    run_classify(mixed, log=quiet)
    assert explain(mixed, "Notes-10-17") == [
        "Notes-10-17: score 0, not flagged",
        "  title: Notes",
        "  labels: none",
    ]


def test_run_explain_never_prints_a_clear_password(mixed):
    # The combo list was hashed when it was stored, so the rules never saw a password
    text = mixed.execute(
        "SELECT s.text FROM snapshots s JOIN pages p ON p.id = s.page_id WHERE p.path = ?",
        ("Accounts-10-17",),
    ).fetchone()[0]
    assert "hunter" not in text
    assert text.count("SECRET{") == 4
    run_classify(mixed, log=quiet)
    out = "\n".join(explain(mixed, "Accounts-10-17"))
    assert "+4 combo_lines            user0@mail.example.com:SECRET{ x4" in out
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
    assert lines[-2:] == ["  retired rule", "    +2 old_rule               something"]


def test_run_explain_shows_only_the_resolver_score_of_a_held_out_page(mixed):
    # Synthetic held-out rows: one resolver shape and one combo list. No title,
    # label, category, hit or indicator: a rule could be written from any of them.
    put(mixed, "Known-01-02", SPOOF_TITLE, API_SAMPLE, API_SAMPLE, held_out=True)
    put(mixed, "Known-01-03", "Accounts", "", COMBO_BODY, held_out=True)
    run_classify(mixed, log=quiet)
    assert explain(mixed, "Known-01-02") == [
        "Known-01-02: score 6, flagged",
        "held-out page: evidence withheld",
    ]
    assert explain(mixed, "Known-01-03") == [
        "Known-01-03: score 1, not flagged",
        "held-out page: evidence withheld",
    ]


def test_run_explain_says_so_when_there_is_no_score(swept):
    lines = []
    assert run_explain(swept, "Hello-10-17-9", log=lines.append) is False  # stored, not classified
    assert run_explain(swept, "Nope-01-01", log=lines.append) is False  # not stored
    assert lines == [
        "Hello-10-17-9: no score stored, run classify first",
        "Nope-01-01: no score stored, run classify first",
    ]


# --- the command ---


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("this command must not build a client")

    monkeypatch.setattr("graphwatch.cli.TelegraphClient", refuse)
    monkeypatch.setattr("graphwatch.cli.FeedClient", refuse)


@pytest.fixture
def classify_db(tmp_path):
    """A database file with a spoof page, an API test page, a proxy list and a plain page."""
    db = tmp_path / "g.sqlite"
    c = connect(db)
    put(c, "Hello-10-17-9", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    put(c, "Hello-10-17-7", "Hello", API_SAMPLE, API_SAMPLE)
    put(c, "Proxy-10-17", "Proxy", "", PROXY_BODY)
    put(c, "Notes-10-17", "Notes", "", PLAIN_BODY)
    c.close()
    return db


def test_main_classify_needs_no_client_config_or_wordlists(classify_db, capsys, no_network):
    main(["--config", str(classify_db.parent / "missing.env"), "classify", "--db", str(classify_db)])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "classified 4 pages at threshold 4: 1 flagged, 2 near misses, 0 templated bodies"
    assert lines[1] == "held-out: 0/0 flagged"
    proxy = next(line for line in lines if line.split()[:1] == ["proxy_list"])
    assert proxy.split() == ["proxy_list", "labelled", "1,", "primary", "1,", "near", "misses", "0"]
    # then the unlabelled share, the score distribution in order, and the run time
    assert lines[-6].split() == ["unlabelled", "1", "(25.0%", "of", "pages)"]
    assert lines[-5] == "scored every page: 4 snapshots, and 0 older ones again"
    assert lines[-4:-1] == ["  score +0: 1", "  score +1: 2", "  score +6: 1"]
    assert re.fullmatch(SECONDS, lines[-1])


def test_main_classify_threshold_full_and_workers_options(classify_db, capsys, no_network, monkeypatch):
    main(["classify", "--db", str(classify_db), "--threshold", "1"])
    assert "at threshold 1: 3 flagged" in capsys.readouterr().out
    # the same threshold again is an ordinary night, unless --full says otherwise
    main(["classify", "--db", str(classify_db), "--threshold", "1"])
    assert "scored 0 new or changed snapshots" in capsys.readouterr().out
    started = []

    def scorer(templated, threshold, workers):
        started.append((threshold, workers))
        return Scorer(templated, threshold, 1)

    monkeypatch.setattr("graphwatch.cli.Scorer", scorer)
    main(["classify", "--db", str(classify_db), "--threshold", "1", "--full", "--workers", "3"])
    assert "scored every page: 4 snapshots" in capsys.readouterr().out
    assert started == [(1, 3)]
    # at 0 every page with no hit at all would be flagged and re-polled
    with pytest.raises(SystemExit, match="--threshold has to be 1 or more"):
        main(["classify", "--db", str(classify_db), "--threshold", "0"])


def test_main_classify_explain_reads_the_stored_result(classify_db, capsys, no_network):
    main(["classify", "--db", str(classify_db)])
    capsys.readouterr()
    main(["classify", "--db", str(classify_db), "--explain", "Proxy-10-17"])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "Proxy-10-17: score 1, not flagged"
    assert lines[2] == "  labels: proxy_list (primary)"
    assert "  proxy_list +5" in lines
    assert not any("classified" in line for line in lines)  # explain does not rescore


# --------------------------------------------------------------------------
# re-sweep (issue #37): run_resweep and sweep --resweep
# (plan/resweep-plan-2026-11-04.md)
# --------------------------------------------------------------------------


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


def test_run_resweep_of_unchanged_pages_moves_last_seen_and_keeps_only_the_view_count(stored):
    # Decided 22 November: a page polled every ten minutes would otherwise
    # add 144 identical rows a day. A view count that ticked is not a change.
    live = {**LIVE, "Hello-10-17-2": live_page("second", views=40)}
    client, session = make_resweep_client(live)
    lines = []
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert sorted(session.paths) == sorted(LIVE)
    assert counts == {"refreshed": 3, "changed": 0, "gone": 0, "failed": 0}
    assert lines == []
    run_resweep(stored, client, everything(stored), KEY, log=lines.append)  # ten minutes later
    assert snapshots_of(stored, "Hello-10-17-2") == [("second", 1)]
    assert views_of(stored, "Hello-10-17-2") == [40, 40]
    assert last_seen(stored, "Hello-10-17-2") > T0
    assert stored.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 3
    for path in LIVE:
        assert kinds(stored, path) == ["discovered"]


def test_run_resweep_reports_a_rotation_once_as_a_content_changed_event(stored):
    # The actor's shape: the same page, a new address in the title.
    live = {**LIVE, "Hello-10-17-1": live_page("9.9.9.9 first")}
    client, _ = make_resweep_client(live)
    lines = []
    before = time.time()
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert counts == {"refreshed": 3, "changed": 1, "gone": 0, "failed": 0}
    assert lines == ["Hello-10-17-1: content changed"]
    # the event carries the time of the fetch that saw the change
    ts = stored.execute("SELECT ts FROM events WHERE kind = 'content_changed'").fetchone()[0]
    assert before <= ts <= time.time()
    assert ts == last_seen(stored, "Hello-10-17-1")
    # the next poll sees the same page and reports nothing
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert counts["changed"] == 0
    assert kinds(stored, "Hello-10-17-1") == ["discovered", "content_changed"]
    assert [title for title, _ in snapshots_of(stored, "Hello-10-17-1")] == [
        "8.8.8.8 first",
        "9.9.9.9 first",
    ]


def test_a_page_that_changes_back_is_a_second_change(stored):
    live = dict(LIVE)
    client, _ = make_resweep_client(live)
    live["Hello-10-17-1"] = live_page("9.9.9.9 first")
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    live["Hello-10-17-1"] = live_page("8.8.8.8 first")
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts["changed"] == 1
    assert kinds(stored, "Hello-10-17-1").count("content_changed") == 2


def test_run_resweep_marks_a_deleted_page_gone_and_does_not_ask_for_it_again(stored):
    live = {path: page for path, page in LIVE.items() if path != "Hello-10-17-2"}
    client, session = make_resweep_client(live)
    lines = []
    counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    assert counts == {"refreshed": 2, "changed": 0, "gone": 1, "failed": 0}
    assert lines == ["Hello-10-17-2: gone"]
    # what was stored stays, and last_seen is the last time the page was there
    assert snapshots_of(stored, "Hello-10-17-2") == [("second", 1)]
    assert last_seen(stored, "Hello-10-17-2") == T0
    session.paths.clear()
    run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert "Hello-10-17-2" not in session.paths
    assert kinds(stored, "Hello-10-17-2") == ["discovered", "gone"]


def test_run_resweep_a_failed_fetch_changes_nothing_and_is_first_in_line_next_time(stored):
    client, _ = make_resweep_client(dict(LIVE), failing={"Hello-10-17-2"})
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts == {"refreshed": 2, "changed": 0, "gone": 0, "failed": 1}
    assert last_seen(stored, "Hello-10-17-2") == T0
    assert len(snapshots_of(stored, "Hello-10-17-2")) == 1
    # a failure is never taken for a deletion
    assert kinds(stored, "Hello-10-17-2") == ["discovered"]
    assert everything(stored)[0]["path"] == "Hello-10-17-2"


def test_run_resweep_budget_exceeded_is_logged_and_the_unfetched_tail_is_left(stored):
    cutoff = time.time() - 1
    client, session = make_resweep_client(dict(LIVE), budget=2)
    lines = []
    counts = run_resweep(stored, client, resweep_paths(stored, cutoff), KEY, log=lines.append)
    assert counts["refreshed"] == 2
    assert lines == ["budget exceeded"]
    assert len(session.paths) == 2
    left = [row["path"] for row in resweep_paths(stored, cutoff)]
    assert left == sorted(set(LIVE) - set(session.paths))
    assert len(left) == 1


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
    assert hash_secret("hunter2", KEY) in text  # hashed, and with the key the re-sweep was given


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


def test_run_resweep_counts_a_page_nested_too_deep_as_failed_and_goes_on(stored):
    live = {**LIVE, "Hello-10-17-1": {"title": "t", "description": "", "views": 1, "content": [nested(3000)]}}
    client, _ = make_resweep_client(live)
    lines = []
    try:
        counts = run_resweep(stored, client, everything(stored), KEY, log=lines.append)
    except RecursionError:
        counts = None  # caught here: pytest takes over a minute to report a traceback this deep
    assert counts == {"refreshed": 2, "changed": 0, "gone": 0, "failed": 1}
    assert lines == ["Hello-10-17-1: nested too deep to redact, not stored"]
    assert last_seen(stored, "Hello-10-17-1") == T0
    assert len(snapshots_of(stored, "Hello-10-17-1")) == 1


def test_run_resweep_undoes_what_was_written_before_the_overflow(stored, monkeypatch):
    # refresh_snapshot moves last_seen, then stores the snapshot, which redacts the
    # page again one call deeper. A page right at the recursion limit passes the
    # first redaction and overflows in the second. Which depth that is depends on
    # the stack, so the overflow is placed here and not served.
    def overflow_after_the_first_write(conn, page_id, page, ts, key):
        conn.execute("UPDATE pages SET last_seen = ? WHERE id = ?", (ts, page_id))
        raise RecursionError

    monkeypatch.setattr("graphwatch.cli.refresh_snapshot", overflow_after_the_first_write)
    client, _ = make_resweep_client(dict(LIVE))
    counts = run_resweep(stored, client, everything(stored), KEY, log=quiet)
    assert counts == {"refreshed": 0, "changed": 0, "gone": 0, "failed": 3}
    assert not stored.in_transaction
    assert last_seen(stored, "Hello-10-17-1") == T0


# --- the command ---


def resweep_argv(workdir, *extra):
    # A re-sweep reads no word list: the directory named here does not exist.
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
    run_classify(c, log=quiet)  # the title with a public IP flags
    c.close()
    return workdir


@pytest.fixture
def resweep_call(monkeypatch):
    """Replaces run_resweep; the work list and the key main handed it are in the dict."""
    seen = {}

    def fake_run_resweep(conn, client, pages, key, log=print):
        seen.update(paths=[row["path"] for row in pages], key=key)
        return {"refreshed": 1, "changed": 1, "gone": 0, "failed": 0}

    monkeypatch.setattr("graphwatch.cli.run_resweep", fake_run_resweep)
    return seen


def test_main_resweep_prints_the_header_and_the_summary(stored_file, capsys):
    main(resweep_argv(stored_file))
    header, stop, summary = capsys.readouterr().out.splitlines()
    assert header == "Resweep: all days, Pages: 3, Older than: 20h, Budget: 0"
    assert stop == "budget exceeded"
    assert re.fullmatch(
        rf"refreshed 0 pages, 0 changed, 0 gone, 0 failed, 0 requests, {SECONDS}", summary
    )


# Every filter narrows the count in the header and the list that is fetched, alike.
@pytest.mark.parametrize(
    "filters, window, paths",
    [
        ([], "all days", ["Hello-10-17-1", "Hello-10-17-2", "Hello-10-17-3"]),
        (["--flagged"], "all days", ["Hello-10-17-1"]),
        (["--match", "second"], "all days", ["Hello-10-17-2"]),
        (["--match", "no such text anywhere"], "all days", []),
        (
            ["--days", "2", "--today", "2026-10-18"],
            "2 days, From: 10-17 to 10-18",
            ["Hello-10-17-1", "Hello-10-17-2", "Hello-10-17-3"],
        ),
        (["--days", "2", "--today", "2026-11-01"], "2 days, From: 10-31 to 11-01", []),
    ],
)
def test_main_resweep_hands_run_resweep_the_filtered_work_list_and_the_key(
    stored_file, resweep_call, capsys, filters, window, paths
):
    main(resweep_argv(stored_file, *filters))
    header, summary = capsys.readouterr().out.splitlines()
    assert header == f"Resweep: {window}, Pages: {len(paths)}, Older than: 20h, Budget: 0"
    assert resweep_call == {"paths": paths, "key": CONFIG_KEY}
    assert summary.startswith("refreshed 1 pages, 1 changed, 0 gone, 0 failed, 0 requests, ")


def test_main_resweep_older_than_is_in_hours_and_zero_takes_every_page(stored_file, resweep_call, capsys):
    now = time.time()
    c = connect(stored_file / "g.sqlite")
    upsert_page(c, "Hello-10-17-1", now - 5)  # seen five seconds ago
    # A thousand hours, so that five minutes either side of the cutoff are enough
    # to tell 3,600 seconds an hour from anything near it
    upsert_page(c, "Hello-10-17-2", now - 1000 * HOUR + 300)
    upsert_page(c, "Hello-10-17-3", now - 1000 * HOUR - 300)
    c.close()
    main(resweep_argv(stored_file, "--older-than", "1000"))
    assert resweep_call["paths"] == ["Hello-10-17-3"]
    assert "Pages: 1, Older than: 1000h" in capsys.readouterr().out
    # The ten-minute cron line: sweep --resweep --flagged --older-than 0
    main(resweep_argv(stored_file, "--older-than", "0", "--flagged"))
    assert resweep_call["paths"] == ["Hello-10-17-1"]
    assert "Pages: 1, Older than: 0h" in capsys.readouterr().out
    main(resweep_argv(stored_file, "--older-than", "0"))
    assert resweep_call["paths"] == ["Hello-10-17-3", "Hello-10-17-2", "Hello-10-17-1"]  # oldest first


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
    pairs in `known` and the given status for the feeds in `broken`.

    `first` gives a feed's first lookups a status each, an exception to raise,
    or None to answer that one as usual. A key check is answered with
    `key_status` and kept apart in `key_checks`, so `calls` holds lookups only;
    `order` has both, as ("check" or "lookup", feed).
    """

    def __init__(self, known=(), broken=None, first=None, key_status=200):
        self.known = set(known)
        self.broken = dict(broken or {})
        self.first = {feed: list(answers) for feed, answers in (first or {}).items()}
        self.key_status = key_status
        self.calls = []
        self.key_checks = []
        self.order = []

    def request(self, method, url, **kwargs):
        feed = next(name for name, host in FEED_HOST.items() if host in url)
        if url.endswith("/user/me"):
            self.key_checks.append(feed)
            self.order.append(("check", feed))
            return FeedResp(self.key_status, b"{}")
        sent = json.dumps([url, kwargs.get("json"), kwargs.get("data")])
        self.calls.append((feed, sent))
        self.order.append(("lookup", feed))
        if self.first.get(feed):
            answer = self.first[feed].pop(0)
            if isinstance(answer, Exception):
                raise answer
            if answer is not None:
                return FeedResp(answer, b"{}")
        if feed in self.broken:
            return FeedResp(self.broken[feed], b"{}")
        for known_feed, value in self.known:
            if known_feed == feed and value in sent:
                return FeedResp(200, feed_hit(feed, value))
        return FeedResp(200, feed_miss(feed))

    def asked(self, feed) -> int:
        return sum(1 for name, _sent in self.calls if name == feed)


def make_feed_client(known=(), broken=None, keys=FEED_KEYS, first=None, key_status=200, **kwargs):
    session = EnrichSession(known, broken, first, key_status)
    client = FeedClient(keys, session=session, sleep=lambda s: None, **kwargs)
    return client, session


@pytest.fixture
def indicators(conn):
    """Two stored indicators, both addresses, with nothing looked up yet."""
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
    assert counts == {"looked_up": 8, "cached": 0, "known": 0, "unknown": 8, "failed": 0, "retried": 0, "set_aside": 0}
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


def test_run_enrich_does_not_ask_again_and_keeps_the_answer_and_the_day_it_was_given(indicators):
    # Novelty is measured on the day the indicator was found.
    client, _ = make_feed_client()
    run_enrich(indicators, client, log=quiet)
    before = [tuple(r) for r in indicators.execute("SELECT * FROM feed_lookups ORDER BY rowid")]
    later, session = make_feed_client(known={("threatfox", "8.8.8.8")})
    counts = run_enrich(indicators, later, log=quiet)
    # nothing at all is sent, not even a key check: there is nothing to ask
    assert session.order == []
    assert counts == {"looked_up": 0, "cached": 8, "known": 0, "unknown": 0, "failed": 0, "retried": 0, "set_aside": 0}
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


def test_run_enrich_asks_only_the_feeds_it_has_a_key_for_and_a_feed_added_later_catches_up(indicators):
    first, session = make_feed_client(keys={"threatfox": "a", "otx": "o"})
    counts = run_enrich(indicators, first, log=quiet)
    assert counts["looked_up"] == 4
    assert {feed for feed, _sent in session.calls} == {"threatfox", "otx"}
    full, session = make_feed_client()
    counts = run_enrich(indicators, full, log=quiet)
    assert (counts["looked_up"], counts["cached"]) == (4, 4)
    assert {feed for feed, _sent in session.calls} == {"urlhaus", "virustotal"}


def test_run_enrich_a_failed_lookup_stores_nothing_and_is_tried_again(indicators):
    # A failure never becomes a verdict: stored as UNKNOWN it would count as novel.
    client, session = make_feed_client(broken={"urlhaus": 500})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert (counts["failed"], counts["unknown"]) == (2, 6)
    assert not any(feed == "urlhaus" for _value, feed, _verdict in stored_lookups(indicators))
    # each one fails in its turn and once more at the end of the run
    assert lines == [
        "urlhaus 8.8.8.8: 500: unexpected answer",
        "urlhaus 9.9.9.9: 500: unexpected answer",
        "urlhaus 8.8.8.8: 500: unexpected answer again, left for the next run",
        "urlhaus 9.9.9.9: 500: unexpected answer again, left for the next run",
    ]
    assert (counts["looked_up"], counts["retried"], session.asked("urlhaus")) == (8, 2, 4)
    mended, session = make_feed_client()
    counts = run_enrich(indicators, mended, log=quiet)
    assert (counts["looked_up"], counts["cached"]) == (2, 6)
    assert session.asked("urlhaus") == 2


def test_run_enrich_leaves_a_feed_alone_once_its_quota_is_spent(indicators):
    client, session = make_feed_client(broken={"virustotal": 429})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert session.asked("virustotal") == 1  # not once per indicator
    assert lines == ["virustotal: quota spent, left for the next run"]
    assert counts["failed"] == 1
    # and no answer is stored for it: stored as UNKNOWN it would count towards novel
    assert not any(feed == "virustotal" for _value, feed, _verdict in stored_lookups(indicators))
    assert session.asked("threatfox") == 2  # the other feeds carry on


def test_run_enrich_budget_exceeded_is_logged_and_what_was_asked_is_kept(indicators):
    # The key check is a request too: four requests are one check and three lookups
    client, session = make_feed_client(budget=4)
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines == ["budget exceeded"]
    assert counts["looked_up"] == 3
    assert len(stored_lookups(indicators)) == 3
    rest, session = make_feed_client()
    counts = run_enrich(indicators, rest, log=quiet)
    assert (counts["looked_up"], counts["cached"]) == (5, 3)


def test_run_enrich_with_no_budget_sends_nothing_not_even_the_key_check(indicators):
    client, session = make_feed_client(budget=0)
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines == ["budget exceeded"]
    assert session.order == []
    assert counts["looked_up"] == 0

    # Everything is cached, so nothing has to be sent and the budget is never met
    client, _ = make_feed_client()
    run_enrich(indicators, client, log=quiet)
    later, session = make_feed_client(budget=0)
    lines = []
    counts = run_enrich(indicators, later, log=lines.append)
    assert (lines, session.order, counts["cached"]) == ([], [], 8)


# --- a key the feed does not accept ---


def test_run_enrich_checks_the_otx_key_once_before_its_first_lookup(indicators):
    # OTX answers a lookup whatever the key, so only its own check shows a wrong one
    client, session = make_feed_client()
    run_enrich(indicators, client, log=quiet)
    assert session.order[:4] == [
        ("lookup", "threatfox"),
        ("lookup", "urlhaus"),
        ("check", "otx"),
        ("lookup", "otx"),
    ]
    assert session.key_checks == ["otx"]


def test_run_enrich_does_not_ask_a_feed_whose_key_check_was_refused(indicators):
    client, session = make_feed_client(key_status=403)
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines == ["otx: key refused (OTX_KEY), not asked in this run"]
    assert "made-up" not in lines[0]
    assert session.asked("otx") == 0
    assert not any(feed == "otx" for _value, feed, _verdict in stored_lookups(indicators))
    # the other feeds carry on, and nothing counts as failed: nothing was looked up there
    assert counts == {"looked_up": 6, "cached": 0, "known": 0, "unknown": 6, "failed": 0, "retried": 0, "set_aside": 1}

    # the key is checked again on a refresh, and what is stored is kept if it is refused
    client, _ = make_feed_client(known={("otx", "8.8.8.8")})
    run_enrich(indicators, client, log=quiet)
    later, session = make_feed_client(key_status=403)
    run_enrich(indicators, later, refresh=True, log=quiet)
    assert session.asked("otx") == 0
    assert ("8.8.8.8", "otx", "KNOWN") in stored_lookups(indicators)


@pytest.mark.parametrize("key_status", [500, 429, 404])
def test_run_enrich_carries_on_when_the_key_check_gives_no_clear_answer(indicators, key_status):
    # Only a refusal stops the feed: its lookups are right whatever the check said
    client, session = make_feed_client(key_status=key_status)
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    # and it says so once: a wrong key would otherwise go unnoticed on this run
    assert lines == ["otx: the key check gave no clear answer, the key is not verified"]
    assert (session.asked("otx"), counts["unknown"]) == (2, 8)
    assert session.key_checks == ["otx"]


@pytest.mark.parametrize(
    "feed,status,name",
    [("virustotal", 401, "VT_KEY"), ("threatfox", 403, "ABUSE_CH_KEY"), ("urlhaus", 403, "ABUSE_CH_KEY")],
)
def test_run_enrich_leaves_a_feed_alone_once_it_refuses_two_lookups_running(indicators, feed, status, name):
    upsert_indicator(indicators, "ip", "1.1.1.1", "pages", T0 + 120, T0 + 120, 1)
    client, session = make_feed_client(broken={feed: status})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert session.asked(feed) == 2  # not once per indicator, and not once more at the end
    assert lines == [
        f"{feed} 8.8.8.8: {status}: unexpected answer",
        f"{feed} 9.9.9.9: {status}: unexpected answer",
        f"{feed}: refused 2 lookups running, its key ({name}) or this address is not accepted; "
        "not asked in this run",
    ]
    assert (counts["looked_up"], counts["failed"], counts["retried"], counts["unknown"]) == (11, 2, 0, 9)
    assert "made-up" not in " ".join(lines)  # the lines name the config variable, never the key
    assert not any(stored == feed for _value, stored, _verdict in stored_lookups(indicators))


@pytest.mark.parametrize("status", [401, 403])
def test_run_enrich_one_refusal_is_about_one_value_and_the_feed_carries_on(indicators, status):
    # Stopping at the first refusal would stop at the same indicator on every
    # later run too: it is not stored, and the indicators come in the same order.
    upsert_indicator(indicators, "ip", "1.1.1.1", "pages", T0 + 120, T0 + 120, 1)
    client, session = make_feed_client(first={"otx": [status]})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines == [f"otx 8.8.8.8: {status}: unexpected answer"]
    assert session.asked("otx") == 3  # the other two are asked, and the refused one is not asked again
    assert (counts["failed"], counts["retried"]) == (1, 0)
    assert ("9.9.9.9", "otx", "UNKNOWN") in stored_lookups(indicators)
    assert ("1.1.1.1", "otx", "UNKNOWN") in stored_lookups(indicators)
    # and refusals with an answer between them do not add up to a refused key
    upsert_indicator(indicators, "ip", "1.0.0.1", "pages", T0 + 180, T0 + 180, 1)
    client, session = make_feed_client(first={"urlhaus": [status, None, status]})
    lines = []
    run_enrich(indicators, client, refresh=True, log=lines.append)
    assert session.asked("urlhaus") == 4
    assert not any("not asked in this run" in line for line in lines)


# --- a feed that does not answer ---


def six_indicators(conn):
    for n, value in enumerate(["1.1.1.1", "1.0.0.1", "8.8.4.4", "9.9.9.10"], start=2):
        upsert_indicator(conn, "ip", value, "pages", T0 + 60 * n, T0 + 60 * n, 1)
    return conn


def test_run_enrich_leaves_a_feed_alone_after_five_lookups_running_get_no_answer(indicators):
    # A feed that is down costs a 20 second timeout per lookup, and each
    # second try would cost another
    six_indicators(indicators)
    client, session = make_feed_client(first={"otx": [requests.Timeout("timed out")] * 20})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert session.asked("otx") == 5  # the sixth is not asked, and no second try is made
    assert lines[-1] == "otx: no answer to 5 lookups running, left for the next run"
    assert len(lines) == 6
    assert (counts["looked_up"], counts["failed"], counts["retried"], counts["unknown"]) == (23, 5, 0, 18)
    assert session.asked("virustotal") == 6  # the other feeds carry on
    # a server error counts as no answer too
    client, session = make_feed_client(broken={"urlhaus": 503})
    lines = []
    run_enrich(indicators, client, refresh=True, log=lines.append)
    assert session.asked("urlhaus") == 5
    assert lines[-1] == "urlhaus: no answer to 5 lookups running, left for the next run"


def test_run_enrich_timeouts_with_answers_between_them_do_not_stop_the_feed(indicators):
    # What OTX really does: about one lookup in ten times out
    six_indicators(indicators)
    timeout = requests.Timeout("timed out")
    client, session = make_feed_client(first={"otx": [timeout, timeout, None, timeout, timeout, None]})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert not any("left for the next run" in line for line in lines)
    assert (counts["failed"], counts["retried"], counts["unknown"]) == (0, 4, 24)
    assert session.asked("otx") == 10


@pytest.mark.parametrize("status", [404, 400])
def test_run_enrich_makes_no_second_try_for_an_answer_that_will_not_change(indicators, status):
    # Asked again a minute later the feed would say the same, at the price of a request
    client, session = make_feed_client(broken={"urlhaus": status})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert session.asked("urlhaus") == 2
    assert lines == [
        f"urlhaus 8.8.8.8: {status}: unexpected answer",
        f"urlhaus 9.9.9.9: {status}: unexpected answer",
    ]
    assert (counts["failed"], counts["retried"]) == (2, 0)


# --- a failed lookup is tried once more when the others are done ---


@pytest.mark.parametrize("failure", [500, requests.Timeout("timed out"), requests.ConnectionError("reset")])
def test_run_enrich_tries_a_failed_lookup_once_more_at_the_end_and_keeps_its_answer(indicators, failure):
    client, session = make_feed_client(first={"otx": [failure]})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert len(lines) == 1 and lines[0].startswith("otx 8.8.8.8: ")
    # the second try comes after every other lookup, not straight away
    assert session.order[-1] == ("lookup", "otx")
    assert session.order.index(("lookup", "virustotal")) < len(session.order) - 1
    assert session.asked("otx") == 3
    assert counts == {"looked_up": 8, "cached": 0, "known": 0, "unknown": 8, "failed": 0, "retried": 1, "set_aside": 0}
    assert ("8.8.8.8", "otx", "UNKNOWN") in stored_lookups(indicators)
    assert len(stored_lookups(indicators)) == 8


def test_run_enrich_a_second_try_that_finds_the_indicator_stores_and_logs_it(indicators):
    client, _ = make_feed_client(known={("otx", "8.8.8.8")}, first={"otx": [500]})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines == ["otx 8.8.8.8: 500: unexpected answer", "8.8.8.8: known to otx (3 pulses)"]
    assert (counts["known"], counts["unknown"], counts["failed"]) == (1, 7, 0)
    assert ("8.8.8.8", "otx", "KNOWN") in stored_lookups(indicators)


def test_run_enrich_tries_a_failed_lookup_only_once_more(indicators):
    client, session = make_feed_client(first={"otx": [500, None, 500, 500]})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    # 8.8.8.8 fails, 9.9.9.9 answers, then 8.8.8.8 fails its second try and is left
    assert session.asked("otx") == 3
    assert lines[-1] == "otx 8.8.8.8: 500: unexpected answer again, left for the next run"
    assert (counts["looked_up"], counts["failed"], counts["retried"]) == (8, 1, 1)
    assert ("8.8.8.8", "otx", "UNKNOWN") not in stored_lookups(indicators)


def test_run_enrich_makes_no_second_try_for_a_feed_that_was_set_aside_meanwhile(indicators):
    # 8.8.8.8 fails, then 9.9.9.9 finds the quota spent: the second try would only spend more
    client, session = make_feed_client(first={"virustotal": [500, 429]})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert session.asked("virustotal") == 2
    assert lines == [
        "virustotal 8.8.8.8: 500: unexpected answer",
        "virustotal: quota spent, left for the next run",
    ]
    assert (counts["looked_up"], counts["failed"], counts["retried"]) == (8, 2, 0)
    # the same when the feed was set aside for refusing two lookups running
    upsert_indicator(indicators, "ip", "1.1.1.1", "pages", T0 + 120, T0 + 120, 1)
    client, session = make_feed_client(first={"urlhaus": [500, 403, 403]})
    lines = []
    counts = run_enrich(indicators, client, refresh=True, log=lines.append)
    assert session.asked("urlhaus") == 3
    assert sum("not asked in this run" in line for line in lines) == 1
    assert (counts["failed"], counts["retried"]) == (3, 0)


def test_run_enrich_a_second_try_can_find_the_quota_spent_or_be_refused(indicators):
    client, session = make_feed_client(first={"virustotal": [500, None, 429]})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines[-1] == "virustotal: quota spent, left for the next run"
    assert (counts["failed"], counts["retried"]) == (1, 1)
    refused, session = make_feed_client(first={"urlhaus": [500, None, 403]})
    lines = []
    counts = run_enrich(indicators, refused, refresh=True, log=lines.append)
    assert lines[-1] == "urlhaus 8.8.8.8: 403: unexpected answer again, left for the next run"
    assert (counts["failed"], counts["retried"]) == (1, 1)


def test_run_enrich_budget_exceeded_in_the_second_tries_keeps_the_counts_adding_up(indicators):
    # one key check, eight lookups, and nothing left for the second try
    client, session = make_feed_client(first={"otx": [500]}, budget=9)
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines == ["otx 8.8.8.8: 500: unexpected answer", "budget exceeded"]
    assert counts == {"looked_up": 8, "cached": 0, "known": 0, "unknown": 7, "failed": 1, "retried": 0, "set_aside": 0}


# --- the command ---


def test_main_enrich_table_prints_the_stored_table_and_builds_no_client(tmp_path, capsys, no_network):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    indicator_id = upsert_indicator(c, "ip", "8.8.8.8", "pages", T0, T0, 4)
    save_lookup(c, indicator_id, "threatfox", "UNKNOWN", None, T0)
    save_lookup(c, indicator_id, "otx", "UNKNOWN", None, T0)
    c.close()
    main(["--config", str(tmp_path / "missing.env"), "enrich", "--db", str(db), "--table"])
    out = capsys.readouterr().out
    assert out.startswith("| Indicator | Kind | First seen | Pages | Titles | ThreatFox |")
    assert "| `8.8.8[.]8` | ip |" in out
    assert "1 indicators: 1 novel, 0 known, 0 unchecked." in out
    assert "8.8.8.8" not in out


def test_main_enrich_without_a_config_file_exits_naming_the_path(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(tmp_path / "missing.env"), "enrich", "--db", str(tmp_path / "g.sqlite")])
    assert "missing.env" in str(exc.value)


def test_main_enrich_without_any_feed_key_exits_naming_the_keys(tmp_path, no_network):
    config = tmp_path / "config.env"
    config.write_text(CONFIG_LINE, encoding="utf-8")
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


def test_main_enrich_looks_up_the_flagged_pages_indicators_and_never_shows_a_key(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir))
    captured = capsys.readouterr()
    skipped, found, looked_up, verdicts = captured.out.splitlines()
    assert skipped == "no key for virustotal (VT_KEY), skipped"
    assert found == "1 indicators from flagged pages, 0 from the file, feeds: threatfox, urlhaus, otx"
    # five requests: the OTX key check, one lookup each for ThreatFox and
    # URLhaus, and two for OTX, which is asked for a host under two names
    assert re.fullmatch(
        rf"looked up 3, cached 0, known 0, unknown 3, failed 0, retried 0, 5 requests, {SECONDS}", looked_up
    )
    assert verdicts == "1 indicators: 1 novel, 0 known, 0 unchecked"
    sent = " ".join(sent for _feed, sent in session.calls)
    assert "agfc.harper18.workers.dev" in sent
    assert "tenable" not in sent  # the decoy is never looked up
    c = connect(workdir / "g.sqlite")
    # the indicator is stored with when and on how many pages it was seen
    assert [tuple(r) for r in c.execute("SELECT kind, value, source, first_seen, last_seen, pages FROM indicators")] == [
        ("host", "agfc.harper18.workers.dev", "pages", T0, T0, 1)
    ]
    # and with the title of the page that holds it, which the table then prints
    assert [tuple(r) for r in c.execute("SELECT slug, pages FROM indicator_titles")] == [("hello", 1)]
    # every request is in the http log, and no key is there or on the screen
    logged = [tuple(r) for r in c.execute("SELECT * FROM http_log")]
    paths = [r["path"] for r in c.execute("SELECT path FROM http_log ORDER BY id")]
    c.close()
    assert len(logged) == 5
    # the key is checked before OTX's first lookup, which is its third row from the end
    assert paths.index("otx:key check") == 2
    assert paths[3:] == ["otx:agfc.harper18.workers.dev"] * 2
    assert "made-up" not in json.dumps(logged) + captured.out + captured.err


def test_main_enrich_stores_every_title_an_indicator_is_under_and_the_table_prints_them(enrich_workdir, capsys):
    # The same address on a page that is not the actor's: the table has to show both
    workdir, _session = enrich_workdir
    c = connect(workdir / "g.sqlite")
    put(c, "botnet-11-20", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    put(c, "botnet-11-21", SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    run_classify(c, log=quiet)
    c.close()
    main(enrich_argv(workdir))
    c = connect(workdir / "g.sqlite")
    stored = [tuple(r) for r in c.execute("SELECT slug, pages FROM indicator_titles ORDER BY slug")]
    c.close()
    assert stored == [("botnet", 2), ("hello", 1)]
    capsys.readouterr()
    main(enrich_argv(workdir, "--table"))
    out = capsys.readouterr().out
    assert "| host | 2023-11-14 | 3 | botnet, hello |" in out
    assert (
        "By the title of the pages that hold them: botnet: 1 novel, 0 known, 0 unchecked; "
        "hello: 1 novel, 0 known, 0 unchecked (an indicator on pages of several titles counts under each)."
    ) in out


def test_main_enrich_budget_stops_the_lookups(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir, "--budget", "2"))
    out = capsys.readouterr().out
    assert len(session.order) == 2  # the key check and one lookup
    assert "budget exceeded" in out


def with_virustotal(workdir, session, virustotal_answers):
    """Adds a VirusTotal key to the config and a second indicator in a file,
    and scripts VirusTotal's first answers."""
    config = workdir / "config.env"
    config.write_text(config.read_text(encoding="utf-8") + "VT_KEY=vt-key-made-up\n", encoding="utf-8")
    listed = workdir / "indicators.tsv"
    listed.write_text("kind\tvalue\nhost\tprobe-only.trycloudflare.com\n", encoding="utf-8")
    session.first = {"virustotal": list(virustotal_answers)}
    return listed


def test_main_enrich_a_run_cut_short_by_a_quota_does_not_print_more_novel_indicators(enrich_workdir, capsys):
    # The defect of 23 November: with VirusTotal's quota spent part of the way,
    # the indicators it was never asked about were printed as novel.
    workdir, session = enrich_workdir
    listed = with_virustotal(workdir, session, [None, 429])
    with pytest.raises(SystemExit):
        main(enrich_argv(workdir, "--file", str(listed)))
    out = capsys.readouterr().out
    assert "virustotal: quota spent, left for the next run" in out
    assert out.splitlines()[-1] == "2 indicators: 1 novel, 0 known, 1 unchecked"
    main(enrich_argv(workdir, "--table"))
    assert "2 indicators: 1 novel, 0 known, 1 unchecked." in capsys.readouterr().out


def test_main_enrich_a_feed_cut_off_before_its_first_answer_is_still_waited_for(enrich_workdir, capsys):
    # Nothing of VirusTotal's is stored, and it has a key: both indicators wait for it
    workdir, session = enrich_workdir
    listed = with_virustotal(workdir, session, [429])
    with pytest.raises(SystemExit):
        main(enrich_argv(workdir, "--file", str(listed)))
    assert capsys.readouterr().out.splitlines()[-1] == "2 indicators: 0 novel, 0 known, 2 unchecked"
    main(enrich_argv(workdir, "--table"))
    out = capsys.readouterr().out
    assert "2 indicators: 0 novel, 0 known, 2 unchecked." in out
    assert "Novel means unknown to every one of: ThreatFox, URLhaus, OTX, VirusTotal." in out
    # The table printed where there is no config goes by the stored answers alone
    main(["--config", str(workdir / "missing.env"), "enrich", "--db", str(workdir / "g.sqlite"), "--table"])
    out = capsys.readouterr().out
    assert "2 indicators: 2 novel, 0 known, 0 unchecked." in out
    assert "Novel means unknown to every one of: ThreatFox, URLhaus, OTX." in out


# --- the exit status ---


def test_main_enrich_ends_with_a_failing_status_when_a_feed_was_left_alone(enrich_workdir, capsys):
    # Under cron nobody reads the lines: the status is what says the table is not whole
    workdir, session = enrich_workdir
    listed = with_virustotal(workdir, session, [None, 429])
    with pytest.raises(SystemExit) as stopped:
        main(enrich_argv(workdir, "--file", str(listed)))
    assert stopped.value.code == "1 feed was left alone part of the way, see above; run enrich again"
    out = capsys.readouterr().out
    # everything is printed and stored before it stops
    assert out.splitlines()[-1] == "2 indicators: 1 novel, 0 known, 1 unchecked"
    c = connect(workdir / "g.sqlite")
    assert c.execute("SELECT COUNT(*) FROM feed_lookups").fetchone()[0] == 7
    c.close()
    # and it counts every feed that was left alone: here OTX's key is refused as well
    session.first = {"virustotal": [429]}
    session.key_status = 403
    with pytest.raises(SystemExit) as stopped:
        main(enrich_argv(workdir, "--file", str(listed), "--refresh"))
    assert str(stopped.value.code).startswith("2 feeds were left alone")


def test_main_enrich_ends_normally_on_a_budget_stop_or_a_lookup_that_failed(enrich_workdir, capsys):
    # A budget stop is how a run is meant to end, and one failed lookup is tried again next run
    workdir, session = enrich_workdir
    main(enrich_argv(workdir, "--budget", "2"))
    session.first = {"otx": [404]}
    main(enrich_argv(workdir))
    assert "failed 1" in capsys.readouterr().out


@pytest.mark.parametrize(
    "broken,set_aside",
    [({}, 0), ({"virustotal": 429}, 1), ({"virustotal": 401, "urlhaus": 503}, 1), ({"virustotal": 429, "threatfox": 403}, 2)],
)
def test_run_enrich_counts_the_feeds_it_set_aside(indicators, broken, set_aside):
    # Two indicators: enough for two refusals in a row, not for five lookups with no answer
    client, _ = make_feed_client(broken=broken)
    assert run_enrich(indicators, client, log=quiet)["set_aside"] == set_aside


# --- an UNKNOWN is asked for once more when it is old enough ---

RECHECK_S = 14 * 86400.0


def test_run_enrich_asks_once_more_for_an_unknown_that_is_two_weeks_old(indicators):
    # ThreatFox listed this actor's indicators up to 14 days after the sweep had them
    first, _ = make_feed_client()
    run_enrich(indicators, first, log=quiet, recheck_s=RECHECK_S, clock=lambda: T0)
    # with no recheck age nothing is asked again, however old the answers are
    never, session = make_feed_client()
    run_enrich(indicators, never, log=quiet, clock=lambda: T0 + 10 * RECHECK_S)
    assert session.order == []
    early, session = make_feed_client(known={("threatfox", "8.8.8.8")})
    counts = run_enrich(indicators, early, log=quiet, recheck_s=RECHECK_S, clock=lambda: T0 + RECHECK_S - 1)
    assert (session.order, counts["cached"]) == ([], 8)
    due, session = make_feed_client(known={("threatfox", "8.8.8.8")})
    lines = []
    counts = run_enrich(indicators, due, log=lines.append, recheck_s=RECHECK_S, clock=lambda: T0 + RECHECK_S)
    assert (counts["looked_up"], counts["known"], counts["unknown"]) == (8, 1, 7)
    assert lines == ["8.8.8.8: known to threatfox (1 IOCs, Made-up RAT)"]
    # the new answer and its day are stored, and the first answer is kept beside it
    row = indicators.execute(
        "SELECT l.verdict, l.checked_at, f.verdict, f.checked_at FROM feed_lookups l "
        "JOIN first_lookups f USING (indicator_id, feed) JOIN indicators i ON i.id = l.indicator_id "
        "WHERE i.value = '8.8.8.8' AND l.feed = 'threatfox'"
    ).fetchone()
    assert tuple(row) == ("KNOWN", T0 + RECHECK_S, "UNKNOWN", T0)
    # once asked at that age it is not asked again, and a KNOWN never is
    later, session = make_feed_client()
    counts = run_enrich(indicators, later, log=quiet, recheck_s=RECHECK_S, clock=lambda: T0 + 10 * RECHECK_S)
    assert (session.order, counts["cached"]) == ([], 8)


def test_run_enrich_a_recheck_that_fails_keeps_the_stored_answer_and_stays_due(indicators):
    first, _ = make_feed_client()
    run_enrich(indicators, first, log=quiet, recheck_s=RECHECK_S, clock=lambda: T0)
    down, _ = make_feed_client(broken={"otx": 404})
    counts = run_enrich(indicators, down, log=quiet, recheck_s=RECHECK_S, clock=lambda: T0 + RECHECK_S)
    assert counts["failed"] == 2
    assert ("8.8.8.8", "otx", "UNKNOWN") in stored_lookups(indicators)
    mended, session = make_feed_client()
    counts = run_enrich(indicators, mended, log=quiet, recheck_s=RECHECK_S, clock=lambda: T0 + RECHECK_S + 60)
    assert (session.asked("otx"), counts["looked_up"]) == (2, 2)


@pytest.mark.parametrize("days,asked_again", [("14", True), ("0", False), ("30", False)])
def test_main_enrich_recheck_days_sets_the_age(enrich_workdir, capsys, days, asked_again):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir))
    c = connect(workdir / "g.sqlite")
    for table in ("feed_lookups", "first_lookups"):
        c.execute(f"UPDATE {table} SET checked_at = checked_at - ?", (15 * 86400,))
    c.commit()
    c.close()
    session.calls.clear()
    main(enrich_argv(workdir, "--recheck-days", days))
    assert bool(session.calls) is asked_again


def test_main_enrich_refresh_asks_again_for_what_is_stored(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir))
    session.calls.clear()
    capsys.readouterr()
    main(enrich_argv(workdir, "--refresh"))
    assert "looked up 3, cached 0," in capsys.readouterr().out
    assert len(session.calls) == 4  # as many requests as the first run made


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


def test_main_enrich_builds_no_telegraph_client(enrich_workdir, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise AssertionError("enrich must not build a Telegraph client")

    monkeypatch.setattr("graphwatch.cli.TelegraphClient", refuse)
    workdir, _session = enrich_workdir
    main(enrich_argv(workdir))
    assert "looked up 3" in capsys.readouterr().out


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


def test_main_enrich_a_second_run_keeps_every_indicator_and_asks_nothing(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    listed = workdir / "indicators.tsv"
    listed.write_text("kind\tvalue\nhost\tprobe-only.trycloudflare.com\n", encoding="utf-8")
    main(enrich_argv(workdir, "--file", str(listed)))
    session.calls.clear()
    capsys.readouterr()
    main(enrich_argv(workdir))  # the file is not passed this time
    out = capsys.readouterr().out
    assert "dropped" not in out
    assert session.calls == []
    assert "looked up 0, cached 6," in out
    c = connect(workdir / "g.sqlite")
    assert c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 2
    c.close()


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


# --------------------------------------------------------------------------
# several requests under way at once (23 November): whatever the number of
# workers, a run asks for the same pages, stores the same rows and prints
# the same lines as it does with one
# --------------------------------------------------------------------------

MANY = ENTRIES + [
    Entry(title, title, "made-up", False)
    for title in ("Alfa", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf")
]


def day_paths(slug, month, day, counters) -> set[str]:
    return {build_path(slug, month, day, None if n == 1 else n) for n in counters}


# Days of every shape a walk meets: long with holes, short, a page behind a
# hole, a page past the hole the crowd check stopped at, and none at all
CROWDED = (
    day_paths("Alfa", 10, 23, set(range(1, 41)) - {7, 8, 20})
    | day_paths("Bravo", 10, 24, {1, 2, 3})
    | day_paths("Charlie", 10, 23, {1, 2, 5})
    | day_paths("Echo", 10, 24, range(1, 18))
    | day_paths("Echo", 10, 23, {1})
    | day_paths("Hello", 10, 24, {1, 2})
    | day_paths("Golf", 10, 24, {1, 2, 3, 4, 9})
)


def table(conn, sql) -> list[tuple]:
    return [tuple(row) for row in conn.execute(sql)]


def crowd_run(workers, budget=None, conn=None):
    """One crowd check over MANY on its own database, with the request log in
    that database: a connection refuses any thread but the one that opened it."""
    conn = conn or connect(":memory:")
    session = PathSession(CROWDED)
    client = TelegraphClient(
        session=session, sleep=lambda s: None, retries=0, workers=workers, budget=budget, log=http_logger(conn)
    )
    lines = []
    checked = run_crowd(conn, client, MANY, DAYS, gap=2, log=lines.append)
    return {
        "conn": conn,
        "checked": checked,
        "lines": lines,
        "asked": sorted(session.paths),
        "requests": client.requests_made,
        "crowd": table(conn, "SELECT slug, month, day, highest, requests, failures FROM crowd ORDER BY slug, month, day"),
        "logged": conn.execute("SELECT COUNT(*) FROM http_log").fetchone()[0],
    }


@pytest.mark.parametrize("workers", [2, 4, 8])
def test_run_crowd_with_several_workers_counts_what_one_worker_counts(workers):
    one, many = crowd_run(1), crowd_run(workers)
    for part in ("checked", "lines", "asked", "requests", "crowd", "logged"):
        assert many[part] == one[part], part
    assert one["checked"] == len(MANY) * len(DAYS)
    assert one["logged"] == one["requests"] > 60


@pytest.mark.parametrize("workers", [1, 4])
def test_run_crowd_a_budget_stop_with_several_workers_loses_nothing_and_sends_no_more(workers):
    whole = crowd_run(1)
    cut = crowd_run(workers, budget=40)
    assert cut["lines"][-1] == "budget exceeded"
    assert cut["requests"] == cut["logged"] == 40
    # what was counted is counted right, and the next run finishes the rest
    assert set(cut["crowd"]) < set(whole["crowd"])
    rest = crowd_run(workers, conn=cut["conn"])
    assert rest["crowd"] == whole["crowd"]
    assert rest["checked"] == whole["checked"] - cut["checked"]


def sweep_run(workers, budget=None, conn=None, cap=None, failing=()):
    """One sweep over MANY, on the crowd counts a crowd check gave."""
    if conn is None:
        conn = crowd_run(1)["conn"]
        conn.execute("DELETE FROM http_log")
        conn.commit()
    session = SweepSession(CROWDED, failing)
    client = TelegraphClient(
        session=session, sleep=lambda s: None, retries=0, workers=workers, budget=budget, log=http_logger(conn)
    )
    lines = []
    stored, requests = run_sweep(conn, client, MANY, DAYS, KEY, 2, cap, set(), log=lines.append)
    return {
        "conn": conn,
        "stored": stored,
        "summed": requests,
        "lines": lines,
        "asked": sorted(session.paths),
        "requests": client.requests_made,
        "pages": table(conn, "SELECT path FROM pages ORDER BY id"),
        "snapshots": table(conn, "SELECT p.path, s.sha256 FROM snapshots s JOIN pages p ON p.id = s.page_id ORDER BY s.id"),
        "progress": table(
            conn, "SELECT slug, month, day, next_n, done, requests, failures FROM sweep_progress ORDER BY slug, month, day"
        ),
        "events": table(conn, "SELECT page_id, kind FROM events ORDER BY id"),
        "logged": conn.execute("SELECT COUNT(*) FROM http_log").fetchone()[0],
    }


SWEEP_PARTS = ("stored", "summed", "lines", "asked", "requests", "pages", "snapshots", "progress", "events", "logged")


@pytest.mark.parametrize("workers", [2, 4, 8])
def test_run_sweep_with_several_workers_stores_what_one_worker_stores(workers):
    one, many = sweep_run(1), sweep_run(workers)
    for part in SWEEP_PARTS:
        assert many[part] == one[part], part
    # every page is there, in counter order, and not one request more was made
    assert {path for (path,) in one["pages"]} == CROWDED
    assert one["logged"] == one["requests"]

    # and the same with a cap, and with failures in the walk and at its end
    failing = day_paths("Alfa", 10, 23, {3, 41, 42, 43}) | day_paths("Bravo", 10, 24, {4, 5, 6})
    for kwargs in ({"cap": 10}, {"failing": failing}):
        one, many = sweep_run(1, **kwargs), sweep_run(workers, **kwargs)
        for part in SWEEP_PARTS:
            assert many[part] == one[part], (part, kwargs)


@pytest.mark.parametrize("workers", [1, 4])
def test_run_sweep_a_budget_stop_with_several_workers_resumes_to_the_same_pages(workers):
    whole = sweep_run(1)
    cut = sweep_run(workers, budget=30)
    assert cut["lines"][-1] == "budget exceeded"
    assert cut["requests"] == cut["logged"] == 30
    # every page stored so far is one the walk reached, in the order it reached them
    assert cut["pages"] == whole["pages"][: len(cut["pages"])]
    rest = sweep_run(workers, conn=cut["conn"])
    assert rest["pages"] == whole["pages"]
    assert [row[:5] for row in rest["progress"]] == [row[:5] for row in whole["progress"]]
    # The last requests of a budget go to the next counters, not to later
    # ones fetched ahead: eight pages and a budget of five store the first five
    for _ in range(25):
        conn = connect(":memory:")
        seed_crowd(conn, [("Hello", 10, 23, 8)])
        session = SweepSession(day_paths("Hello", 10, 23, range(1, 9)))
        client = TelegraphClient(session=session, sleep=lambda s: None, retries=0, workers=workers, budget=5)
        stored, _ = run_sweep(conn, client, ENTRIES[:1], DAYS[:1], KEY, 2, None, set(), log=quiet)
        assert (stored, sorted(session.paths)) == (5, sorted(day_paths("Hello", 10, 23, range(1, 6))))


def resweep_run(workers, budget=None):
    conn = connect(":memory:")
    live = {f"Hello-10-17-{n}": live_page(f"title {n}") for n in range(2, 42)}
    for path, page in live.items():
        add_snapshot(conn, upsert_page(conn, path, T0), {"path": path, **page}, T0, KEY)
    for n in (5, 6, 20):
        live[f"Hello-10-17-{n}"] = live_page(f"rotated {n}")
    for n in (9, 30):
        del live[f"Hello-10-17-{n}"]
    session = ResweepSession(live, failing={"Hello-10-17-12", "Hello-10-17-13"})
    client = TelegraphClient(
        session=session, sleep=lambda s: None, retries=0, workers=workers, budget=budget, log=http_logger(conn)
    )
    lines = []
    counts = run_resweep(conn, client, everything(conn), KEY, log=lines.append)
    return {
        "counts": counts,
        "lines": lines,
        "asked": sorted(session.paths),
        "events": table(conn, "SELECT p.path, e.kind FROM events e JOIN pages p ON p.id = e.page_id ORDER BY e.id"),
        "snapshots": table(conn, "SELECT p.path, s.title FROM snapshots s JOIN pages p ON p.id = s.page_id ORDER BY s.id"),
        "views": table(conn, "SELECT p.path, v.views FROM views v JOIN pages p ON p.id = v.page_id ORDER BY p.path"),
        "logged": conn.execute("SELECT COUNT(*) FROM http_log").fetchone()[0],
    }


@pytest.mark.parametrize("workers", [2, 4, 8])
def test_run_resweep_and_run_meta_with_several_workers_record_what_one_worker_records(workers):
    one, many = resweep_run(1), resweep_run(workers)
    assert many == one
    assert one["counts"] == {"refreshed": 36, "changed": 3, "gone": 2, "failed": 2}
    assert one["logged"] == 40

    # and the same for the timestamps
    one, many = meta_run(1), meta_run(workers)
    assert many == one
    assert one["counts"] == {"fetched": 22, "changed": 0, "not_found": 6, "failed": 2}


def test_run_resweep_a_budget_stop_with_several_workers_keeps_every_answer_it_paid_for():
    cut = resweep_run(4, budget=10)
    assert cut["lines"][-1] == "budget exceeded"
    assert cut["logged"] == len(cut["asked"]) == 10
    counts = cut["counts"]
    assert counts["refreshed"] + counts["gone"] + counts["failed"] == 10


def meta_run(workers):
    conn = connect(":memory:")
    paths = [f"Hello-10-17-{n}" for n in range(2, 32)]
    rows = seed_pages(conn, paths)
    times = {path: ("2026-10-17T08:00:00+0000", f"2026-10-17T09:{n:02d}:00+0000") for n, path in enumerate(paths[:24])}
    session = HtmlSession(times, failing={paths[3], paths[4]})
    client = TelegraphClient(
        session=session, sleep=lambda s: None, retries=0, workers=workers, log=http_logger(conn)
    )
    lines = []
    counts = run_meta(conn, client, rows, log=lines.append)
    return {
        "counts": counts,
        "lines": lines,
        "asked": sorted(session.paths),
        "meta": table(conn, "SELECT path, published_at, modified_at FROM pages ORDER BY id"),
        "logged": conn.execute("SELECT COUNT(*) FROM http_log").fetchone()[0],
    }


# --- the option ---


def crowd_argv(workdir, *extra):
    return ["--config", str(workdir / "nope.env"), "crowd", *common(workdir, budget="5"),
            "--days", "1", "--today", "2026-11-01", *extra]


def test_main_gives_the_client_four_workers_or_as_many_as_asked_for(workdir, offline, capsys):
    main(crowd_argv(workdir))
    assert offline["workers"] == 4
    # more workers do not raise the rate: it is still the 8 a second of --rate
    assert offline["rate_per_s"] == 8.0
    main(crowd_argv(workdir, "--workers", "6"))
    assert offline["workers"] == 6


@pytest.mark.parametrize("command", ["crowd", "sweep", "meta"])
def test_main_refuses_fewer_than_one_worker(command, tmp_path):
    extra = ["--stale", "24"] if command == "meta" else []
    with pytest.raises(SystemExit) as stopped:
        main(["--config", str(tmp_path / "missing.env"), command, "--db", str(tmp_path / "g.sqlite"), "--workers", "0", *extra])
    assert str(stopped.value) == "--workers has to be 1 or more"


# --- and the requests really are under way together ---


def slowed(session, delay=0.01):
    """Makes a fake session take `delay` seconds an answer and count how many
    requests were under way at once, in session.most."""
    answer = session.get
    lock = threading.Lock()
    session.most = session.under_way = 0

    def get(url, **kwargs):
        with lock:
            session.under_way += 1
            session.most = max(session.most, session.under_way)
        time.sleep(delay)
        try:
            return answer(url, **kwargs)
        finally:
            with lock:
                session.under_way -= 1

    session.get = get
    return session


def threaded_client(session, workers):
    return TelegraphClient(session=session, sleep=lambda s: None, retries=0, workers=workers)


@pytest.mark.parametrize("workers,least", [(1, 1), (4, 2)])
def test_run_sweep_fetches_what_a_walk_is_sure_to_ask_for_ahead_of_it(workers, least):
    conn = crowd_run(1)["conn"]
    session = slowed(SweepSession(CROWDED), 0.003)
    stored, _ = run_sweep(conn, threaded_client(session, workers), MANY, DAYS, KEY, 2, None, set(), log=quiet)
    assert stored == len(CROWDED)
    assert least <= session.most <= workers

    # Most title-days hold nothing and cost gap + 1 requests, none of which
    # depends on another. One at a time they are what kept the rate under 8.
    conn = connect(":memory:")
    seed_crowd(conn, [("Hello", 10, 23, 0)])
    session = slowed(SweepSession(set()), 0.02)
    run_sweep(conn, threaded_client(session, 4), ENTRIES[:1], DAYS[:1], KEY, 2, None, set(), log=quiet)
    assert (session.paths.__len__(), session.most) == (3, 3)


@pytest.mark.parametrize("workers,least", [(1, 1), (4, 2)])
def test_run_resweep_run_meta_and_run_crowd_have_several_requests_under_way_at_once(workers, least):
    conn = connect(":memory:")
    live = {f"Hello-10-17-{n}": live_page(f"title {n}") for n in range(2, 22)}
    for path, page in live.items():
        add_snapshot(conn, upsert_page(conn, path, T0), {"path": path, **page}, T0, KEY)
    session = slowed(ResweepSession(live))
    counts = run_resweep(conn, threaded_client(session, workers), everything(conn), KEY, log=quiet)
    assert counts["refreshed"] == 20
    assert least <= session.most <= workers
    rows = conn.execute("SELECT id, path FROM pages ORDER BY id").fetchall()
    html = slowed(HtmlSession({path: ("2026-10-17T08:00:00+0000", "2026-10-17T09:00:00+0000") for path in live}))
    counts = run_meta(conn, threaded_client(html, workers), rows, log=quiet)
    assert counts["fetched"] == 20
    assert least <= html.most <= workers

    # and the crowd check counts several title-days at once
    session = slowed(PathSession(CROWDED), 0.003)
    run_crowd(connect(":memory:"), threaded_client(session, workers), MANY, DAYS, gap=2, log=quiet)
    assert least <= session.most <= workers


