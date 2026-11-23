"""Tests for graphwatch.cli, the runner.

The runner is split so the wiring can be tested without the network: main()
parses arguments and builds real objects; the run_* functions take those
objects and do the work. Here each run_* gets a client whose session answers
from what the test gives it, and main() gets a budget of 0 or a client on a
fake session.
"""

import hashlib
import json
import re
import runpy
import time
import urllib.parse
import warnings
from datetime import date, datetime
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
from graphwatch.db import (
    add_snapshot,
    connect,
    load_progress,
    resweep_paths,
    save_lookup,
    save_score,
    store_meta,
    upsert_indicator,
    upsert_page,
)
from graphwatch.feeds import FeedClient
from graphwatch.redact import hash_secret
from graphwatch.rules import CATEGORIES, RULES
from graphwatch.slugify import Entry
from graphwatch.telegraph import Outcome, TelegraphClient

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
            dict(db=DB, wordlists=LISTS, days=14, gap=2, rate=8.0, budget=None, today=None, unfrozen=False),
        ),
        (
            ["sweep"],
            dict(
                db=DB, wordlists=LISTS, days=None, gap=2, rate=8.0, budget=230000, cap=None,
                count_only_above=700, today=None, unfrozen=False,
                resweep=False, older_than=20.0, flagged=False, match=None,
            ),
        ),
        (["meta", "--stale", "24"], dict(db=DB, rate=8.0, budget=230000, limit=5000, stale=24.0)),
        (["freeze"], dict(wordlists=LISTS)),
        (["classify"], dict(db=DB, threshold=4, explain=None)),
        (["enrich"], dict(db=DB, file=None, refresh=False, budget=None, table=False)),
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
    assert load_progress(conn, "Hello", 10, 23) == (4, False)
    row = conn.execute("SELECT failures FROM sweep_progress").fetchone()
    assert row["failures"] == 2
    assert lines == ["Hello 10-23: 1 pages, 3 requests"]


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
    assert lines[-1].split() == ["unlabelled", "0", "(0.0%", "of", "pages)"]


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
    assert len(lines) == 2 + len(CATEGORIES) + 1
    for category, line in zip(CATEGORIES, lines[2:-1]):
        assert line.split() == [
            category,
            "labelled", f"{counts['labelled'][category]},",
            "primary", f"{counts['primary'][category]},",
            "near", "misses", f"{counts['category_near_miss'][category]}",
        ]
    assert lines[3].split() == ["template_spam", "labelled", "3,", "primary", "3,", "near", "misses", "0"]
    assert lines[-1].split() == ["unlabelled", "3", "(27.3%", "of", "pages)"]


def test_run_classify_twice_replaces_rather_than_adds(mixed):
    def rows():
        return [mixed.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("scores", "hits", "labels")]

    run_classify(mixed, log=quiet)
    first = rows()
    run_classify(mixed, log=quiet)
    assert rows() == first
    assert first[0] == 11


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
    lines = []
    after = run_classify(mixed, log=lines.append)
    assert after == {**before, "held_out": 3, "held_out_flagged": 1}
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
    # the actor edits pages in place: once a resolver, still one to watch
    assert flagged_list(conn) == ["Hello-10-17-9"]


def test_a_stale_flag_on_an_older_snapshot_is_cleared(conn):
    # The false positives of 22 November: flagged once, and a re-poll has since added a snapshot.
    with_an_older_flagged_snapshot(conn, "PayPal-10-31-12", "PayPal", "", "example.ua@gmail.com write to us", 5)
    assert flagged_list(conn) == ["PayPal-10-31-12"]
    run_classify(conn, log=quiet)
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
    assert lines[-5].split() == ["unlabelled", "1", "(25.0%", "of", "pages)"]
    assert lines[-4:-1] == ["  score +0: 1", "  score +1: 2", "  score +6: 1"]
    assert re.fullmatch(SECONDS, lines[-1])


def test_main_classify_threshold_option(classify_db, capsys, no_network):
    main(["classify", "--db", str(classify_db), "--threshold", "1"])
    assert "at threshold 1: 3 flagged" in capsys.readouterr().out


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


def test_run_enrich_does_not_ask_again_and_keeps_the_answer_and_the_day_it_was_given(indicators):
    # Novelty is measured on the day the indicator was found.
    client, _ = make_feed_client()
    run_enrich(indicators, client, log=quiet)
    before = [tuple(r) for r in indicators.execute("SELECT * FROM feed_lookups ORDER BY rowid")]
    later, session = make_feed_client(known={("threatfox", "8.8.8.8")})
    counts = run_enrich(indicators, later, log=quiet)
    assert session.calls == []
    assert counts == {"looked_up": 0, "cached": 8, "known": 0, "unknown": 0, "failed": 0}
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
    client, _ = make_feed_client(broken={"urlhaus": 500})
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert (counts["failed"], counts["unknown"]) == (2, 6)
    assert not any(feed == "urlhaus" for _value, feed, _verdict in stored_lookups(indicators))
    assert len(lines) == 2 and all(line.startswith("urlhaus ") for line in lines)
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
    client, session = make_feed_client(budget=3)
    lines = []
    counts = run_enrich(indicators, client, log=lines.append)
    assert lines == ["budget exceeded"]
    assert counts["looked_up"] == 3
    assert len(stored_lookups(indicators)) == 3
    rest, session = make_feed_client()
    counts = run_enrich(indicators, rest, log=quiet)
    assert (counts["looked_up"], counts["cached"]) == (5, 3)


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
    assert out.startswith("| Indicator | Kind | First seen | Pages | ThreatFox |")
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
    assert re.fullmatch(
        rf"looked up 3, cached 0, known 0, unknown 3, failed 0, 4 requests, {SECONDS}", looked_up
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
    # every request is in the http log, and no key is there or on the screen
    logged = [tuple(r) for r in c.execute("SELECT * FROM http_log")]
    c.close()
    assert len(logged) == 4
    assert "made-up" not in json.dumps(logged) + captured.out + captured.err


def test_main_enrich_budget_stops_the_lookups(enrich_workdir, capsys):
    workdir, session = enrich_workdir
    main(enrich_argv(workdir, "--budget", "2"))
    out = capsys.readouterr().out
    assert len(session.calls) == 2
    assert "budget exceeded" in out


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
