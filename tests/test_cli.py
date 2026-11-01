"""Tests for graphwatch.cli, the runner.

The runner is split so the wiring can be tested without the network: main()
parses arguments and builds real objects; run_crowd() takes those objects and
does the work. Here run_crowd gets a client whose session answers from a set
of existing paths.
"""

import urllib.parse
from pathlib import Path

import pytest

from graphwatch.cli import make_probe, parse_args, run_crowd
from graphwatch.db import connect
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
    rows = conn.execute("SELECT slug, month, day, highest FROM crowd ORDER BY slug, month, day").fetchall()
    assert [tuple(r) for r in rows] == [
        ("Hello", 10, 23, 0),
        ("Hello", 10, 24, 2),
        ("Povіstka", 10, 23, 1),
        ("Povіstka", 10, 24, 0),
    ]


def test_run_crowd_registers_the_titles(conn):
    client, _ = make_client(set())
    run_crowd(conn, client, ENTRIES, DAYS, log=lambda s: None)
    rows = conn.execute("SELECT title, slug, source FROM titles ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("Hello", "Hello", "greetings"), ("Повістка", "Povіstka", "lures")]


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
    assert {r[0] for r in rows} == {"Hello"}


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
    args = parse_args(["crowd", "--days", "3", "--gap", "1", "--rate", "4", "--budget", "500", "--db", "x.sqlite"])
    assert (args.days, args.gap, args.rate, args.budget) == (3, 1, 4.0, 500)
    assert str(args.db) == "x.sqlite"


def test_parse_args_requires_a_command():
    with pytest.raises(SystemExit):
        parse_args([])
