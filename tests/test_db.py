"""Tests for graphwatch.db.

Every test runs against an in-memory SQLite database, so nothing here touches
the disk or the network. Pages come from plan/fixtures.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from graphwatch.db import (
    SCHEMA,
    _resweep_where,
    add_event,
    add_snapshot,
    cached_feeds,
    connect,
    delete_stale_indicators,
    explain_rows,
    fingerprint,
    flagged_page_ids,
    flagged_pages,
    held_out_paths,
    http_logger,
    indicator_rows,
    is_gone,
    label_rows,
    latest_snapshots,
    live_older_snapshots,
    load_known,
    load_progress,
    lookup_rows,
    page_snapshots,
    title_rows,
    mark_gone,
    parse_path,
    refresh_snapshot,
    release_indicator_to_file,
    resweep_cost,
    resweep_paths,
    save_labels,
    save_lookup,
    save_progress,
    save_score,
    stale_pages,
    store_fetch,
    store_meta,
    upsert_indicator,
    upsert_page,
    upsert_title,
)
from graphwatch.slugify import Entry
from graphwatch.telegraph import Fetch, Outcome, TelegraphClient, page_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plan" / "fixtures"
KNOWN = ROOT / "known.txt"

T0 = 1_700_000_000.0  # a fixed "now" so timestamps are predictable
HOUR = 3600.0
DAY = 86400.0
RECHECK = 14 * DAY  # the age at which an UNKNOWN is asked for once more
KEY = b"test-key"  # any fixed HMAC key; redaction output only has to be stable

ALL_TABLES = {
    "titles",
    "pages",
    "snapshots",
    "events",
    "http_log",
    "crowd",
    "sweep_progress",
    "scores",
    "classify_state",
    "hits",
    "labels",
    "views",
    "indicators",
    "feed_lookups",
    "first_lookups",
    "indicator_titles",
}


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def tables(conn) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {r[0] for r in rows}


def count(conn, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def events_of(conn, page_id: int, kind: str) -> list[float]:
    sql = "SELECT ts FROM events WHERE page_id = ? AND kind = ? ORDER BY id"
    return [r["ts"] for r in conn.execute(sql, (page_id, kind))]


def last_seen_of(conn, page_id: int) -> float:
    return conn.execute("SELECT last_seen FROM pages WHERE id = ?", (page_id,)).fetchone()[0]


def held_out_of(conn, page_id: int) -> int:
    return conn.execute("SELECT held_out FROM pages WHERE id = ?", (page_id,)).fetchone()[0]


def snapshots_of(conn, page_id: int) -> int:
    sql = "SELECT COUNT(*) FROM snapshots WHERE page_id = ?"
    return conn.execute(sql, (page_id,)).fetchone()[0]


def author_of(conn, page_id: int) -> tuple:
    sql = "SELECT author_name, author_url FROM pages WHERE id = ?"
    return tuple(conn.execute(sql, (page_id,)).fetchone())


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


# --------------------------------------------------------------------------
# connect and schema
# --------------------------------------------------------------------------


def test_connect_creates_every_table(conn):
    assert tables(conn) == ALL_TABLES


def test_connect_adds_the_newer_tables_to_an_older_database_and_keeps_its_rows(tmp_path):
    # A new table needs no migration: CREATE TABLE IF NOT EXISTS is enough.
    db = tmp_path / "g.sqlite"
    old = sqlite3.connect(str(db))
    old.executescript(SCHEMA.split("CREATE TABLE IF NOT EXISTS labels")[0])
    old.execute("INSERT INTO events (ts, kind) VALUES (?, ?)", (T0, "x"))
    old.commit()
    old.close()
    for _ in range(2):  # the second connect finds every table already there
        c = connect(db)
        assert tables(c) == ALL_TABLES
        assert count(c, "events") == 1
        c.close()


def test_connect_enforces_foreign_keys(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO snapshots (page_id, fetched_at, content, text, sha256) "
            "VALUES (?, ?, ?, ?, ?)",
            (999, T0, "[]", "", "0" * 64),
        )


def test_connect_asks_sqlite_to_wait_a_minute_for_another_writer(conn):
    # The nightly job and the ten-minute re-poll share one file. sqlite3's own
    # default is 5 s, and a test with two real writers cannot tell 5 from 60
    # without waiting that long, so this reads what the connection was told.
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 60_000


# --------------------------------------------------------------------------
# parse_path
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("Vizit-12-28", ("Vizit", 12, 28, None)),
        ("Hello-01-23-161", ("Hello", 1, 23, 161)),
        ("mark-01-20-5", ("mark", 1, 20, 5)),
        ("do-Penthouse---Grati-11-17", ("do-Penthouse---Grati", 11, 17, None)),
        ("Povіstka-10-25", ("Povіstka", 10, 25, None)),  # Cyrillic і
        # 10-16 is the date; "Test-10" is not a slug plus a counter.
        ("Test-10-16", ("Test", 10, 16, None)),
        # A counter that could be a day after a day that could be a month: the
        # greedy regex used to read these as a slug ending in the month and a
        # date shifted right by one field.
        ("T-11-01-10", ("T", 11, 1, 10)),
        ("Test-10-11-12", ("Test", 10, 11, 12)),  # ambiguous; the counter reading wins
        # A slug that itself ends in a date, posted on another day.
        ("Test-10-16-10-17", ("Test-10-16", 10, 17, None)),
        ("Test-10-16-10-17-3", ("Test-10-16", 10, 17, 3)),
    ],
)
def test_parse_path_splits_slug_month_day_counter(path, expected):
    assert parse_path(path) == expected


def test_parse_path_takes_every_month_from_01_to_12_and_day_from_01_to_31():
    for month in range(1, 13):
        for day in range(1, 32):
            assert parse_path(f"x-{month:02d}-{day:02d}") == ("x", month, day, None)


@pytest.mark.parametrize(
    "bad",
    [
        "Vizit",
        "Vizit-12",
        "Vizit-1-28",
        "Vizit-12-8",
        "-12-28",
        "Vizit-12-28-",
        "Vizit-12-28-x",
        "Vizit-00-10",
        "Vizit-13-01",
        "Vizit-12-00",
        "Vizit-12-32",
    ],
)
def test_parse_path_rejects_malformed_paths(bad):
    with pytest.raises(ValueError):
        parse_path(bad)


# --------------------------------------------------------------------------
# titles
# --------------------------------------------------------------------------


def test_upsert_title_inserts_and_returns_an_id(conn):
    tid = upsert_title(conn, Entry("Повістка", "Povіstka", "lures", False), T0)
    row = conn.execute("SELECT * FROM titles WHERE id = ?", (tid,)).fetchone()
    assert row["title"] == "Повістка"
    assert row["slug"] == "povіstka"
    assert row["source"] == "lures"
    assert row["crowd_only"] == 0
    assert row["added_at"] == T0


# Finding 2: TEST and Test name the same page, so they are one title row.
# Telegraph also answers Hi with Hİ, which SQLite's NOCASE does not fold.
@pytest.mark.parametrize("first, again", [("Test", "TEST"), ("Hi", "Hİ")])
def test_upsert_title_of_a_slug_in_another_case_returns_the_same_row(conn, first, again):
    a = upsert_title(conn, Entry(first, first, "a", False), T0)
    b = upsert_title(conn, Entry(again, again, "b", False), T0 + 1)
    assert a == b
    assert count(conn, "titles") == 1


def test_upsert_title_records_crowd_only(conn):
    tid = upsert_title(conn, Entry("Maybe", "Maybe", "pending", True), T0)
    assert (
        conn.execute("SELECT crowd_only FROM titles WHERE id = ?", (tid,)).fetchone()[0]
        == 1
    )


# --------------------------------------------------------------------------
# pages
# --------------------------------------------------------------------------


def test_upsert_page_inserts_parsed_fields(conn):
    pid = upsert_page(conn, "Hello-01-23-161", T0)
    row = conn.execute("SELECT * FROM pages WHERE id = ?", (pid,)).fetchone()
    # Finding 2: the stored path is the API's `path` field, case and all;
    # only the slug is folded.
    assert row["path"] == "Hello-01-23-161"
    assert (row["slug"], row["month"], row["day"], row["counter"]) == (
        "hello",
        1,
        23,
        161,
    )
    assert row["held_out"] == 0
    assert row["first_seen"] == T0
    assert row["last_seen"] == T0


def test_upsert_page_counter_is_null_when_absent(conn):
    pid = upsert_page(conn, "Vizit-12-28", T0)
    assert (
        conn.execute("SELECT counter FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        is None
    )


def test_upsert_page_second_time_updates_last_seen_only(conn):
    a = upsert_page(conn, "Vizit-12-28", T0)
    b = upsert_page(conn, "Vizit-12-28", T0 + 60)
    assert a == b
    row = conn.execute(
        "SELECT first_seen, last_seen FROM pages WHERE id = ?", (a,)
    ).fetchone()
    assert row["first_seen"] == T0
    assert row["last_seen"] == T0 + 60
    assert count(conn, "pages") == 1


# Held out first and swept later, or swept first and added to known.txt later:
# either way the page is in the evaluation set from then on.
@pytest.mark.parametrize("first, second", [(True, False), (False, True)])
def test_upsert_page_held_out_once_is_held_out_for_good(conn, first, second):
    pid = upsert_page(conn, "Vizit-12-28", T0, held_out=first)
    upsert_page(conn, "Vizit-12-28", T0 + 1, held_out=second)
    assert held_out_of(conn, pid) == 1


@pytest.mark.parametrize(
    "title_slug, path, stored_slug",
    [
        ("Hello", "hello-10-24", "hello"),
        # Telegraph answered a request for Hi-10-30-261 with the path Hİ-10-30-261.
        ("Hi", "Hİ-10-30-261", "hi"),
        ("Mobіlіzacіya", "MOBІLІZACІYA-10-19", "mobіlіzacіya"),  # Cyrillic і and І
    ],
)
def test_upsert_page_links_to_its_title_across_case(conn, title_slug, path, stored_slug):
    tid = upsert_title(conn, Entry(title_slug, title_slug, "greetings", False), T0)
    pid = upsert_page(conn, path, T0)
    row = conn.execute(
        "SELECT slug, title_id FROM pages WHERE id = ?", (pid,)
    ).fetchone()
    assert row["title_id"] == tid
    assert row["slug"] == stored_slug


def test_upsert_page_without_a_matching_title_has_null_title_id(conn):
    pid = upsert_page(conn, "f8bfl6sp-01-02", T0)
    assert (
        conn.execute("SELECT title_id FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        is None
    )


def test_upsert_page_first_insert_writes_a_discovered_event(conn):
    pid = upsert_page(conn, "Vizit-12-28", T0)
    upsert_page(conn, "Vizit-12-28", T0 + 1)
    rows = conn.execute(
        "SELECT kind, ts FROM events WHERE page_id = ?", (pid,)
    ).fetchall()
    assert [(r["kind"], r["ts"]) for r in rows] == [("discovered", T0)]


def test_upsert_page_rejects_a_malformed_path_and_stores_nothing(conn):
    with pytest.raises(ValueError):
        upsert_page(conn, "not-a-path", T0)
    assert count(conn, "pages") == 0
    assert count(conn, "events") == 0


# --------------------------------------------------------------------------
# snapshots
# --------------------------------------------------------------------------

PAGE = {
    "path": "Hello-10-17-1",
    "title": "8.8.8.8",
    "description": "d",
    "views": 5,
    "content": ["x"],
    "author_name": "a",
    "author_url": "https://t.me/a",
}


def test_add_snapshot_stores_the_page_fields(conn):
    page = fixture_page("Vizit-12-28")  # redacted when it was recorded
    pid = upsert_page(conn, page["path"], T0)
    sid, _changed = add_snapshot(conn, pid, page, T0, KEY)
    row = conn.execute("SELECT * FROM snapshots WHERE id = ?", (sid,)).fetchone()
    assert row["page_id"] == pid
    assert row["fetched_at"] == T0
    assert row["title"] == page["title"]
    assert row["description"] == page["description"]
    assert row["views"] == page["views"]
    assert json.loads(row["content"]) == page["content"]
    assert row["text"] == page_text(page)
    assert row["sha256"] == fingerprint(page["title"], page["description"], page["content"])


def test_fingerprint_of_a_fixed_page_is_the_hash_it_has_always_been():
    # Every stored sha256 was made this way. If the three fields were written
    # out differently (key order, spacing, escaped letters), every page would
    # look edited the next time it is polled.
    nodes = [{"tag": "a", "attrs": {"href": "https://example.org/"}, "children": ["тут"]}]
    expected = "2a54e83391246a6475ace7568802d145bc10c0a19dba7f37de39c435075fa15f"
    assert fingerprint("Привіт", None, nodes) == expected
    reordered = [{"children": ["тут"], "attrs": {"href": "https://example.org/"}, "tag": "a"}]
    assert fingerprint("Привіт", None, reordered) == expected


def test_add_snapshot_first_snapshot_of_a_page_is_not_a_change(conn):
    other = upsert_page(conn, "Hello-10-17-2", T0)
    add_snapshot(conn, other, {**PAGE, "title": "another page"}, T0, KEY)
    pid = upsert_page(conn, "Hello-10-17-1", T0 + 1)
    _, changed = add_snapshot(conn, pid, PAGE, T0 + 1, KEY)
    assert changed is False
    assert events_of(conn, pid, "content_changed") == []


# Finding 8: titles change after publication, and Gamaredon's pointer lives in
# the title, so a title change is a content change like the other two.
@pytest.mark.parametrize(
    "edit", [{"title": "9.9.9.9"}, {"description": "e"}, {"content": ["y"]}]
)
def test_add_snapshot_of_an_edited_page_writes_one_content_changed_event(conn, edit):
    pid = upsert_page(conn, "Hello-10-17-1", T0)
    add_snapshot(conn, pid, PAGE, T0, KEY)
    _, changed = add_snapshot(conn, pid, {**PAGE, **edit}, T0 + 60, KEY)
    assert changed is True
    assert events_of(conn, pid, "content_changed") == [T0 + 60]


# Views and the author fields are not part of the fingerprint: a page nobody
# edited gets a snapshot with the new view count and no event.
@pytest.mark.parametrize(
    "difference",
    [{"views": 9}, {"author_name": "b", "author_url": "https://t.me/b"}],
)
def test_add_snapshot_of_a_page_nobody_edited_is_stored_and_is_not_a_change(conn, difference):
    pid = upsert_page(conn, "Hello-10-17-1", T0)
    add_snapshot(conn, pid, PAGE, T0, KEY)
    _, changed = add_snapshot(conn, pid, {**PAGE, **difference}, T0 + 60, KEY)
    assert changed is False
    assert events_of(conn, pid, "content_changed") == []
    assert count(conn, "snapshots") == 2


def test_add_snapshot_compares_against_the_latest_snapshot_not_an_earlier_one(conn):
    pid = upsert_page(conn, "Hello-10-17-1", T0)
    add_snapshot(conn, pid, PAGE, T0, KEY)
    add_snapshot(conn, pid, {**PAGE, "title": "second"}, T0 + 1, KEY)
    # Stored in the same second as the one before: the later row is the latest
    add_snapshot(conn, pid, {**PAGE, "title": "third"}, T0 + 1, KEY)
    _, changed = add_snapshot(conn, pid, {**PAGE, "title": "third"}, T0 + 2, KEY)
    assert changed is False


def test_add_snapshot_tolerates_missing_optional_fields(conn):
    pid = upsert_page(conn, "x-01-01", T0)
    sid, _ = add_snapshot(conn, pid, {"path": "x-01-01", "content": []}, T0, KEY)
    row = conn.execute(
        "SELECT title, description, views FROM snapshots WHERE id = ?", (sid,)
    ).fetchone()
    assert (row["title"], row["description"], row["views"]) == (None, None, None)
    assert author_of(conn, pid) == (None, None)


def test_add_snapshot_stores_the_newest_author_on_its_own_page_row(conn):
    other = upsert_page(conn, "y-01-01", T0)
    add_snapshot(conn, other, {**PAGE, "author_name": "o", "author_url": "https://t.me/o"}, T0, KEY)
    pid = upsert_page(conn, "x-01-01", T0)
    add_snapshot(conn, pid, {**PAGE, "author_name": "Nadia", "author_url": "https://t.me/nadia"}, T0, KEY)
    assert author_of(conn, pid) == ("Nadia", "https://t.me/nadia")
    add_snapshot(conn, pid, PAGE, T0 + 1, KEY)
    assert author_of(conn, pid) == ("a", "https://t.me/a")
    assert author_of(conn, other) == ("o", "https://t.me/o")


# --- redaction happens at ingest ---------------------------------------------

RAW_KEY_1 = "VzQ3NktFUDh0Tm5qdHZSdw=="
RAW_KEY_2 = "T0lpc01IOHdHdGhzNjltOWJBR2Z3MTVNcU14NjdsdTJnNW1Oa3RiaA=="
RAW_HELLO_TITLE = f"198.13.32.106?rakuten.ne.jp@opportunizz.pro/!{RAW_KEY_1}?{RAW_KEY_2}?dGViaQ==?eWVsNA=="


def test_add_snapshot_stores_redacted_title_text_and_content(conn):
    # Issue #18: no sweep may store a page before redaction. Every stored
    # column that carries page text must hold tokens, never the raw keys.
    page = {
        "path": "Hello-10-17-154",
        "title": RAW_HELLO_TITLE,
        "description": "password: hunter2",
        "content": [{"tag": "p", "children": ["card 4111 1111 1111 1111"]}],
    }
    pid = upsert_page(conn, page["path"], T0)
    add_snapshot(conn, pid, page, T0, KEY)
    row = conn.execute(
        "SELECT title, description, content, text FROM snapshots"
    ).fetchone()
    stored = "\n".join([row["title"], row["description"], row["content"], row["text"]])
    for raw in (RAW_KEY_1, RAW_KEY_2, "hunter2", "4111"):
        assert raw not in stored
    assert (
        stored.count("SECRET{") >= 4
    )  # two keys, once each in title and text, plus two more
    assert "198.13.32.106" in row["title"]  # the pointer survives
    assert "dGViaQ==" in row["title"]  # the labels survive


def test_add_snapshot_fingerprint_is_of_the_redacted_page(conn):
    # A raw fetch and its already-redacted twin must fingerprint the same,
    # or every re-fetch after a key rotation of ours would look like a change.
    from graphwatch.redact import redact_page

    page = {"path": "x-01-01", "title": "password: hunter2", "content": []}
    pid = upsert_page(conn, page["path"], T0)
    add_snapshot(conn, pid, page, T0, KEY)
    _, changed = add_snapshot(conn, pid, redact_page(page, KEY), T0 + 1, KEY)
    assert changed is False


def test_add_snapshot_does_not_mutate_the_page_it_is_given(conn):
    page = {"path": "x-01-01", "title": "password: hunter2", "content": []}
    before = json.loads(json.dumps(page))
    pid = upsert_page(conn, page["path"], T0)
    add_snapshot(conn, pid, page, T0, KEY)
    assert page == before


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------


def test_add_event_stores_kind_and_detail(conn):
    pid = upsert_page(conn, "Vizit-12-28", T0)
    eid = add_event(conn, pid, "flagged", T0, detail="rule:userinfo_spoof")
    row = conn.execute("SELECT * FROM events WHERE id = ?", (eid,)).fetchone()
    assert (row["page_id"], row["kind"], row["ts"], row["detail"]) == (
        pid,
        "flagged",
        T0,
        "rule:userinfo_spoof",
    )


def test_add_event_allows_no_page(conn):
    # sweep_started, budget_exhausted and the like belong to no page
    eid = add_event(conn, None, "sweep_started", T0)
    assert (
        conn.execute("SELECT page_id FROM events WHERE id = ?", (eid,)).fetchone()[0]
        is None
    )


# --------------------------------------------------------------------------
# http_log
# --------------------------------------------------------------------------


class FakeSession:
    def __init__(self, body: bytes):
        self.body = body

    def get(self, url, **kwargs):
        class R:
            status_code = 200
            content = self.body

        return R()


def test_http_logger_writes_one_row_per_attempt(conn):
    body = (FIXTURES / "not-found.json").read_bytes()
    client = TelegraphClient(
        session=FakeSession(body), sleep=lambda s: None, log=http_logger(conn)
    )
    client.get_page("Nope-01-01")
    client.get_page("Nope-01-02")
    rows = conn.execute("SELECT * FROM http_log ORDER BY id").fetchall()
    assert [r["path"] for r in rows] == ["Nope-01-01", "Nope-01-02"]
    assert rows[0]["attempt"] == 1
    assert rows[0]["status"] == 200
    assert rows[0]["outcome"] == "NOT_FOUND"
    assert rows[0]["error"] == "PAGE_NOT_FOUND"
    assert rows[0]["bytes"] == len(body)
    assert rows[0]["elapsed_ms"] >= 0
    assert rows[0]["ts"] > 0


# --------------------------------------------------------------------------
# store_fetch: the one entry point the sweep and the held-out loader share
# --------------------------------------------------------------------------


def make_fetch(name: str) -> Fetch:
    page = fixture_page(name)
    return Fetch(page["path"], Outcome.FOUND, page, None, 200, 12)


def test_store_fetch_found_upserts_an_ordinary_page_and_adds_a_snapshot(conn):
    pid = store_fetch(conn, make_fetch("Vizit-12-28"), T0, KEY)
    row = conn.execute("SELECT path, held_out FROM pages WHERE id = ?", (pid,)).fetchone()
    assert (row["path"], row["held_out"]) == ("Vizit-12-28", 0)
    assert snapshots_of(conn, pid) == 1


def test_store_fetch_uses_the_api_path_not_the_requested_one(conn):
    page = fixture_page("Vizit-12-28")
    fetch = Fetch(
        "VIZIT-12-28", Outcome.FOUND, page, None, 200, 12
    )  # requested in caps
    pid = store_fetch(conn, fetch, T0, KEY)
    assert (
        conn.execute("SELECT path FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        == "Vizit-12-28"
    )


@pytest.mark.parametrize(
    "fetch",
    [
        Fetch("Nope-01-01", Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND", 200, 5),
        Fetch("Vizit-12-28", Outcome.FAILED, None, "request error: down", None, 5),
    ],
    ids=["not found", "failed"],
)
def test_store_fetch_stores_nothing_unless_the_page_was_found(conn, fetch):
    assert store_fetch(conn, fetch, T0, KEY) is None
    assert count(conn, "pages") == 0


def test_store_fetch_passes_held_out_through(conn):
    pid = store_fetch(conn, make_fetch("ki06-05-02"), T0, KEY, held_out=True)
    assert held_out_of(conn, pid) == 1


def test_store_fetch_twice_is_one_page_two_snapshots_and_its_author(conn):
    # The nightly sweep stores every page it fetches, seen before or not.
    fetch = Fetch(PAGE["path"], Outcome.FOUND, PAGE, None, 200, 12)
    a = store_fetch(conn, fetch, T0, KEY)
    b = store_fetch(conn, fetch, T0 + 1, KEY)
    assert a == b
    assert count(conn, "pages") == 1
    assert count(conn, "snapshots") == 2
    assert author_of(conn, a) == ("a", "https://t.me/a")


# --------------------------------------------------------------------------
# the held-out set
# --------------------------------------------------------------------------


def test_load_known_registers_every_path_as_held_out(conn):
    ids = load_known(conn, KNOWN, T0)
    expected = [
        l.strip()
        for l in KNOWN.read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.startswith("#")
    ]
    assert len(ids) == len(expected) == 16  # the plan says 15; known.txt has 16
    assert sorted(held_out_paths(conn)) == sorted(expected)
    assert (
        conn.execute("SELECT COUNT(*) FROM pages WHERE held_out = 0").fetchone()[0] == 0
    )


def test_load_known_skips_comments_and_blank_lines(conn, tmp_path):
    f = tmp_path / "known.txt"
    f.write_text("# header\n\nVizit-12-28\n  \n  # indented\nki06-05-02\n", encoding="utf-8")
    ids = load_known(conn, f, T0)
    assert len(ids) == 2
    assert held_out_paths(conn) == ["Vizit-12-28", "ki06-05-02"]


def test_held_out_paths_lists_only_held_out_pages_in_insertion_order(conn):
    upsert_page(conn, "b-01-01", T0, held_out=True)
    upsert_page(conn, "Hello-10-17-5", T0)
    upsert_page(conn, "a-01-01", T0, held_out=True)
    assert held_out_paths(conn) == ["b-01-01", "a-01-01"]


# --- sweep_progress (issue #20) -----------------------------------------------


def test_load_progress_unswept_day_starts_at_one_and_is_not_done(conn):
    assert load_progress(conn, "Hello", 10, 17) == (1, False)


def test_save_progress_second_save_updates_in_place(conn):
    save_progress(conn, "Hello", 10, 17, 5, False, 7, 1, T0)
    assert load_progress(conn, "Hello", 10, 17) == (5, False)
    save_progress(conn, "Hello", 10, 17, 9, True, 12, 2, T0 + 60)
    assert load_progress(conn, "Hello", 10, 17) == (9, True)
    assert load_progress(conn, "Hello", 10, 17)[1] is True  # a bool, not the stored 1
    row = conn.execute("SELECT * FROM sweep_progress").fetchone()
    assert (row["requests"], row["failures"], row["updated_at"]) == (12, 2, T0 + 60)
    assert count(conn, "sweep_progress") == 1


def test_progress_of_a_slug_is_one_row_across_unicode_case(conn):
    # Cyrillic і and І, which SQLite's NOCASE does not fold
    save_progress(conn, "Mobіlіzacіya", 10, 19, 5, False, 7, 0, T0)
    save_progress(conn, "MOBІLІZACІYA", 10, 19, 7, True, 9, 0, T0 + 1)
    assert count(conn, "sweep_progress") == 1
    assert load_progress(conn, "mobіlіzacіya", 10, 19) == (7, True)
    assert load_progress(conn, "MOBІLІZACІYA", 10, 19) == (7, True)


def test_save_progress_days_are_independent(conn):
    save_progress(conn, "Hello", 10, 17, 5, True, 7, 0, T0)
    save_progress(conn, "Hello", 10, 18, 2, False, 3, 1, T0)
    save_progress(conn, "Test", 10, 17, 9, False, 9, 0, T0)
    assert load_progress(conn, "Hello", 10, 17) == (5, True)
    assert load_progress(conn, "Hello", 10, 18) == (2, False)
    assert load_progress(conn, "Test", 10, 17) == (9, False)
    assert load_progress(conn, "Test", 10, 18) == (1, False)


# --------------------------------------------------------------------------
# page metadata (plan/page-meta-plan-2026-11-04.md)
# --------------------------------------------------------------------------


def iso_ts(s: str) -> float:
    # Telegraph writes "+0000"; fromisoformat accepts that on Python 3.11+.
    return datetime.fromisoformat(s).timestamp()


PUB = iso_ts("2026-10-19T03:00:08+0000")
MOD1 = iso_ts("2026-11-04T15:06:39+0000")
MOD2 = iso_ts("2026-11-05T09:00:00+0000")


def meta(published_at=PUB, modified_at=MOD1) -> dict:
    return {"published_at": published_at, "modified_at": modified_at}


def meta_row(conn, pid) -> tuple:
    return tuple(
        conn.execute(
            "SELECT published_at, modified_at, meta_seen_at FROM pages WHERE id = ?",
            (pid,),
        ).fetchone()
    )


def change_events(conn, pid) -> list[tuple]:
    sql = "SELECT ts, detail FROM events WHERE page_id = ? AND kind = 'modified_at_changed' ORDER BY id"
    return [tuple(r) for r in conn.execute(sql, (pid,))]


def test_store_meta_first_store_fills_all_three_and_is_not_a_change(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    assert store_meta(conn, pid, meta(), T0) is False
    assert meta_row(conn, pid) == (PUB, MOD1, T0)
    assert change_events(conn, pid) == []


def test_store_meta_same_modified_at_writes_no_event_and_moves_meta_seen_at(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(), T0)
    assert store_meta(conn, pid, meta(), T0 + 60) is False
    assert change_events(conn, pid) == []
    assert meta_row(conn, pid) == (PUB, MOD1, T0 + 60)


def test_store_meta_changed_modified_at_writes_one_event_with_both_values_in_utc(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(modified_at=MOD1), T0)
    assert store_meta(conn, pid, meta(modified_at=MOD2), T0 + 60) is True
    # Whatever the machine's local zone, the detail reads as UTC.
    there = (T0 + 60, "2026-11-04T15:06:39+00:00 -> 2026-11-05T09:00:00+00:00")
    assert change_events(conn, pid) == [there]
    assert meta_row(conn, pid) == (PUB, MOD2, T0 + 60)
    # Back to the first value is a second change, and never a content_changed
    assert store_meta(conn, pid, meta(modified_at=MOD1), T0 + 120) is True
    back = (T0 + 120, "2026-11-05T09:00:00+00:00 -> 2026-11-04T15:06:39+00:00")
    assert change_events(conn, pid) == [there, back]
    kinds = {r["kind"] for r in conn.execute("SELECT kind FROM events WHERE page_id = ?", (pid,))}
    assert kinds == {"discovered", "modified_at_changed"}


def test_store_meta_never_overwrites_published_at(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(published_at=PUB), T0)
    store_meta(conn, pid, meta(published_at=PUB + 5), T0 + 1)
    assert meta_row(conn, pid) == (PUB, MOD1, T0 + 1)


def test_store_meta_reads_and_writes_the_one_page(conn):
    a = upsert_page(conn, "Hello-10-19-130", T0)
    b = upsert_page(conn, "Hello-10-19-131", T0)
    store_meta(conn, a, meta(modified_at=MOD1), T0)
    # The first value of page b is not a change from the value of page a
    assert store_meta(conn, b, meta(modified_at=MOD2), T0 + 1) is False
    assert change_events(conn, b) == []
    assert meta_row(conn, a) == (PUB, MOD1, T0)


# page selector for the meta command


def id_paths(rows):
    return [(r["id"], r["path"]) for r in rows]


def test_pages_stale_returns_never_seen_pages_first_then_oldest(conn):
    old = upsert_page(conn, "b-01-01", T0)
    never = upsert_page(conn, "a-01-01", T0)
    fresh = upsert_page(conn, "c-01-01", T0)
    older = upsert_page(conn, "d-01-01", T0)
    now = T0 + 100 * 3600
    store_meta(conn, old, meta(), now - 48 * 3600)
    store_meta(conn, fresh, meta(), now - 1 * 3600)
    store_meta(conn, older, meta(), now - 72 * 3600)
    rows = stale_pages(conn, 24, now, 10)
    assert id_paths(rows) == [(never, "a-01-01"), (older, "d-01-01"), (old, "b-01-01")]


def test_pages_stale_boundary_is_strictly_older(conn):
    pid = upsert_page(conn, "a-01-01", T0)
    now = T0 + 100 * 3600
    store_meta(conn, pid, meta(), now - 24 * 3600)  # exactly 24 h: not stale yet
    assert stale_pages(conn, 24, now, 10) == []
    assert id_paths(stale_pages(conn, 24, now + 1, 10)) == [(pid, "a-01-01")]
    # --stale 0 is every page seen before now, not a missing value
    assert id_paths(stale_pages(conn, 0, now - 24 * 3600 + 1, 10)) == [(pid, "a-01-01")]


def test_pages_stale_respects_the_limit(conn):
    for i in range(5):
        upsert_page(conn, f"p{i}-01-01", T0)
    rows = stale_pages(conn, 24, T0, 3)
    assert [r["path"] for r in rows] == ["p0-01-01", "p1-01-01", "p2-01-01"]


# --------------------------------------------------------------------------
# scores and hits (issue #29)
# --------------------------------------------------------------------------

# (rule, weight, evidence, matches)
HITS = [
    ("userinfo_spoof", 5, "a.com@b.pro", 1),
    ("telegram_link", -1, "t.me/", 3),
]


def stored_page(conn, path: str, name: str = "Test-10-16", ts: float = T0, **kwargs):
    """Store one fixture page under `path`; returns (page_id, snapshot_id)."""
    page_id = upsert_page(conn, path, ts, **kwargs)
    snapshot_id, _changed = add_snapshot(conn, page_id, fixture_page(name), ts, KEY)
    return page_id, snapshot_id


def test_latest_snapshots_yields_one_row_per_page_in_page_order(conn):
    a, snap_a = stored_page(conn, "a-01-01")
    b, snap_b = stored_page(conn, "b-01-01", "Hello-10-17-5", held_out=True)
    rows = latest_snapshots(conn).fetchall()
    assert [(r["page_id"], r["snapshot_id"], r["path"], r["held_out"]) for r in rows] == [
        (a, snap_a, "a-01-01", 0),
        (b, snap_b, "b-01-01", 1),
    ]


def test_latest_snapshots_carries_the_fields_the_rules_read(conn):
    stored_page(conn, "a-01-01", "Hello-10-17-5")
    row = latest_snapshots(conn).fetchone()
    page = fixture_page("Hello-10-17-5")
    assert row["title"] == page["title"]
    assert row["description"] == page["description"]
    assert row["text"] == page_text(page)
    assert json.loads(row["content"]) == page["content"]  # for the link targets


# An edit a minute later, and one stored in the same second as the first
@pytest.mark.parametrize("seconds_later", [60, 0])
def test_latest_snapshots_picks_the_newest_snapshot_of_an_edited_page(conn, seconds_later):
    page_id, _first = stored_page(conn, "a-01-01", "Test-10-16", T0)
    second, changed = add_snapshot(
        conn, page_id, fixture_page("Hello-10-17-5"), T0 + seconds_later, KEY
    )
    assert changed
    rows = latest_snapshots(conn).fetchall()
    assert [r["snapshot_id"] for r in rows] == [second]
    assert rows[0]["title"] == fixture_page("Hello-10-17-5")["title"]


def test_latest_snapshots_skips_pages_that_have_no_snapshot(conn):
    upsert_page(conn, "a-01-01", T0)
    assert latest_snapshots(conn).fetchall() == []


def test_latest_snapshots_can_be_read_a_batch_at_a_time(conn):
    ids = [stored_page(conn, f"a-01-0{n}")[0] for n in range(1, 6)]
    first = latest_snapshots(conn, 0, 2).fetchall()
    second = latest_snapshots(conn, first[-1]["page_id"], 2).fetchall()
    third = latest_snapshots(conn, second[-1]["page_id"], 2).fetchall()
    assert [r["page_id"] for r in first + second + third] == ids
    assert latest_snapshots(conn, ids[-1], 2).fetchall() == []


def test_latest_snapshots_can_leave_the_content_out(conn):
    stored_page(conn, "a-01-01")
    row = latest_snapshots(conn, content=False).fetchone()
    assert row["content"] is None
    assert row["text"] == page_text(fixture_page("Test-10-16"))


def test_save_score_stores_the_score_row(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, "ab" * 32, HITS, T0 + 5)
    row = conn.execute("SELECT * FROM scores").fetchone()
    assert dict(row) == {
        "snapshot_id": snap,
        "page_id": page_id,
        "score": 6,
        "flagged": 1,
        "body_sha256": "ab" * 32,
        "classified_at": T0 + 5,
    }


def test_save_score_stores_one_hit_row_per_hit_in_order(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    rows = conn.execute(
        "SELECT snapshot_id, rule, weight, evidence, matches FROM hits ORDER BY id"
    ).fetchall()
    assert [tuple(r) for r in rows] == [(snap, *hit) for hit in HITS]


def test_save_score_accepts_a_page_with_no_hits_and_no_body_hash(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 0, False, None, [], T0)
    row = conn.execute("SELECT score, flagged, body_sha256 FROM scores").fetchone()
    assert tuple(row) == (0, 0, None)
    assert count(conn, "hits") == 0


def test_save_score_twice_replaces_the_first_result(conn):
    # Rerunning the classifier after a rule change must not pile up rows.
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    save_score(conn, snap, page_id, 1, False, None, HITS[1:], T0 + 9)
    assert [tuple(r) for r in conn.execute("SELECT score, flagged FROM scores")] == [
        (1, 0)
    ]
    assert [r["rule"] for r in conn.execute("SELECT rule FROM hits")] == [
        "telegram_link"
    ]


def test_save_score_leaves_other_snapshots_alone(conn):
    a, snap_a = stored_page(conn, "a-01-01")
    b, snap_b = stored_page(conn, "b-01-01")
    save_score(conn, snap_a, a, 6, True, None, HITS, T0)
    save_score(conn, snap_b, b, 0, False, None, [], T0)
    save_score(conn, snap_b, b, 1, False, None, HITS[1:], T0)
    assert count(conn, "scores") == 2
    assert count(conn, "hits") == 3


def test_explain_rows_returns_the_score_of_that_page_and_its_hits(conn):
    a, snap_a = stored_page(conn, "a-01-01", "Hello-10-17-5")
    b, snap_b = stored_page(conn, "b-01-01", ts=T0 + 60)
    save_score(conn, snap_a, a, 6, True, None, HITS, T0)
    save_score(conn, snap_b, b, 0, False, None, HITS[1:], T0 + 61)
    row, hits = explain_rows(conn, "a-01-01")
    page = fixture_page("Hello-10-17-5")
    assert dict(row) == {
        "snapshot_id": snap_a,  # for the label lookup
        "path": "a-01-01",
        "held_out": 0,
        "title": page["title"],
        "text": page_text(page),
        "score": 6,
        "flagged": 1,
    }
    assert [tuple(h) for h in hits] == HITS


def test_explain_rows_is_empty_for_an_unknown_path_and_a_page_not_yet_classified(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    stored_page(conn, "b-01-01")
    assert explain_rows(conn, "nope-01-01") == (None, [])
    assert explain_rows(conn, "b-01-01") == (None, [])


def test_explain_rows_uses_the_newest_scored_snapshot(conn):
    page_id, first = stored_page(conn, "a-01-01", "Test-10-16", T0)
    second, _ = add_snapshot(conn, page_id, fixture_page("Hello-10-17-5"), T0 + 60, KEY)
    save_score(conn, first, page_id, 0, False, None, HITS[1:], T0)
    save_score(conn, second, page_id, 6, True, None, HITS, T0 + 61)
    row, hits = explain_rows(conn, "a-01-01")
    assert row["score"] == 6
    assert [tuple(h) for h in hits] == HITS


# --------------------------------------------------------------------------
# labels: one row per category that scored (classification plan, 2026-11-15)
# --------------------------------------------------------------------------

# (category, score, assigned, is_primary)
LABELS = [
    ("leaked_credentials", 6, True, True),
    ("seo_spam", 4, True, False),
    ("pointer", 3, False, False),
    ("resolver", -1, False, False),
]


def all_labels(conn) -> list[tuple]:
    sql = "SELECT snapshot_id, page_id, category, score, assigned, is_primary FROM labels ORDER BY rowid"
    return [tuple(r) for r in conn.execute(sql)]


def test_save_labels_round_trip(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_labels(conn, snap, page_id, LABELS)
    assert all_labels(conn) == [
        (snap, page_id, "leaked_credentials", 6, 1, 1),
        (snap, page_id, "seo_spam", 4, 1, 0),
        (snap, page_id, "pointer", 3, 0, 0),
        (snap, page_id, "resolver", -1, 0, 0),
    ]


def test_label_rows_returns_one_snapshots_rows_in_stored_order(conn):
    a, snap_a = stored_page(conn, "a-01-01")
    b, snap_b = stored_page(conn, "b-01-01")
    save_labels(conn, snap_a, a, LABELS)
    save_labels(conn, snap_b, b, [("prose", 4, True, True)])
    rows = label_rows(conn, snap_a)
    assert [r["category"] for r in rows] == [label[0] for label in LABELS]
    assert [tuple(r) for r in label_rows(conn, snap_b)] == [("prose", 4, 1, 1)]


def test_save_labels_twice_replaces_the_snapshots_rows(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_labels(conn, snap, page_id, LABELS)
    save_labels(conn, snap, page_id, [("prose", 4, True, True)])
    assert all_labels(conn) == [(snap, page_id, "prose", 4, 1, 1)]


def test_save_labels_with_no_rows_clears_that_snapshot_and_no_other(conn):
    # A page that no longer scores in any category
    a, snap_a = stored_page(conn, "a-01-01")
    b, snap_b = stored_page(conn, "b-01-01")
    save_labels(conn, snap_a, a, [("pointer", 4, True, True)])
    save_labels(conn, snap_b, b, [("prose", 4, True, True)])
    save_labels(conn, snap_a, a, [])
    assert all_labels(conn) == [(snap_b, b, "prose", 4, 1, 1)]


def test_a_category_is_stored_once_per_snapshot(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    twice = [("prose", 4, True, True), ("prose", 5, True, False)]
    with pytest.raises(sqlite3.IntegrityError):
        save_labels(conn, snap, page_id, twice)


def test_save_score_and_save_labels_do_not_touch_each_others_rows(conn):
    # classify calls one and then the other for the same snapshot
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    save_labels(conn, snap, page_id, LABELS)
    save_score(conn, snap, page_id, 1, False, None, HITS[1:], T0 + 9)
    assert len(all_labels(conn)) == len(LABELS)
    save_labels(conn, snap, page_id, [])
    assert count(conn, "hits") == 1


def test_save_score_and_save_labels_leave_the_commit_to_the_caller(conn):
    # classify commits a batch of pages at a time; a rollback must undo
    # whatever of the batch was written.
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    save_labels(conn, snap, page_id, LABELS)
    conn.rollback()
    assert [count(conn, table) for table in ("scores", "hits", "labels")] == [0, 0, 0]


# --------------------------------------------------------------------------
# re-sweep: the work list and the gone marker (issue #37,
# plan/resweep-plan-2026-11-04.md)
# --------------------------------------------------------------------------


def seen_page(conn, path: str, last_seen: float) -> int:
    """A stored page with one snapshot, last seen at the given time."""
    page_id = upsert_page(conn, path, last_seen)
    add_snapshot(conn, page_id, {"title": path, "content": [f"body of {path}"]}, last_seen, KEY)
    return page_id


def flag(conn, page_id: int, flagged: bool = True) -> None:
    snap = conn.execute(
        "SELECT id FROM snapshots WHERE page_id = ? ORDER BY id DESC LIMIT 1", (page_id,)
    ).fetchone()[0]
    save_score(conn, snap, page_id, 6 if flagged else 0, flagged, None, [], T0)
    conn.commit()


def work(conn, cutoff, **kwargs) -> list[str]:
    return [row["path"] for row in resweep_paths(conn, cutoff, **kwargs)]


def test_resweep_paths_lists_pages_last_seen_before_the_cutoff(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-10-17-2", T0 + 2 * HOUR)
    assert work(conn, T0) == []  # the cutoff is strict
    assert id_paths(resweep_paths(conn, T0 + HOUR)) == [(page_id, "Hello-10-17-1")]
    assert work(conn, T0 + 3 * HOUR) == ["Hello-10-17-1", "Hello-10-17-2"]


def test_resweep_paths_is_oldest_first_then_by_title_day_and_counter(conn):
    seen_page(conn, "Hello-10-18-1", T0 + 60)
    seen_page(conn, "Test-10-17-1", T0)
    seen_page(conn, "Hello-10-17-10", T0)
    seen_page(conn, "Hello-10-17-9", T0)
    seen_page(conn, "Hello-10-16-11", T0)
    seen_page(conn, "Hello-09-30-1", T0)
    assert work(conn, T0 + HOUR) == [
        "Hello-09-30-1",
        "Hello-10-16-11",
        "Hello-10-17-9",  # by the counter as a number, not by the path as text
        "Hello-10-17-10",
        "Test-10-17-1",
        "Hello-10-18-1",
    ]


def test_resweep_paths_respects_the_window(conn):
    seen_page(conn, "Hello-10-16-1", T0)
    seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-11-17-1", T0)
    assert work(conn, T0 + HOUR, days=[(10, 17)]) == ["Hello-10-17-1"]
    assert work(conn, T0 + HOUR, days=[(10, 16), (11, 17)]) == ["Hello-10-16-1", "Hello-11-17-1"]
    assert len(work(conn, T0 + HOUR, days=None)) == 3


def test_resweep_paths_with_a_window_of_no_days_is_empty_not_an_error(conn):
    seen_page(conn, "Hello-10-17-1", T0)
    assert resweep_paths(conn, T0 + HOUR, days=[]) == []
    assert resweep_cost(conn, T0 + HOUR, days=[]) == 0


def test_resweep_paths_respects_the_limit(conn):
    for n in range(1, 6):
        seen_page(conn, f"Hello-10-17-{n}", T0 + n)
    assert work(conn, T0 + HOUR, limit=2) == ["Hello-10-17-1", "Hello-10-17-2"]


def test_a_page_fetched_again_drops_out_of_the_work_list(conn):
    # last_seen is the progress marker: nothing else has to be reset.
    seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-10-17-2", T0)
    cutoff = T0 + HOUR
    fetch = Fetch(
        "Hello-10-17-1",
        Outcome.FOUND,
        {"path": "Hello-10-17-1", "title": "t", "content": ["again"]},
        None,
        200,
        5,
    )
    store_fetch(conn, fetch, cutoff + 5, KEY)
    assert work(conn, cutoff) == ["Hello-10-17-2"]


def test_resweep_paths_can_keep_to_flagged_pages(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-17-2", T0)
    seen_page(conn, "Hello-10-17-3", T0)  # never classified
    flag(conn, a, True)
    flag(conn, b, False)
    assert work(conn, T0 + HOUR, flagged=True) == ["Hello-10-17-1"]
    assert len(work(conn, T0 + HOUR)) == 3
    # The list is built from the few flagged scores, through their own index,
    # and not by asking the scores about every page (ten seconds on 730,000)
    where, params = _resweep_where(T0 + HOUR, None, True, None)
    plan = [row["detail"] for row in conn.execute(f"EXPLAIN QUERY PLAN SELECT p.id FROM pages p WHERE {where}", params)]
    assert any("scores_flagged" in step for step in plan), plan
    assert not any(step.startswith("SCAN p") for step in plan), plan


def test_a_page_flagged_once_stays_on_the_flagged_list_after_an_edit(conn):
    # The actor edits in place. A new snapshot has no score until classify
    # runs, and may never be flagged again; the page is still one to watch.
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    flag(conn, page_id, True)
    add_snapshot(conn, page_id, {"title": "t", "content": ["rotated"]}, T0 + 60, KEY)
    assert work(conn, T0 + HOUR, flagged=True) == ["Hello-10-17-1"]
    flag(conn, page_id, False)
    assert work(conn, T0 + HOUR, flagged=True) == ["Hello-10-17-1"]


def test_resweep_paths_can_keep_to_pages_whose_newest_text_matches(conn):
    seen_page(conn, "Hello-10-17-1", T0)
    page_id = seen_page(conn, "Hello-10-17-2", T0)
    add_snapshot(conn, page_id, {"title": "t", "content": ["now 8.8.8.8"]}, T0 + 60, KEY)
    assert work(conn, T0 + HOUR, match="8.8.8.8") == ["Hello-10-17-2"]
    # The older snapshot of the second page does not count.
    assert work(conn, T0 + HOUR, match="body of Hello-10-17-2") == []
    assert work(conn, T0 + HOUR, match="body of Hello-10-17-1") == ["Hello-10-17-1"]


def test_match_is_a_plain_substring_not_a_like_pattern(conn):
    seen_page(conn, "Hello-10-17-1", T0)
    assert work(conn, T0 + HOUR, match="%") == []
    assert work(conn, T0 + HOUR, match="_") == []


def test_the_filters_combine(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-18-1", T0)
    seen_page(conn, "Hello-10-18-2", T0)  # in the window and matching, never flagged
    flag(conn, a)
    flag(conn, b)
    assert work(conn, T0 + HOUR, days=[(10, 18)], flagged=True, match="body of") == ["Hello-10-18-1"]


def test_resweep_cost_is_the_length_of_the_work_list(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-10-17-2", T0)
    seen_page(conn, "Hello-10-18-1", T0 + 2 * HOUR)
    flag(conn, a)
    for kwargs in (
        {},
        {"days": [(10, 17)]},
        {"flagged": True},
        {"match": "Hello-10-17-2"},
        {"days": [(10, 17)], "flagged": True},
    ):
        for cutoff in (T0, T0 + HOUR, T0 + 3 * HOUR):
            assert resweep_cost(conn, cutoff, **kwargs) == len(resweep_paths(conn, cutoff, **kwargs))
    assert resweep_cost(conn, T0 + HOUR) == 2


def test_mark_gone_writes_one_gone_event_and_keeps_the_page_as_it_was(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    mark_gone(conn, page_id, T0 + 99)
    assert events_of(conn, page_id, "gone") == [T0 + 99]
    # last_seen stays the last time the page was really there
    assert last_seen_of(conn, page_id) == T0
    assert count(conn, "snapshots") == 1


def test_a_gone_page_is_left_out_of_the_work_list_and_the_cost(conn):
    # Otherwise it would be asked for again every night.
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-10-17-2", T0)
    mark_gone(conn, page_id, T0 + 99)
    assert work(conn, T0 + HOUR) == ["Hello-10-17-2"]
    assert resweep_cost(conn, T0 + HOUR) == 1


def test_is_gone_follows_the_newest_gone_or_returned_event_of_that_page(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    other = seen_page(conn, "Hello-10-17-2", T0)
    assert is_gone(conn, page_id) is False
    mark_gone(conn, page_id, T0 + 10)
    assert is_gone(conn, page_id) is True
    assert is_gone(conn, other) is False
    add_event(conn, page_id, "returned", T0 + 20)
    assert is_gone(conn, page_id) is False
    mark_gone(conn, page_id, T0 + 30)
    assert is_gone(conn, page_id) is True


def test_other_event_kinds_do_not_change_whether_a_page_is_gone(conn):
    here = seen_page(conn, "Hello-10-17-1", T0)
    gone = seen_page(conn, "Hello-10-17-2", T0)
    mark_gone(conn, gone, T0 + 10)
    for page_id in (here, gone):
        add_event(conn, page_id, "modified_at_changed", T0 + 20)
    assert (is_gone(conn, here), is_gone(conn, gone)) == (False, True)
    assert work(conn, T0 + HOUR) == ["Hello-10-17-1"]


def test_a_gone_page_that_is_fetched_again_gets_one_returned_event(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    upsert_page(conn, "Hello-10-17-1", T0 + 5)  # an ordinary refetch: it never left
    assert events_of(conn, page_id, "returned") == []
    mark_gone(conn, page_id, T0 + 10)
    upsert_page(conn, "Hello-10-17-1", T0 + 20)
    upsert_page(conn, "Hello-10-17-1", T0 + 30)  # still there: not returned twice
    assert events_of(conn, page_id, "returned") == [T0 + 20]
    assert is_gone(conn, page_id) is False
    assert work(conn, T0 + HOUR) == ["Hello-10-17-1"]  # and back on the work list


# --------------------------------------------------------------------------
# indicators and feed_lookups (issue #38, plan/enrichment-plan-2026-11-22.md)
# --------------------------------------------------------------------------


def indicator(conn, indicator_id: int) -> dict:
    return dict(conn.execute("SELECT * FROM indicators WHERE id = ?", (indicator_id,)).fetchone())


def seen_on(conn, indicator_id: int) -> tuple:
    row = indicator(conn, indicator_id)
    return (row["source"], row["first_seen"], row["last_seen"], row["pages"])


def test_upsert_indicator_stores_a_new_indicator(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 4)
    assert indicator(conn, indicator_id) == {
        "id": indicator_id,
        "kind": "ip",
        "value": "8.8.8.8",
        "source": "pages",
        "first_seen": T0,
        "last_seen": T0 + 60,
        "pages": 4,
    }


def test_upsert_indicator_from_a_file_has_no_times_and_no_pages(conn):
    indicator_id = upsert_indicator(conn, "host", "c2.example.org", "indicators.tsv")
    assert seen_on(conn, indicator_id) == ("indicators.tsv", None, None, 0)


def test_the_same_value_under_two_kinds_is_two_indicators(conn):
    a = upsert_indicator(conn, "host", "8.8.8.8", "pages")
    b = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    assert a != b


def test_upsert_indicator_from_pages_stores_what_the_pages_say_now(conn):
    # collect_indicators reads every snapshot of every flagged page each run,
    # so its answer is the whole truth: after a rule fix fewer pages may hold
    # the indicator, and the first of them may be a later one.
    other = upsert_indicator(conn, "ip", "9.9.9.9", "pages", T0, T0, 1)
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 200, 5)
    again = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0 + 50, T0 + 150, 2)
    assert again == indicator_id
    assert count(conn, "indicators") == 2
    assert seen_on(conn, indicator_id) == ("pages", T0 + 50, T0 + 150, 2)
    assert seen_on(conn, other) == ("pages", T0, T0, 1)


def test_upsert_indicator_does_not_lose_times_to_a_file_row(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 3)
    assert upsert_indicator(conn, "ip", "8.8.8.8", "indicators.tsv") == indicator_id
    assert seen_on(conn, indicator_id) == ("pages", T0, T0 + 60, 3)


def test_a_file_indicator_later_found_on_pages_becomes_a_pages_indicator(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "indicators.tsv")
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 2)
    assert seen_on(conn, indicator_id) == ("pages", T0, T0 + 60, 2)


def test_upsert_indicator_keeps_the_lookups_stored_against_it(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0)
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 2)
    assert cached_feeds(conn, indicator_id) == {"otx"}


def test_release_indicator_to_file_gives_a_pages_indicator_back_to_the_file(conn):
    # No flagged page holds it any more and the file still names it
    released = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 3)
    on_pages = upsert_indicator(conn, "ip", "9.9.9.9", "pages", T0, T0 + 60, 3)
    release_indicator_to_file(conn, "ip", "8.8.8.8", "indicators.tsv")
    assert seen_on(conn, released) == ("indicators.tsv", None, None, 0)
    assert seen_on(conn, on_pages) == ("pages", T0, T0 + 60, 3)


def test_release_indicator_to_file_leaves_another_files_indicator_with_that_file(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "first.tsv")
    release_indicator_to_file(conn, "ip", "8.8.8.8", "second.tsv")
    assert seen_on(conn, indicator_id) == ("first.tsv", None, None, 0)


def test_delete_stale_indicators_drops_page_indicators_that_are_not_current(conn):
    keep = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    # The same value under another kind is another indicator, and not current
    gone = upsert_indicator(conn, "host", "8.8.8.8", "pages", T0, T0, 1)
    listed = upsert_indicator(conn, "host", "probe.example.org", "indicators.tsv")
    for indicator_id in (keep, gone, listed):
        save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0)
    assert delete_stale_indicators(conn, {("ip", "8.8.8.8")}) == 1
    assert [(r["kind"], r["value"]) for r in indicator_rows(conn)] == [
        ("host", "probe.example.org"),
        ("ip", "8.8.8.8"),
    ]
    assert count(conn, "feed_lookups") == 2
    assert cached_feeds(conn, keep) == {"otx"}


def test_save_lookup_round_trip(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    other = upsert_indicator(conn, "ip", "9.9.9.9", "pages")
    save_lookup(conn, indicator_id, "threatfox", "KNOWN", "2 IOCs", T0 + 5)
    save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0 + 6)
    save_lookup(conn, other, "urlhaus", "UNKNOWN", None, T0 + 7)
    # the answer, and after it the first answer, which is the same one so far
    assert [tuple(r) for r in lookup_rows(conn, indicator_id)] == [
        ("otx", "UNKNOWN", None, T0 + 6, "UNKNOWN", T0 + 6),
        ("threatfox", "KNOWN", "2 IOCs", T0 + 5, "KNOWN", T0 + 5),
    ]


def test_save_lookup_twice_replaces_the_answer_for_that_feed(conn):
    # What --refresh does: the newer answer and its time win.
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0)
    save_lookup(conn, indicator_id, "otx", "KNOWN", "1 pulses", T0 + 99)
    assert [tuple(r) for r in lookup_rows(conn, indicator_id)] == [
        ("otx", "KNOWN", "1 pulses", T0 + 99, "UNKNOWN", T0)
    ]


def test_save_lookup_keeps_the_first_answer_however_often_it_is_replaced(conn):
    # What a feed knew when the indicator was found is the Novelty measure
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0)
    save_lookup(conn, indicator_id, "otx", "KNOWN", "1 pulses", T0 + 99)
    save_lookup(conn, indicator_id, "otx", "KNOWN", "3 pulses", T0 + 200)
    assert [tuple(r) for r in conn.execute("SELECT * FROM first_lookups")] == [
        (indicator_id, "otx", "UNKNOWN", None, T0)
    ]
    assert tuple(lookup_rows(conn, indicator_id)[0])[1:4] == ("KNOWN", "3 pulses", T0 + 200)


def test_an_answer_stored_before_first_lookups_existed_becomes_the_first_answer(conn):
    # Production's first 152 answers were stored the day before the table was added
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    conn.execute(
        "INSERT INTO feed_lookups (indicator_id, feed, verdict, detail, checked_at) VALUES (?, ?, ?, ?, ?)",
        (indicator_id, "threatfox", "UNKNOWN", None, T0),
    )
    conn.commit()
    # read as it stands, the stored answer is its own first answer
    assert tuple(lookup_rows(conn, indicator_id)[0]) == ("threatfox", "UNKNOWN", None, T0, "UNKNOWN", T0)
    # and its age is measured from that day
    assert cached_feeds(conn, indicator_id, RECHECK, T0 + RECHECK - 1) == {"threatfox"}
    assert cached_feeds(conn, indicator_id, RECHECK, T0 + RECHECK) == set()
    save_lookup(conn, indicator_id, "threatfox", "KNOWN", "1 IOCs, Made-up RAT", T0 + 14 * DAY)
    assert tuple(lookup_rows(conn, indicator_id)[0]) == (
        "threatfox", "KNOWN", "1 IOCs, Made-up RAT", T0 + 14 * DAY, "UNKNOWN", T0,
    )


def test_an_indicators_titles_are_what_the_flagged_pages_say_in_this_run(conn):
    def titles(indicator_id):
        return [tuple(row) for row in title_rows(conn, indicator_id)]

    a = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 4, {"botnet": 1, "hello": 3})
    listed = upsert_indicator(conn, "ip", "9.9.9.9", "indicators.tsv")
    other = upsert_indicator(conn, "ip", "8.8.4.4", "pages", T0, T0, 1, {"hello": 1})
    assert titles(a) == [("hello", 3), ("botnet", 1)]  # the title on most pages first
    assert titles(listed) == []
    # the next run replaces them, as it replaces the times and the page count
    assert upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 2, {"hello": 1, "alfa": 1}) == a
    assert titles(a) == [("alfa", 1), ("hello", 1)]
    # a file that names the indicator changes nothing on a row the pages gave
    upsert_indicator(conn, "ip", "8.8.8.8", "indicators.tsv")
    assert titles(a) == [("alfa", 1), ("hello", 1)]
    # given back to the file it is on no page any more
    release_indicator_to_file(conn, "ip", "8.8.8.8", "indicators.tsv")
    assert titles(a) == []
    assert titles(other) == [("hello", 1)]  # and no other indicator loses its own
    # Code from before the titles were kept gives an indicator back to its
    # file and leaves them behind. The next run of this code clears them.
    conn.execute("INSERT INTO indicator_titles (indicator_id, slug, pages) VALUES (?, 'hello', 2)", (a,))
    assert delete_stale_indicators(conn, {("ip", "8.8.4.4")}) == 0
    assert (titles(a), titles(other)) == ([], [("hello", 1)])
    # and a stale indicator takes its titles with it
    assert delete_stale_indicators(conn, set()) == 1
    assert conn.execute("SELECT COUNT(*) FROM indicator_titles").fetchone()[0] == 0


def test_delete_stale_indicators_takes_the_first_answers_with_it(conn):
    gone = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    kept = upsert_indicator(conn, "ip", "9.9.9.9", "pages")
    save_lookup(conn, gone, "otx", "UNKNOWN", None, T0)
    save_lookup(conn, kept, "otx", "UNKNOWN", None, T0)
    assert delete_stale_indicators(conn, {("ip", "9.9.9.9")}) == 1
    assert [r[0] for r in conn.execute("SELECT indicator_id FROM first_lookups")] == [kept]
    # Code from before the table existed deletes the answers and the indicator
    # and knows nothing of first_lookups: after a rollback it must still work
    conn.execute("DELETE FROM feed_lookups WHERE indicator_id = ?", (kept,))
    conn.execute("DELETE FROM indicators WHERE id = ?", (kept,))
    assert conn.execute("SELECT COUNT(*) FROM first_lookups").fetchone()[0] == 0




@pytest.mark.parametrize(
    "verdict,first_at,asked_at,now,stands",
    [
        ("UNKNOWN", T0, T0, T0 + RECHECK - 1, True),  # not old enough yet
        ("UNKNOWN", T0, T0, T0 + RECHECK, False),  # old enough: asked for once more
        ("UNKNOWN", T0, T0 + 3 * DAY, T0 + RECHECK, False),  # a refresh on day 3 was too early to count
        ("UNKNOWN", T0, T0 + RECHECK, T0 + 40 * DAY, True),  # asked at that age: never again
        ("UNKNOWN", T0, T0 + 20 * DAY, T0 + 400 * DAY, True),
        ("KNOWN", T0, T0, T0 + 400 * DAY, True),  # a KNOWN is not asked for again
    ],
)
def test_cached_feeds_lets_an_old_unknown_be_asked_for_once_more(conn, verdict, first_at, asked_at, now, stands):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    save_lookup(conn, indicator_id, "otx", verdict, None, first_at)
    if asked_at != first_at:
        save_lookup(conn, indicator_id, "otx", verdict, None, asked_at)
    assert cached_feeds(conn, indicator_id, RECHECK, now) == ({"otx"} if stands else set())
    # with no recheck age nothing is ever asked for again
    assert cached_feeds(conn, indicator_id) == {"otx"}


def test_cached_feeds_names_the_feeds_that_answered_for_one_indicator(conn):
    a = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    b = upsert_indicator(conn, "ip", "9.9.9.9", "pages")
    never = upsert_indicator(conn, "ip", "1.1.1.1", "pages")
    save_lookup(conn, a, "otx", "UNKNOWN", None, T0)
    save_lookup(conn, a, "virustotal", "KNOWN", "x", T0)
    save_lookup(conn, b, "threatfox", "UNKNOWN", None, T0)
    assert cached_feeds(conn, a) == {"otx", "virustotal"}
    assert cached_feeds(conn, b) == {"threatfox"}
    assert cached_feeds(conn, never) == set()


def test_indicator_rows_is_by_kind_then_first_seen_with_untimed_ones_last(conn):
    upsert_indicator(conn, "ip", "9.9.9.9", "pages", T0 + 60, T0 + 60, 1)
    upsert_indicator(conn, "ip", "1.1.1.1", "indicators.tsv")
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    upsert_indicator(conn, "host", "c2.example.org", "pages", T0 + 600, T0 + 600, 1)
    assert [(r["kind"], r["value"]) for r in indicator_rows(conn)] == [
        ("host", "c2.example.org"),
        ("ip", "8.8.8.8"),
        ("ip", "9.9.9.9"),
        ("ip", "1.1.1.1"),
    ]


def test_flagged_page_ids_lists_each_flagged_page_once_lowest_first(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-17-2", T0 + 30)
    flag(conn, b, True)
    flag(conn, a, True)
    # a second flagged snapshot of the same page is still one page
    add_snapshot(conn, a, {"title": "t", "content": ["rotated"]}, T0 + 60, KEY)
    flag(conn, a, True)
    assert conn.execute("SELECT COUNT(*) FROM scores WHERE flagged = 1").fetchone()[0] == 3
    assert flagged_page_ids(conn) == [a, b]
    # with the title each was found under, which says whose page it is
    c = seen_page(conn, "botnet-11-20", T0 + 90)
    flag(conn, c, True)
    assert [tuple(row) for row in flagged_pages(conn)] == [(a, "hello"), (b, "hello"), (c, "botnet")]


def test_flagged_page_ids_leaves_out_unflagged_and_held_out_pages(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-17-2", T0)
    seen_page(conn, "Hello-10-17-3", T0)  # never classified
    known = upsert_page(conn, "Known-01-02", T0, held_out=True)
    add_snapshot(conn, known, {"title": "k", "content": ["x"]}, T0, KEY)
    flag(conn, a, True)
    flag(conn, b, False)
    flag(conn, known, True)
    assert flagged_page_ids(conn) == [a]
    # The actor edits in place: the newest snapshot need not be the flagged one.
    add_snapshot(conn, a, {"title": "t", "content": ["rotated"]}, T0 + 60, KEY)
    flag(conn, a, False)
    assert flagged_page_ids(conn) == [a]


def test_page_snapshots_reads_every_snapshot_of_the_one_page_oldest_first(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-17-2", T0 + 30)
    add_snapshot(conn, a, {"title": "t", "content": ["rotated"]}, T0 + 60, KEY)
    rows = page_snapshots(conn, a)
    assert [(r["page_id"], r["fetched_at"]) for r in rows] == [(a, T0), (a, T0 + 60)]
    assert (rows[1]["title"], rows[1]["text"]) == ("t", "t\n\nrotated")
    assert rows[0]["id"] < rows[1]["id"]
    # No author field: those are stored raw and never published
    assert set(rows[0].keys()) == {"id", "page_id", "fetched_at", "title", "text"}
    assert [r["page_id"] for r in page_snapshots(conn, b)] == [b]
    assert page_snapshots(conn, 999) == []
    # a tie in time is broken by the order they were stored
    tied, _changed = add_snapshot(conn, a, {"title": "t", "content": ["again"]}, T0 + 60, KEY)
    assert [r["id"] for r in page_snapshots(conn, a)][-1] == tied


def test_page_snapshots_hands_out_a_list_and_leaves_no_read_open(conn):
    # A cursor left open holds a read lock, and every other writer's commit
    # waits behind it. A list has been read to its end.
    a = seen_page(conn, "Hello-10-17-1", T0)
    assert isinstance(page_snapshots(conn, a), list)
    assert isinstance(flagged_page_ids(conn), list)


# --------------------------------------------------------------------------
# the ten-minute re-poll: a snapshot only on change, views kept apart
# (decided 22 November)
# --------------------------------------------------------------------------


def poll_page(title="t", body="same", views=5) -> dict:
    return {"path": "Hello-10-17-1", "title": title, "description": body, "views": views, "content": [body]}


def stored_poll_page(conn) -> int:
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    add_snapshot(conn, page_id, poll_page(), T0, KEY)
    return page_id


def test_refresh_snapshot_of_an_unchanged_page_keeps_its_view_count_and_stores_no_snapshot(conn):
    page_id = stored_poll_page(conn)
    assert refresh_snapshot(conn, page_id, poll_page(views=9), T0 + 600, KEY) is False
    refresh_snapshot(conn, page_id, poll_page(views=12), T0 + 1200, KEY)
    assert count(conn, "snapshots") == 1
    assert events_of(conn, page_id, "content_changed") == []
    rows = [tuple(r) for r in conn.execute("SELECT page_id, fetched_at, views FROM views ORDER BY fetched_at")]
    assert rows == [(page_id, T0 + 600, 9), (page_id, T0 + 1200, 12)]


def test_refresh_snapshot_moves_last_seen_of_that_page_whether_or_not_it_changed(conn):
    other = seen_page(conn, "Hello-10-17-2", T0)
    page_id = stored_poll_page(conn)
    refresh_snapshot(conn, page_id, poll_page(), T0 + 600, KEY)
    assert last_seen_of(conn, page_id) == T0 + 600
    refresh_snapshot(conn, page_id, poll_page(title="new"), T0 + 1200, KEY)
    assert last_seen_of(conn, page_id) == T0 + 1200
    assert last_seen_of(conn, other) == T0


def test_refresh_snapshot_of_a_changed_page_stores_it_and_writes_the_event(conn):
    page_id = stored_poll_page(conn)
    assert refresh_snapshot(conn, page_id, poll_page(title="9.9.9.9"), T0 + 600, KEY) is True
    titles = [r["title"] for r in conn.execute("SELECT title FROM snapshots ORDER BY id")]
    assert titles == ["t", "9.9.9.9"]
    assert events_of(conn, page_id, "content_changed") == [T0 + 600]
    assert count(conn, "views") == 0


def test_refresh_snapshot_compares_after_redaction(conn):
    # The stored fingerprint is of the redacted page, so the raw page has to
    # be redacted before the two are compared.
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    page = poll_page(body="password: hunter2")
    add_snapshot(conn, page_id, page, T0, KEY)
    assert refresh_snapshot(conn, page_id, page, T0 + 600, KEY) is False
    assert count(conn, "snapshots") == 1


def test_refresh_snapshot_compares_with_the_newest_snapshot_of_that_page(conn):
    page_id = stored_poll_page(conn)
    add_snapshot(conn, page_id, poll_page(title="edited"), T0 + 60, KEY)
    seen_page(conn, "Hello-10-17-2", T0 + 120)  # newer, and another page's
    assert refresh_snapshot(conn, page_id, poll_page(title="edited"), T0 + 600, KEY) is False
    assert snapshots_of(conn, page_id) == 2


def test_refresh_snapshot_of_a_page_with_no_snapshot_stores_the_first(conn):
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    assert refresh_snapshot(conn, page_id, poll_page(), T0 + 600, KEY) is False
    assert count(conn, "snapshots") == 1


def test_refresh_snapshot_goes_by_the_page_id_not_the_path_in_the_answer(conn):
    page_id = upsert_page(conn, "mark-01-20-5", T0, held_out=True)
    add_snapshot(conn, page_id, poll_page(), T0, KEY)
    answer = {**poll_page(title="edited"), "path": "Mark-01-20-5"}
    refresh_snapshot(conn, page_id, answer, T0 + 600, KEY)
    assert [tuple(r) for r in conn.execute("SELECT id, path, held_out FROM pages")] == [(page_id, "mark-01-20-5", 1)]
    assert snapshots_of(conn, page_id) == 2


def test_two_polls_at_the_same_instant_keep_one_views_row(conn):
    page_id = stored_poll_page(conn)
    refresh_snapshot(conn, page_id, poll_page(views=9), T0 + 600, KEY)
    refresh_snapshot(conn, page_id, poll_page(views=10), T0 + 600, KEY)
    assert [r["views"] for r in conn.execute("SELECT views FROM views")] == [10]


def test_live_older_snapshots_are_the_older_ones_that_are_flagged_or_hold_the_templated_hit(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-17-2", T0)
    c = seen_page(conn, "Hello-10-17-3", T0)
    d = seen_page(conn, "Hello-10-17-4", T0)
    flag(conn, a, True)
    flag(conn, b, False)
    flag(conn, d, True)  # flagged, and its one snapshot is its newest: nothing older
    # c lost its flag to the templated penalty, and has to be able to get it back
    first = {page: conn.execute("SELECT MIN(id) FROM snapshots WHERE page_id = ?", (page,)).fetchone()[0] for page in (a, b, c)}
    save_score(conn, first[c], c, 2, False, "abc", [("templated_body", -2, "body abc", 1), ("other", 4, "x", 1)], T0)
    add_snapshot(conn, a, {"title": "t", "content": ["second"]}, T0 + 60, KEY)
    add_snapshot(conn, a, {"title": "t", "content": ["third"]}, T0 + 120, KEY)
    add_snapshot(conn, b, {"title": "t", "content": ["second"]}, T0 + 60, KEY)
    add_snapshot(conn, c, {"title": "t", "content": ["second"]}, T0 + 60, KEY)
    conn.commit()
    # Of page a's two older snapshots only the first holds a score; the second
    # was never scored and cannot make the page flagged. b's is not flagged.
    assert live_older_snapshots(conn, "templated_body", 4) == [first[a], first[c]]
    # any other hit keeps no row alive
    assert live_older_snapshots(conn, "another_rule", 4) == [first[a]]
    # A row that a run at a higher threshold left unflagged is found again
    # by a run at a threshold its score reaches: c's 2 here, at 2 and not at 3
    assert live_older_snapshots(conn, "another_rule", 3) == [first[a]]
    assert live_older_snapshots(conn, "another_rule", 2) == [first[a], first[c]]


# --- what the second review of 22 November found -------------------------------------


def test_a_changed_snapshot_and_its_event_are_one_transaction(tmp_path):
    # add_event commits on its own. Had add_snapshot used it, a run that died
    # after the event and before the snapshot would leave an event with no
    # snapshot, and the next poll would write the event a second time.
    db = tmp_path / "g.sqlite"
    writer = connect(db)
    page_id = upsert_page(writer, "Hello-10-17-1", T0)
    add_snapshot(writer, page_id, poll_page(), T0, KEY)
    statements = []
    writer.set_trace_callback(statements.append)
    add_snapshot(writer, page_id, poll_page(title="9.9.9.9"), T0 + 600, KEY)
    writer.set_trace_callback(None)
    event_at = next(i for i, sql in enumerate(statements) if sql.startswith("INSERT INTO events"))
    snapshot_at = next(i for i, sql in enumerate(statements) if "INSERT INTO snapshots" in sql)
    commits = [i for i, sql in enumerate(statements) if sql.strip().upper() == "COMMIT"]
    assert event_at < snapshot_at
    assert not [i for i in commits if event_at < i < snapshot_at]
    writer.close()


def test_refresh_snapshot_of_a_changed_page_commits_once(tmp_path):
    db = tmp_path / "g.sqlite"
    writer = connect(db)
    page_id = upsert_page(writer, "Hello-10-17-1", T0)
    add_snapshot(writer, page_id, poll_page(), T0, KEY)
    statements = []
    writer.set_trace_callback(statements.append)
    refresh_snapshot(writer, page_id, poll_page(title="9.9.9.9"), T0 + 600, KEY)
    writer.set_trace_callback(None)
    assert sum(1 for sql in statements if sql.strip().upper() == "COMMIT") == 1
    writer.close()


def test_refresh_snapshot_of_an_unchanged_page_refreshes_the_author_fields(conn):
    other = upsert_page(conn, "Hello-10-17-2", T0)
    add_snapshot(conn, other, PAGE, T0, KEY)
    page_id = stored_poll_page(conn)
    page = {**poll_page(), "author_name": "new name", "author_url": "https://t.me/new"}
    assert refresh_snapshot(conn, page_id, page, T0 + 600, KEY) is False
    assert author_of(conn, page_id) == ("new name", "https://t.me/new")
    assert author_of(conn, other) == ("a", "https://t.me/a")


# --------------------------------------------------------------------------
# who commits: the nightly job and the re-poll write to one file, and a run
# can be stopped by its budget or a crash after any unit of work
# --------------------------------------------------------------------------

LOG_ROW = {
    "ts": T0,
    "path": "a-01-01",
    "attempt": 1,
    "status": 200,
    "outcome": "NOT_FOUND",
    "error": "PAGE_NOT_FOUND",
    "elapsed_ms": 5,
    "bytes": 40,
}

# Each write starts from one stored page (Hello-10-17-1, with one snapshot of
# poll_page()) and one indicator from pages (ip 8.8.8.8), and gets their ids.
WRITES = {
    "add_event": lambda c, page, ind: add_event(c, page, "flagged", T0 + 1),
    "upsert_title": lambda c, page, ind: upsert_title(c, Entry("Test", "Test", "greetings", False), T0),
    "upsert_page, new": lambda c, page, ind: upsert_page(c, "Hello-10-17-2", T0 + 1),
    "upsert_page, seen before": lambda c, page, ind: upsert_page(c, "Hello-10-17-1", T0 + 1),
    "add_snapshot, changed": lambda c, page, ind: add_snapshot(c, page, poll_page(title="new"), T0 + 1, KEY),
    "add_snapshot, unchanged": lambda c, page, ind: add_snapshot(c, page, poll_page(), T0 + 1, KEY),
    "refresh_snapshot, unchanged": lambda c, page, ind: refresh_snapshot(c, page, poll_page(), T0 + 1, KEY),
    "store_meta": lambda c, page, ind: store_meta(c, page, meta(), T0 + 1),
    "http_logger": lambda c, page, ind: http_logger(c)(LOG_ROW),
    "save_progress": lambda c, page, ind: save_progress(c, "Hello", 10, 17, 5, False, 7, 0, T0),
    "upsert_indicator, new": lambda c, page, ind: upsert_indicator(c, "ip", "9.9.9.9", "pages", T0, T0, 1),
    "upsert_indicator, seen before": lambda c, page, ind: upsert_indicator(c, "ip", "8.8.8.8", "pages", T0, T0 + 1, 2),
    "release_indicator_to_file": lambda c, page, ind: release_indicator_to_file(c, "ip", "8.8.8.8", "indicators.tsv"),
    "delete_stale_indicators": lambda c, page, ind: delete_stale_indicators(c, set()),
    "save_lookup": lambda c, page, ind: save_lookup(c, ind, "otx", "UNKNOWN", None, T0),
}


@pytest.mark.parametrize("name", WRITES)
def test_a_write_is_committed_when_its_function_returns(conn, name):
    page_id = stored_poll_page(conn)
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    conn.commit()
    changes = conn.total_changes
    WRITES[name](conn, page_id, indicator_id)
    assert conn.total_changes > changes  # it did write
    # True from a connection's first write until its commit
    assert not conn.in_transaction
