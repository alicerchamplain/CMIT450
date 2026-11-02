"""Tests for graphwatch.db.

Every test runs against an in-memory SQLite database, so nothing here touches
the disk or the network. Pages come from plan/fixtures.
"""

import json
import sqlite3
from pathlib import Path

import pytest

from graphwatch.db import (
    SCHEMA,
    add_event,
    add_snapshot,
    connect,
    held_out_paths,
    http_logger,
    load_known,
    parse_path,
    load_progress,
    save_progress,
    store_fetch,
    upsert_page,
    upsert_title,
)
from graphwatch.slugify import Entry
from graphwatch.telegraph import Fetch, Outcome, TelegraphClient

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plan" / "fixtures"
KNOWN = ROOT / "known.txt"

T0 = 1_700_000_000.0  # a fixed "now" so timestamps are predictable
KEY = b"test-key"  # any fixed HMAC key; redaction output only has to be stable


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def tables(conn) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {r[0] for r in rows}


def columns(conn, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


# --------------------------------------------------------------------------
# connect and schema
# --------------------------------------------------------------------------


def test_connect_creates_the_planned_tables(conn):
    assert {
        "titles",
        "pages",
        "snapshots",
        "events",
        "http_log",
        "crowd",
        "sweep_progress",
    } <= tables(conn)


def test_connect_is_idempotent_on_an_existing_file(tmp_path):
    db = tmp_path / "g.sqlite"
    c1 = connect(db)
    c1.execute("INSERT INTO events (ts, kind) VALUES (?, ?)", (T0, "x"))
    c1.commit()
    c1.close()
    c2 = connect(db)  # must not fail on CREATE TABLE, must not wipe data
    assert c2.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    c2.close()


def test_connect_returns_rows_addressable_by_name(conn):
    conn.execute("INSERT INTO events (ts, kind) VALUES (?, ?)", (T0, "x"))
    row = conn.execute("SELECT kind FROM events").fetchone()
    assert row["kind"] == "x"


def test_connect_enforces_foreign_keys(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO snapshots (page_id, fetched_at, content, text, sha256) "
            "VALUES (?, ?, ?, ?, ?)",
            (999, T0, "[]", "", "0" * 64),
        )


def test_schema_is_plain_sql_text():
    assert isinstance(SCHEMA, str)
    assert "CREATE TABLE IF NOT EXISTS" in SCHEMA


@pytest.mark.parametrize(
    "table, expected",
    [
        ("titles", {"id", "title", "slug", "source", "crowd_only", "added_at"}),
        (
            "pages",
            {
                "id",
                "path",
                "slug",
                "month",
                "day",
                "counter",
                "title_id",
                "held_out",
                "first_seen",
                "last_seen",
            },
        ),
        (
            "snapshots",
            {
                "id",
                "page_id",
                "fetched_at",
                "title",
                "description",
                "views",
                "content",
                "text",
                "sha256",
            },
        ),
        ("events", {"id", "page_id", "ts", "kind", "detail"}),
        (
            "http_log",
            {
                "id",
                "ts",
                "path",
                "attempt",
                "status",
                "outcome",
                "error",
                "elapsed_ms",
                "bytes",
            },
        ),
    ],
)
def test_tables_have_the_planned_columns(conn, table, expected):
    assert expected <= columns(conn, table)


# --------------------------------------------------------------------------
# parse_path
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("Vizit-12-28", ("Vizit", 12, 28, None)),
        ("Hello-01-23-161", ("Hello", 1, 23, 161)),
        ("mark-01-20-5", ("mark", 1, 20, 5)),
        ("ki06-05-02", ("ki06", 5, 2, None)),
        ("Hello-World-10-24", ("Hello-World", 10, 24, None)),
        ("do-Penthouse---Grati-11-17", ("do-Penthouse---Grati", 11, 17, None)),
        ("Povіstka-10-25", ("Povіstka", 10, 25, None)),  # Cyrillic і
        ("video-10-17", ("video", 10, 17, None)),
        # Two-digit counters: the greedy regex used to read these as a slug
        # ending in the month and a date shifted right by one field.
        ("Hello-10-17-15", ("Hello", 10, 17, 15)),
        ("Hello-10-17-10", ("Hello", 10, 17, 10)),
        ("T-11-01-10", ("T", 11, 1, 10)),
        ("Test-10-11-12", ("Test", 10, 11, 12)),  # ambiguous; the counter reading wins
        # A slug that itself ends in a date, posted on another day.
        ("Test-10-16-10-17", ("Test-10-16", 10, 17, None)),
        ("Test-10-16-10-17-3", ("Test-10-16", 10, 17, 3)),
    ],
)
def test_parse_path_splits_slug_month_day_counter(path, expected):
    assert parse_path(path) == expected


def test_parse_path_slug_with_digits_is_not_mistaken_for_a_date():
    # 10-16 is the date; "Test-10" is not a slug plus a counter.
    assert parse_path("Test-10-16") == ("Test", 10, 16, None)


@pytest.mark.parametrize(
    "bad",
    [
        "Vizit",
        "Vizit-12",
        "Vizit-1-28",
        "-12-28",
        "Vizit-12-28-",
        "",
        "Vizit-13-01",
        "Vizit-12-32",
        "Vizit-00-10",
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


def test_upsert_title_same_slug_returns_the_same_id(conn):
    a = upsert_title(conn, Entry("Test", "Test", "greetings", False), T0)
    b = upsert_title(conn, Entry("Test", "Test", "greetings", False), T0 + 1)
    assert a == b
    assert conn.execute("SELECT COUNT(*) FROM titles").fetchone()[0] == 1


def test_upsert_title_slug_is_case_insensitive(conn):
    # Finding 2: TEST and Test name the same page, so they are one title row.
    a = upsert_title(conn, Entry("Test", "Test", "a", False), T0)
    b = upsert_title(conn, Entry("TEST", "TEST", "b", False), T0)
    assert a == b


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
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 1


def test_upsert_page_path_is_stored_exactly_as_given(conn):
    # Finding 2: the stored path must be the API's `path` field, case and all.
    pid = upsert_page(conn, "video-10-17", T0)
    assert (
        conn.execute("SELECT path FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        == "video-10-17"
    )


def test_upsert_page_held_out_is_sticky(conn):
    pid = upsert_page(conn, "Vizit-12-28", T0, held_out=True)
    upsert_page(conn, "Vizit-12-28", T0 + 1)  # a later sweep sees it again
    assert (
        conn.execute("SELECT held_out FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        == 1
    )


def test_upsert_page_links_to_a_title_by_slug_case_insensitively(conn):
    tid = upsert_title(conn, Entry("Hello", "Hello", "greetings", False), T0)
    pid = upsert_page(conn, "hello-10-24", T0)
    assert (
        conn.execute("SELECT title_id FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        == tid
    )


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


def test_upsert_page_rejects_a_malformed_path(conn):
    with pytest.raises(ValueError):
        upsert_page(conn, "not-a-path", T0)


# --------------------------------------------------------------------------
# snapshots
# --------------------------------------------------------------------------


def test_add_snapshot_stores_the_page_fields(conn):
    page = fixture_page("Vizit-12-28")
    pid = upsert_page(conn, page["path"], T0)
    sid, changed = add_snapshot(conn, pid, page, T0, KEY)
    row = conn.execute("SELECT * FROM snapshots WHERE id = ?", (sid,)).fetchone()
    assert row["page_id"] == pid
    assert row["fetched_at"] == T0
    assert row["title"] == page["title"]
    assert row["description"] == page["description"]
    assert row["views"] == page["views"]
    assert json.loads(row["content"]) == page["content"]
    assert "workers.dev" in row["text"]  # page_text, not raw JSON
    assert len(row["sha256"]) == 64 and int(row["sha256"], 16) >= 0


def test_add_snapshot_first_snapshot_is_not_a_change(conn):
    page = fixture_page("Vizit-12-28")
    pid = upsert_page(conn, page["path"], T0)
    _, changed = add_snapshot(conn, pid, page, T0, KEY)
    assert changed is False
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM events WHERE kind = 'content_changed'"
        ).fetchone()[0]
        == 0
    )


def test_add_snapshot_identical_content_is_not_a_change(conn):
    page = fixture_page("Vizit-12-28")
    pid = upsert_page(conn, page["path"], T0)
    add_snapshot(conn, pid, page, T0, KEY)
    again = dict(page, views=page["views"] + 1000)  # views alone do not count
    sid2, changed = add_snapshot(conn, pid, again, T0 + 3600, KEY)
    assert changed is False
    assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 2


def test_add_snapshot_changed_content_writes_an_event(conn):
    page = fixture_page("Vizit-12-28")
    pid = upsert_page(conn, page["path"], T0)
    add_snapshot(conn, pid, page, T0, KEY)
    rotated = dict(page, content=[{"tag": "p", "children": ["new pointer"]}])
    _, changed = add_snapshot(conn, pid, rotated, T0 + 3600, KEY)
    assert changed is True
    rows = conn.execute(
        "SELECT kind, ts FROM events WHERE page_id = ? AND kind = 'content_changed'",
        (pid,),
    ).fetchall()
    assert [(r["kind"], r["ts"]) for r in rows] == [("content_changed", T0 + 3600)]


def test_add_snapshot_title_change_counts_as_a_change(conn):
    # Finding 8: titles change after publication, and Gamaredon's pointer
    # lives in the title, so a title change is a content change.
    page = fixture_page("Hello-10-17-154")
    pid = upsert_page(conn, page["path"], T0)
    add_snapshot(conn, pid, page, T0, KEY)
    _, changed = add_snapshot(conn, pid, dict(page, title="TMP"), T0 + 1, KEY)
    assert changed is True


def test_add_snapshot_hash_is_the_same_for_the_same_content(conn):
    page = fixture_page("ki06-05-02")
    pid = upsert_page(conn, page["path"], T0)
    add_snapshot(conn, pid, page, T0, KEY)
    add_snapshot(conn, pid, json.loads(json.dumps(page)), T0 + 1, KEY)  # a fresh copy
    hashes = [r[0] for r in conn.execute("SELECT sha256 FROM snapshots").fetchall()]
    assert hashes[0] == hashes[1]


def test_add_snapshot_compares_against_the_latest_snapshot_not_the_first(conn):
    page = fixture_page("Vizit-12-28")
    pid = upsert_page(conn, page["path"], T0)
    other = dict(page, content=[{"tag": "p", "children": ["b"]}])
    add_snapshot(conn, pid, page, T0, KEY)
    add_snapshot(conn, pid, other, T0 + 1, KEY)  # changed
    _, changed = add_snapshot(conn, pid, other, T0 + 2, KEY)  # same as latest
    assert changed is False


def test_add_snapshot_tolerates_missing_optional_fields(conn):
    pid = upsert_page(conn, "x-01-01", T0)
    sid, _ = add_snapshot(conn, pid, {"path": "x-01-01", "content": []}, T0, KEY)
    row = conn.execute(
        "SELECT title, description, views FROM snapshots WHERE id = ?", (sid,)
    ).fetchone()
    assert (row["title"], row["description"], row["views"]) == (None, None, None)


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
    assert len(rows) == 2
    assert rows[0]["path"] == "Nope-01-01"
    assert rows[0]["attempt"] == 1
    assert rows[0]["status"] == 200
    assert rows[0]["outcome"] == "NOT_FOUND"
    assert rows[0]["error"] == "PAGE_NOT_FOUND"
    assert rows[0]["bytes"] == len(body)
    assert rows[0]["elapsed_ms"] >= 0
    assert rows[0]["ts"] > 0


def test_http_logger_rows_survive_without_an_explicit_commit(tmp_path):
    # The logger is called from inside the client at 8/s; it must commit
    # itself, or a crash loses the whole night's log.
    db = tmp_path / "g.sqlite"
    c1 = connect(db)
    log = http_logger(c1)
    log(
        {
            "ts": T0,
            "path": "a-01-01",
            "attempt": 1,
            "status": 200,
            "outcome": "NOT_FOUND",
            "error": "PAGE_NOT_FOUND",
            "elapsed_ms": 5,
            "bytes": 40,
        }
    )
    c2 = connect(db)
    assert c2.execute("SELECT COUNT(*) FROM http_log").fetchone()[0] == 1
    c1.close()
    c2.close()


# --------------------------------------------------------------------------
# store_fetch: the one entry point the sweep and the held-out loader share
# --------------------------------------------------------------------------


def make_fetch(name: str) -> Fetch:
    page = fixture_page(name)
    return Fetch(page["path"], Outcome.FOUND, page, None, 200, 12)


def test_store_fetch_found_upserts_page_and_adds_snapshot(conn):
    pid = store_fetch(conn, make_fetch("Vizit-12-28"), T0, KEY)
    assert pid is not None
    assert (
        conn.execute("SELECT path FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        == "Vizit-12-28"
    )
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM snapshots WHERE page_id = ?", (pid,)
        ).fetchone()[0]
        == 1
    )


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


def test_store_fetch_not_found_stores_nothing(conn):
    fetch = Fetch("Nope-01-01", Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND", 200, 5)
    assert store_fetch(conn, fetch, T0, KEY) is None
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 0


def test_store_fetch_failed_stores_nothing(conn):
    fetch = Fetch("Vizit-12-28", Outcome.FAILED, None, "request error: down", None, 5)
    assert store_fetch(conn, fetch, T0, KEY) is None
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 0


def test_store_fetch_passes_held_out_through(conn):
    pid = store_fetch(conn, make_fetch("ki06-05-02"), T0, KEY, held_out=True)
    assert (
        conn.execute("SELECT held_out FROM pages WHERE id = ?", (pid,)).fetchone()[0]
        == 1
    )


def test_store_fetch_twice_is_one_page_two_snapshots(conn):
    a = store_fetch(conn, make_fetch("Vizit-12-28"), T0, KEY)
    b = store_fetch(conn, make_fetch("Vizit-12-28"), T0 + 1, KEY)
    assert a == b
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 2


def test_store_fetch_commits(tmp_path):
    db = tmp_path / "g.sqlite"
    c1 = connect(db)
    store_fetch(c1, make_fetch("Vizit-12-28"), T0, KEY)
    c2 = connect(db)
    assert c2.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 1
    c1.close()
    c2.close()


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
    f.write_text("# header\n\nVizit-12-28\n  \nki06-05-02\n", encoding="utf-8")
    ids = load_known(conn, f, T0)
    assert len(ids) == 2
    assert held_out_paths(conn) == ["Vizit-12-28", "ki06-05-02"]


def test_load_known_twice_does_not_duplicate(conn):
    load_known(conn, KNOWN, T0)
    load_known(conn, KNOWN, T0 + 1)
    assert conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0] == 16


def test_held_out_paths_excludes_ordinary_pages(conn):
    upsert_page(conn, "Vizit-12-28", T0, held_out=True)
    upsert_page(conn, "Hello-10-17-5", T0)
    assert held_out_paths(conn) == ["Vizit-12-28"]


def test_held_out_paths_is_in_insertion_order(conn):
    for p in ("b-01-01", "a-01-01", "c-01-01"):
        upsert_page(conn, p, T0, held_out=True)
    assert held_out_paths(conn) == ["b-01-01", "a-01-01", "c-01-01"]


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


# --- sweep_progress (issue #20) -----------------------------------------------


def test_sweep_progress_has_the_planned_columns(conn):
    assert columns(conn, "sweep_progress") >= {
        "slug",
        "month",
        "day",
        "next_n",
        "done",
        "requests",
        "failures",
        "updated_at",
    }


def test_load_progress_unswept_day_starts_at_one_and_is_not_done(conn):
    assert load_progress(conn, "Hello", 10, 17) == (1, False)


def test_save_progress_then_load_round_trips(conn):
    save_progress(conn, "Hello", 10, 17, 42, False, 50, 3, T0)
    assert load_progress(conn, "Hello", 10, 17) == (42, False)


def test_load_progress_done_is_a_bool(conn):
    save_progress(conn, "Hello", 10, 17, 155, True, 160, 0, T0)
    next_n, done = load_progress(conn, "Hello", 10, 17)
    assert next_n == 155
    assert done is True


def test_save_progress_second_save_updates_in_place(conn):
    save_progress(conn, "Hello", 10, 17, 5, False, 7, 1, T0)
    save_progress(conn, "Hello", 10, 17, 9, True, 12, 1, T0 + 60)
    assert load_progress(conn, "Hello", 10, 17) == (9, True)
    row = conn.execute("SELECT * FROM sweep_progress").fetchone()
    assert (row["requests"], row["failures"], row["updated_at"]) == (12, 1, T0 + 60)
    assert conn.execute("SELECT COUNT(*) FROM sweep_progress").fetchone()[0] == 1


def test_save_progress_slug_is_case_insensitive(conn):
    save_progress(conn, "Hello", 10, 17, 5, False, 7, 0, T0)
    save_progress(conn, "hello", 10, 17, 6, False, 8, 0, T0 + 1)
    assert conn.execute("SELECT COUNT(*) FROM sweep_progress").fetchone()[0] == 1
    assert load_progress(conn, "HELLO", 10, 17) == (6, False)


def test_save_progress_days_are_independent(conn):
    save_progress(conn, "Hello", 10, 17, 5, True, 7, 0, T0)
    save_progress(conn, "Hello", 10, 18, 2, False, 3, 1, T0)
    save_progress(conn, "Test", 10, 17, 9, False, 9, 0, T0)
    assert load_progress(conn, "Hello", 10, 17) == (5, True)
    assert load_progress(conn, "Hello", 10, 18) == (2, False)
    assert load_progress(conn, "Test", 10, 17) == (9, False)
    assert load_progress(conn, "Test", 10, 18) == (1, False)


def test_save_progress_commits(tmp_path):
    path = tmp_path / "p.sqlite"
    c1 = connect(path)
    save_progress(c1, "Hello", 10, 17, 5, False, 7, 0, T0)
    c2 = connect(path)
    assert load_progress(c2, "Hello", 10, 17) == (5, False)
    c1.close()
    c2.close()


# --------------------------------------------------------------------------
# Unicode case folding across tables (found after the first full sweep)
# --------------------------------------------------------------------------


def test_upsert_page_links_to_a_title_across_unicode_case(conn):
    # Telegraph answered a request for Hi-10-30-261 with the path Hİ-10-30-261.
    tid = upsert_title(conn, Entry("Hi", "Hi", "greetings", False), T0)
    pid = upsert_page(conn, "Hİ-10-30-261", T0)
    row = conn.execute(
        "SELECT slug, title_id FROM pages WHERE id = ?", (pid,)
    ).fetchone()
    assert row["title_id"] == tid
    assert row["slug"] == "hi"


def test_upsert_page_links_cyrillic_capital_i_to_its_title(conn):
    tid = upsert_title(conn, Entry("Мобілізація", "Mobіlіzacіya", "lures", False), T0)
    pid = upsert_page(conn, "MOBІLІZACІYA-10-19", T0)
    row = conn.execute(
        "SELECT slug, title_id FROM pages WHERE id = ?", (pid,)
    ).fetchone()
    assert row["title_id"] == tid
    assert row["slug"] == "mobіlіzacіya"


def test_upsert_title_unicode_case_variants_are_one_row(conn):
    a = upsert_title(conn, Entry("Hi", "Hi", "a", False), T0)
    b = upsert_title(conn, Entry("HI", "Hİ", "b", False), T0)
    assert a == b
    assert conn.execute("SELECT COUNT(*) FROM titles").fetchone()[0] == 1


def test_progress_round_trips_across_unicode_case(conn):
    save_progress(conn, "Mobіlіzacіya", 10, 19, 7, True, 9, 0, T0)
    assert load_progress(conn, "MOBІLІZACІYA", 10, 19) == (7, True)
    assert load_progress(conn, "mobіlіzacіya", 10, 19) == (7, True)
    assert conn.execute("SELECT COUNT(*) FROM sweep_progress").fetchone()[0] == 1
