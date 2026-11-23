"""Tests for graphwatch.db.

Every test runs against an in-memory SQLite database, so nothing here touches
the disk or the network. Pages come from plan/fixtures.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from graphwatch.db import (
    SCHEMA,
    add_event,
    add_snapshot,
    cached_feeds,
    connect,
    explain_rows,
    flagged_page_snapshots,
    held_out_paths,
    http_logger,
    indicator_rows,
    is_gone,
    label_rows,
    latest_snapshots,
    load_known,
    parse_path,
    refresh_snapshot,
    superseded_flagged_snapshots,
    delete_stale_indicators,
    BUSY_TIMEOUT_S,
    load_progress,
    lookup_rows,
    mark_gone,
    resweep_cost,
    resweep_paths,
    stale_pages,
    save_labels,
    save_lookup,
    save_progress,
    save_score,
    store_fetch,
    store_meta,
    upsert_indicator,
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
        "scores",
        "hits",
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
                "published_at",
                "modified_at",
                "meta_seen_at",
                "author_name",
                "author_url",
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


# --------------------------------------------------------------------------
# page metadata (plan/page-meta-plan-2026-11-04.md)
# --------------------------------------------------------------------------

META_COLUMNS = {"published_at", "modified_at", "meta_seen_at", "author_name", "author_url"}



def iso_ts(s: str) -> float:
    # Telegraph writes "+0000"; fromisoformat accepts that on Python 3.11+.
    return datetime.fromisoformat(s).timestamp()


PUB = iso_ts("2026-10-19T03:00:08+0000")
MOD1 = iso_ts("2026-11-04T15:06:39+0000")
MOD2 = iso_ts("2026-11-05T09:00:00+0000")


def meta(published_at=PUB, modified_at=MOD1) -> dict:
    return {"published_at": published_at, "modified_at": modified_at}


def meta_row(conn, pid):
    return conn.execute(
        "SELECT published_at, modified_at, meta_seen_at FROM pages WHERE id = ?",
        (pid,),
    ).fetchone()


def change_events(conn, pid):
    return conn.execute(
        "SELECT * FROM events WHERE page_id = ? AND kind = 'modified_at_changed' ORDER BY id",
        (pid,),
    ).fetchall()


# schema




def test_fresh_database_has_the_meta_columns(conn):
    assert META_COLUMNS <= columns(conn, "pages")






def test_schema_text_also_has_the_meta_columns():
    # New databases should not depend on the migration step.
    for col in META_COLUMNS:
        assert col in SCHEMA


# author fields from the API


def test_add_snapshot_stores_author_on_the_page_row(conn):
    page = {
        "path": "x-01-01",
        "content": [],
        "author_name": "Nadia",
        "author_url": "https://t.me/nadia",
    }
    pid = upsert_page(conn, "x-01-01", T0)
    add_snapshot(conn, pid, page, T0, KEY)
    row = conn.execute(
        "SELECT author_name, author_url FROM pages WHERE id = ?", (pid,)
    ).fetchone()
    assert (row["author_name"], row["author_url"]) == ("Nadia", "https://t.me/nadia")


def test_add_snapshot_later_author_overwrites_the_earlier_one(conn):
    pid = upsert_page(conn, "x-01-01", T0)
    add_snapshot(conn, pid, {"path": "x-01-01", "content": [], "author_name": "a"}, T0, KEY)
    add_snapshot(conn, pid, {"path": "x-01-01", "content": [], "author_name": "b"}, T0 + 1, KEY)
    row = conn.execute("SELECT author_name FROM pages WHERE id = ?", (pid,)).fetchone()
    assert row["author_name"] == "b"


def test_add_snapshot_missing_author_leaves_null(conn):
    pid = upsert_page(conn, "x-01-01", T0)
    add_snapshot(conn, pid, {"path": "x-01-01", "content": []}, T0, KEY)
    row = conn.execute(
        "SELECT author_name, author_url FROM pages WHERE id = ?", (pid,)
    ).fetchone()
    assert (row["author_name"], row["author_url"]) == (None, None)


def test_add_snapshot_author_does_not_count_as_a_content_change(conn):
    pid = upsert_page(conn, "x-01-01", T0)
    add_snapshot(conn, pid, {"path": "x-01-01", "content": [], "author_name": "a"}, T0, KEY)
    _, changed = add_snapshot(
        conn, pid, {"path": "x-01-01", "content": [], "author_name": "b"}, T0 + 1, KEY
    )
    assert changed is False


def test_store_fetch_stores_author_fields(conn):
    page = {**fixture_page("Vizit-12-28"), "author_name": "n", "author_url": "u"}
    fetch = Fetch(page["path"], Outcome.FOUND, page, None, 200, 1)
    pid = store_fetch(conn, fetch, T0, KEY)
    row = conn.execute(
        "SELECT author_name, author_url FROM pages WHERE id = ?", (pid,)
    ).fetchone()
    assert (row["author_name"], row["author_url"]) == ("n", "u")


def test_store_fetch_commits_author_fields(tmp_path):
    db = tmp_path / "a.db"
    c1 = connect(db)
    page = {"path": "x-01-01", "content": [], "author_name": "n"}
    store_fetch(c1, Fetch("x-01-01", Outcome.FOUND, page, None, 200, 1), T0, KEY)
    c2 = connect(db)
    assert c2.execute("SELECT author_name FROM pages").fetchone()[0] == "n"
    c1.close()
    c2.close()


# store_meta


def test_store_meta_first_store_fills_all_three_and_is_not_a_change(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    assert store_meta(conn, pid, meta(), T0) is False
    row = meta_row(conn, pid)
    assert (row["published_at"], row["modified_at"], row["meta_seen_at"]) == (
        PUB,
        MOD1,
        T0,
    )
    assert change_events(conn, pid) == []


def test_store_meta_timestamps_are_unix_seconds(conn):
    # Same unit as first_seen and fetched_at: REAL seconds, not ISO text.
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(), T0)
    row = meta_row(conn, pid)
    assert isinstance(row["published_at"], float)
    assert isinstance(row["modified_at"], float)
    assert row["published_at"] == 1792378808.0  # 2026-10-19T03:00:08Z


def test_store_meta_same_modified_at_writes_no_event(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(), T0)
    assert store_meta(conn, pid, meta(), T0 + 60) is False
    assert change_events(conn, pid) == []


def test_store_meta_changed_modified_at_writes_one_event_with_both_values(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(modified_at=MOD1), T0)
    assert store_meta(conn, pid, meta(modified_at=MOD2), T0 + 60) is True

    events = change_events(conn, pid)
    assert len(events) == 1
    ev = events[0]
    assert ev["ts"] == T0 + 60
    detail = ev["detail"]
    assert " -> " in detail
    old, new = detail.split(" -> ")
    assert old.startswith("2026-11-04T15:06:39")
    assert new.startswith("2026-11-05T09:00:00")

    assert meta_row(conn, pid)["modified_at"] == MOD2


def test_store_meta_event_detail_is_utc(conn):
    # Whatever the machine's local zone, the detail must read as UTC.
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(modified_at=MOD1), T0)
    store_meta(conn, pid, meta(modified_at=MOD2), T0 + 1)
    detail = change_events(conn, pid)[0]["detail"]
    expected_new = datetime.fromtimestamp(MOD2, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    assert expected_new in detail


def test_store_meta_change_back_and_forth_is_two_events(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(modified_at=MOD1), T0)
    store_meta(conn, pid, meta(modified_at=MOD2), T0 + 1)
    store_meta(conn, pid, meta(modified_at=MOD1), T0 + 2)
    assert len(change_events(conn, pid)) == 2


def test_store_meta_never_overwrites_published_at(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(published_at=PUB), T0)
    store_meta(conn, pid, meta(published_at=PUB + 5), T0 + 1)
    assert meta_row(conn, pid)["published_at"] == PUB


def test_store_meta_updates_meta_seen_at_every_time(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(), T0)
    store_meta(conn, pid, meta(), T0 + 99)
    assert meta_row(conn, pid)["meta_seen_at"] == T0 + 99


def test_store_meta_does_not_write_content_changed(conn):
    pid = upsert_page(conn, "Hello-10-19-130", T0)
    store_meta(conn, pid, meta(modified_at=MOD1), T0)
    store_meta(conn, pid, meta(modified_at=MOD2), T0 + 1)
    kinds = {r["kind"] for r in conn.execute("SELECT kind FROM events WHERE page_id = ?", (pid,))}
    assert kinds == {"discovered", "modified_at_changed"}


def test_store_meta_commits(tmp_path):
    db = tmp_path / "m.db"
    c1 = connect(db)
    pid = upsert_page(c1, "Hello-10-19-130", T0)
    store_meta(c1, pid, meta(), T0)
    c2 = connect(db)
    assert meta_row(c2, pid)["modified_at"] == MOD1
    c1.close()
    c2.close()


# page selector for the meta command



def id_paths(rows):
    return [(r["id"], r["path"]) for r in rows]
























def test_pages_stale_returns_never_seen_pages_first_then_oldest(conn):
    never = upsert_page(conn, "a-01-01", T0)
    old = upsert_page(conn, "b-01-01", T0)
    fresh = upsert_page(conn, "c-01-01", T0)
    now = T0 + 100 * 3600
    store_meta(conn, old, meta(), now - 48 * 3600)
    store_meta(conn, fresh, meta(), now - 1 * 3600)
    rows = stale_pages(conn, 24, now, 10)
    assert id_paths(rows) == [(never, "a-01-01"), (old, "b-01-01")]


def test_pages_stale_boundary_is_strictly_older(conn):
    pid = upsert_page(conn, "a-01-01", T0)
    now = T0 + 100 * 3600
    store_meta(conn, pid, meta(), now - 24 * 3600)  # exactly 24 h: not stale yet
    assert stale_pages(conn, 24, now, 10) == []
    assert id_paths(stale_pages(conn, 24, now + 1, 10)) == [(pid, "a-01-01")]


def test_pages_stale_respects_the_limit(conn):
    for i in range(5):
        upsert_page(conn, f"p{i}-01-01", T0)
    assert len(stale_pages(conn, 24, T0, 3)) == 3


def test_pages_stale_zero_hours_means_everything_seen_before_now(conn):
    pid = upsert_page(conn, "a-01-01", T0)
    store_meta(conn, pid, meta(), T0)
    assert id_paths(stale_pages(conn, 0, T0 + 1, 10)) == [(pid, "a-01-01")]


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
    b, snap_b = stored_page(conn, "b-01-01", "Hello-10-17-5")
    rows = latest_snapshots(conn).fetchall()
    assert [(r["page_id"], r["snapshot_id"], r["path"]) for r in rows] == [
        (a, snap_a, "a-01-01"),
        (b, snap_b, "b-01-01"),
    ]


def test_latest_snapshots_carries_the_fields_the_rules_read(conn):
    stored_page(conn, "a-01-01", "Hello-10-17-5")
    row = latest_snapshots(conn).fetchone()
    page = fixture_page("Hello-10-17-5")
    assert row["title"] == page["title"]
    assert row["description"] == page["description"]
    assert row["text"].startswith(page["title"] + "\n")
    assert row["held_out"] == 0
    assert json.loads(row["content"]) == page["content"]  # for the link targets


def test_latest_snapshots_picks_the_newest_snapshot_of_an_edited_page(conn):
    page_id, first = stored_page(conn, "a-01-01", "Test-10-16", T0)
    second, changed = add_snapshot(
        conn, page_id, fixture_page("Hello-10-17-5"), T0 + 60, KEY
    )
    assert changed
    rows = latest_snapshots(conn).fetchall()
    assert [r["snapshot_id"] for r in rows] == [second]
    assert rows[0]["title"] == fixture_page("Hello-10-17-5")["title"]


def test_latest_snapshots_marks_held_out_pages(conn):
    stored_page(conn, "a-01-01", held_out=True)
    assert latest_snapshots(conn).fetchone()["held_out"] == 1


def test_latest_snapshots_skips_pages_that_have_no_snapshot(conn):
    upsert_page(conn, "a-01-01", T0)
    assert latest_snapshots(conn).fetchall() == []


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


def test_save_score_stores_negative_weights_and_match_counts(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 4, True, None, HITS, T0)
    rows = conn.execute("SELECT rule, weight, matches FROM hits ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("userinfo_spoof", 5, 1), ("telegram_link", -1, 3)]


def test_hits_matches_column_defaults_to_one(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    conn.execute(
        "INSERT INTO hits (snapshot_id, rule, weight, evidence) VALUES (?, 'x', 1, 'e')",
        (snap,),
    )
    assert conn.execute("SELECT matches FROM hits").fetchone()[0] == 1


def test_save_score_accepts_a_page_with_no_hits_and_no_body_hash(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 0, False, None, [], T0)
    row = conn.execute("SELECT score, flagged, body_sha256 FROM scores").fetchone()
    assert tuple(row) == (0, 0, None)
    assert conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0] == 0


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
    assert conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0] == 3


def test_save_score_does_not_commit(tmp_path):
    # The caller commits in batches; a rollback must undo an uncommitted score.
    c = connect(tmp_path / "g.sqlite")
    page_id, snap = stored_page(c, "a-01-01")
    save_score(c, snap, page_id, 6, True, None, HITS, T0)
    c.rollback()
    assert c.execute("SELECT COUNT(*) FROM scores").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM hits").fetchone()[0] == 0
    c.close()


def test_explain_rows_returns_the_score_and_its_hits(conn):
    page_id, snap = stored_page(conn, "a-01-01", "Hello-10-17-5")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    row, hits = explain_rows(conn, "a-01-01")
    assert (row["path"], row["score"], row["flagged"], row["held_out"]) == (
        "a-01-01",
        6,
        1,
        0,
    )
    assert row["title"] == fixture_page("Hello-10-17-5")["title"]
    assert [tuple(h) for h in hits] == HITS


def test_explain_rows_is_empty_for_an_unknown_path(conn):
    assert explain_rows(conn, "nope-01-01") == (None, [])


def test_explain_rows_is_empty_for_a_page_not_yet_classified(conn):
    stored_page(conn, "a-01-01")
    assert explain_rows(conn, "a-01-01") == (None, [])


def test_explain_rows_uses_the_newest_scored_snapshot(conn):
    page_id, first = stored_page(conn, "a-01-01", "Test-10-16", T0)
    second, _ = add_snapshot(conn, page_id, fixture_page("Hello-10-17-5"), T0 + 60, KEY)
    save_score(conn, first, page_id, 0, False, None, [], T0)
    save_score(conn, second, page_id, 6, True, None, HITS, T0 + 61)
    row, hits = explain_rows(conn, "a-01-01")
    assert row["score"] == 6
    assert len(hits) == 2


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


def test_connect_creates_the_labels_table(conn):
    assert "labels" in tables(conn)
    assert columns(conn, "labels") == {
        "snapshot_id",
        "page_id",
        "category",
        "score",
        "assigned",
        "is_primary",
    }


def test_connect_adds_the_labels_table_to_a_database_made_before_it(tmp_path):
    # A new table needs no migration: CREATE TABLE IF NOT EXISTS is enough.
    db = tmp_path / "g.sqlite"
    old = sqlite3.connect(str(db))
    old.executescript(SCHEMA.split("CREATE TABLE IF NOT EXISTS labels")[0])
    old.commit()
    old.close()
    c = connect(db)
    assert "labels" in tables(c)
    c.close()


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


def test_label_rows_is_empty_for_a_snapshot_with_no_labels(conn):
    _page_id, snap = stored_page(conn, "a-01-01")
    assert label_rows(conn, snap) == []


def test_save_labels_twice_replaces_the_snapshots_rows(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_labels(conn, snap, page_id, LABELS)
    save_labels(conn, snap, page_id, [("prose", 4, True, True)])
    assert all_labels(conn) == [(snap, page_id, "prose", 4, 1, 1)]


def test_save_labels_with_no_rows_clears_a_page_that_no_longer_scores(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_labels(conn, snap, page_id, LABELS)
    save_labels(conn, snap, page_id, [])
    assert all_labels(conn) == []


def test_save_labels_leaves_other_snapshots_alone(conn):
    a, snap_a = stored_page(conn, "a-01-01")
    b, snap_b = stored_page(conn, "b-01-01")
    save_labels(conn, snap_a, a, LABELS)
    save_labels(conn, snap_b, b, [("prose", 4, True, True)])
    save_labels(conn, snap_b, b, [])
    assert len(all_labels(conn)) == len(LABELS)


def test_a_category_is_stored_once_per_snapshot(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    twice = [("prose", 4, True, True), ("prose", 5, True, False)]
    with pytest.raises(sqlite3.IntegrityError):
        save_labels(conn, snap, page_id, twice)


def test_save_labels_does_not_commit(tmp_path):
    db = tmp_path / "g.sqlite"
    c = connect(db)
    page_id, snap = stored_page(c, "a-01-01")
    save_labels(c, snap, page_id, LABELS)
    reader = connect(db)
    assert reader.execute("SELECT COUNT(*) FROM labels").fetchone()[0] == 0
    c.commit()
    assert reader.execute("SELECT COUNT(*) FROM labels").fetchone()[0] == len(LABELS)
    reader.close()
    c.close()


def test_save_score_and_save_labels_do_not_touch_each_others_rows(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    save_labels(conn, snap, page_id, LABELS)
    save_score(conn, snap, page_id, 1, False, None, HITS[1:], T0 + 9)
    assert len(all_labels(conn)) == len(LABELS)
    save_labels(conn, snap, page_id, [])
    assert conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0] == 1


def test_near_misses_of_a_category_can_be_queried_like_the_resolvers(conn):
    # What the table is for: assigned = 0 with a positive score is a near miss.
    a, snap_a = stored_page(conn, "a-01-01")
    b, snap_b = stored_page(conn, "b-01-01")
    save_labels(conn, snap_a, a, [("pointer", 4, True, True)])
    save_labels(conn, snap_b, b, [("pointer", 3, False, False)])
    sql = """
    SELECT p.path FROM labels l JOIN pages p ON p.id = l.page_id
    WHERE l.category = 'pointer' AND l.assigned = 0 AND l.score > 0
    """
    assert [r["path"] for r in conn.execute(sql)] == ["b-01-01"]


def test_explain_rows_carries_the_snapshot_id_for_the_label_lookup(conn):
    page_id, snap = stored_page(conn, "a-01-01")
    save_score(conn, snap, page_id, 6, True, None, HITS, T0)
    row, _hits = explain_rows(conn, "a-01-01")
    assert row["snapshot_id"] == snap


# --------------------------------------------------------------------------
# re-sweep: the work list and the gone marker (issue #37,
# plan/resweep-plan-2026-11-04.md)
# --------------------------------------------------------------------------

HOUR = 3600.0


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


def events_of(conn, page_id: int, kind: str) -> list[float]:
    sql = "SELECT ts FROM events WHERE page_id = ? AND kind = ? ORDER BY id"
    return [r["ts"] for r in conn.execute(sql, (page_id, kind))]


def test_resweep_paths_lists_pages_last_seen_before_the_cutoff(conn):
    seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-10-17-2", T0 + 2 * HOUR)
    assert work(conn, T0 + HOUR) == ["Hello-10-17-1"]
    assert work(conn, T0 + 3 * HOUR) == ["Hello-10-17-1", "Hello-10-17-2"]


def test_resweep_paths_cutoff_is_strict(conn):
    seen_page(conn, "Hello-10-17-1", T0)
    assert work(conn, T0) == []


def test_resweep_paths_returns_the_id_with_the_path(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    row = resweep_paths(conn, T0 + HOUR)[0]
    assert (row["id"], row["path"]) == (page_id, "Hello-10-17-1")


def test_resweep_paths_is_oldest_first_then_by_title_day_and_counter(conn):
    seen_page(conn, "Hello-10-18-1", T0 + 60)
    seen_page(conn, "Test-10-17-1", T0)
    seen_page(conn, "Hello-10-17-2", T0)
    seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-10-16-9", T0)
    assert work(conn, T0 + HOUR) == [
        "Hello-10-16-9",
        "Hello-10-17-1",
        "Hello-10-17-2",
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


def test_mark_gone_writes_exactly_one_event_with_the_fetch_time(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    mark_gone(conn, page_id, T0 + 99)
    assert events_of(conn, page_id, "gone") == [T0 + 99]


def test_mark_gone_keeps_the_page_its_snapshots_and_last_seen(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    mark_gone(conn, page_id, T0 + 99)
    row = conn.execute("SELECT last_seen FROM pages WHERE id = ?", (page_id,)).fetchone()
    assert row["last_seen"] == T0
    assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 1


def test_a_gone_page_is_left_out_of_the_work_list_and_the_cost(conn):
    # Otherwise it would be asked for again every night.
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    seen_page(conn, "Hello-10-17-2", T0)
    mark_gone(conn, page_id, T0 + 99)
    assert work(conn, T0 + HOUR) == ["Hello-10-17-2"]
    assert resweep_cost(conn, T0 + HOUR) == 1


def test_is_gone_follows_the_newest_gone_or_returned_event(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    assert is_gone(conn, page_id) is False
    mark_gone(conn, page_id, T0 + 10)
    assert is_gone(conn, page_id) is True
    add_event(conn, page_id, "returned", T0 + 20)
    assert is_gone(conn, page_id) is False
    mark_gone(conn, page_id, T0 + 30)
    assert is_gone(conn, page_id) is True


def test_other_event_kinds_do_not_make_a_page_gone(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    add_event(conn, page_id, "content_changed", T0 + 10)
    assert is_gone(conn, page_id) is False
    assert work(conn, T0 + HOUR) == ["Hello-10-17-1"]


def test_a_gone_page_that_is_fetched_again_gets_a_returned_event(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    mark_gone(conn, page_id, T0 + 10)
    upsert_page(conn, "Hello-10-17-1", T0 + 20)
    assert events_of(conn, page_id, "returned") == [T0 + 20]
    assert is_gone(conn, page_id) is False


def test_a_returned_page_is_back_on_the_work_list(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    mark_gone(conn, page_id, T0 + 10)
    upsert_page(conn, "Hello-10-17-1", T0 + 20)
    assert work(conn, T0 + HOUR) == ["Hello-10-17-1"]


def test_an_ordinary_refetch_writes_no_returned_event(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    upsert_page(conn, "Hello-10-17-1", T0 + 20)
    assert events_of(conn, page_id, "returned") == []


def test_returned_is_written_once_not_on_every_later_fetch(conn):
    page_id = seen_page(conn, "Hello-10-17-1", T0)
    mark_gone(conn, page_id, T0 + 10)
    upsert_page(conn, "Hello-10-17-1", T0 + 20)
    upsert_page(conn, "Hello-10-17-1", T0 + 30)
    assert events_of(conn, page_id, "returned") == [T0 + 20]


# --- what a second fetch records (resweep plan, step 3) ---


def test_views_are_not_part_of_the_fingerprint(conn):
    # A page nobody edited gets a snapshot with the new view count and no event.
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    page = {"title": "t", "description": "d", "views": 5, "content": ["same"]}
    add_snapshot(conn, page_id, page, T0, KEY)
    _snap, changed = add_snapshot(conn, page_id, {**page, "views": 9}, T0 + 60, KEY)
    assert changed is False
    assert events_of(conn, page_id, "content_changed") == []
    views = [r["views"] for r in conn.execute("SELECT views FROM snapshots ORDER BY id")]
    assert views == [5, 9]


def test_a_rotation_writes_one_content_changed_event_at_the_fetch_time(conn):
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    add_snapshot(conn, page_id, {"title": "8.8.8.8", "content": ["x"]}, T0, KEY)
    _snap, changed = add_snapshot(conn, page_id, {"title": "9.9.9.9", "content": ["x"]}, T0 + 60, KEY)
    assert changed is True
    assert events_of(conn, page_id, "content_changed") == [T0 + 60]


# --------------------------------------------------------------------------
# indicators and feed_lookups (issue #38, plan/enrichment-plan-2026-11-22.md)
# --------------------------------------------------------------------------


def indicator(conn, indicator_id: int) -> dict:
    return dict(conn.execute("SELECT * FROM indicators WHERE id = ?", (indicator_id,)).fetchone())


def test_connect_creates_the_enrichment_tables(conn):
    assert {"indicators", "feed_lookups"} <= tables(conn)
    assert columns(conn, "indicators") == {
        "id", "kind", "value", "source", "first_seen", "last_seen", "pages",
    }
    assert columns(conn, "feed_lookups") == {
        "indicator_id", "feed", "verdict", "detail", "checked_at",
    }


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
    row = indicator(conn, indicator_id)
    assert (row["source"], row["first_seen"], row["last_seen"], row["pages"]) == (
        "indicators.tsv", None, None, 0,
    )


def test_upsert_indicator_twice_keeps_one_row_and_its_id(conn):
    first = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    second = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    assert first == second
    assert conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 1


def test_the_same_value_under_two_kinds_is_two_indicators(conn):
    a = upsert_indicator(conn, "host", "8.8.8.8", "pages")
    b = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    assert a != b


def test_upsert_indicator_from_pages_stores_what_the_pages_say_now(conn):
    # collect_indicators reads every snapshot of every flagged page each run,
    # so its answer is the whole truth: after a rule fix fewer pages may hold
    # the indicator, and the first of them may be a later one.
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 200, 5)
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0 + 50, T0 + 150, 2)
    row = indicator(conn, indicator_id)
    assert (row["first_seen"], row["last_seen"], row["pages"]) == (T0 + 50, T0 + 150, 2)


def test_upsert_indicator_does_not_lose_times_to_a_file_row(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 3)
    upsert_indicator(conn, "ip", "8.8.8.8", "indicators.tsv")
    row = indicator(conn, indicator_id)
    assert (row["source"], row["first_seen"], row["last_seen"], row["pages"]) == (
        "pages", T0, T0 + 60, 3,
    )


def test_a_file_indicator_later_found_on_pages_becomes_a_pages_indicator(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "indicators.tsv")
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 2)
    row = indicator(conn, indicator_id)
    assert (row["source"], row["first_seen"], row["pages"]) == ("pages", T0, 2)


def test_upsert_indicator_keeps_the_lookups_stored_against_it(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0)
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + 60, 2)
    assert cached_feeds(conn, indicator_id) == {"otx"}


def test_save_lookup_round_trip(conn):
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    save_lookup(conn, indicator_id, "threatfox", "KNOWN", "2 IOCs", T0 + 5)
    save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0 + 6)
    assert [tuple(r) for r in lookup_rows(conn, indicator_id)] == [
        ("otx", "UNKNOWN", None, T0 + 6),
        ("threatfox", "KNOWN", "2 IOCs", T0 + 5),
    ]


def test_save_lookup_twice_replaces_the_answer_for_that_feed(conn):
    # What --refresh does: the newer answer and its time win.
    indicator_id = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0)
    save_lookup(conn, indicator_id, "otx", "KNOWN", "1 pulses", T0 + 99)
    assert [tuple(r) for r in lookup_rows(conn, indicator_id)] == [
        ("otx", "KNOWN", "1 pulses", T0 + 99)
    ]


def test_cached_feeds_names_the_feeds_that_answered_for_one_indicator(conn):
    a = upsert_indicator(conn, "ip", "8.8.8.8", "pages")
    b = upsert_indicator(conn, "ip", "9.9.9.9", "pages")
    save_lookup(conn, a, "otx", "UNKNOWN", None, T0)
    save_lookup(conn, a, "virustotal", "KNOWN", "x", T0)
    save_lookup(conn, b, "threatfox", "UNKNOWN", None, T0)
    assert cached_feeds(conn, a) == {"otx", "virustotal"}
    assert cached_feeds(conn, b) == {"threatfox"}


def test_cached_feeds_is_empty_for_an_indicator_never_looked_up(conn):
    assert cached_feeds(conn, upsert_indicator(conn, "ip", "8.8.8.8", "pages")) == set()


def test_a_lookup_survives_closing_the_database(tmp_path):
    # The cache is what lets a run that was cut off pick up where it stopped.
    db = tmp_path / "g.sqlite"
    c = connect(db)
    indicator_id = upsert_indicator(c, "ip", "8.8.8.8", "pages")
    save_lookup(c, indicator_id, "otx", "UNKNOWN", None, T0)
    c.close()
    c = connect(db)
    assert cached_feeds(c, indicator_id) == {"otx"}
    c.close()


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


def test_flagged_page_snapshots_reads_every_snapshot_of_a_flagged_page(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    flag(conn, a, True)
    add_snapshot(conn, a, {"title": "t", "content": ["rotated"]}, T0 + 60, KEY)
    rows = flagged_page_snapshots(conn).fetchall()
    assert [(r["page_id"], r["fetched_at"]) for r in rows] == [(a, T0), (a, T0 + 60)]
    assert set(rows[0].keys()) == {"page_id", "fetched_at", "title", "text"}


def test_flagged_page_snapshots_leaves_out_unflagged_and_held_out_pages(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-17-2", T0)
    seen_page(conn, "Hello-10-17-3", T0)  # never classified
    known = upsert_page(conn, "Known-01-02", T0, held_out=True)
    add_snapshot(conn, known, {"title": "k", "content": ["x"]}, T0, KEY)
    flag(conn, a, True)
    flag(conn, b, False)
    flag(conn, known, True)
    assert [r["page_id"] for r in flagged_page_snapshots(conn)] == [a]


def test_flagged_page_snapshots_reads_no_author_field(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    flag(conn, a, True)
    row = flagged_page_snapshots(conn).fetchone()
    assert not {"author_name", "author_url"} & set(row.keys())


# --------------------------------------------------------------------------
# the ten-minute re-poll: a snapshot only on change, views kept apart, and
# two writers that wait for each other (decided 22 November)
# --------------------------------------------------------------------------


def poll_page(title="t", body="same", views=5) -> dict:
    return {"path": "Hello-10-17-1", "title": title, "description": body, "views": views, "content": [body]}


def stored_poll_page(conn) -> int:
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    add_snapshot(conn, page_id, poll_page(), T0, KEY)
    return page_id


def test_connect_creates_the_views_table(conn):
    assert "views" in tables(conn)
    assert columns(conn, "views") == {"page_id", "fetched_at", "views"}


def test_refresh_snapshot_of_an_unchanged_page_stores_no_snapshot(conn):
    page_id = stored_poll_page(conn)
    assert refresh_snapshot(conn, page_id, poll_page(views=9), T0 + 600, KEY) is False
    assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 1
    assert events_of(conn, page_id, "content_changed") == []


def test_refresh_snapshot_keeps_the_view_count_of_an_unchanged_page(conn):
    page_id = stored_poll_page(conn)
    refresh_snapshot(conn, page_id, poll_page(views=9), T0 + 600, KEY)
    refresh_snapshot(conn, page_id, poll_page(views=12), T0 + 1200, KEY)
    rows = [tuple(r) for r in conn.execute("SELECT page_id, fetched_at, views FROM views ORDER BY fetched_at")]
    assert rows == [(page_id, T0 + 600, 9), (page_id, T0 + 1200, 12)]


def test_refresh_snapshot_moves_last_seen_whether_or_not_the_page_changed(conn):
    page_id = stored_poll_page(conn)
    refresh_snapshot(conn, page_id, poll_page(), T0 + 600, KEY)
    assert conn.execute("SELECT last_seen FROM pages WHERE id = ?", (page_id,)).fetchone()[0] == T0 + 600
    refresh_snapshot(conn, page_id, poll_page(title="new"), T0 + 1200, KEY)
    assert conn.execute("SELECT last_seen FROM pages WHERE id = ?", (page_id,)).fetchone()[0] == T0 + 1200


def test_refresh_snapshot_of_a_changed_page_stores_it_and_writes_the_event(conn):
    page_id = stored_poll_page(conn)
    assert refresh_snapshot(conn, page_id, poll_page(title="9.9.9.9"), T0 + 600, KEY) is True
    titles = [r["title"] for r in conn.execute("SELECT title FROM snapshots ORDER BY id")]
    assert titles == ["t", "9.9.9.9"]
    assert events_of(conn, page_id, "content_changed") == [T0 + 600]
    assert conn.execute("SELECT COUNT(*) FROM views").fetchone()[0] == 0


def test_refresh_snapshot_compares_after_redaction(conn):
    # The stored fingerprint is of the redacted page, so the raw page has to
    # be redacted before the two are compared.
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    page = poll_page(body="password: hunter2")
    add_snapshot(conn, page_id, page, T0, KEY)
    assert refresh_snapshot(conn, page_id, page, T0 + 600, KEY) is False


def test_refresh_snapshot_of_a_page_with_no_snapshot_stores_the_first(conn):
    page_id = upsert_page(conn, "Hello-10-17-1", T0)
    assert refresh_snapshot(conn, page_id, poll_page(), T0 + 600, KEY) is False
    assert conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 1


def test_refresh_snapshot_goes_by_the_page_id_not_the_path_in_the_answer(conn):
    page_id = upsert_page(conn, "mark-01-20-5", T0, held_out=True)
    add_snapshot(conn, page_id, poll_page(), T0, KEY)
    answer = {**poll_page(title="edited"), "path": "Mark-01-20-5"}
    refresh_snapshot(conn, page_id, answer, T0 + 600, KEY)
    assert [tuple(r) for r in conn.execute("SELECT id, path, held_out FROM pages")] == [(page_id, "mark-01-20-5", 1)]
    assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE page_id = ?", (page_id,)).fetchone()[0] == 2


def test_two_polls_at_the_same_instant_keep_one_views_row(conn):
    page_id = stored_poll_page(conn)
    refresh_snapshot(conn, page_id, poll_page(views=9), T0 + 600, KEY)
    refresh_snapshot(conn, page_id, poll_page(views=10), T0 + 600, KEY)
    assert [r["views"] for r in conn.execute("SELECT views FROM views")] == [10]


def test_the_busy_timeout_is_a_minute():
    assert BUSY_TIMEOUT_S == 60


def test_a_writer_waits_for_another_writer_instead_of_failing(tmp_path, monkeypatch):
    # The nightly job and the ten-minute re-poll share one file.
    import threading

    db = tmp_path / "g.sqlite"
    first = connect(db)
    first.execute("BEGIN IMMEDIATE")
    first.execute("INSERT INTO events (ts, kind) VALUES (?, ?)", (T0, "held"))
    done = []

    def second_writer():
        second = connect(db)
        add_event(second, None, "waited", T0 + 1)
        done.append(True)
        second.close()

    thread = threading.Thread(target=second_writer)
    thread.start()
    thread.join(0.3)
    assert done == []  # still waiting, not failed
    first.commit()
    thread.join(10)
    assert done == [True]
    kinds = {r[0] for r in first.execute("SELECT kind FROM events")}
    assert kinds == {"held", "waited"}
    first.close()


def test_resweep_paths_with_a_window_of_no_days_is_empty_not_an_error(conn):
    seen_page(conn, "Hello-10-17-1", T0)
    assert resweep_paths(conn, T0 + HOUR, days=[]) == []
    assert resweep_cost(conn, T0 + HOUR, days=[]) == 0


def test_superseded_flagged_snapshots_are_the_older_snapshots_of_flagged_pages(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    b = seen_page(conn, "Hello-10-17-2", T0)
    flag(conn, a, True)
    flag(conn, b, False)
    add_snapshot(conn, a, {"title": "t", "content": ["second"]}, T0 + 60, KEY)
    add_snapshot(conn, a, {"title": "t", "content": ["third"]}, T0 + 120, KEY)
    add_snapshot(conn, b, {"title": "t", "content": ["second"]}, T0 + 60, KEY)
    rows = superseded_flagged_snapshots(conn)
    # Of page a's two older snapshots only the first holds a flagged score;
    # the second was never scored and cannot make the page flagged.
    oldest = conn.execute("SELECT MIN(id) FROM snapshots WHERE page_id = ?", (a,)).fetchone()[0]
    assert [(r["page_id"], r["snapshot_id"]) for r in rows] == [(a, oldest)]
    newest = conn.execute("SELECT MAX(id) FROM snapshots WHERE page_id = ?", (a,)).fetchone()[0]
    assert newest not in [r["snapshot_id"] for r in rows]
    assert set(rows[0].keys()) == {"snapshot_id", "page_id", "title", "description", "text", "content"}


def test_a_flagged_page_with_one_snapshot_has_nothing_superseded(conn):
    a = seen_page(conn, "Hello-10-17-1", T0)
    flag(conn, a, True)
    assert superseded_flagged_snapshots(conn) == []


def test_delete_stale_indicators_drops_page_indicators_that_are_not_current(conn):
    keep = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    gone = upsert_indicator(conn, "host", "old.example.org", "pages", T0, T0, 1)
    listed = upsert_indicator(conn, "host", "probe.example.org", "indicators.tsv")
    for indicator_id in (keep, gone, listed):
        save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0)
    assert delete_stale_indicators(conn, {("ip", "8.8.8.8")}) == 1
    assert [(r["kind"], r["value"]) for r in indicator_rows(conn)] == [
        ("host", "probe.example.org"),
        ("ip", "8.8.8.8"),
    ]
    assert conn.execute("SELECT COUNT(*) FROM feed_lookups").fetchone()[0] == 2
    assert cached_feeds(conn, keep) == {"otx"}


def test_delete_stale_indicators_with_everything_current_deletes_nothing(conn):
    upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    assert delete_stale_indicators(conn, {("ip", "8.8.8.8"), ("ip", "9.9.9.9")}) == 0


# --- what the second review of 22 November found -------------------------------------


def test_latest_snapshots_can_be_read_a_batch_at_a_time(conn):
    ids = [stored_page(conn, f"a-01-0{n}")[0] for n in range(1, 6)]
    first = latest_snapshots(conn, 0, 2).fetchall()
    second = latest_snapshots(conn, first[-1]["page_id"], 2).fetchall()
    third = latest_snapshots(conn, second[-1]["page_id"], 2).fetchall()
    assert [r["page_id"] for r in first + second + third] == ids
    assert latest_snapshots(conn, ids[-1], 2).fetchall() == []


def test_latest_snapshots_can_leave_the_content_out(conn):
    stored_page(conn, "a-01-01")
    assert latest_snapshots(conn, content=False).fetchone()["content"] is None
    assert latest_snapshots(conn).fetchone()["content"] is not None


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


def test_refresh_snapshot_of_an_unchanged_page_refreshes_the_author_fields(conn):
    page_id = stored_poll_page(conn)
    page = {**poll_page(), "author_name": "new name", "author_url": "https://t.me/new"}
    assert refresh_snapshot(conn, page_id, page, T0 + 600, KEY) is False
    row = conn.execute("SELECT author_name, author_url FROM pages WHERE id = ?", (page_id,)).fetchone()
    assert tuple(row) == ("new name", "https://t.me/new")
