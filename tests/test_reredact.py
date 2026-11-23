"""Tests for the one-time re-redaction of stored snapshots.

Rows are written straight into the snapshots table the way an older ingest
left them, with a secret shape still in clear. Every secret here is made up.
"""

import json
import sqlite3

import pytest

from graphwatch.db import add_snapshot, connect, fingerprint, upsert_page
from graphwatch.redact import hash_secret, redact_page
from graphwatch.reredact import main, reredact, reredact_snapshot
from graphwatch.telegraph import page_text

T0 = 1_700_000_000.0
KEY = b"test-key"
UUID = "0f1e2d3c-4b5a-6978-8695-a4b3c2d1e0f9"
PROXY = f"vless://{UUID}@vpn.example.org:443"


def store_raw(conn, path, title, body, ts=T0) -> int:
    """Insert a snapshot with no redaction at all, like a pattern that did not exist yet."""
    page_id = upsert_page(conn, path, ts)
    page = {"title": title, "description": body, "content": [{"tag": "p", "children": [body]}]}
    cur = conn.execute(
        """
        INSERT INTO snapshots (page_id, fetched_at, title, description, views, content, text, sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            page_id,
            ts,
            page["title"],
            page["description"],
            3,
            json.dumps(page["content"], ensure_ascii=False),
            page_text(page),
            fingerprint(page["title"], page["description"], page["content"]),
        ),
    )
    conn.commit()
    return cur.lastrowid


def snapshot(conn, snapshot_id):
    return conn.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def old_db(conn):
    """One snapshot with a secret in clear, one with nothing to hash."""
    store_raw(conn, "proxy-11-02", "free proxy", f"use {PROXY} today")
    store_raw(conn, "Hello-11-02", "Hello", "nothing to see here")
    return conn


def first_snapshot_id(conn, path) -> int:
    sql = """
    SELECT s.id FROM snapshots s JOIN pages p ON p.id = s.page_id
    WHERE p.path = ? ORDER BY s.id LIMIT 1
    """
    return conn.execute(sql, (path,)).fetchone()[0]


def leaky(conn) -> int:
    return first_snapshot_id(conn, "proxy-11-02")


def clean(conn) -> int:
    return first_snapshot_id(conn, "Hello-11-02")


def test_fingerprint_is_what_add_snapshot_stores(conn):
    page_id = upsert_page(conn, "Hello-11-02", T0)
    page = {"title": "Hello", "description": "d", "views": 9, "content": [{"tag": "p", "children": ["x"]}]}
    snapshot_id, _ = add_snapshot(conn, page_id, page, T0, KEY)
    assert snapshot(conn, snapshot_id)["sha256"] == fingerprint("Hello", "d", page["content"])


def test_fingerprint_ignores_nothing_it_is_given():
    base = fingerprint("t", "d", ["x"])
    assert fingerprint("T", "d", ["x"]) != base
    assert fingerprint("t", "D", ["x"]) != base
    assert fingerprint("t", "d", ["y"]) != base


def test_reredact_snapshot_returns_none_when_nothing_changes(old_db):
    assert reredact_snapshot(snapshot(old_db, clean(old_db)), KEY) is None


def test_reredact_snapshot_returns_every_rewritten_column(old_db):
    new = reredact_snapshot(snapshot(old_db, leaky(old_db)), KEY)
    assert set(new) == {"title", "description", "content", "text", "sha256"}
    assert UUID not in new["content"]
    assert UUID not in new["text"]


def test_reredact_hashes_the_secret_in_content_text_and_description(old_db):
    reredact(old_db, KEY, log=lambda s: None)
    row = snapshot(old_db, leaky(old_db))
    token = hash_secret(UUID, KEY)
    for column in ("content", "text", "description"):
        assert UUID not in row[column], column
        assert token in row[column], column
    assert "vpn.example.org:443" in row["text"]


def test_reredact_stores_what_a_fresh_ingest_would_store(old_db):
    # The point of the pass: a re-poll of an unchanged page must find the same
    # fingerprint, or it would log a content_changed that never happened.
    reredact(old_db, KEY, log=lambda s: None)
    row = snapshot(old_db, leaky(old_db))
    body = f"use {PROXY} today"
    fresh = redact_page(
        {"title": "free proxy", "description": body, "content": [{"tag": "p", "children": [body]}]},
        KEY,
    )
    assert row["sha256"] == fingerprint(fresh["title"], fresh["description"], fresh["content"])
    assert row["text"] == page_text(fresh)
    assert json.loads(row["content"]) == fresh["content"]


def test_a_repoll_after_reredact_sees_no_change(old_db):
    reredact(old_db, KEY, log=lambda s: None)
    page_id = snapshot(old_db, leaky(old_db))["page_id"]
    body = f"use {PROXY} today"
    page = {"title": "free proxy", "description": body, "content": [{"tag": "p", "children": [body]}]}
    _, changed = add_snapshot(old_db, page_id, page, T0 + 60, KEY)
    assert changed is False


def test_reredact_leaves_an_unchanged_snapshot_exactly_as_it_was(old_db):
    before = tuple(snapshot(old_db, clean(old_db)))
    reredact(old_db, KEY, log=lambda s: None)
    assert tuple(snapshot(old_db, clean(old_db))) == before


def test_reredact_keeps_views_fetched_at_and_the_page(old_db):
    before = snapshot(old_db, leaky(old_db))
    reredact(old_db, KEY, log=lambda s: None)
    after = snapshot(old_db, leaky(old_db))
    for column in ("id", "page_id", "fetched_at", "views", "title"):
        assert after[column] == before[column], column


def test_reredact_writes_no_event(old_db):
    events = old_db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    reredact(old_db, KEY, log=lambda s: None)
    assert old_db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events
    kinds = {r[0] for r in old_db.execute("SELECT kind FROM events")}
    assert "content_changed" not in kinds


def test_reredact_counts_snapshots_and_pages(old_db):
    page_id = snapshot(old_db, leaky(old_db))["page_id"]
    old_db.execute(
        "INSERT INTO snapshots (page_id, fetched_at, title, description, views, content, text, sha256) "
        "SELECT page_id, fetched_at + 60, title, description, views, content, text, sha256 "
        "FROM snapshots WHERE page_id = ?",
        (page_id,),
    )
    counts = reredact(old_db, KEY, log=lambda s: None)
    assert counts == {"snapshots": 3, "changed": 2, "pages": 1, "hashed_schemes": 0}


def test_reredact_covers_every_snapshot_of_a_page_not_only_the_newest(old_db):
    page_id = snapshot(old_db, leaky(old_db))["page_id"]
    add_snapshot(old_db, page_id, {"title": "free proxy", "content": ["gone"]}, T0 + 60, KEY)
    reredact(old_db, KEY, log=lambda s: None)
    assert UUID not in snapshot(old_db, leaky(old_db))["text"]


def test_reredact_twice_changes_nothing_the_second_time(old_db):
    reredact(old_db, KEY, log=lambda s: None)
    first = tuple(snapshot(old_db, leaky(old_db)))
    counts = reredact(old_db, KEY, log=lambda s: None)
    assert counts["changed"] == 0
    assert tuple(snapshot(old_db, leaky(old_db))) == first


def test_dry_run_counts_and_writes_nothing(old_db):
    before = tuple(snapshot(old_db, leaky(old_db)))
    counts = reredact(old_db, KEY, dry_run=True, log=lambda s: None)
    assert counts == {"snapshots": 2, "changed": 1, "pages": 1, "hashed_schemes": 0}
    assert tuple(snapshot(old_db, leaky(old_db))) == before


def test_reredact_works_across_batches(conn, monkeypatch):
    monkeypatch.setattr("graphwatch.reredact.BATCH", 2)
    ids = [store_raw(conn, f"proxy-11-02-{n}", "t", f"use {PROXY} n{n}") for n in range(1, 6)]
    lines = []
    counts = reredact(conn, KEY, log=lines.append)
    assert counts["changed"] == 5
    assert all(UUID not in snapshot(conn, i)["text"] for i in ids)
    assert len(lines) == 3  # batches of 2, 2 and 1


def test_reredact_logs_counts_only(old_db):
    lines = []
    reredact(old_db, KEY, log=lines.append)
    out = "\n".join(lines)
    assert "2 snapshots read, 1 changed" in out
    assert "vpn.example.org" not in out
    assert "proxy-11-02" not in out


def test_the_same_key_gives_the_token_the_sweep_gave(old_db):
    # A secret hashed at ingest and the same secret hashed by this pass match.
    page_id = upsert_page(old_db, "proxy-11-03", T0)
    add_snapshot(old_db, page_id, {"title": "t", "content": [PROXY]}, T0, KEY)
    reredact(old_db, KEY, log=lambda s: None)
    token = hash_secret(UUID, KEY)
    rows = old_db.execute("SELECT text FROM snapshots WHERE text LIKE '%vless://%'").fetchall()
    assert len(rows) == 2
    assert all(token in row["text"] for row in rows)


# --- the command ---------------------------------------------------------------


def write_config(tmp_path, text="HMAC_KEY=test-key\n"):
    path = tmp_path / "config.env"
    path.write_text(text, encoding="utf-8")
    return path


def file_db(tmp_path):
    path = tmp_path / "g.sqlite"
    c = connect(path)
    store_raw(c, "proxy-11-02", "free proxy", f"use {PROXY} today")
    c.close()
    return path


def texts(path):
    c = sqlite3.connect(str(path))
    try:
        return [r[0] for r in c.execute("SELECT text FROM snapshots")]
    finally:
        c.close()


def test_main_rewrites_the_file_and_reports(tmp_path, capsys):
    db = file_db(tmp_path)
    assert main([str(db), "--config", str(write_config(tmp_path))]) == 0
    assert "changed 1 of 1 snapshots on 1 pages" in capsys.readouterr().out
    assert UUID not in texts(db)[0]
    assert hash_secret(UUID, KEY) in texts(db)[0]


def test_main_dry_run_leaves_the_file_alone(tmp_path, capsys):
    db = file_db(tmp_path)
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert "would change 1 of 1 snapshots" in capsys.readouterr().out
    assert UUID in texts(db)[0]


def test_main_refuses_a_missing_database(tmp_path, capsys):
    assert main([str(tmp_path / "nope.sqlite"), "--config", str(write_config(tmp_path))]) == 2
    assert "no such file" in capsys.readouterr().err
    assert not (tmp_path / "nope.sqlite").exists()


def test_main_refuses_without_a_config_file(tmp_path, capsys):
    db = file_db(tmp_path)
    assert main([str(db), "--config", str(tmp_path / "missing.env")]) == 2
    assert "Config file not found" in capsys.readouterr().err
    assert UUID in texts(db)[0]


def test_main_refuses_without_the_key_and_never_prints_one(tmp_path, capsys):
    db = file_db(tmp_path)
    config = write_config(tmp_path, "OTHER=sensitive-value\n")
    assert main([str(db), "--config", str(config)]) == 2
    captured = capsys.readouterr()
    assert "HMAC_KEY not set" in captured.err
    assert "sensitive-value" not in captured.out + captured.err


# --- what the review of 22 November found ---------------------------------------------

from graphwatch.db import save_labels, save_score  # noqa: E402
from graphwatch.reredact import SCHEMES, restore_schemes, scheme_hashes  # noqa: E402

TOKEN = "a1b2c3d4e5f6a7b8c9d0"
LABELLED_LINK = f"link:https://d.example/in?token={TOKEN}"


def as_stored_since_6_november(raw: str) -> str:
    """What the committed patterns stored: the bare login pattern hashed the
    scheme after a label, and no pattern for the token existed."""
    return raw.replace(":https://", ":" + hash_secret("https", KEY) + "://")


def test_the_pattern_of_5_november_did_hash_the_scheme_after_a_label():
    # The premise of the next tests: this is the pattern as it was committed.
    import re

    old = re.compile(r"(?<![\w@./:-])([\w.+-]*[^\W\d_][\w.+-]*)(:)(?!/)(?=[^\s:]*\D)([^\s:]+)")
    assert old.search("link:https://d.example/").group(3) == "https"


def test_a_fresh_fetch_keeps_the_scheme_after_a_label_now():
    out = redact_page({"title": "t", "content": [LABELLED_LINK]}, KEY)["content"][0]
    assert out == "link:https://d.example/in?token=" + hash_secret(TOKEN, KEY)


def test_scheme_hashes_covers_three_spellings_of_every_scheme():
    hashes = scheme_hashes(KEY)
    # s3 reads the same in upper case and with a capital, so it gives two
    assert len(hashes) == 3 * len(SCHEMES) - 1
    assert hashes[hash_secret("https", KEY) + "://"] == "https://"
    assert hashes[hash_secret("HTTPS", KEY) + "://"] == "HTTPS://"
    assert hashes[hash_secret("Vless", KEY) + "://"] == "Vless://"


def test_restore_schemes_puts_the_scheme_back_and_touches_nothing_else():
    hashes = scheme_hashes(KEY)
    other = hash_secret("hunter2", KEY)
    stored = f"link:{hash_secret('https', KEY)}://d.example/x pw {other} and {other}://y"
    assert restore_schemes(stored, hashes) == f"link:https://d.example/x pw {other} and {other}://y"
    assert restore_schemes(None, hashes) is None
    assert restore_schemes("plain text", hashes) == "plain text"


def test_restore_schemes_needs_the_same_key():
    stored = f"link:{hash_secret('https', KEY)}://d.example/x"
    assert restore_schemes(stored, scheme_hashes(b"another-key")) == stored


def test_a_token_behind_a_hashed_scheme_is_found_and_hashed(conn):
    # The row as the nightly sweep has stored it since 6 November: reredact
    # reported "changed 0" for it before this fix and left the token in clear.
    snapshot_id = store_raw(conn, "x-11-10", "t", as_stored_since_6_november(LABELLED_LINK))
    counts = reredact(conn, KEY, log=lambda s: None)
    assert counts["changed"] == 1
    row = snapshot(conn, snapshot_id)
    assert TOKEN not in row["text"] + row["content"] + row["description"]
    assert hash_secret(TOKEN, KEY) in row["text"]


@pytest.mark.parametrize(
    "raw",
    [
        LABELLED_LINK,
        f"DE1:vless://{UUID}@vpn.example.org:443?security=tls",
        "proxy:socks5://user:pass@8.8.8.8:1080",
        f"Ссылка:https://m.dating.example.com/autologin?key={TOKEN}{TOKEN}",
    ],
)
def test_a_row_stored_by_the_old_patterns_comes_out_as_a_fresh_fetch_would(conn, raw):
    stored = as_stored_since_6_november(raw).replace(
        ":vless://", ":" + hash_secret("vless", KEY) + "://"
    ).replace(":socks5://", ":" + hash_secret("socks5", KEY) + "://")
    snapshot_id = store_raw(conn, "x-11-10", "t", stored)
    reredact(conn, KEY, log=lambda s: None)
    row = snapshot(conn, snapshot_id)
    fresh = redact_page({"title": "t", "description": raw, "content": [{"tag": "p", "children": [raw]}]}, KEY)
    assert row["text"] == page_text(fresh)
    assert row["sha256"] == fingerprint(fresh["title"], fresh["description"], fresh["content"])
    _, changed = add_snapshot(
        conn, row["page_id"], {"title": "t", "description": raw, "content": [{"tag": "p", "children": [raw]}]}, T0 + 60, KEY
    )
    assert changed is False


def test_a_secret_in_a_link_target_is_rewritten(conn):
    page_id = upsert_page(conn, "x-11-10", T0)
    content = [{"tag": "a", "attrs": {"href": f"https://d.example/autologin?token={TOKEN}"}, "children": ["click"]}]
    conn.execute(
        "INSERT INTO snapshots (page_id, fetched_at, title, description, views, content, text, sha256) "
        "VALUES (?, ?, 't', 'click', 1, ?, 't\\nclick\\nclick', 'old')",
        (page_id, T0, json.dumps(content)),
    )
    conn.commit()
    counts = reredact(conn, KEY, log=lambda s: None)
    assert counts["changed"] == 1
    row = conn.execute("SELECT * FROM snapshots").fetchone()
    assert TOKEN not in row["content"]
    assert row["text"] == "t\nclick\nclick"  # the text never held the target
    assert row["sha256"] != "old"


def test_a_snapshot_with_a_null_description_is_rewritten_not_crashed_on(conn):
    page_id = upsert_page(conn, "x-11-10", T0)
    conn.execute(
        "INSERT INTO snapshots (page_id, fetched_at, title, description, views, content, text, sha256) "
        "VALUES (?, ?, NULL, NULL, 1, ?, ?, 'old')",
        (page_id, T0, json.dumps([PROXY]), "\n\n" + PROXY),
    )
    conn.commit()
    counts = reredact(conn, KEY, log=lambda s: None)
    assert counts["changed"] == 1
    row = conn.execute("SELECT * FROM snapshots").fetchone()
    assert (row["title"], row["description"]) == (None, None)
    assert UUID not in row["text"]


def classifier_rows(conn, snapshot_id) -> tuple[int, int, int]:
    return tuple(
        conn.execute(f"SELECT COUNT(*) FROM {table} WHERE snapshot_id = ?", (snapshot_id,)).fetchone()[0]
        for table in ("scores", "hits", "labels")
    )


def test_the_hits_and_labels_of_a_rewritten_snapshot_are_deleted_and_its_score_kept(old_db):
    # A stored hit quotes the old text as its evidence. The score row stays:
    # it is what says the page was flagged, and classify scores it again.
    for snapshot_id in (leaky(old_db), clean(old_db)):
        page_id = snapshot(old_db, snapshot_id)["page_id"]
        save_score(old_db, snapshot_id, page_id, 4, True, None, [("proxy_uri", 4, PROXY, 1)], T0)
        save_labels(old_db, snapshot_id, page_id, [("proxy_list", 4, True, True)])
    old_db.commit()
    reredact(old_db, KEY, log=lambda s: None)
    assert classifier_rows(old_db, leaky(old_db)) == (1, 0, 0)
    assert classifier_rows(old_db, clean(old_db)) == (1, 1, 1)
    # The only hit left that quotes the proxy link is the clean snapshot's own row
    left = [r[0] for r in old_db.execute("SELECT snapshot_id FROM hits WHERE evidence LIKE ?", (f"%{UUID}%",))]
    assert left == [clean(old_db)]


def test_a_dry_run_keeps_the_classifier_rows(old_db):
    snapshot_id = leaky(old_db)
    save_score(old_db, snapshot_id, snapshot(old_db, snapshot_id)["page_id"], 4, True, None, [], T0)
    old_db.commit()
    reredact(old_db, KEY, dry_run=True, log=lambda s: None)
    assert classifier_rows(old_db, snapshot_id) == (1, 0, 0)


def test_main_adds_the_tables_a_database_made_before_today_lacks(tmp_path, capsys):
    db = tmp_path / "g.sqlite"
    c = sqlite3.connect(str(db))
    c.executescript(
        """
        CREATE TABLE pages (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, slug TEXT NOT NULL,
            month INTEGER NOT NULL, day INTEGER NOT NULL, counter INTEGER, title_id INTEGER,
            held_out INTEGER NOT NULL DEFAULT 0, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
            published_at REAL, modified_at REAL, meta_seen_at REAL, author_name TEXT, author_url TEXT);
        CREATE TABLE snapshots (id INTEGER PRIMARY KEY, page_id INTEGER NOT NULL, fetched_at REAL NOT NULL,
            title TEXT, description TEXT, views INTEGER, content TEXT NOT NULL, text TEXT NOT NULL, sha256 TEXT NOT NULL);
        """
    )
    c.execute("INSERT INTO pages (path, slug, month, day, first_seen, last_seen) VALUES ('x-11-10', 'x', 11, 10, 0, 0)")
    c.execute(
        "INSERT INTO snapshots (page_id, fetched_at, title, description, content, text, sha256) VALUES (1, 0, 't', '', ?, ?, 'old')",
        (json.dumps([PROXY]), "t\n\n" + PROXY),
    )
    c.commit()
    c.close()
    assert main([str(db), "--config", str(write_config(tmp_path))]) == 0
    assert "changed 1 of 1 snapshots" in capsys.readouterr().out


# --- what the second review of 22 November found -------------------------------------


@pytest.mark.parametrize("scheme", ["sftp", "mongodb", "wss", "rtmp", "SFTP", "Postgres"])
def test_more_schemes_are_put_back(conn, scheme):
    raw = f"db:{scheme}://bob:hunter2@files.example.com/x"
    stored = raw.replace(f":{scheme}://", ":" + hash_secret(scheme, KEY) + "://")
    snapshot_id = store_raw(conn, "x-11-10", "t", stored)
    counts = reredact(conn, KEY, log=lambda s: None)
    row = snapshot(conn, snapshot_id)
    assert "hunter2" not in row["text"]
    assert f"{scheme}://" in row["text"]
    assert counts["hashed_schemes"] == 0


def test_a_scheme_that_is_not_known_is_counted_and_reported(conn, tmp_path, capsys):
    # The hash cannot be turned back into a word that is not on the list, so
    # the row is counted: it will read as changed when the page is fetched again.
    stored = "link:" + hash_secret("gopher", KEY) + "://d.example/x"
    store_raw(conn, "x-11-10", "t", stored)
    store_raw(conn, "y-11-10", "t", "nothing to see")
    counts = reredact(conn, KEY, dry_run=True, log=lambda s: None)
    assert counts["hashed_schemes"] == 1
    db = tmp_path / "g.sqlite"
    c = connect(db)
    store_raw(c, "x-11-10", "t", stored)
    c.close()
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert "1 snapshots still hold a hashed URL scheme" in capsys.readouterr().out


def test_a_dry_run_does_not_add_tables_to_an_old_database(tmp_path, capsys):
    db = tmp_path / "g.sqlite"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE snapshots (id INTEGER PRIMARY KEY, page_id INTEGER, fetched_at REAL, title TEXT, description TEXT, views INTEGER, content TEXT, text TEXT, sha256 TEXT)")
    c.execute("INSERT INTO snapshots VALUES (1, 1, 0, 't', '', 1, ?, ?, 'old')", (json.dumps([PROXY]), "t\n\n" + PROXY))
    c.commit()
    c.close()
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert "would change 1 of 1 snapshots" in capsys.readouterr().out
    c = sqlite3.connect(str(db))
    names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    c.close()
    assert names == {"snapshots"}


# --- what the third review of 22 November found --------------------------------------


def test_a_page_flagged_on_an_older_snapshot_is_still_flagged_after_reredact_and_classify(conn):
    # reredact used to delete the score of every snapshot it rewrote. Classify
    # only scores a page's newest snapshot and the older ones that hold a
    # flagged score, so the older flag was gone for good and the page fell
    # off the re-poll's list.
    from graphwatch.cli import run_classify
    from graphwatch.db import resweep_paths

    page_id = upsert_page(conn, "Hello-11-10-5", T0)
    spoof = {"title": "www.tenable.com@agfc.harper18.workers.dev/", "description": "Hello,+world!", "content": [f"Hello,+world! {PROXY}"]}
    conn.execute(
        "INSERT INTO snapshots (page_id, fetched_at, title, description, views, content, text, sha256) VALUES (?, ?, ?, ?, 1, ?, ?, 'old')",
        (page_id, T0, spoof["title"], spoof["description"], json.dumps(spoof["content"]), page_text(spoof)),
    )
    conn.commit()
    run_classify(conn, log=lambda s: None)  # the night the spoof was the newest snapshot
    add_snapshot(conn, page_id, {"title": "quiet now", "description": "", "content": ["nothing here at all, really"]}, T0 + 60, KEY)
    run_classify(conn, log=lambda s: None)
    assert [r["path"] for r in resweep_paths(conn, T0 + 3600, flagged=True)] == ["Hello-11-10-5"]
    assert reredact(conn, KEY, log=lambda s: None)["changed"] == 1
    run_classify(conn, log=lambda s: None)
    assert [r["path"] for r in resweep_paths(conn, T0 + 3600, flagged=True)] == ["Hello-11-10-5"]


def test_a_dry_run_opens_a_database_whose_path_has_a_hash_or_a_question_mark(tmp_path, capsys):
    folder = tmp_path / "odd #1 ?name"
    folder.mkdir()
    db = folder / "g.sqlite"
    c = connect(db)
    store_raw(c, "proxy-11-02", "free proxy", f"use {PROXY} today")
    c.close()
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert "would change 1 of 1 snapshots" in capsys.readouterr().out
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.env", "odd #1 ?name"]
