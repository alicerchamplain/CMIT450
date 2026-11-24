"""Tests for the one-time re-redaction of stored snapshots.

Rows are written straight into the snapshots table the way an older ingest
left them, with a secret shape still in clear. Every secret here is made up.
"""

import json
import re
import runpy
import sqlite3
import sys

import pytest

from graphwatch.cli import run_classify
from graphwatch.db import (
    add_snapshot,
    classify_mark,
    connect,
    fingerprint,
    resweep_paths,
    save_labels,
    save_score,
    set_classify_mark,
    upsert_page,
)
from graphwatch.redact import BARE_LOGIN_PASSWORD_PATTERN, hash_secret, redact_page
from graphwatch.reredact import (
    SCHEMES,
    main,
    port_hashes,
    reredact,
    reredact_snapshot,
    restore_ports,
    restore_schemes,
    scheme_hashes,
)
from graphwatch.telegraph import page_text

T0 = 1_700_000_000.0
# 32 bytes, the shortest key hmac_key accepts, because main reads it from a config file
KEY = b"test-key" * 4
UUID = "0f1e2d3c-4b5a-6978-8695-a4b3c2d1e0f9"
PROXY = f"vless://{UUID}@vpn.example.org:443"
TOKEN = "a1b2c3d4e5f6a7b8c9d0"
LOGIN_LINK = f"https://d.example/in?token={TOKEN}"
LABELLED_LINK = "link:" + LOGIN_LINK

# The columns a rewrite touches
REWRITTEN = ("title", "description", "content", "text", "sha256")


def page_of(title, body) -> dict:
    return {"title": title, "description": body, "content": [{"tag": "p", "children": [body]}]}


LEAKY_PAGE = page_of("free proxy", f"use {PROXY} today")


def store_page(conn, path, page, ts=T0) -> int:
    """Insert a snapshot with no redaction at all, like a pattern that did not exist yet."""
    page_id = upsert_page(conn, path, ts)
    title, description, content = page.get("title"), page.get("description"), page["content"]
    cur = conn.execute(
        """
        INSERT INTO snapshots (page_id, fetched_at, title, description, views, content, text, sha256)
        VALUES (?, ?, ?, ?, 3, ?, ?, ?)
        """,
        (
            page_id,
            ts,
            title,
            description,
            json.dumps(content, ensure_ascii=False),
            page_text(page),
            fingerprint(title, description, content),
        ),
    )
    conn.commit()
    return cur.lastrowid


def store_raw(conn, path, title, body, ts=T0) -> int:
    return store_page(conn, path, page_of(title, body), ts)


def snapshot(conn, snapshot_id):
    return conn.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()


def rewritten(row) -> dict:
    return {column: row[column] for column in REWRITTEN}


def as_ingested_today(page) -> dict:
    """What a fetch of this page tonight stores in those columns, from the real ingest."""
    c = connect(":memory:")
    snapshot_id, _ = add_snapshot(c, upsert_page(c, "fresh-11-02", T0), page, T0, KEY)
    row = rewritten(snapshot(c, snapshot_id))
    c.close()
    return row


def classifier_rows(conn, snapshot_id) -> tuple[int, int, int]:
    return tuple(
        conn.execute(f"SELECT COUNT(*) FROM {table} WHERE snapshot_id = ?", (snapshot_id,)).fetchone()[0]
        for table in ("scores", "hits", "labels")
    )


def classify_as_a_proxy_list(conn, snapshot_id) -> None:
    page_id = snapshot(conn, snapshot_id)["page_id"]
    save_score(conn, snapshot_id, page_id, 4, True, None, [("proxy_uri", 4, PROXY, 1)], T0)
    save_labels(conn, snapshot_id, page_id, [("proxy_list", 4, True, True)])
    conn.commit()


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


# The snapshot ids in old_db
LEAKY, CLEAN = 1, 2


@pytest.fixture
def old_db(conn):
    """One snapshot with a secret in clear, one with nothing to hash."""
    assert store_page(conn, "proxy-11-02", LEAKY_PAGE) == LEAKY
    assert store_raw(conn, "Hello-11-02", "Hello", "nothing to see here") == CLEAN
    return conn


def test_fingerprint_ignores_nothing_it_is_given():
    # The rewritten sha256 stands for all three fields; no other test would
    # notice a fingerprint that left the description out
    base = fingerprint("t", "d", ["x"])
    assert fingerprint("T", "d", ["x"]) != base
    assert fingerprint("t", "D", ["x"]) != base
    assert fingerprint("t", "d", ["y"]) != base


def test_reredact_hashes_the_secret_in_content_text_and_description(old_db):
    reredact(old_db, KEY, log=lambda s: None)
    row = snapshot(old_db, LEAKY)
    token = hash_secret(UUID, KEY)
    for column in ("content", "text", "description"):
        assert UUID not in row[column], column
        assert token in row[column], column
    assert "vpn.example.org:443" in row["text"]


def test_reredact_stores_what_a_fetch_tonight_would_store_and_touches_no_other_column(old_db):
    # The point of the pass: a re-poll of an unchanged page must find the same
    # fingerprint, or it would log a content_changed that never happened.
    before = dict(snapshot(old_db, LEAKY))
    reredact(old_db, KEY, log=lambda s: None)
    after = dict(snapshot(old_db, LEAKY))
    assert after == {**before, **as_ingested_today(LEAKY_PAGE)}
    _, changed = add_snapshot(old_db, after["page_id"], LEAKY_PAGE, T0 + 60, KEY)
    assert changed is False


def test_reredact_leaves_an_unchanged_snapshot_exactly_as_it_was(old_db):
    before = tuple(snapshot(old_db, CLEAN))
    reredact(old_db, KEY, log=lambda s: None)
    assert tuple(snapshot(old_db, CLEAN)) == before


def test_reredact_writes_no_event(old_db):
    events = old_db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    reredact(old_db, KEY, log=lambda s: None)
    assert old_db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events


def test_reredact_rewrites_each_snapshot_of_a_page_on_its_own_and_counts_the_page_once(old_db):
    # The page was fetched twice more: the same once, and then with the proxy gone
    again = store_page(old_db, "proxy-11-02", LEAKY_PAGE, ts=T0 + 60)
    gone = store_raw(old_db, "proxy-11-02", "free proxy", "no proxy today", ts=T0 + 120)
    before = tuple(snapshot(old_db, gone))
    counts = reredact(old_db, KEY, log=lambda s: None)
    assert counts == {"snapshots": 4, "changed": 2, "pages": 1, "hashed_schemes": 0}
    assert rewritten(snapshot(old_db, LEAKY)) == rewritten(snapshot(old_db, again))
    assert UUID not in snapshot(old_db, again)["text"]
    assert tuple(snapshot(old_db, gone)) == before


def test_reredact_twice_changes_nothing_the_second_time(old_db):
    reredact(old_db, KEY, log=lambda s: None)
    writes = old_db.total_changes
    assert reredact(old_db, KEY, log=lambda s: None)["changed"] == 0
    assert old_db.total_changes == writes


def test_dry_run_counts_and_writes_nothing(old_db):
    # The hit and the label are there so that deleting them would show
    classify_as_a_proxy_list(old_db, LEAKY)
    writes = old_db.total_changes
    counts = reredact(old_db, KEY, dry_run=True, log=lambda s: None)
    assert counts == {"snapshots": 2, "changed": 1, "pages": 1, "hashed_schemes": 0}
    assert old_db.total_changes == writes


def test_each_batch_is_committed_so_a_stopped_run_can_be_started_again(conn, monkeypatch):
    monkeypatch.setattr("graphwatch.reredact.BATCH", 2)
    ids = [store_raw(conn, f"proxy-11-02-{n}", "t", f"use {PROXY} n{n}") for n in range(1, 6)]

    def stop(line):
        raise KeyboardInterrupt

    # The log is written after each batch: stop the run at the first line
    with pytest.raises(KeyboardInterrupt):
        reredact(conn, KEY, log=stop)
    conn.rollback()
    assert [UUID in snapshot(conn, i)["text"] for i in ids] == [False, False, True, True, True]
    lines = []
    assert reredact(conn, KEY, log=lines.append)["changed"] == 3
    assert not any(UUID in snapshot(conn, i)["text"] for i in ids)
    # Counts and nothing else: no path, no host
    assert lines == [
        "2 snapshots read, 0 changed",
        "4 snapshots read, 2 changed",
        "5 snapshots read, 3 changed",
    ]


# --- the command ---------------------------------------------------------------


def write_config(tmp_path, text="HMAC_KEY=" + KEY.decode() + "\n"):
    path = tmp_path / "config.env"
    path.write_text(text, encoding="utf-8")
    return path


def file_db(tmp_path, body=f"use {PROXY} today"):
    path = tmp_path / "g.sqlite"
    path.parent.mkdir(exist_ok=True)
    c = connect(path)
    store_raw(c, "proxy-11-02", "free proxy", body)
    c.close()
    return path


def old_file_db(tmp_path):
    """A database from before the classifier: pages and snapshots and no other table."""
    path = tmp_path / "old.sqlite"
    c = sqlite3.connect(str(path))
    c.executescript(
        """
        CREATE TABLE pages (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, slug TEXT NOT NULL,
            month INTEGER NOT NULL, day INTEGER NOT NULL, counter INTEGER, title_id INTEGER,
            held_out INTEGER NOT NULL DEFAULT 0, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
            published_at REAL, modified_at REAL, meta_seen_at REAL, author_name TEXT, author_url TEXT);
        CREATE TABLE snapshots (id INTEGER PRIMARY KEY, page_id INTEGER NOT NULL, fetched_at REAL NOT NULL,
            title TEXT, description TEXT, views INTEGER, content TEXT NOT NULL, text TEXT NOT NULL, sha256 TEXT NOT NULL);
        INSERT INTO pages (path, slug, month, day, first_seen, last_seen) VALUES ('x-11-10', 'x', 11, 10, 0, 0);
        """
    )
    c.execute(
        "INSERT INTO snapshots (page_id, fetched_at, title, description, content, text, sha256) VALUES (1, 0, 't', '', ?, ?, 'old')",
        (json.dumps([PROXY]), "t\n\n" + PROXY),
    )
    c.commit()
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
    assert capsys.readouterr().out == (
        "1 snapshots read, 1 changed\nchanged 1 of 1 snapshots on 1 pages\n"
    )
    assert UUID not in texts(db)[0]
    assert hash_secret(UUID, KEY) in texts(db)[0]


def test_main_adds_the_tables_a_database_made_before_today_lacks(tmp_path, capsys):
    db = old_file_db(tmp_path)
    assert main([str(db), "--config", str(write_config(tmp_path))]) == 0
    assert "changed 1 of 1 snapshots" in capsys.readouterr().out
    assert UUID not in texts(db)[0]


def test_a_dry_run_leaves_the_file_as_it_was_and_adds_no_table_to_an_old_database(tmp_path, capsys):
    db = old_file_db(tmp_path)
    before = db.read_bytes()
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert "would change 1 of 1 snapshots on 1 pages" in capsys.readouterr().out
    assert db.read_bytes() == before


def test_a_dry_run_opens_the_database_read_only(tmp_path, monkeypatch):
    # Whatever the pass does, a dry run cannot write to the file
    refused = []

    def try_to_write(conn, key, dry_run, log):
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM snapshots")
        refused.append(dry_run)
        return {"snapshots": 0, "changed": 0, "pages": 0, "hashed_schemes": 0}

    monkeypatch.setattr("graphwatch.reredact.reredact", try_to_write)
    db = file_db(tmp_path)
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert refused == [True]


def test_a_dry_run_opens_a_database_whose_path_has_a_hash_or_a_question_mark(tmp_path, capsys):
    db = file_db(tmp_path / "odd #1 ?name")
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert "would change 1 of 1 snapshots" in capsys.readouterr().out
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.env", "odd #1 ?name"]


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


def test_main_refuses_a_key_that_is_too_short_and_never_prints_it(tmp_path, capsys):
    db = file_db(tmp_path)
    config = write_config(tmp_path, "HMAC_KEY=short-sensitive-value\n")
    assert main([str(db), "--config", str(config)]) == 2
    captured = capsys.readouterr()
    assert "HMAC_KEY is shorter than 32 bytes" in captured.err
    assert "short-sensitive-value" not in captured.out + captured.err
    assert UUID in texts(db)[0]


def test_run_as_a_module_it_exits_with_what_main_returns(tmp_path, monkeypatch):
    # python -m graphwatch.reredact <db>, the usage in the module's docstring
    argv = ["reredact", str(tmp_path / "nope.sqlite"), "--config", str(tmp_path / "missing.env")]
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.delitem(sys.modules, "graphwatch.reredact")
    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("graphwatch.reredact", run_name="__main__")
    assert stopped.value.code == 2


# --- what the review of 22 November found ---------------------------------------------


def as_stored_since_6_november(raw: str) -> str:
    """What the committed patterns stored: the bare login pattern hashed the
    scheme after a label, and no pattern for the secret behind it existed.

    The scheme only. The patterns of 6 November also took the port of a proxy
    link for a password and hashed it, which no pass can put back, so a real
    vless or socks5 row still differs from a fresh fetch by its port."""
    return re.sub(r"(?<=:)\w+(?=://)", lambda m: hash_secret(m.group(0), KEY), raw)


def test_the_pattern_of_5_november_hashed_the_scheme_after_a_label_and_todays_does_not():
    # The pattern as it was committed. It is why the rows below look as they
    # do: as_stored_since_6_november has to agree with it.
    old = re.compile(r"(?<![\w@./:-])([\w.+-]*[^\W\d_][\w.+-]*)(:)(?!/)(?=[^\s:]*\D)([^\s:]+)")
    then = old.sub(lambda m: m.group(1) + ":" + hash_secret(m.group(3), KEY), LABELLED_LINK)
    assert then == as_stored_since_6_november(LABELLED_LINK)
    assert then == f"link:{hash_secret('https', KEY)}://d.example/in?token={TOKEN}"
    now = redact_page({"title": "t", "content": [LABELLED_LINK]}, KEY)["content"][0]
    assert now == "link:https://d.example/in?token=" + hash_secret(TOKEN, KEY)


def test_scheme_hashes_covers_three_spellings_of_every_scheme():
    hashes = scheme_hashes(KEY)
    # s3 reads the same in upper case and with a capital, so it gives two
    assert len(hashes) == 3 * len(SCHEMES) - 1
    assert hashes[hash_secret("https", KEY) + "://"] == "https://"
    assert hashes[hash_secret("HTTPS", KEY) + "://"] == "HTTPS://"
    assert hashes[hash_secret("Vless", KEY) + "://"] == "Vless://"
    # The first list was too short: the second review of 22 November added these
    assert {"sftp", "mongodb", "wss", "rtmp", "postgres"} <= set(SCHEMES)


def test_restore_schemes_puts_the_scheme_back_and_touches_nothing_else():
    hashes = scheme_hashes(KEY)
    # A password that is a scheme's name stays hashed: only what stands before :// is a scheme
    password, other = hash_secret("redis", KEY), hash_secret("hunter2", KEY)
    stored = f"link:{hash_secret('https', KEY)}://d.example/x pw {password} and {other}://y"
    assert restore_schemes(stored, hashes) == f"link:https://d.example/x pw {password} and {other}://y"
    assert restore_schemes(None, hashes) is None
    assert restore_schemes("plain text", hashes) == "plain text"
    # It needs the key the sweep used
    assert restore_schemes(stored, scheme_hashes(b"another-key")) == stored


def test_reredact_snapshot_gives_the_rewritten_columns_or_none(conn):
    clean = store_raw(conn, "Hello-11-02", "Hello", "nothing to see here")
    old = store_raw(conn, "x-11-10", "t", as_stored_since_6_november(LABELLED_LINK))
    assert reredact_snapshot(snapshot(conn, clean), KEY) is None
    # Given no scheme hashes, it works them out from the key
    assert reredact_snapshot(snapshot(conn, old), KEY) == as_ingested_today(page_of("t", LABELLED_LINK))


@pytest.mark.parametrize(
    "raw, secret",
    [
        (LABELLED_LINK, TOKEN),
        (f"DE1:vless://{UUID}@vpn.example.org:443?security=tls", UUID),
        ("proxy:socks5://user:pass@8.8.8.8:1080", "user:pass"),
        (f"Ссылка:https://m.dating.example.com/autologin?key={TOKEN}{TOKEN}", TOKEN),
        # the second review: a scheme the first list lacked, and the other two spellings
        ("db:mongodb://bob:hunter2@files.example.com/x", "hunter2"),
        ("db:SFTP://bob:hunter2@files.example.com/x", "hunter2"),
        ("db:Postgres://bob:hunter2@files.example.com/x", "hunter2"),
    ],
)
def test_a_row_stored_by_the_old_patterns_comes_out_as_a_fresh_fetch_would(conn, raw, secret):
    # The row as the nightly sweep stored it from 6 November, in the title and
    # in the body: reredact reported "changed 0" for it before the fix and
    # left the secret behind the hashed scheme in clear.
    stored = as_stored_since_6_november(raw)
    assert stored != raw and secret in stored
    snapshot_id = store_raw(conn, "x-11-10", stored, stored)
    counts = reredact(conn, KEY, log=lambda s: None)
    assert counts == {"snapshots": 1, "changed": 1, "pages": 1, "hashed_schemes": 0}
    row = snapshot(conn, snapshot_id)
    assert secret not in "".join(row[column] for column in REWRITTEN)
    assert rewritten(row) == as_ingested_today(page_of(raw, raw))
    assert reredact(conn, KEY, log=lambda s: None)["changed"] == 0


def test_a_hashed_scheme_with_no_secret_behind_it_is_put_back_too(conn):
    # Nothing is left to hash, but the row still differs from a fresh fetch
    raw = "link:https://d.example/x"
    snapshot_id = store_raw(conn, "x-11-10", "t", as_stored_since_6_november(raw))
    assert reredact(conn, KEY, log=lambda s: None)["changed"] == 1
    assert rewritten(snapshot(conn, snapshot_id)) == as_ingested_today(page_of("t", raw))


# --- a proxy line stored with its port hashed and its password in clear ------------------

PROXY_LINE = "proxy.example.org:8080:bob:hunter2pw"


def as_stored_until_23_november(line: str) -> str:
    """A host:port:user:password line as it was stored: the port hashed, as the
    password of a login called proxy.example.org, and the password in clear."""
    host, port, rest = line.split(":", 2)
    return f"{host}:{hash_secret(port, KEY)}:{rest}"


def test_the_bare_login_pattern_hashes_the_port_of_a_proxy_line_and_nothing_else():
    # Why the rows below look as they do: as_stored_until_23_november has to
    # agree with the pattern, which is the same one today.
    then = BARE_LOGIN_PASSWORD_PATTERN.sub(
        lambda m: m.group(0)[: m.start(3) - m.start()] + hash_secret(m.group(3), KEY), PROXY_LINE
    )
    assert then == as_stored_until_23_november(PROXY_LINE)
    assert then == f"proxy.example.org:{hash_secret('8080', KEY)}:bob:hunter2pw"


def test_port_hashes_covers_every_string_of_one_to_five_digits():
    hashes = port_hashes(KEY)
    assert len(hashes) == 10 + 100 + 1000 + 10000 + 100000
    for digits in ("0", "80", "8080", "65535", "99999", "00080"):
        assert hashes[hash_secret(digits, KEY)] == digits
    assert hash_secret("100000", KEY) not in hashes
    # Worked out once for a key and kept
    assert port_hashes(KEY) is hashes
    assert hash_secret("8080", KEY) not in port_hashes(b"another-key" * 3)


@pytest.mark.parametrize(
    "line",
    [
        PROXY_LINE,
        "PX-1.Example-Host.ORG:8080:bob:hunter2pw",  # in any case, with hyphens
        "a.b2:00080:u:p",  # labels of one character, a digit in the last, a port with zeros in front
        "proxy.xn--p1ai:8080:bob:hunter2pw",  # a hyphen in the last label
        'proxy.example.org:8080:bo"b:hunter2pw',  # a quote in the user, which a title can hold
    ],
)
def test_restore_ports_puts_the_port_back_whatever_the_host_is_called(line):
    assert restore_ports(as_stored_until_23_november(line), KEY) == line


def test_restore_ports_puts_the_port_of_a_proxy_line_back_and_touches_nothing_else():
    stored = as_stored_until_23_november(PROXY_LINE)
    assert restore_ports(f"use {stored} today", KEY) == f"use {PROXY_LINE} today"
    assert restore_ports(None, KEY) is None
    assert restore_ports("plain text", KEY) == "plain text"
    # It needs the key the sweep used
    assert restore_ports(stored, b"another-key" * 3) == stored


@pytest.mark.parametrize(
    "stored",
    [
        # A password, not a port: only the hash of one to five digits is put back
        f"first.last:{hash_secret('hunter2', KEY)}:First:Last",
        f"first.last:{hash_secret('123456', KEY)}:First:Last",
        # A hashed port with no user and password after it is not a proxy line,
        # and put back it would only be hashed again
        f"proxy.example.org:{hash_secret('8080', KEY)}",
        f"proxy.example.org:{hash_secret('8080', KEY)}:bob",
        f"proxy.example.org:{hash_secret('8080', KEY)} bob:x",
        # One label is not a host
        f"port:{hash_secret('8080', KEY)}:bob:hunter2pw",
    ],
)
def test_restore_ports_leaves_any_other_hash_where_it_is(stored):
    assert restore_ports(stored, KEY) == stored


@pytest.mark.parametrize(
    "raw, secret",
    [
        (PROXY_LINE, "hunter2pw"),
        ("free: proxy.example.org:8080:bob:hunter2pw and px2.example.org:00080:amy:other-pw-2", "other-pw-2"),
        ('say "proxy.example.org:8080:bob:hunter2pw" twice', "hunter2pw"),  # quotes are escaped in the content column
        # An address has no letter, so nothing was hashed in this line at all
        ("203.0.113.7:8080:bob:hunter2pw", "hunter2pw"),
    ],
)
def test_a_proxy_line_stored_with_its_password_in_clear_comes_out_as_a_fresh_fetch_would(conn, raw, secret):
    stored = re.sub(r"[\w.-]+\.org:\d+:\S+", lambda m: as_stored_until_23_november(m.group(0)), raw)
    assert secret in stored
    snapshot_id = store_raw(conn, "x-11-10", stored, stored)
    counts = reredact(conn, KEY, log=lambda s: None)
    assert counts == {"snapshots": 1, "changed": 1, "pages": 1, "hashed_schemes": 0}
    row = snapshot(conn, snapshot_id)
    assert secret not in "".join(row[column] for column in REWRITTEN)
    assert rewritten(row) == as_ingested_today(page_of(raw, raw))
    assert reredact(conn, KEY, log=lambda s: None)["changed"] == 0


def test_a_hashed_password_in_front_of_two_more_fields_is_not_taken_for_a_port(conn):
    stored = f"first.last:{hash_secret('hunter2', KEY)}:First:Last"
    snapshot_id = store_raw(conn, "x-11-10", "t", stored)
    before = rewritten(snapshot(conn, snapshot_id))
    assert reredact(conn, KEY, log=lambda s: None)["changed"] == 0
    assert rewritten(snapshot(conn, snapshot_id)) == before


HASHED_FIELD = hash_secret("8080", KEY)
LONG_STORED_RUNS = {
    "hashed fields": ("a.b:" + HASHED_FIELD + ":") * 800,
    "dotted labels and a hash": "ab.cd-" * 10000 + ":" + HASHED_FIELD + ":u:p",
    "hosts with no hash": "a.b:" * 15000,
    "dotted labels and no hash": "ab.cd-" * 10000 + " " + HASHED_FIELD,
    "a hash and a long user": "a.b:" + HASHED_FIELD + ":" + "u" * 60000,
}


@pytest.mark.parametrize("text", LONG_STORED_RUNS.values(), ids=LONG_STORED_RUNS.keys())
def test_restore_ports_is_quick_on_a_long_run(text, laptop_seconds):
    port_hashes(KEY)  # not what is timed: it is worked out once for a run
    assert laptop_seconds(lambda: restore_ports(text, KEY)) < 1.0


@pytest.mark.parametrize(
    "where, page, secret",
    [
        ("the title", {"title": PROXY, "description": "d", "content": ["nothing here"]}, UUID),
        ("the description", {"title": "t", "description": PROXY, "content": ["nothing here"]}, UUID),
        # The text never holds a link's target, so only content and sha256 change
        (
            "a link target",
            {"title": "t", "description": "click", "content": [{"tag": "a", "attrs": {"href": LOGIN_LINK}, "children": ["click"]}]},
            TOKEN,
        ),
        # A page stored with no title and no description has NULL in both
        # columns, and the pass crashed on the first one it met
        ("the body under a NULL title and description", {"content": [PROXY]}, UUID),
    ],
)
def test_a_secret_in_only_one_place_is_enough_to_rewrite_the_row(conn, where, page, secret):
    snapshot_id = store_page(conn, "x-11-10", page)
    assert secret in "".join(str(value) for value in snapshot(conn, snapshot_id)), where
    assert reredact(conn, KEY, log=lambda s: None)["changed"] == 1, where
    row = snapshot(conn, snapshot_id)
    assert secret not in "".join(str(value) for value in row), where
    assert rewritten(row) == as_ingested_today(page), where


def test_the_hits_and_labels_of_a_rewritten_snapshot_are_deleted_and_its_score_kept(old_db):
    # A stored hit quotes the old text as its evidence. The score row stays:
    # it is what says the page was flagged, and classify scores it again.
    for snapshot_id in (LEAKY, CLEAN):
        classify_as_a_proxy_list(old_db, snapshot_id)
    # the templated-body hit quotes a hash and no text, and classify finds
    # an older snapshot's penalty by it
    old_db.execute("INSERT INTO hits (snapshot_id, rule, weight, evidence) VALUES (?, 'templated_body', -2, 'body abc')", (LEAKY,))
    set_classify_mark(old_db, "the rules of the last classify run")
    old_db.commit()
    # a dry run rewrites nothing, so the scores are as good as they were
    reredact(old_db, KEY, dry_run=True, log=lambda s: None)
    assert classify_mark(old_db) == "the rules of the last classify run"
    reredact(old_db, KEY, log=lambda s: None)
    assert classifier_rows(old_db, LEAKY) == (1, 1, 0)
    assert [r["rule"] for r in old_db.execute("SELECT rule FROM hits WHERE snapshot_id = ?", (LEAKY,))] == ["templated_body"]
    assert classifier_rows(old_db, CLEAN) == (1, 1, 1)
    # The kept score was made from the old text, and classify scores a page
    # again only when its mark is gone: the rewrite takes the mark with it
    assert classify_mark(old_db) is None
    old_db.rollback()  # and that was committed with the rewrite
    assert classify_mark(old_db) is None
    # a second pass finds nothing to rewrite and leaves a new mark alone
    set_classify_mark(old_db, "after the next classify run")
    old_db.commit()
    assert reredact(old_db, KEY, log=lambda s: None)["changed"] == 0
    assert classify_mark(old_db) == "after the next classify run"


# --- what the second review of 22 November found -------------------------------------


def test_a_scheme_that_is_not_known_is_counted_and_reported(conn, tmp_path, capsys):
    # The hash cannot be turned back into a word that is not on the list, so
    # the row is counted: it will read as changed when the page is fetched again.
    # The scheme is made up, so that no scheme added to the list turns this red.
    stored = as_stored_since_6_november("link:notascheme://d.example/x")
    store_raw(conn, "x-11-10", "t", stored)
    store_raw(conn, "y-11-10", "t", "nothing to see")
    counts = reredact(conn, KEY, dry_run=True, log=lambda s: None)
    assert counts == {"snapshots": 2, "changed": 0, "pages": 0, "hashed_schemes": 1}
    db = file_db(tmp_path, body=stored)
    assert main([str(db), "--dry-run", "--config", str(write_config(tmp_path))]) == 0
    assert "1 snapshots still hold a hashed URL scheme" in capsys.readouterr().out


# --- what the third review of 22 November found --------------------------------------


def test_a_page_flagged_on_an_older_snapshot_is_still_flagged_after_reredact_and_classify(conn):
    # reredact used to delete the score of every snapshot it rewrote. Classify
    # only scores a page's newest snapshot and the older ones that hold a
    # flagged score, so the older flag was gone for good and the page fell
    # off the re-poll's list.
    spoof = {
        "title": "www.tenable.com@agfc.harper18.workers.dev/",
        "description": "Hello,+world!",
        "content": [f"Hello,+world! {PROXY}"],
    }
    store_page(conn, "Hello-11-10-5", spoof)
    run_classify(conn, log=lambda s: None)  # the night the spoof was the newest snapshot
    page_id = snapshot(conn, 1)["page_id"]
    quiet = {"title": "quiet now", "description": "", "content": ["nothing here at all, really"]}
    add_snapshot(conn, page_id, quiet, T0 + 60, KEY)
    run_classify(conn, log=lambda s: None)
    assert [r["path"] for r in resweep_paths(conn, T0 + 3600, flagged=True)] == ["Hello-11-10-5"]
    assert reredact(conn, KEY, log=lambda s: None)["changed"] == 1
    run_classify(conn, log=lambda s: None)
    assert [r["path"] for r in resweep_paths(conn, T0 + 3600, flagged=True)] == ["Hello-11-10-5"]
