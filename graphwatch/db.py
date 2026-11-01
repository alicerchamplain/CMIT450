"""Database functions for managing telegraph data"""

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from sqlite3 import Connection

from graphwatch.slugify import Entry
from graphwatch.telegraph import Outcome, page_text

SCHEMA = """
CREATE TABLE IF NOT EXISTS titles (
    id          INTEGER PRIMARY KEY,
    title       TEXT    NOT NULL,
    slug        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    source      TEXT    NOT NULL,
    crowd_only  INTEGER NOT NULL DEFAULT 0,
    added_at    REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS pages (
    id          INTEGER PRIMARY KEY,
    path        TEXT    NOT NULL UNIQUE,
    slug        TEXT    NOT NULL,
    month       INTEGER NOT NULL,
    day         INTEGER NOT NULL,
    counter     INTEGER,
    title_id    INTEGER REFERENCES titles(id),
    held_out    INTEGER NOT NULL DEFAULT 0,
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS pages_slug_day ON pages (slug COLLATE NOCASE, month, day);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY,
    page_id     INTEGER NOT NULL REFERENCES pages(id),
    fetched_at  REAL    NOT NULL,
    title       TEXT,
    description TEXT,
    views       INTEGER,
    content     TEXT    NOT NULL,
    text        TEXT    NOT NULL,
    sha256      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS snapshots_page_time ON snapshots (page_id, fetched_at);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    page_id     INTEGER REFERENCES pages(id),
    ts          REAL    NOT NULL,
    kind        TEXT    NOT NULL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS events_page ON events (page_id);

CREATE TABLE IF NOT EXISTS http_log (
    id          INTEGER PRIMARY KEY,
    ts          REAL    NOT NULL,
    path        TEXT    NOT NULL,
    attempt     INTEGER NOT NULL,
    status      INTEGER,
    outcome     TEXT    NOT NULL,
    error       TEXT,
    elapsed_ms  INTEGER NOT NULL,
    bytes       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS http_log_ts ON http_log (ts);
"""


path_regex = r"^(.+)-(\d{2})-(\d{2})(?:-(\d+))?$"
# ^ and $	anchors: match the whole string, not a fragment inside it
# (.+)             : group 1, the slug: one or more of any character
# -(\d{2})	       : hyphen then group 2, exactly two digits: the month
# -(\d{2})	       : hyphen then group 3, two digits: the day
# (?:-(\d+))?	   : optional: a hyphen then group 4, one or more digits, the counter

PATTERN = re.compile(path_regex)


def connect(path: str):
    """Function to connect to the sqlite3 db, loads SCHEMA and enables foreign keys

    Args:
        path (_type_): Path to the db file

    Returns:
        sqlite3 connection: Connection to the db
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def add_event(conn: Connection, page_id: int, kind: str, ts: float, detail=None) -> int:
    """Generic function to insert events into the db

    Args:
        conn (Connection): sql connection
        page_id (int | None): page id
        kind (string): event type
        ts (float): timestamp
        detail (string, optional): Details of the event. Defaults to None.

    Returns:
        int: new row id
    """
    sql = "INSERT INTO events (page_id, kind, ts, detail) VALUES (?, ?, ?, ?)"
    params = (page_id, kind, ts, detail)
    cur = conn.execute(sql, params)
    newrowid = cur.lastrowid
    conn.commit()
    return newrowid


def add_snapshot(
    conn: Connection, page_id: int, page: dict, ts: float
) -> tuple[int, bool]:
    """Function to add page snapshots, hash them, and see if they updated

    Args:
        conn (Connection): SQL db connection
        page_id (int): Page id
        page (dict): Page content
        ts (float): Timestamp

    Returns:
        tuple[int, bool]: Returns the lastrowid and a bool to say if the page hash changed
    """
    title = page.get("title")
    description = page.get("description")
    views = page.get("views")
    content = page.get("content", [])
    fingerprint = {"title": title, "description": description, "content": content}
    canonical = json.dumps(
        fingerprint, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    hash_select = "SELECT sha256 FROM snapshots WHERE page_id = ? ORDER BY fetched_at DESC, id DESC LIMIT 1"
    hash_params = (page_id,)
    previous = conn.execute(hash_select, hash_params).fetchone()
    changed = previous is not None and previous["sha256"] != sha
    if changed:
        add_event(conn, page_id, "content_changed", ts)
    # Redaction (issue #18) should go in here
    snapshot_insert = """
    INSERT INTO snapshots (page_id, fetched_at, title, description, views, content, text, sha256)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    snapshot_params = (
        page_id,
        ts,
        title,
        description,
        views,
        json.dumps(content, ensure_ascii=False),
        page_text(page),
        sha,
    )
    cur = conn.execute(snapshot_insert, snapshot_params)
    conn.commit()
    return cur.lastrowid, changed


def held_out_paths():
    return


def http_logger():
    return


def load_known():
    return


def parse_path(path: str) -> tuple[str, int, int, int | None]:
    """Parses Slug path into it's 3-4 parts

    Args:
        path (str): The slug path

    Raises:
        ValueError: Error if the path doesn't match the regex for valid slugs

    Returns:
        tuple[str, int, int, int | None]: Slug in 4 parts (title, month, day, counter)
    """
    m = PATTERN.fullmatch(path)
    if not m:
        raise ValueError(path)
    return (
        m.group(1),
        int(m.group(2)),
        int(m.group(3)),
        int(m.group(4)) if m.group(4) is not None else None,
    )


def store_fetch():
    return


def upsert_page(conn: Connection, path: str, ts: float, held_out: bool = False) -> int:
    """Update and insert (upsert) a page in the db

    Args:
        conn (Connection): SQL db connection
        path (str): Page path
        ts (float): timestamp
        held_out (bool, optional): Bool to flag if the page is part of the eval set. Defaults to False.

    Returns:
        int: _description_
    """
    slug, month, day, counter = parse_path(path)
    page_select = "SELECT id FROM pages WHERE path = ?"
    page_params = (path,)
    existing = conn.execute(page_select, page_params).fetchone()
    title_select = "SELECT id FROM titles WHERE slug = ? COLLATE NOCASE"
    title_params = (slug,)
    title_row = conn.execute(title_select, title_params).fetchone()
    title_id = title_row["id"] if title_row is not None else None
    upsert_sql = """
    INSERT INTO pages (path, slug, month, day, counter, title_id, held_out, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(path) DO UPDATE SET
    last_seen = excluded.last_seen,
    held_out  = MAX(held_out, excluded.held_out)
    """
    upsert_params = (path, slug, month, day, counter, title_id, int(held_out), ts, ts)
    cur = conn.execute(upsert_sql, upsert_params)
    if existing is not None:
        page_id = existing["id"]
    else:
        page_id = cur.lastrowid
        add_event(conn, page_id, "discovered", ts)
    conn.commit()

    return page_id


def upsert_title(conn: Connection, entry: Entry, ts: float) -> int:
    """Update and insert (upsert) title entries into the db

    Args:
        conn (Connection): SQL Connection
        entry (Entry): Entry to upsert
        ts (float): Timestamp

    Returns:
        int: row id
    """
    sql_insert = """
    INSERT INTO titles (title, slug, source, crowd_only, added_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(slug) DO NOTHING
    """
    params_insert = (entry.title, entry.slug, entry.source, int(entry.crowd_only), ts)
    conn.execute(sql_insert, params_insert)
    sql_select = "SELECT id FROM titles WHERE slug = ?"
    params_select = (entry.slug,)
    row = conn.execute(sql_select, params_select).fetchone()
    title_id = row["id"]
    conn.commit()
    return title_id
