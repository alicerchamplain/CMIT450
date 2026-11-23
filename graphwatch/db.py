"""Database functions for managing telegraph data"""

import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from sqlite3 import Connection

from graphwatch.redact import redact_page
from graphwatch.slugify import Entry, normalize_slug
from graphwatch.telegraph import Fetch, Outcome, page_text

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
    last_seen   REAL    NOT NULL,
    published_at  REAL,
    modified_at   REAL,
    meta_seen_at  REAL,
    author_name   TEXT,
    author_url    TEXT
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

CREATE TABLE IF NOT EXISTS crowd (
    id          INTEGER PRIMARY KEY,
    slug        TEXT    NOT NULL,
    month       INTEGER NOT NULL,
    day         INTEGER NOT NULL,
    highest     INTEGER NOT NULL,
    requests    INTEGER NOT NULL,
    failures    INTEGER NOT NULL,
    checked_at  REAL    NOT NULL,
    UNIQUE (slug COLLATE NOCASE, month, day)
);

CREATE TABLE IF NOT EXISTS sweep_progress (
    id          INTEGER PRIMARY KEY,
    slug        TEXT    NOT NULL,
    month       INTEGER NOT NULL,
    day         INTEGER NOT NULL,
    next_n      INTEGER NOT NULL,
    done        INTEGER NOT NULL DEFAULT 0,
    requests    INTEGER NOT NULL DEFAULT 0,
    failures    INTEGER NOT NULL DEFAULT 0,
    updated_at  REAL    NOT NULL,
    UNIQUE (slug COLLATE NOCASE, month, day)
);

CREATE TABLE IF NOT EXISTS scores (
    snapshot_id   INTEGER PRIMARY KEY REFERENCES snapshots(id),
    page_id       INTEGER NOT NULL REFERENCES pages(id),
    score         INTEGER NOT NULL,
    flagged       INTEGER NOT NULL,
    body_sha256   TEXT,
    classified_at REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS scores_page ON scores (page_id);
CREATE INDEX IF NOT EXISTS scores_score ON scores (score);

CREATE TABLE IF NOT EXISTS hits (
    id          INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    rule        TEXT    NOT NULL,
    weight      INTEGER NOT NULL,
    evidence    TEXT    NOT NULL,
    matches     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS hits_snapshot ON hits (snapshot_id);

CREATE TABLE IF NOT EXISTS labels (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    page_id     INTEGER NOT NULL REFERENCES pages(id),
    category    TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    assigned    INTEGER NOT NULL,  -- 1 when score reached the threshold
    is_primary  INTEGER NOT NULL,  -- 1 on the label used in single-count tables
    PRIMARY KEY (snapshot_id, category)
);
CREATE INDEX IF NOT EXISTS labels_category ON labels (category, assigned);
"""


# ^ and $ anchors        : match the whole string, not a fragment inside it
# (.+?)                  : group 1, the slug: one or more of any character, non-greedy
# -(0[1-9]|1[0-2])       : hyphen then group 2, exactly two digits: 01-12 the month
# -(0[1-9]|[12]\d|3[01]) : hyphen then group 3, two digits: 01-31 the day
# (?:-(\d+))?	         : optional: a hyphen then group 4, one or more digits, the counter
PATTERN = re.compile(r"^(.+?)-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?:-(\d+))?$")


def connect(path: str | Path):
    """Function to connect to the sqlite3 db, loads SCHEMA and enables foreign keys

    Args:
        path (String): Path to the db file

    Returns:
        sqlite3 connection: Connection to the db
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def parse_path(path: str) -> tuple[str, int, int, int | None]:
    """Parses a Telegraph path into its 3-4 parts

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


def add_event(
    conn: Connection,
    page_id: int | None,
    kind: str,
    ts: float,
    detail: str | None = None,
) -> int:
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
    params_insert = (
        entry.title,
        normalize_slug(entry.slug),
        entry.source,
        int(entry.crowd_only),
        ts,
    )
    conn.execute(sql_insert, params_insert)
    sql_select = "SELECT id FROM titles WHERE slug = ?"
    params_select = (normalize_slug(entry.slug),)
    row = conn.execute(sql_select, params_select).fetchone()
    title_id = row["id"]
    conn.commit()
    return title_id


def upsert_page(conn: Connection, path: str, ts: float, held_out: bool = False) -> int:
    """Update and insert (upsert) a page in the db

    Args:
        conn (Connection): SQL db connection
        path (str): Page path
        ts (float): timestamp
        held_out (bool, optional): Bool to flag if the page is part of the eval set. Defaults to False.

    Returns:
        int: Page id
    """
    slug, month, day, counter = parse_path(path)
    page_select = "SELECT id FROM pages WHERE path = ?"
    page_params = (path,)
    existing = conn.execute(page_select, page_params).fetchone()
    title_select = "SELECT id FROM titles WHERE slug = ? COLLATE NOCASE"
    title_params = (normalize_slug(slug),)
    title_row = conn.execute(title_select, title_params).fetchone()
    title_id = title_row["id"] if title_row is not None else None
    upsert_sql = """
    INSERT INTO pages (path, slug, month, day, counter, title_id, held_out, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(path) DO UPDATE SET
    last_seen = excluded.last_seen,
    held_out  = MAX(held_out, excluded.held_out)
    """
    upsert_params = (
        path,
        normalize_slug(slug),
        month,
        day,
        counter,
        title_id,
        int(held_out),
        ts,
        ts,
    )
    cur = conn.execute(upsert_sql, upsert_params)
    if existing is not None:
        page_id = existing["id"]
    else:
        page_id = cur.lastrowid
        add_event(conn, page_id, "discovered", ts)
    conn.commit()

    return page_id


def add_snapshot(
    conn: Connection, page_id: int, page: dict, ts: float, key: bytes
) -> tuple[int, bool]:
    """Function to add page snapshots, hash them, and see if they updated

    Args:
        conn (Connection): SQL db connection
        page_id (int): Page id
        page (dict): Page content
        ts (float): Timestamp
        key (bytes): The hmac key for redactions

    Returns:
        tuple[int, bool]: Returns the lastrowid and a bool to say if the page hash changed
    """
    page = redact_page(page, key)
    title = page.get("title")
    description = page.get("description")
    views = page.get("views")
    content = page.get("content", [])
    fingerprint = {"title": title, "description": description, "content": content}
    author_name = page.get("author_name")
    author_url = page.get("author_url")
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
    page_update = "UPDATE pages SET author_name = ?, author_url = ? WHERE id = ?"
    page_update_params = (
        author_name,
        author_url,
        page_id,
    )
    conn.execute(page_update, page_update_params)
    conn.commit()
    return cur.lastrowid, changed


def store_fetch(
    conn: Connection,
    fetch: Fetch,
    ts: float,
    key: bytes,
    held_out: bool = False,
) -> int | None:
    """The glue between the client and the database for storing fetch results in the db

    Args:
        conn (Connection): SQL db connection
        fetch (Fetch): The fetch to store
        ts (float): Timestamp
        key (bytes): the hmac key for redaction
        held_out (bool, optional): If the fetch is part of the eval set. Defaults to False.


    Returns:
        int|None: Page id or none if no outcome
    """
    if fetch.outcome is not Outcome.FOUND:
        return None
    page_id = upsert_page(conn, fetch.page["path"], ts, held_out=held_out)
    add_snapshot(conn, page_id, fetch.page, ts, key)
    return page_id


def store_meta(conn: Connection, page_id: int, meta: dict, ts: float) -> bool:
    """The glue between the client and the database for storing http_meta results in the db

    Args:
        conn (Connection): SQL db connection
        page_id (int): The page id to store
        meta (dict): The meta dictionary
        ts (float): timestamp

    Returns:
        bool: Whether the modified_at changed
    """
    sql = " SELECT modified_at FROM pages WHERE id = ?"
    row = conn.execute(sql, (page_id,)).fetchone()
    previous = row["modified_at"]
    modified_at = meta["modified_at"]

    changed = previous is not None and previous != modified_at
    meta_update = "UPDATE pages SET published_at = COALESCE(published_at, ?), modified_at = ?, meta_seen_at = ? WHERE id = ?"
    meta_update_params = (
        meta["published_at"],
        modified_at,
        ts,
        page_id,
    )
    conn.execute(meta_update, meta_update_params)

    if changed:
        new_iso = datetime.fromtimestamp(modified_at, UTC).isoformat()
        old_iso = datetime.fromtimestamp(previous, UTC).isoformat()
        add_event(
            conn,
            page_id,
            "modified_at_changed",
            ts,
            detail=f"{old_iso} -> {new_iso}",
        )
    conn.commit()
    return changed


def http_logger(conn: Connection):
    """Function to get the logger

    Args:
        conn (Connection): SQL db connection

    Returns:
        function: log function
    """

    def log(row: dict):
        sql = "INSERT INTO http_log (ts, path, attempt, status, outcome, error, elapsed_ms, bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        params = (
            row["ts"],
            row["path"],
            row["attempt"],
            row["status"],
            row["outcome"],
            row["error"],
            row["elapsed_ms"],
            row["bytes"],
        )
        conn.execute(sql, params)
        conn.commit()

    return log


def load_known(conn: Connection, known_file: str, ts: float) -> list[int]:
    """Load and upsert the eval set in known.txt

    Args:
        conn (Connection): Sql db connection
        known_file (str): Path to known.txt file holding the eval set
        ts (float): Timestamp

    Returns:
        list[int]: List of page ids
    """
    ids = []
    for line in Path(known_file).read_text(encoding="utf-8").splitlines():
        path = line.strip()
        if not path or path.startswith("#"):
            continue
        page_id = upsert_page(conn, path, ts, held_out=True)
        ids.append(page_id)
    return ids


def held_out_paths(conn: Connection) -> list[str]:
    """Fetch list of held_out page paths

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[str]: List of paths
    """
    sql = "SELECT path FROM pages WHERE held_out = 1 ORDER BY id"
    rows = conn.execute(sql).fetchall()
    return [row["path"] for row in rows]

def stale_pages(conn: Connection, hours: float, now: float, limit: int) -> list[sqlite3.Row]:
    """Fetch list of stale pages not checked in the past $hours

    Args:
        conn (Connection): SQL db connection
        hours (float): past hours to consider something stale
        now (float): current time
        limit (int): query limit
    Returns:
        list[sqlite3.Row]: List of paths
    """
    cutoff = now - hours * 3600
    sql = """
    SELECT id, path FROM pages
    WHERE meta_seen_at IS NULL OR meta_seen_at < ?
    ORDER BY meta_seen_at IS NOT NULL, meta_seen_at, id
    LIMIT ?
    """
    return conn.execute(sql, (cutoff, limit)).fetchall()


def load_progress(
    conn: Connection, slug: str, month: int, day: int
) -> tuple[int, bool]:
    """Check sweep progress, return 1, false if a given day hasn't been swept

    Args:
        conn (Connection): SQL db connection
        slug (str): Slug to check progress of
        month (int): Month to check progress of
        day (int): Day to check progress of

    Returns:
        tuple[int, bool]: Next counter to start at and if sweep is done
    """
    sql = """
    SELECT next_n, done FROM sweep_progress
    WHERE slug = ? COLLATE NOCASE AND month = ? AND day = ?
    """
    params = (
        normalize_slug(slug),
        month,
        day,
    )
    row = conn.execute(sql, params).fetchone()
    if row:
        return (row["next_n"], bool(row["done"]))
    else:
        return (1, False)


def save_progress(
    conn: Connection,
    slug: str,
    month: int,
    day: int,
    next_n: int,
    done: bool,
    requests: int,
    failures: int,
    ts: float,
) -> None:
    """Function to save sweep progress to the db

    Args:
        conn (Connection): SQL db connection
        slug (str): Slug to save progress of
        month (int): Month to save progress of
        day (int): Day to save progress of
        next_n (int): The next counter to sweep
        done (bool): If the sweep is done
        requests (int): The running number of requests
        failures (int): The running number of failures
        ts (float): Timestamp
    """
    sql = """
        INSERT INTO sweep_progress (slug, month, day, next_n, done, requests, failures, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug, month, day) DO UPDATE SET
        next_n     = excluded.next_n,
        done       = excluded.done,
        requests   = excluded.requests,
        failures   = excluded.failures,
        updated_at = excluded.updated_at
        """
    params = (
        normalize_slug(slug),
        month,
        day,
        next_n,
        int(done),
        requests,
        failures,
        ts,
    )
    conn.execute(sql, params)
    conn.commit()


def latest_snapshots(
    conn: Connection,
    after_page_id: int = 0,
    limit: int | None = None,
    content: bool = True,
) -> sqlite3.Cursor:
    """Function to read the newest snapshot of every page, for the classifier

    The classifier asks for a batch of pages at a time, reads the batch whole
    and only then writes its scores. A cursor left open over the whole table
    would hold a read lock for the length of the run, and SQLite does not let
    a connection that is reading wait its turn to write.

    Args:
        conn (Connection): SQL db connection
        after_page_id (int, optional): only pages with a larger id, so the
            next batch starts where the last one ended. Defaults to 0.
        limit (int | None, optional): how many pages. Defaults to None, all.
        content (bool, optional): False leaves the stored nodes out of the
            row (content is NULL), for a pass that only reads the text.
            Defaults to True.

    Returns:
        sqlite3.Cursor: one row per page, in page id order, with snapshot_id,
            page_id, path, held_out, title, description, text and content
    """
    sql = f"""
    SELECT s.id AS snapshot_id, p.id AS page_id, p.path, p.held_out,
           s.title, s.description, s.text,
           {"s.content" if content else "NULL"} AS content
    FROM pages p
    JOIN snapshots s ON s.id = (
        SELECT id FROM snapshots WHERE page_id = p.id
        ORDER BY fetched_at DESC, id DESC LIMIT 1
    )
    WHERE p.id > ?
    ORDER BY p.id
    """
    params: list = [after_page_id]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params)


def superseded_flagged_snapshots(conn: Connection) -> list[sqlite3.Row]:
    """Function to read the older snapshots that hold a flagged score

    latest_snapshots gives the classifier each page's newest snapshot. An
    older snapshot keeps whatever score it got on the night it was the
    newest, under that night's rules. "Has this page ever been flagged" is
    read from those rows, by the re-poll and by enrichment, so the ones that
    say yes have to be scored again under today's rules. An older snapshot
    with no score, or with a score that is not flagged, cannot make a page
    flagged and is left alone; that is most of them once a page is polled
    every ten minutes.

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[sqlite3.Row]: rows of snapshot_id, page_id, title, description,
            text and content, for snapshots that are not their page's newest
    """
    sql = """
    SELECT s.id AS snapshot_id, s.page_id, s.title, s.description, s.text, s.content
    FROM snapshots s
    JOIN scores sc ON sc.snapshot_id = s.id AND sc.flagged = 1
    WHERE s.id != (
        SELECT id FROM snapshots WHERE page_id = s.page_id
        ORDER BY fetched_at DESC, id DESC LIMIT 1
      )
    ORDER BY s.id
    """
    return conn.execute(sql).fetchall()


def save_score(
    conn: Connection,
    snapshot_id: int,
    page_id: int,
    score: int,
    flagged: bool,
    body_sha256: str | None,
    hits: list[tuple[str, int, str, int]],
    ts: float,
) -> None:
    """Function to store one snapshot's score and the rule hits behind it

    A second call for the same snapshot replaces the first, so the classifier
    can be rerun after a rule changes. Does not commit: the caller commits in
    batches.

    Args:
        conn (Connection): SQL db connection
        snapshot_id (int): The snapshot that was scored
        page_id (int): The page the snapshot belongs to
        score (int): Sum of the weights of the rules that fired
        flagged (bool): True if the score reached the threshold
        body_sha256 (str | None): Hash of the body text, None for short bodies
        hits (list[tuple[str, int, str, int]]): one (rule name, weight,
            evidence, matches) per rule that fired; matches is how many times
            the rule matched on the page
        ts (float): Timestamp of the classifier run
    """
    conn.execute("DELETE FROM hits WHERE snapshot_id = ?", (snapshot_id,))
    conn.execute("DELETE FROM scores WHERE snapshot_id = ?", (snapshot_id,))
    score_insert = """
    INSERT INTO scores (snapshot_id, page_id, score, flagged, body_sha256, classified_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """
    score_params = (snapshot_id, page_id, score, int(flagged), body_sha256, ts)
    conn.execute(score_insert, score_params)
    hit_insert = """
    INSERT INTO hits (snapshot_id, rule, weight, evidence, matches)
    VALUES (?, ?, ?, ?, ?)
    """
    hit_params = [(snapshot_id, *hit) for hit in hits]
    conn.executemany(hit_insert, hit_params)


def save_labels(
    conn: Connection,
    snapshot_id: int,
    page_id: int,
    labels: list[tuple[str, int, bool, bool]],
) -> None:
    """Function to store one snapshot's score in each category

    A second call for the same snapshot replaces the first, like save_score.
    Does not commit: the caller commits in batches.

    Args:
        conn (Connection): SQL db connection
        snapshot_id (int): The snapshot that was scored
        page_id (int): The page the snapshot belongs to
        labels (list[tuple[str, int, bool, bool]]): one (category, score,
            assigned, is_primary) per category to store. The caller leaves
            out the categories that scored 0, so a near miss is a row with
            assigned = 0.
    """
    conn.execute("DELETE FROM labels WHERE snapshot_id = ?", (snapshot_id,))
    label_insert = """
    INSERT INTO labels (snapshot_id, page_id, category, score, assigned, is_primary)
    VALUES (?, ?, ?, ?, ?, ?)
    """
    label_params = [
        (snapshot_id, page_id, category, score, int(assigned), int(is_primary))
        for category, score, assigned, is_primary in labels
    ]
    conn.executemany(label_insert, label_params)


def label_rows(conn: Connection, snapshot_id: int) -> list[sqlite3.Row]:
    """Function to load the category scores stored for one snapshot

    Args:
        conn (Connection): SQL db connection
        snapshot_id (int): The snapshot to look up

    Returns:
        list[sqlite3.Row]: rows of category, score, assigned and is_primary
            in the order they were stored
    """
    label_select = """
    SELECT category, score, assigned, is_primary FROM labels
    WHERE snapshot_id = ? ORDER BY rowid
    """
    return conn.execute(label_select, (snapshot_id,)).fetchall()


def explain_rows(
    conn: Connection, path: str
) -> tuple[sqlite3.Row | None, list[sqlite3.Row]]:
    """Function to load the newest score for one page and the hits behind it

    Args:
        conn (Connection): SQL db connection
        path (str): The page path as Telegraph spells it, e.g. Hello-10-17-154

    Returns:
        tuple[sqlite3.Row | None, list[sqlite3.Row]]: The score row (snapshot_id,
            path, held_out, title, text, score, flagged) and its hits (rule, weight,
            evidence, matches) in the order they were stored. (None, []) if the
            page is unknown or has not been classified.
    """
    score_select = """
    SELECT sc.snapshot_id, p.path, p.held_out, s.title, s.text, sc.score, sc.flagged
    FROM pages p
    JOIN scores sc ON sc.page_id = p.id
    JOIN snapshots s ON s.id = sc.snapshot_id
    WHERE p.path = ?
    ORDER BY s.fetched_at DESC, s.id DESC LIMIT 1
    """
    row = conn.execute(score_select, (path,)).fetchone()
    if row is None:
        return None, []
    hit_select = """
    SELECT rule, weight, evidence, matches FROM hits
    WHERE snapshot_id = ? ORDER BY id
    """
    hits = conn.execute(hit_select, (row["snapshot_id"],)).fetchall()
    return row, hits
