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

CREATE TABLE IF NOT EXISTS views (
    page_id     INTEGER NOT NULL REFERENCES pages(id),
    fetched_at  REAL    NOT NULL,
    views       INTEGER,
    PRIMARY KEY (page_id, fetched_at)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS indicators (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    source      TEXT    NOT NULL,  -- 'pages' or the name of the file it came from
    first_seen  REAL,              -- fetch time of the first snapshot that held it
    last_seen   REAL,
    pages       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS feed_lookups (
    indicator_id INTEGER NOT NULL REFERENCES indicators(id),
    feed         TEXT    NOT NULL,
    verdict      TEXT    NOT NULL,  -- KNOWN or UNKNOWN; a FAILED lookup is not stored
    detail       TEXT,
    checked_at   REAL    NOT NULL,
    PRIMARY KEY (indicator_id, feed)
);

CREATE TABLE IF NOT EXISTS indicator_titles (
    -- the titles of the flagged pages that hold an indicator: hello for the
    -- actor's Hello pages, and whatever else the classifier flagged
    indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    slug         TEXT    NOT NULL,
    pages        INTEGER NOT NULL,  -- how many pages of that title hold it
    PRIMARY KEY (indicator_id, slug)
);

CREATE TABLE IF NOT EXISTS first_lookups (
    -- ON DELETE CASCADE: code from before this table existed deletes an
    -- indicator without knowing of it, and must still be able to
    indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    feed         TEXT    NOT NULL,
    verdict      TEXT    NOT NULL,  -- what the feed said the first time it answered
    detail       TEXT,
    checked_at   REAL    NOT NULL,
    PRIMARY KEY (indicator_id, feed)
);
"""


# ^ and $ anchors        : match the whole string, not a fragment inside it
# (.+?)                  : group 1, the slug: one or more of any character, non-greedy
# -(0[1-9]|1[0-2])       : hyphen then group 2, exactly two digits: 01-12 the month
# -(0[1-9]|[12]\d|3[01]) : hyphen then group 3, two digits: 01-31 the day
# (?:-(\d+))?	         : optional: a hyphen then group 4, one or more digits, the counter
PATTERN = re.compile(r"^(.+?)-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?:-(\d+))?$")

# How long a write waits for another process to finish its own, in seconds.
# The nightly job and the ten-minute re-poll share one database file and
# SQLite lets one of them write at a time; sqlite3's own default is 5.
BUSY_TIMEOUT_S = 60


def connect(path: str | Path):
    """Function to connect to the sqlite3 db, loads SCHEMA and enables foreign keys

    Args:
        path (String): Path to the db file

    Returns:
        sqlite3 connection: Connection to the db
    """
    conn = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_S)
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
        # A page the re-sweep marked gone has been fetched again
        if is_gone(conn, page_id):
            add_event(conn, page_id, "returned", ts)
    else:
        page_id = cur.lastrowid
        add_event(conn, page_id, "discovered", ts)
    conn.commit()

    return page_id


def fingerprint(title: str | None, description: str | None, content: list) -> str:
    """Function to hash the parts of a page that make it one version or another

    Views are left out, so a page nobody edited keeps its fingerprint however
    often it is read. The page has to be redacted first: the fingerprint is
    of what is stored.

    Args:
        title (str | None): The redacted page title
        description (str | None): The redacted page description
        content (list): The redacted page content nodes

    Returns:
        str: sha256 hex digest of the three fields as canonical JSON
    """
    fields = {"title": title, "description": description, "content": content}
    canonical = json.dumps(
        fields, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    author_name = page.get("author_name")
    author_url = page.get("author_url")
    sha = fingerprint(title, description, content)
    hash_select = "SELECT sha256 FROM snapshots WHERE page_id = ? ORDER BY fetched_at DESC, id DESC LIMIT 1"
    hash_params = (page_id,)
    previous = conn.execute(hash_select, hash_params).fetchone()
    changed = previous is not None and previous["sha256"] != sha
    if changed:
        # Not add_event, which commits on its own: the event and the snapshot
        # it is about are written in one transaction, so a run that dies in
        # between leaves neither and the next fetch records the change once
        event_insert = "INSERT INTO events (page_id, kind, ts, detail) VALUES (?, ?, ?, ?)"
        conn.execute(event_insert, (page_id, "content_changed", ts, None))
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


def refresh_snapshot(
    conn: Connection, page_id: int, page: dict, ts: float, key: bytes
) -> bool:
    """Function to record that a stored page was fetched again

    The page's last_seen moves to now. If the page reads the same as its
    newest snapshot, no snapshot is added: the view count goes into the views
    table, which is all that is new about it. If it reads differently, the
    new version is stored as a snapshot and add_snapshot writes the
    content_changed event. A page that is fetched every ten minutes would
    otherwise add 144 identical rows a day.

    The page is found by its id, not by the path Telegraph answers with,
    which can be spelled in another case than the path that was asked for.

    Args:
        conn (Connection): SQL db connection
        page_id (int): The stored page that was fetched again
        page (dict): Page content as Telegraph returned it
        ts (float): Timestamp of the fetch
        key (bytes): The hmac key for redactions

    Returns:
        bool: True if the content changed and a snapshot was stored
    """
    redacted = redact_page(page, key)
    sha = fingerprint(
        redacted.get("title"), redacted.get("description"), redacted.get("content", [])
    )
    hash_select = "SELECT sha256 FROM snapshots WHERE page_id = ? ORDER BY fetched_at DESC, id DESC LIMIT 1"
    previous = conn.execute(hash_select, (page_id,)).fetchone()
    conn.execute("UPDATE pages SET last_seen = ? WHERE id = ?", (ts, page_id))
    if previous is not None and previous["sha256"] == sha:
        views_insert = "INSERT OR REPLACE INTO views (page_id, fetched_at, views) VALUES (?, ?, ?)"
        conn.execute(views_insert, (page_id, ts, page.get("views")))
        # The author fields are not part of the fingerprint, so they are
        # refreshed here the way add_snapshot refreshes them
        author_update = "UPDATE pages SET author_name = ?, author_url = ? WHERE id = ?"
        conn.execute(author_update, (page.get("author_name"), page.get("author_url"), page_id))
        conn.commit()
        return False
    _snapshot_id, changed = add_snapshot(conn, page_id, page, ts, key)
    return changed


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


# A page is gone while the newest of its gone and returned events is a gone
NOT_GONE = """
    COALESCE((
        SELECT e.kind FROM events e
        WHERE e.page_id = p.id AND e.kind IN ('gone', 'returned')
        ORDER BY e.ts DESC, e.id DESC LIMIT 1
    ), 'returned') != 'gone'
"""


def is_gone(conn: Connection, page_id: int) -> bool:
    """Check if the re-sweep found a page deleted and it has not come back since

    Args:
        conn (Connection): SQL db connection
        page_id (int): The page to check

    Returns:
        bool: True if the page's newest gone or returned event is a gone
    """
    sql = """
    SELECT kind FROM events
    WHERE page_id = ? AND kind IN ('gone', 'returned')
    ORDER BY ts DESC, id DESC LIMIT 1
    """
    row = conn.execute(sql, (page_id,)).fetchone()
    return row is not None and row["kind"] == "gone"


def mark_gone(conn: Connection, page_id: int, ts: float) -> None:
    """Record that a stored page now answers PAGE_NOT_FOUND

    The page row and its snapshots stay, and last_seen is not touched: it is
    the last time the page was really there. The gone event is what keeps
    the page out of the next re-sweep.

    Args:
        conn (Connection): SQL db connection
        page_id (int): The page that is gone
        ts (float): Timestamp of the fetch that found it gone
    """
    add_event(conn, page_id, "gone", ts)


def _resweep_where(
    cutoff: float,
    days: list[tuple[int, int]] | None,
    flagged: bool,
    match: str | None,
) -> tuple[str, list]:
    """Build the WHERE clause the re-sweep work list and its cost share

    Returns:
        tuple[str, list]: the SQL after WHERE and its parameters
    """
    clauses = ["p.last_seen < ?", NOT_GONE]
    params: list = [cutoff]
    if days is not None and not days:
        # A window of no days holds no page
        clauses.append("0")
    elif days is not None:
        marks = ", ".join("(?, ?)" for _ in days)
        clauses.append(f"(p.month, p.day) IN (VALUES {marks})")
        for month, day in days:
            params.extend((month, day))
    if flagged:
        # Any snapshot ever flagged: the actor edits pages in place, so a
        # page that stopped looking like a resolver is still one to watch
        clauses.append(
            "EXISTS (SELECT 1 FROM scores sc WHERE sc.page_id = p.id AND sc.flagged = 1)"
        )
    if match is not None:
        clauses.append(
            """instr((
                SELECT s.text FROM snapshots s WHERE s.page_id = p.id
                ORDER BY s.fetched_at DESC, s.id DESC LIMIT 1
            ), ?) > 0"""
        )
        params.append(match)
    return " AND ".join(clauses), params


def resweep_paths(
    conn: Connection,
    cutoff: float,
    days: list[tuple[int, int]] | None = None,
    flagged: bool = False,
    match: str | None = None,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    """Fetch the stored pages that a re-sweep should fetch again, oldest first

    last_seen is the progress marker: store_fetch moves it forward, so a page
    drops out of this list the moment it is fetched and a run stopped by the
    budget is picked up by the next one with nothing to reset.

    Args:
        conn (Connection): SQL db connection
        cutoff (float): only pages last seen before this timestamp
        days (list[tuple[int, int]] | None, optional): (month, day) pairs to
            keep to, or None for every day. Defaults to None.
        flagged (bool, optional): only pages the classifier has ever flagged.
            Defaults to False.
        match (str | None, optional): only pages whose newest snapshot text
            contains this string. Defaults to None.
        limit (int | None, optional): query limit. Defaults to None.

    Returns:
        list[sqlite3.Row]: rows of id and path
    """
    where, params = _resweep_where(cutoff, days, flagged, match)
    sql = f"""
    SELECT p.id, p.path FROM pages p
    WHERE {where}
    ORDER BY p.last_seen, p.slug, p.month, p.day, p.counter
    """
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return conn.execute(sql, params).fetchall()


def resweep_cost(
    conn: Connection,
    cutoff: float,
    days: list[tuple[int, int]] | None = None,
    flagged: bool = False,
    match: str | None = None,
) -> int:
    """Count the requests a re-sweep needs: one per page in its work list

    Args:
        conn (Connection): SQL db connection
        cutoff (float): only pages last seen before this timestamp
        days (list[tuple[int, int]] | None, optional): (month, day) pairs to
            keep to, or None for every day. Defaults to None.
        flagged (bool, optional): only pages the classifier has ever flagged.
            Defaults to False.
        match (str | None, optional): only pages whose newest snapshot text
            contains this string. Defaults to None.

    Returns:
        int: the length of the list resweep_paths would return with no limit
    """
    where, params = _resweep_where(cutoff, days, flagged, match)
    sql = f"SELECT COUNT(*) FROM pages p WHERE {where}"
    return conn.execute(sql, params).fetchone()[0]


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


def upsert_indicator(
    conn: Connection,
    kind: str,
    value: str,
    source: str,
    first_seen: float | None = None,
    last_seen: float | None = None,
    pages: int = 0,
    titles: dict[str, int] | None = None,
) -> int:
    """Update and insert (upsert) an indicator in the db

    A second call for the same kind and value keeps the row and its id, so
    the lookups stored against it stay. A call with source 'pages' sets
    first_seen, last_seen, pages and the titles to what the flagged pages
    say in this run. A call from a file changes nothing on a row that
    exists, so an indicator found on pages keeps the source 'pages', its
    times and its titles.

    Args:
        conn (Connection): SQL db connection
        kind (str): ip, host or url
        value (str): the indicator itself
        source (str): 'pages', or the name of the file it came from
        first_seen (float | None, optional): fetch time of the first snapshot
            that held it. Defaults to None.
        last_seen (float | None, optional): fetch time of the last snapshot
            that held it. Defaults to None.
        pages (int, optional): how many pages held it. Defaults to 0.
        titles (dict[str, int] | None, optional): for source 'pages', the
            slug of each title whose flagged pages hold it and how many of
            them do. Defaults to None, for none.

    Returns:
        int: indicator id
    """

    def set_titles(indicator_id: int) -> None:
        # What the flagged pages say now replaces what they said last run
        conn.execute("DELETE FROM indicator_titles WHERE indicator_id = ?", (indicator_id,))
        conn.executemany(
            "INSERT INTO indicator_titles (indicator_id, slug, pages) VALUES (?, ?, ?)",
            [(indicator_id, slug, count) for slug, count in (titles or {}).items()],
        )

    select = "SELECT * FROM indicators WHERE kind = ? AND value = ?"
    existing = conn.execute(select, (kind, value)).fetchone()
    if existing is None:
        insert = """
        INSERT INTO indicators (kind, value, source, first_seen, last_seen, pages)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        cur = conn.execute(insert, (kind, value, source, first_seen, last_seen, pages))
        if source == "pages":
            set_titles(cur.lastrowid)
        conn.commit()
        return cur.lastrowid
    if source != "pages":
        # A file names an indicator and says nothing about where it was seen
        return existing["id"]
    # What the flagged pages say now replaces what they said last run: after
    # a rule fix fewer pages may hold the indicator, and later ones
    update = """
    UPDATE indicators SET source = ?, first_seen = ?, last_seen = ?, pages = ?
    WHERE id = ?
    """
    conn.execute(update, ("pages", first_seen, last_seen, pages, existing["id"]))
    set_titles(existing["id"])
    conn.commit()
    return existing["id"]


def release_indicator_to_file(conn: Connection, kind: str, value: str, source: str) -> None:
    """Give an indicator back to the file that names it

    An indicator that a file names and that a flagged page also held has the
    source 'pages'. When no flagged page holds it any more the file still
    names it, so it becomes the file's again: no times, no pages and no
    titles, and delete_stale_indicators leaves it alone.

    Args:
        conn (Connection): SQL db connection
        kind (str): ip, host or url
        value (str): the indicator itself
        source (str): the name of the file that names it
    """
    held = """
    DELETE FROM indicator_titles WHERE indicator_id IN (
        SELECT id FROM indicators WHERE kind = ? AND value = ? AND source = 'pages'
    )
    """
    sql = """
    UPDATE indicators SET source = ?, first_seen = NULL, last_seen = NULL, pages = 0
    WHERE kind = ? AND value = ? AND source = 'pages'
    """
    conn.execute(held, (kind, value))
    conn.execute(sql, (source, kind, value))
    conn.commit()


def delete_stale_indicators(conn: Connection, current: set[tuple[str, str]]) -> int:
    """Function to drop the indicators that no flagged page holds any more

    An indicator found on pages stays in the table only while a flagged page
    still gives it. After a rule fix, or a fix to the extractor, the pages
    that gave it may no longer be flagged, and the novelty table must not
    keep counting it. Indicators that came from a file are the author's own
    list and are left alone.

    Args:
        conn (Connection): SQL db connection
        current (set[tuple[str, str]]): the (kind, value) pairs found on
            flagged pages, or named in a file, in this run

    Returns:
        int: how many indicators were deleted, with their stored lookups
    """
    # A title belongs to an indicator that pages hold. Code from before the
    # titles were kept gives an indicator back to its file and leaves them
    conn.execute(
        "DELETE FROM indicator_titles WHERE indicator_id IN "
        "(SELECT id FROM indicators WHERE source != 'pages')"
    )
    rows = conn.execute("SELECT id, kind, value FROM indicators WHERE source = 'pages'").fetchall()
    stale = [row["id"] for row in rows if (row["kind"], row["value"]) not in current]
    for indicator_id in stale:
        conn.execute("DELETE FROM feed_lookups WHERE indicator_id = ?", (indicator_id,))
        conn.execute("DELETE FROM first_lookups WHERE indicator_id = ?", (indicator_id,))
        conn.execute("DELETE FROM indicator_titles WHERE indicator_id = ?", (indicator_id,))
        conn.execute("DELETE FROM indicators WHERE id = ?", (indicator_id,))
    conn.commit()
    return len(stale)


def save_lookup(
    conn: Connection,
    indicator_id: int,
    feed: str,
    verdict: str,
    detail: str | None,
    ts: float,
) -> None:
    """Function to store what one feed said about one indicator

    A second call for the same indicator and feed replaces the first in
    feed_lookups, which is what --refresh and the recheck are for. The first
    answer stays in first_lookups: what a feed knew when the indicator was
    found is what Novelty measures, and a later answer must not write over it.

    Args:
        conn (Connection): SQL db connection
        indicator_id (int): The indicator that was looked up
        feed (str): The feed that answered
        verdict (str): KNOWN or UNKNOWN
        detail (str | None): what the feed holds, in a few words
        ts (float): Timestamp of the lookup
    """
    sql = """
    INSERT INTO feed_lookups (indicator_id, feed, verdict, detail, checked_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(indicator_id, feed) DO UPDATE SET
    verdict    = excluded.verdict,
    detail     = excluded.detail,
    checked_at = excluded.checked_at
    """
    # An answer stored before first_lookups existed is the first answer
    keep_stored = """
    INSERT OR IGNORE INTO first_lookups (indicator_id, feed, verdict, detail, checked_at)
    SELECT indicator_id, feed, verdict, detail, checked_at FROM feed_lookups
    WHERE indicator_id = ? AND feed = ?
    """
    keep_this = """
    INSERT OR IGNORE INTO first_lookups (indicator_id, feed, verdict, detail, checked_at)
    VALUES (?, ?, ?, ?, ?)
    """
    conn.execute(keep_stored, (indicator_id, feed))
    conn.execute(keep_this, (indicator_id, feed, verdict, detail, ts))
    conn.execute(sql, (indicator_id, feed, verdict, detail, ts))
    conn.commit()


def cached_feeds(
    conn: Connection, indicator_id: int, recheck_s: float | None = None, now: float | None = None
) -> set[str]:
    """Fetch the feeds whose stored answer for an indicator does not have to be asked for again

    With recheck_s, an UNKNOWN is left out once, so that it is asked for
    again: when the feed's first answer is at least that old and the stored
    one was given before it reached that age. A feed that did not know an
    indicator on the day it was found may list it a week or two later.

    Args:
        conn (Connection): SQL db connection
        indicator_id (int): The indicator to look up
        recheck_s (float | None, optional): the age in seconds at which an
            UNKNOWN is asked for once more, or None for never. Defaults to None.
        now (float | None, optional): the time to measure that age from;
            needed with recheck_s. Defaults to None.

    Returns:
        set[str]: feed names with a stored verdict that stands
    """
    sql = """
    SELECT l.feed, l.verdict, l.checked_at, COALESCE(f.checked_at, l.checked_at) AS first_at
    FROM feed_lookups l
    LEFT JOIN first_lookups f ON f.indicator_id = l.indicator_id AND f.feed = l.feed
    WHERE l.indicator_id = ?
    """
    cached = set()
    for row in conn.execute(sql, (indicator_id,)).fetchall():
        if recheck_s is not None and row["verdict"] == "UNKNOWN":
            old_enough = now - row["first_at"] >= recheck_s
            asked_since = row["checked_at"] - row["first_at"] >= recheck_s
            if old_enough and not asked_since:
                continue
        cached.add(row["feed"])
    return cached


def indicator_rows(conn: Connection) -> list[sqlite3.Row]:
    """Fetch every stored indicator, in the order the novelty table lists them

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[sqlite3.Row]: indicator rows, by kind and then by first_seen,
            with the ones that have no first_seen last
    """
    sql = """
    SELECT id, kind, value, source, first_seen, last_seen, pages FROM indicators
    ORDER BY kind, first_seen IS NULL, first_seen, value
    """
    return conn.execute(sql).fetchall()


def lookup_rows(conn: Connection, indicator_id: int) -> list[sqlite3.Row]:
    """Fetch the stored verdicts for one indicator

    Args:
        conn (Connection): SQL db connection
        indicator_id (int): The indicator to look up

    Returns:
        list[sqlite3.Row]: rows of feed, verdict, detail and checked_at, and
            first_verdict and first_checked_at: what the feed said the first
            time, which is the same answer until the indicator is asked
            about again
    """
    sql = """
    SELECT l.feed, l.verdict, l.detail, l.checked_at,
           COALESCE(f.verdict, l.verdict) AS first_verdict,
           COALESCE(f.checked_at, l.checked_at) AS first_checked_at
    FROM feed_lookups l
    LEFT JOIN first_lookups f ON f.indicator_id = l.indicator_id AND f.feed = l.feed
    WHERE l.indicator_id = ? ORDER BY l.feed
    """
    return conn.execute(sql, (indicator_id,)).fetchall()


def flagged_pages(conn: Connection) -> list[sqlite3.Row]:
    """Function to list the pages the classifier has flagged, with their titles

    A page counts if any of its snapshots holds a flagged score. Held-out
    pages are left out. The read starts from the scores, which is a short
    scan, and not from the snapshots: the re-poll adds thousands of those a
    day to the flagged pages.

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[sqlite3.Row]: rows of id and slug, the title the page was found
            under, lowest id first
    """
    sql = """
    SELECT id, slug FROM pages
    WHERE held_out = 0 AND id IN (SELECT page_id FROM scores WHERE flagged = 1)
    ORDER BY id
    """
    return conn.execute(sql).fetchall()


def flagged_page_ids(conn: Connection) -> list[int]:
    """Function to list the ids of the pages the classifier has flagged

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[int]: page ids from flagged_pages, lowest first
    """
    return [row["id"] for row in flagged_pages(conn)]


def title_rows(conn: Connection, indicator_id: int) -> list[sqlite3.Row]:
    """Fetch the titles whose flagged pages hold one indicator

    Args:
        conn (Connection): SQL db connection
        indicator_id (int): The indicator to look up

    Returns:
        list[sqlite3.Row]: rows of slug and pages, the title on most pages first
    """
    sql = """
    SELECT slug, pages FROM indicator_titles
    WHERE indicator_id = ? ORDER BY pages DESC, slug
    """
    return conn.execute(sql, (indicator_id,)).fetchall()


def page_snapshots(conn: Connection, page_id: int) -> list[sqlite3.Row]:
    """Function to read every snapshot of one page

    Every snapshot, not only the newest: the actor edits pages in place, so
    the address a page held last week is in an older snapshot. The rows are
    read whole before they are handed out. A cursor left open while the
    caller works would hold a read lock, and on this database an open read
    makes every other writer's commit wait.

    Args:
        conn (Connection): SQL db connection
        page_id (int): The page to read

    Returns:
        list[sqlite3.Row]: rows of id, page_id, fetched_at, title and text,
            oldest first
    """
    sql = """
    SELECT id, page_id, fetched_at, title, text FROM snapshots
    WHERE page_id = ? ORDER BY fetched_at, id
    """
    return conn.execute(sql, (page_id,)).fetchall()
