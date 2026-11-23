"""One-day probe: how often do the actor's pages change? (for #37)

Polls a fixed set of known resolver pages through the JSON API on a fixed
interval and stores every poll in a scratch database, never the main one.
It uses the package's own client and ingest, so the allowlist, the pacing,
the request log, redaction and the fingerprint are the ones the sweep uses:

  snapshots  one row per poll, with views and the sha256 of the redacted page
  events     a content_changed row whenever the sha256 differs from the poll before
  http_log   one row per request attempt, so a NOT_FOUND or FAILED poll is on record
  probe_pages  what each polled page is: shape, year, where the year came from

Run from the repo root on the VPS:

  .venv/bin/python /tmp/graphwatch-probe/repoll_probe.py data/repoll-probe.sqlite
  .venv/bin/python /tmp/graphwatch-probe/repoll_probe.py data/repoll-probe.sqlite --report

It takes no lock: it writes only to its own database, and sixteen requests
every ten minutes do not get in the nightly job's way.
"""

import argparse
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

from graphwatch.config import CONFIG, hmac_key, load_config
from graphwatch.db import connect, http_logger, store_fetch
from graphwatch.telegraph import BudgetExceeded, Outcome, TelegraphClient

# Four pages from each of four days: the pointer and the spoof page of each year.
# ptr17 and ptr20 are the pointer pages by their score (+17 has no decodable
# host, +20 has one). The year is the HTML published_time where meta has been
# fetched ("meta"); for 15 November it is taken from the counter order, lower
# pair first, which held on all 31 days that have metadata ("counter").
PAGES = (
    ("Hello-10-03-141", "ptr17", 2025, "meta"),
    ("Hello-10-03-142", "spoof", 2025, "meta"),
    ("Hello-10-03-151", "spoof", 2026, "meta"),
    ("Hello-10-03-153", "ptr20", 2026, "meta"),
    ("Hello-10-19-130", "ptr17", 2025, "meta"),
    ("Hello-10-19-131", "spoof", 2025, "meta"),
    ("Hello-10-19-141", "spoof", 2026, "meta"),
    ("Hello-10-19-143", "ptr20", 2026, "meta"),
    ("Hello-11-04-125", "ptr17", 2025, "meta"),
    ("Hello-11-04-126", "spoof", 2025, "meta"),
    ("Hello-11-04-137", "spoof", 2026, "meta"),
    ("Hello-11-04-138", "ptr20", 2026, "meta"),
    ("Hello-11-15-128", "spoof", 2025, "counter"),
    ("Hello-11-15-129", "ptr17", 2025, "counter"),
    ("Hello-11-15-132", "spoof", 2026, "counter"),
    ("Hello-11-15-133", "ptr20", 2026, "counter"),
)

PROBE_SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_pages (
    path        TEXT PRIMARY KEY,
    shape       TEXT NOT NULL,
    year        INTEGER NOT NULL,
    year_source TEXT NOT NULL
);
"""


def stamp(ts: float) -> str:
    """A UTC timestamp for a log line"""
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S")


def poll_round(conn, client, key: bytes, paths, now=time.time) -> dict:
    """Function to fetch every page once and store what came back

    Args:
        conn: connection to the scratch database
        client (TelegraphClient): the client to fetch with
        key (bytes): the hmac key for redaction
        paths: the page paths to poll
        now (optional): wall clock. Defaults to time.time.

    Returns:
        dict: counts for found, not_found, failed and changed, and the paths
            that changed in this round
    """
    counts = {"found": 0, "not_found": 0, "failed": 0, "changed": 0, "changed_paths": []}
    for path in paths:
        fetch = client.get_page(path)
        if fetch.outcome is Outcome.FOUND:
            ts = now()
            page_id = store_fetch(conn, fetch, ts, key)
            counts["found"] += 1
            # store_fetch writes the event with the snapshot's own timestamp.
            hit = conn.execute(
                "SELECT 1 FROM events WHERE page_id = ? AND kind = 'content_changed' AND ts = ?",
                (page_id, ts),
            ).fetchone()
            if hit is not None:
                counts["changed"] += 1
                counts["changed_paths"].append(path)
        elif fetch.outcome is Outcome.NOT_FOUND:
            counts["not_found"] += 1
        else:
            counts["failed"] += 1
    return counts


def run(
    conn,
    client,
    key: bytes,
    paths,
    interval_s: float,
    hours: float,
    now=time.time,
    sleep=time.sleep,
    log=print,
) -> int:
    """Function to poll on the interval until the time is up

    Rounds start on whole multiples of the interval (:00, :10, ... for 600 s),
    so the poll times are the same whenever the script was started. A round
    that fails for any reason is logged and the next one still runs.

    Args:
        conn: connection to the scratch database
        client (TelegraphClient): the client to fetch with
        key (bytes): the hmac key for redaction
        paths: the page paths to poll
        interval_s (float): seconds between rounds
        hours (float): how long to keep polling; 0 means one round and stop
        now (optional): wall clock. Defaults to time.time.
        sleep (optional): Defaults to time.sleep.
        log (optional): Logging function. Defaults to print.

    Returns:
        int: the number of rounds run
    """
    end = now() + hours * 3600
    rounds = 0
    while True:
        started = now()
        try:
            counts = poll_round(conn, client, key, paths, now)
            changed = " ".join(counts["changed_paths"])
            log(
                f"{stamp(started)} round {rounds + 1}: found {counts['found']}, "
                f"not found {counts['not_found']}, failed {counts['failed']}, "
                f"changed {counts['changed']} {changed}".rstrip()
            )
        except BudgetExceeded:
            log(f"{stamp(started)} budget exceeded, stopping")
            return rounds
        except Exception as error:  # noqa: BLE001  a bad round must not end the day
            log(f"{stamp(started)} round {rounds + 1} failed: {error!r}")
        rounds += 1
        # The next whole multiple of the interval after this moment.
        next_start = (now() // interval_s + 1) * interval_s
        if next_start > end:
            return rounds
        sleep(next_start - now())


def report(conn, log=print) -> None:
    """Function to print what the probe has seen so far, per page

    Counts and times only: no titles and no body text.

    Args:
        conn: connection to the scratch database
        log (optional): Logging function. Defaults to print.
    """
    sql = """
    SELECT pp.path, pp.shape, pp.year,
           COUNT(s.id) AS polls,
           COUNT(DISTINCT s.sha256) AS versions,
           MIN(s.fetched_at) AS first_poll, MAX(s.fetched_at) AS last_poll,
           MIN(s.views) AS views_min, MAX(s.views) AS views_max,
           (SELECT COUNT(*) FROM events e
            WHERE e.page_id = p.id AND e.kind = 'content_changed') AS changes
    FROM probe_pages pp
    LEFT JOIN pages p ON p.path = pp.path
    LEFT JOIN snapshots s ON s.page_id = p.id
    GROUP BY pp.path ORDER BY pp.path
    """
    log(f"{'page':<17}{'shape':<7}{'year':<6}{'polls':>6}{'changes':>8}{'versions':>9}  views     span")
    for row in conn.execute(sql):
        span = ""
        if row["first_poll"] is not None:
            span = f"{stamp(row['first_poll'])[5:16]} to {stamp(row['last_poll'])[5:16]}"
        views = f"{row['views_min']}..{row['views_max']}" if row["polls"] else "-"
        log(
            f"{row['path']:<17}{row['shape']:<7}{row['year']:<6}{row['polls']:>6}"
            f"{row['changes']:>8}{row['versions']:>9}  {views:<9} {span}"
        )
    for outcome, attempts in conn.execute(
        "SELECT outcome, COUNT(*) FROM http_log GROUP BY outcome ORDER BY outcome"
    ):
        log(f"requests {outcome}: {attempts}")


def main(argv=None) -> None:
    """Parse the command line and run the probe or its report"""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db", type=Path, help="scratch database, never the main one")
    parser.add_argument("--interval", type=float, default=600.0, help="seconds between rounds")
    parser.add_argument("--hours", type=float, default=24.0, help="0 runs one round")
    parser.add_argument("--rate", type=float, default=2.0, help="requests per second")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--paths", nargs="+", help="poll only these pages from the list")
    parser.add_argument("--report", action="store_true", help="print a summary and exit")
    args = parser.parse_args(argv)

    if args.db.name == "graphwatch.sqlite":
        raise SystemExit("refusing to write to the main database")

    if args.report:
        ro = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        ro.row_factory = sqlite3.Row
        report(ro)
        return

    pages = [page for page in PAGES if not args.paths or page[0] in args.paths]
    if not pages:
        raise SystemExit("no page in the list matches --paths")
    key = hmac_key(load_config(args.config))
    conn = connect(args.db)
    conn.executescript(PROBE_SCHEMA)
    conn.executemany("INSERT OR IGNORE INTO probe_pages VALUES (?, ?, ?, ?)", pages)
    conn.commit()

    paths = [page[0] for page in pages]
    rounds_planned = int(args.hours * 3600 // args.interval) + 2
    # Each poll is one request, three with both retries; leave room for a bad hour.
    budget = rounds_planned * len(paths) * 2
    client = TelegraphClient(rate_per_s=args.rate, budget=budget, log=http_logger(conn))
    out = lambda s: print(s, flush=True)  # noqa: E731
    out(
        f"{stamp(time.time())} polling {len(paths)} pages every {args.interval:.0f}s "
        f"for {args.hours:g}h into {args.db}, budget {budget:,}"
    )
    rounds = run(conn, client, key, paths, args.interval, args.hours, log=out)
    out(f"{stamp(time.time())} done: {rounds} rounds, {client.requests_made:,} requests")


if __name__ == "__main__":
    main()
