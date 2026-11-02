"""Command line interface: python -m graphwatch.cli <command> [options]"""

import argparse
import sys
import time
from datetime import date
from pathlib import Path
from sqlite3 import Connection

from graphwatch.config import CONFIG, hmac_key, load_config
from graphwatch.crowd import crowd_check, load_done, recent_days, save_day_count
from graphwatch.db import connect, http_logger, upsert_title
from graphwatch.slugify import Entry, load_wordlists
from graphwatch.telegraph import BudgetExceeded, TelegraphClient


def require_key(path: Path) -> bytes:
    """Helper function to load the hmac key

    Args:
        path (Path): Path to config.env

    Raises:
        SystemExit: Exit if config file not found
        SystemExit: Exit if HMAC_KEY is not set in the config file

    Returns:
        bytes: The bytes of the HMAC_KEY
    """
    try:
        return hmac_key(load_config(path))
    except FileNotFoundError:
        raise SystemExit(f"Config file not found: {path}")
    except KeyError:
        raise SystemExit(f"HMAC_KEY not set in {path}")


def make_probe(client: TelegraphClient):
    """Wrap the telegraph client as a probe callable

    Args:
        client (TelegraphClient): the api client

    Returns:
        callable: probe(path) returning an Outcome
    """

    def probe(path: str):
        return client.get_page(path, content=False).outcome

    return probe


def run_crowd(
    conn: Connection,
    client: TelegraphClient,
    entries: list[Entry],
    days: list[tuple[int, int]],
    gap: int = 2,
    log=print,
) -> int:
    """Run the crowd check over every word list entry and day, saving as it goes

    Args:
        conn (Connection): database connection from db.connect
        client (TelegraphClient): the client to probe with
        entries (list[Entry]): word list entries from load_wordlists
        days (list[tuple[int, int]]): (month, day) pairs from recent_days
        gap (int, optional): missing counters to tolerate. Defaults to 2.
        log (optional): callable taking one string per line of progress.
            Defaults to print.

    Returns:
        int: how many (slug, day) pairs were checked this run
    """
    for entry in entries:
        upsert_title(conn, entry, time.time())
    slugs = [entry.slug for entry in entries]
    done = load_done(conn)
    probe = make_probe(client)
    checked = 0
    try:
        for dc in crowd_check(probe, slugs, days, gap=gap, done=done):
            save_day_count(conn, dc, time.time())
            checked += 1
            if dc.highest:
                log(
                    f"{dc.slug} {dc.month:02d}-{dc.day:02d}: {dc.highest} pages, {dc.requests} requests"
                )
    except BudgetExceeded:
        log("budget exceeded")
    return checked


def parse_args(argv: list[str]):
    """Parse the command line

    Args:
        argv (list[str]): arguments without the program name, as in
            sys.argv[1:]

    Returns:
        argparse.Namespace: command plus that command's options

    Raises:
        SystemExit: on no command, an unknown command, or --help
    """
    parser = argparse.ArgumentParser(prog="graphwatch")
    sub = parser.add_subparsers(dest="command", required=True)
    crowd = sub.add_parser("crowd", help="count pages per title per day")
    crowd.add_argument("--db", type=Path, default=Path("data/graphwatch.sqlite"))
    crowd.add_argument("--config", type=Path, default=CONFIG)
    crowd.add_argument("--wordlists", type=Path, default=Path("wordlists"))
    crowd.add_argument("--days", type=int, default=14)
    crowd.add_argument("--gap", type=int, default=2)
    crowd.add_argument("--rate", type=float, default=8.0)
    crowd.add_argument("--budget", type=int, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    """Entry point: build the real objects and run the chosen command

    Args:
        argv (list[str] | None, optional): arguments for parse_args, or None
            to read sys.argv. Defaults to None.
    """
    args = parse_args(argv if argv is not None else sys.argv[1:])
    conn = connect(args.db)
    client = TelegraphClient(
        rate_per_s=args.rate, budget=args.budget, log=http_logger(conn)
    )
    entries = load_wordlists(args.wordlists)
    days = recent_days(date.today(), args.days)
    started = time.time()
    checked = run_crowd(
        conn, client, entries, days, gap=args.gap, log=lambda s: print(s, flush=True)
    )
    print(
        f"checked {checked} title-days, {client.requests_made} requests, {time.time() - started:.0f}s",
        flush=True,
    )


if __name__ == "__main__":
    main()
