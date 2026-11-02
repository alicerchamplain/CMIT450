"""Command line interface: python -m graphwatch.cli <command> [options]"""

import argparse
import sys
import time
from datetime import date
from pathlib import Path
from sqlite3 import Connection

from graphwatch.config import CONFIG, hmac_key, load_config
from graphwatch.crowd import (
    count_only_slugs,
    crowd_check,
    fit_window,
    load_done,
    load_expected,
    recent_days,
    save_day_count,
    sweep_cost,
)
from graphwatch.db import (
    connect,
    http_logger,
    load_progress,
    parse_path,
    save_progress,
    store_fetch,
    upsert_title,
)
from graphwatch.slugify import Entry, load_wordlists, normalize_slug
from graphwatch.sweep import sweep_day
from graphwatch.telegraph import BudgetExceeded, Fetch, TelegraphClient


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


def make_fetch(client: TelegraphClient):
    """Wrap the telegraph client as a fetch callable

    Args:
        client (TelegraphClient): the api client

    Returns:
        callable: fetch(path) returning the full get_page fetch
    """

    def fetch(path: str) -> Fetch:
        return client.get_page(path)

    return fetch


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


def run_sweep(
    conn: Connection,
    client: TelegraphClient,
    entries: list[Entry],
    days: list[tuple[int, int]],
    key: bytes,
    gap: int,
    cap: int | None,
    exclude: set[str],
    log=print,
) -> tuple[int, int]:

    for entry in entries:
        upsert_title(conn, entry, time.time())
    expected = load_expected(conn)
    fetch = make_fetch(client)
    stored = 0
    requests = 0
    try:
        for entry in entries:
            # The database speaks normalized keys; the network speaks the raw slug.
            slug = entry.slug
            slug_key = normalize_slug(slug)
            if slug_key in exclude:
                continue
            for month, day in days:
                next_n, done = load_progress(conn, slug_key, month, day)
                if done:
                    continue
                gen = sweep_day(
                    fetch,
                    slug,
                    month,
                    day,
                    next_n,
                    expected.get((slug_key, month, day), 0),
                    gap,
                    cap,
                )
                while True:
                    try:
                        f = next(gen)
                    except StopIteration as stop:
                        summary = stop.value
                        break
                    store_fetch(conn, f, time.time(), key)
                    stored += 1
                    counter = parse_path(f.page["path"])[3] or 1
                    save_progress(
                        conn,
                        slug_key,
                        month,
                        day,
                        counter + 1,
                        False,
                        0,
                        0,
                        time.time(),
                    )
                save_progress(
                    conn,
                    slug_key,
                    month,
                    day,
                    summary.next_n,
                    summary.done,
                    summary.requests,
                    summary.failures,
                    time.time(),
                )
                requests += summary.requests
                if summary.found:
                    log(
                        f"{slug} {month:02d}-{day:02d}: {len(summary.found)} pages, {summary.requests} requests"
                    )
    except BudgetExceeded:
        log("budget exceeded")
    return stored, requests


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
    parser.add_argument("--config", type=Path, default=CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)
    crowd = sub.add_parser("crowd", help="count pages per title per day")
    crowd.add_argument("--db", type=Path, default=Path("data/graphwatch.sqlite"))
    crowd.add_argument("--wordlists", type=Path, default=Path("wordlists"))
    crowd.add_argument("--days", type=int, default=14)
    crowd.add_argument("--gap", type=int, default=2)
    crowd.add_argument("--rate", type=float, default=8.0)
    crowd.add_argument("--budget", type=int, default=None)
    sweep = sub.add_parser("sweep", help="collect pages per title per day")
    sweep.add_argument("--db", type=Path, default=Path("data/graphwatch.sqlite"))
    sweep.add_argument("--wordlists", type=Path, default=Path("wordlists"))
    sweep.add_argument("--days", type=int, default=None)
    sweep.add_argument("--gap", type=int, default=2)
    sweep.add_argument("--rate", type=float, default=8.0)
    sweep.add_argument("--budget", type=int, default=230000)
    sweep.add_argument("--cap", type=int, default=None)
    sweep.add_argument("--count-only-above", type=int, default=10000)
    sweep.add_argument("--today", type=date.fromisoformat, default=None)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    """Entry point: build the real objects and run the chosen command

    Args:
        argv (list[str] | None, optional): arguments for parse_args, or None
            to read sys.argv. Defaults to None.
    """
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "sweep":
        key = require_key(args.config)
    conn = connect(args.db)
    client = TelegraphClient(
        rate_per_s=args.rate, budget=args.budget, log=http_logger(conn)
    )
    entries = load_wordlists(args.wordlists)

    if args.command == "crowd":
        days = recent_days(date.today(), args.days)
        started = time.time()
        checked = run_crowd(
            conn,
            client,
            entries,
            days,
            gap=args.gap,
            log=lambda s: print(s, flush=True),
        )
        print(
            f"checked {checked} title-days, {client.requests_made} requests, {time.time() - started:.0f}s",
            flush=True,
        )
    elif args.command == "sweep":
        exclude = count_only_slugs(conn, args.count_only_above)
        today = args.today or date.today()
        if args.days is None:
            n_days = fit_window(conn, today, args.budget, args.gap, exclude, args.cap)
            if n_days == 0:
                raise SystemExit("no window fits the budget")
        else:
            n_days = args.days
        days = recent_days(today, n_days)
        cost = sweep_cost(conn, days, args.gap, exclude, args.cap)
        print(
            f"Window Size: {n_days}, From: {days[0][0]:02d}-{days[0][1]:02d} to {days[-1][0]:02d}-{days[-1][1]:02d}, "
            f"Estimated Requests: {cost:,}, Budget: {args.budget:,}, Count Only {len(exclude)}",
            flush=True,
        )
        started = time.time()
        stored, _requests = run_sweep(
            conn,
            client,
            entries,
            days,
            key,
            args.gap,
            args.cap,
            exclude,
            log=lambda s: print(s, flush=True),
        )
        elapsed = time.time() - started
        print(
            f"Stored {stored:,} pages, {client.requests_made:,} requests, "
            f"{client.requests_made / max(elapsed, 1):.1f}/s, {elapsed:.0f}s",
            flush=True,
        )


if __name__ == "__main__":
    main()
