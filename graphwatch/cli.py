"""Command line interface: python -m graphwatch.cli <command> [options]"""

import argparse
import sys
import time
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from sqlite3 import Connection

from graphwatch.classify import (
    body_hash,
    classify_page,
    computed_rules,
    link_targets,
    templated_hashes,
)
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
    explain_rows,
    http_logger,
    label_rows,
    latest_snapshots,
    load_progress,
    mark_gone,
    parse_path,
    refresh_snapshot,
    resweep_cost,
    resweep_paths,
    save_labels,
    save_progress,
    save_score,
    stale_pages,
    store_fetch,
    store_meta,
    superseded_flagged_snapshots,
    upsert_title,
)
from graphwatch.extract import extract
from graphwatch.rules import (
    CATEGORIES,
    RULES,
    THRESHOLD,
    body_of,
    category_scores,
    labels_for,
    primary_label,
    score,
)
from graphwatch.slugify import (
    Entry,
    WordlistsChanged,
    load_wordlists,
    normalize_slug,
    read_sums,
    write_sums,
)
from graphwatch.sweep import sweep_day
from graphwatch.telegraph import BudgetExceeded, Fetch, Outcome, TelegraphClient

CLASSIFY_BATCH = 1000


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


def load_frozen(directory: Path, unfrozen: bool = False) -> list[Entry]:
    """Glue function to load frozen wordlists and check if they have changed

    Args:
        directory (Path): Wordlist directory
        unfrozen (bool, optional): Override bool. Defaults to False.

    Raises:
        SystemExit: Exits if the wordlists have changed

    Returns:
        list[Entry]: Unique list of sluggified strings from wordlists
    """
    try:
        return load_wordlists(directory, verify=not unfrozen)
    except WordlistsChanged as e:
        raise SystemExit(
            f"wordlists differ from {directory / 'SHA256SUMS'} "
            f"run `freeze` to accept the changes or pass --unfrozen\n{e}"
        )


def run_freeze(directory: Path, log=print) -> Path:
    entries = load_wordlists(directory)
    out = write_sums(directory)
    sums = read_sums(out)
    for name, digest in sums.items():
        titles = sum(1 for entry in entries if entry.source == Path(name).stem)
        log(f"{name:24} {titles:5} titles  {digest}")
    log(f"{len(entries)} titles in {len(sums)} lists, wrote {out}")
    return out


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
    """Function to manage running sweeps

    Args:
        conn (Connection): _description_
        client (TelegraphClient): _description_
        entries (list[Entry]): _description_
        days (list[tuple[int, int]]): _description_
        key (bytes): _description_
        gap (int): _description_
        cap (int | None): _description_
        exclude (set[str]): _description_
        log (_type_, optional): _description_. Defaults to print.

    Returns:
        tuple[int, int]: _description_
    """

    for entry in entries:
        upsert_title(conn, entry, time.time())
    expected = load_expected(conn)
    fetch = make_fetch(client)
    stored = 0
    requests = 0
    uncounted = 0
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
                if (slug_key, month, day) not in expected:
                    # Without a crowd count the walk has no known end and would
                    # stop at the first hole, so the day is left for a later run.
                    uncounted += 1
                    continue
                gen = sweep_day(
                    fetch,
                    slug,
                    month,
                    day,
                    next_n,
                    expected[(slug_key, month, day)],
                    gap,
                    cap,
                )
                while True:
                    try:
                        f = next(gen)
                    except StopIteration as stop:
                        summary = stop.value
                        break
                    try:
                        store_fetch(conn, f, time.time(), key)
                        stored += 1
                    except RecursionError:
                        # A page nested deeper than Python can walk cannot be
                        # redacted, so it is not stored. The walk moves on:
                        # stopping here would stop it here every night.
                        log(f"{f.page['path']}: nested too deep to redact, not stored")
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
    if uncounted:
        log(
            f"skipped {uncounted} title-days with no crowd count; run crowd for those days, then sweep again"
        )
    return stored, requests


def run_resweep(
    conn: Connection, client: TelegraphClient, pages: list, key: bytes, log=print
) -> dict:
    """Function to fetch stored pages again and record what happened to each

    A page that is still there has its last_seen moved. If its fingerprint
    moved too, it gets a new snapshot and a content_changed event; if not,
    only its view count is kept. A page that answers PAGE_NOT_FOUND gets a
    gone event. A failed fetch changes nothing, so last_seen stays old and
    the page is first in line on the next run.

    Args:
        conn (Connection): SQL db connection
        client (TelegraphClient): Telegraph client
        pages (list): rows of id and path from resweep_paths
        key (bytes): the hmac key for redaction
        log (optional): Logging function. Defaults to print.

    Returns:
        dict: counts of refreshed, changed, gone and failed
    """
    counts = {"refreshed": 0, "changed": 0, "gone": 0, "failed": 0}
    try:
        for row in pages:
            fetch = client.get_page(row["path"])
            ts = time.time()
            if fetch.outcome is Outcome.FOUND:
                # By the row's id: Telegraph may answer with the path in
                # another spelling than the one stored, and the row asked
                # for is the one that has to leave the work list
                try:
                    changed = refresh_snapshot(conn, row["id"], fetch.page, ts, key)
                except RecursionError:
                    # Nested deeper than Python can walk: it cannot be
                    # redacted, so it is not stored, and the run goes on
                    conn.rollback()
                    counts["failed"] += 1
                    log(f"{row['path']}: nested too deep to redact, not stored")
                    continue
                counts["refreshed"] += 1
                if changed:
                    counts["changed"] += 1
                    log(f"{row['path']}: content changed")
            elif fetch.outcome is Outcome.NOT_FOUND:
                mark_gone(conn, row["id"], ts)
                counts["gone"] += 1
                log(f"{row['path']}: gone")
            else:
                counts["failed"] += 1
    except BudgetExceeded:
        log("budget exceeded")
    return counts


def run_meta(conn: Connection, client: TelegraphClient, pages: list, log=print) -> dict:
    """Function to orchestrate store_meta

    Args:
        conn (Connection): Sql db connection
        client (TelegraphClient): Telegraph client
        pages (list): List of pages
        log (_type_, optional): Log. Defaults to print.

    Returns:
        dict: dictionary of counts
    """
    counts = {"fetched": 0, "changed": 0, "not_found": 0, "failed": 0}
    try:
        for row in pages:
            fetch = client.get_html(row["path"])
            if fetch.outcome is Outcome.FOUND:
                changed = store_meta(conn, row["id"], fetch.page, time.time())
                counts["fetched"] += 1
                if changed:
                    counts["changed"] += 1
                    iso = datetime.fromtimestamp(
                        fetch.page["modified_at"], UTC
                    ).isoformat()
                    log(f"{row['path']}: modified_at changed to {iso}")
            elif fetch.outcome is Outcome.NOT_FOUND:
                counts["not_found"] += 1
            else:
                counts["failed"] += 1
                log(f"{row['path']}: {fetch.error}")
    except BudgetExceeded:
        log("budget exceeded")
    return counts


def snapshot_batches(conn: Connection, content: bool = True):
    """The newest snapshot of every page, CLASSIFY_BATCH pages at a time

    Each batch is read whole before it is handed out, so nothing is being
    read from the database while the caller works on it or writes.

    Args:
        conn (Connection): SQL db connection
        content (bool, optional): False leaves the stored nodes out, for a
            pass that only reads the text. Defaults to True.

    Yields:
        list[sqlite3.Row]: the next batch of rows from latest_snapshots
    """
    after_page_id = 0
    while True:
        rows = latest_snapshots(conn, after_page_id, CLASSIFY_BATCH, content).fetchall()
        if not rows:
            return
        yield rows
        after_page_id = rows[-1]["page_id"]


def run_classify(conn: Connection, threshold: int = THRESHOLD, log=print) -> dict:
    """Function to score the newest snapshot of every page and store the result

    Two passes over the snapshots. The first finds the templated bodies, which
    needs every page; the second scores each page and saves its hits. Makes no
    network requests.

    Both passes read a batch of pages, finish reading, and only then work on
    it, and the second writes a batch's results in one short transaction.
    The ten-minute re-poll writes to the same file: it has to be able to get
    its turn between two batches, and classify has to be able to wait for it.

    Args:
        conn (Connection): SQL db connection
        threshold (int, optional): flag at this score or above. Defaults to
            THRESHOLD.
        log (optional): Logging function. Defaults to print.

    Returns:
        dict: pages, flagged and near_miss count the sweep's pages by their
            resolver score; held_out and held_out_flagged count the evaluation
            set; scores is a Counter of sweep pages per resolver score.
            labelled, primary and category_near_miss are Counters of sweep
            pages per category, and unlabelled is the sweep pages with no
            label at all. rescored is how many older snapshots of flagged
            pages were scored again.
    """

    def body_text(row) -> str:
        return body_of(row["title"], row["description"], row["text"])

    pairs = (
        (body_hash(body_text(row)), row["title"])
        for batch in snapshot_batches(conn, content=False)
        for row in batch
    )
    templated = templated_hashes(pairs)
    counts = {
        "pages": 0,
        "flagged": 0,
        "near_miss": 0,
        "held_out": 0,
        "held_out_flagged": 0,
        "scores": Counter(),
        "labelled": Counter(),
        "primary": Counter(),
        "category_near_miss": Counter(),
        "unlabelled": 0,
        "rescored": 0,
    }
    ts = time.time()

    def scored(row) -> tuple:
        """Everything classify stores for one snapshot, worked out with no write open"""
        body = body_text(row)
        digest = body_hash(body)
        # The addresses behind the page's links, which its text does not show
        links = link_targets(row["content"], row["text"])
        computed = computed_rules(body, digest if digest in templated else None, links)
        hits = classify_page(
            row["title"], row["description"], row["text"], computed, links=links
        )
        # The resolver verdict, as before the categories existed
        total = score(hits)
        stored_hits = [
            (hit.rule.name, hit.rule.weight, hit.evidence, hit.matches) for hit in hits
        ]
        by_category = category_scores(hits)
        labels = labels_for(by_category, threshold)
        primary = primary_label(labels)
        # A category that scored 0 gets no row, so a row with assigned = 0
        # is a near miss or an excluded page
        stored_labels = [
            (category, value, category in labels, category == primary)
            for category, value in by_category.items()
            if value != 0
        ]
        return total, digest, stored_hits, by_category, labels, primary, stored_labels

    def save(row, result) -> None:
        total, digest, stored_hits, _by_category, _labels, _primary, stored_labels = result
        save_score(
            conn,
            row["snapshot_id"],
            row["page_id"],
            total,
            total >= threshold,
            digest,
            stored_hits,
            ts,
        )
        save_labels(conn, row["snapshot_id"], row["page_id"], stored_labels)

    for batch in snapshot_batches(conn):
        results = [scored(row) for row in batch]
        # Only now is anything written, and the commit follows at once
        for row, result in zip(batch, results):
            save(row, result)
        conn.commit()
        for row, result in zip(batch, results):
            total, _digest, _hits, by_category, labels, primary, _stored = result
            flagged = total >= threshold
            if row["held_out"]:
                counts["held_out"] += 1
                counts["held_out_flagged"] += flagged
                continue
            counts["pages"] += 1
            counts["flagged"] += flagged
            counts["near_miss"] += 0 < total < threshold
            counts["scores"][total] += 1
            for category, value in by_category.items():
                if category in labels:
                    counts["labelled"][category] += 1
                elif value > 0:
                    counts["category_near_miss"][category] += 1
            if primary is None:
                counts["unlabelled"] += 1
            else:
                counts["primary"][primary] += 1
    # The older snapshots that hold a flagged score are scored again too, so
    # that a flag from an earlier rule table does not outlive the rule. They
    # are not counted: every count above is of each page's newest snapshot.
    older = superseded_flagged_snapshots(conn)
    results = [scored(row) for row in older]
    for row, result in zip(older, results):
        save(row, result)
        counts["rescored"] += 1
    conn.commit()
    log(
        f"classified {counts['pages']:,} pages at threshold {threshold}: "
        f"{counts['flagged']:,} flagged, {counts['near_miss']:,} near misses, "
        f"{len(templated):,} templated bodies"
    )
    # Counts only: which held-out pages missed is never printed.
    log(f"held-out: {counts['held_out_flagged']}/{counts['held_out']} flagged")
    for category in CATEGORIES:
        log(
            f"  {category:<20} labelled {counts['labelled'][category]:>9,}, "
            f"primary {counts['primary'][category]:>9,}, "
            f"near misses {counts['category_near_miss'][category]:>9,}"
        )
    share = counts["unlabelled"] / counts["pages"] if counts["pages"] else 0
    log(f"  {'unlabelled':<20} {counts['unlabelled']:>18,} ({share:.1%} of pages)")
    return counts


def run_explain(conn: Connection, path: str, log=print) -> bool:
    """Function to print why one page scored what it did, from the stored hits

    The first line is the resolver verdict. Then come the page's labels and
    its hits, grouped by category. A hit's category is looked up in RULES,
    because the hits table does not store it; a rule that has since left the
    table is listed under "retired rule". A flagged page also gets the
    indicators the extractor finds in it. A held-out page gets its resolver
    score and nothing else: its evidence is what a rule would be written
    from, and the evaluation set is never read for that.

    Args:
        conn (Connection): SQL db connection
        path (str): The page path as Telegraph spells it, e.g. Hello-10-17-154
        log (optional): Logging function. Defaults to print.

    Returns:
        bool: False if the page is unknown or has not been classified
    """
    row, hits = explain_rows(conn, path)
    if row is None:
        log(f"{path}: no score stored, run classify first")
        return False
    verdict = "flagged" if row["flagged"] else "not flagged"
    if row["held_out"]:
        log(f"{row['path']}: score {row['score']}, {verdict}")
        log("held-out page: evidence withheld")
        return True
    log(f"{row['path']}: score {row['score']}, {verdict}")
    log(f"  title: {row['title']}")
    labels = label_rows(conn, row["snapshot_id"])
    assigned = [
        label["category"] + (" (primary)" if label["is_primary"] else "")
        for label in labels
        if label["assigned"]
    ]
    log(f"  labels: {', '.join(assigned) if assigned else 'none'}")
    category_of = {rule.name: rule.category for rule in RULES}
    totals = {label["category"]: label["score"] for label in labels}
    for group in (*CATEGORIES, "retired rule"):
        members = [
            hit for hit in hits if category_of.get(hit["rule"], "retired rule") == group
        ]
        if not members:
            continue
        # A retired rule has no category, so its group has no score
        log(f"  {group} {totals.get(group, 0):+d}" if group in CATEGORIES else f"  {group}")
        for hit in members:
            # A rule that matched more than once shows how often: "x3"
            times = f" x{hit['matches']}" if hit["matches"] > 1 else ""
            log(f"    {hit['weight']:+d} {hit['rule']:<22} {hit['evidence']}{times}")
    if row["flagged"]:
        for indicator in extract(row["title"], row["text"]):
            log(f"  {indicator.kind:<5} {indicator.value} ({indicator.source})")
    return True


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
    crowd.add_argument("--today", type=date.fromisoformat, default=None)
    crowd.add_argument(
        "--unfrozen", action="store_true", help="skip the SHA256SUMS check"
    )
    sweep = sub.add_parser("sweep", help="collect pages per title per day")
    sweep.add_argument("--db", type=Path, default=Path("data/graphwatch.sqlite"))
    sweep.add_argument("--wordlists", type=Path, default=Path("wordlists"))
    sweep.add_argument("--days", type=int, default=None)
    sweep.add_argument("--gap", type=int, default=2)
    sweep.add_argument("--rate", type=float, default=8.0)
    sweep.add_argument("--budget", type=int, default=230000)
    sweep.add_argument("--cap", type=int, default=None)
    sweep.add_argument(
        "--count-only-above",
        type=int,
        default=700,
        help="average pages per day at which a title is counted, not swept",
    )
    sweep.add_argument("--today", type=date.fromisoformat, default=None)
    sweep.add_argument(
        "--unfrozen", action="store_true", help="skip the SHA256SUMS check"
    )
    sweep.add_argument(
        "--resweep", action="store_true", help="fetch stored pages again"
    )
    sweep.add_argument(
        "--older-than",
        type=float,
        default=20.0,
        help="with --resweep: only pages last seen this many hours ago or more",
    )
    sweep.add_argument(
        "--flagged",
        action="store_true",
        help="with --resweep: only pages the classifier has flagged",
    )
    sweep.add_argument(
        "--match",
        metavar="TEXT",
        default=None,
        help="with --resweep: only pages whose newest text contains TEXT",
    )
    meta = sub.add_parser("meta", help="fetch page timestamps")
    meta.add_argument("--db", type=Path, default=Path("data/graphwatch.sqlite"))
    meta.add_argument("--rate", type=float, default=8.0)
    meta.add_argument("--budget", type=int, default=230000)
    meta.add_argument("--limit", type=int, default=5000)
    meta.add_argument("--stale", type=float, required=True, help="hours")
    freeze = sub.add_parser("freeze", help="write wordlists/SHA256SUMS")
    freeze.add_argument("--wordlists", type=Path, default=Path("wordlists"))
    classify = sub.add_parser("classify", help="score stored pages with the rules")
    classify.add_argument("--db", type=Path, default=Path("data/graphwatch.sqlite"))
    classify.add_argument("--threshold", type=int, default=THRESHOLD)
    classify.add_argument(
        "--explain", metavar="PATH", help="show one page's stored score and hits"
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    """Entry point: build the real objects and run the chosen command

    Args:
        argv (list[str] | None, optional): arguments for parse_args, or None
            to read sys.argv. Defaults to None.
    """
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "sweep" and args.days is not None and args.days < 1:
        raise SystemExit("--days has to be 1 or more")
    if args.command == "freeze":
        run_freeze(args.wordlists, log=lambda s: print(s, flush=True))
        return
    if args.command == "classify":
        # No client is built: classifying never touches the network.
        conn = connect(args.db)
        if args.explain:
            run_explain(conn, args.explain, log=lambda s: print(s, flush=True))
            return
        started = time.time()
        counts = run_classify(conn, args.threshold, log=lambda s: print(s, flush=True))
        for value, pages in sorted(counts["scores"].items()):
            print(f"  score {value:+d}: {pages:,}", flush=True)
        print(f"{time.time() - started:.0f}s", flush=True)
        return
    if args.command == "sweep":
        key = require_key(args.config)
    resweep = args.command == "sweep" and args.resweep
    # A re-sweep walks stored pages, not titles, so it reads no word list
    if args.command in ("crowd", "sweep") and not resweep:
        entries = load_frozen(args.wordlists, args.unfrozen)
    conn = connect(args.db)
    client = TelegraphClient(
        rate_per_s=args.rate, budget=args.budget, log=http_logger(conn)
    )
    if resweep:
        started = time.time()
        cutoff = started - args.older_than * 3600
        if args.days is None:
            days = None
            window = "all days"
        else:
            days = recent_days(args.today or date.today(), args.days)
            window = (
                f"{args.days} days, From: {days[0][0]:02d}-{days[0][1]:02d} "
                f"to {days[-1][0]:02d}-{days[-1][1]:02d}"
            )
        cost = resweep_cost(conn, cutoff, days, args.flagged, args.match)
        print(
            f"Resweep: {window}, Pages: {cost:,}, "
            f"Older than: {args.older_than:g}h, Budget: {args.budget:,}",
            flush=True,
        )
        pages = resweep_paths(conn, cutoff, days, args.flagged, args.match)
        counts = run_resweep(
            conn, client, pages, key, log=lambda s: print(s, flush=True)
        )
        elapsed = time.time() - started
        print(
            f"refreshed {counts['refreshed']:,} pages, {counts['changed']:,} changed, "
            f"{counts['gone']:,} gone, {counts['failed']:,} failed, "
            f"{client.requests_made:,} requests, {elapsed:.0f}s",
            flush=True,
        )
        return
    if args.command == "crowd":
        days = recent_days(args.today or date.today(), args.days)
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
    elif args.command == "meta":
        pages = stale_pages(conn, args.stale, time.time(), args.limit)
        print(
            f"{len(pages)} selected",
            flush=True,
        )
        started = time.time()
        counts = run_meta(conn, client, pages, log=lambda s: print(s, flush=True))
        elapsed = time.time() - started
        print(
            f"Fetched {counts['fetched']}, changed {counts['changed']}, not found {counts['not_found']}, failed {counts['failed']}, {client.requests_made:,} requests, "
            f"{client.requests_made / max(elapsed, 1):.1f}/s, {elapsed:.0f}s",
            flush=True,
        )


if __name__ == "__main__":
    main()
