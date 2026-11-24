"""Command line interface: python -m graphwatch.cli <command> [options]"""

import argparse
import sys
import time
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from sqlite3 import Connection, Row

from graphwatch.classify import (
    body_hash,
    classify_page,
    computed_rules,
    link_targets,
    templated_hashes,
)
from graphwatch.config import CONFIG, hmac_key, load_config
from graphwatch.crowd import (
    count_day,
    crowd_units,
    count_only_slugs,
    fit_window,
    load_done,
    load_expected,
    recent_days,
    save_day_count,
    sweep_cost,
)
from graphwatch.db import (
    cached_feeds,
    connect,
    delete_stale_indicators,
    release_indicator_to_file,
    explain_rows,
    http_logger,
    indicator_rows,
    label_rows,
    latest_snapshots,
    load_progress,
    mark_gone,
    parse_path,
    refresh_snapshot,
    resweep_cost,
    resweep_paths,
    save_labels,
    save_lookup,
    save_progress,
    save_score,
    stale_pages,
    store_fetch,
    store_meta,
    superseded_flagged_snapshots,
    upsert_indicator,
    upsert_title,
)
from graphwatch.enrich import (
    collect_indicators,
    count_verdicts,
    novelty_rows,
    read_indicator_file,
    render_novelty_table,
)
from graphwatch.extract import extract
from graphwatch.feeds import (
    FEEDS,
    KEY_NAMES,
    FeedClient,
    KeyCheck,
    Verdict,
    failure_kind,
    feed_keys,
)
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
from graphwatch.telegraph import Ahead, BudgetExceeded, Fetch, Outcome, Pool, TelegraphClient

CLASSIFY_BATCH = 1000


def require_key(path: Path) -> bytes:
    """Helper function to load the hmac key

    Args:
        path (Path): Path to config.env

    Raises:
        SystemExit: Exit if config file not found
        SystemExit: Exit if HMAC_KEY is not set in the config file
        SystemExit: Exit if HMAC_KEY is too short

    Returns:
        bytes: The bytes of the HMAC_KEY
    """
    try:
        return hmac_key(load_config(path))
    except FileNotFoundError:
        raise SystemExit(f"Config file not found: {path}")
    except KeyError:
        raise SystemExit(f"HMAC_KEY not set in {path}")
    except ValueError as too_short:
        raise SystemExit(f"{too_short}: {path}")


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

    Each title-day is counted on its own, so as many as the client has
    workers are counted at once. The counts are saved here, in order, on the
    calling thread.

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

    def count(unit: tuple[str, int, int]):
        slug, month, day = unit
        return count_day(probe, slug, month, day, gap=gap)

    with Pool(client) as pool:
        try:
            for _unit, dc in pool.map(count, crowd_units(slugs, days, done)):
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
    """Function to walk every title on every day and store the pages found

    A title-day is walked from where the last run left it, to the crowd
    count and then on to the first hole. Each page is stored, and the place
    reached is saved, before the next one is looked at, so a budget stop or
    a crash loses nothing. The counters a walk is certain to ask for are
    fetched ahead of it, as many at once as the client has workers; storing
    stays in counter order on the calling thread.

    Args:
        conn (Connection): SQL db connection
        client (TelegraphClient): Telegraph client
        entries (list[Entry]): word list entries from load_wordlists
        days (list[tuple[int, int]]): (month, day) pairs from recent_days
        key (bytes): the hmac key for redaction
        gap (int): missing counters to tolerate past the crowd count
        cap (int | None): the last counter to fetch on a day, or None
        exclude (set[str]): normalized slugs that are counted, not swept
        log (optional): Logging function. Defaults to print.

    Returns:
        tuple[int, int]: pages stored, and requests the finished walks made
    """

    for entry in entries:
        upsert_title(conn, entry, time.time())
    expected = load_expected(conn)
    stored = 0
    requests = 0
    uncounted = 0
    with Pool(client) as pool:
        ahead = Ahead(pool, make_fetch(client))
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
                        ahead.fetch,
                        slug,
                        month,
                        day,
                        next_n,
                        expected[(slug_key, month, day)],
                        gap,
                        cap,
                        hint=ahead.hint,
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

    def again(row) -> Fetch:
        return client.get_page(row["path"])

    with Pool(client) as pool:
        try:
            for row, fetch in pool.map(again, pages):
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
    """Function to fetch pages' HTML for their timestamps and store what changed

    Args:
        conn (Connection): Sql db connection
        client (TelegraphClient): Telegraph client
        pages (list): rows of id and path from stale_pages
        log (optional): Logging function. Defaults to print.

    Returns:
        dict: counts of fetched, changed, not_found and failed
    """
    counts = {"fetched": 0, "changed": 0, "not_found": 0, "failed": 0}

    def html(row) -> Fetch:
        return client.get_html(row["path"])

    with Pool(client) as pool:
        try:
            for row, fetch in pool.map(html, pages):
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


# How many lookups in a row a feed may refuse (401 or 403) before run_enrich
# takes its key to be refused, and how many in a row may get no answer before
# it takes the feed to be down. One refusal can be about one value, and OTX
# times out on about one lookup in ten (five of 50 on 23 November 2026).
REFUSED_LIMIT = 2
NO_ANSWER_LIMIT = 5


def run_enrich(
    conn: Connection,
    client: FeedClient,
    refresh: bool = False,
    log=print,
    recheck_s: float | None = None,
    clock=time.time,
) -> dict:
    """Function to look every stored indicator up in every feed the client has a key for

    An answer that is already stored is not asked for again unless refresh
    is set, so a run that was cut off picks up where it stopped. The one
    exception is an UNKNOWN whose first answer has become recheck_s old: it
    is asked for once more, because a feed may list an indicator days after
    the sweep found it. A failed lookup stores nothing. One that got no answer, or a server error, is
    tried once more when the others are done, because a feed that timed out
    has usually answered by then; after that it is left for the next run.

    A feed is left alone for the rest of the run when its quota is spent
    (a 429), when it refuses REFUSED_LIMIT lookups in a row or its key
    check, or when NO_ANSWER_LIMIT lookups in a row get no answer. A feed
    whose wrong key would not show in a lookup is asked about its key before
    its first lookup of the run.

    Args:
        conn (Connection): SQL db connection
        client (FeedClient): the feed client
        refresh (bool, optional): ask again for answers that are already
            stored. Defaults to False.
        log (optional): Logging function. Defaults to print.
        recheck_s (float | None, optional): the age in seconds at which a
            stored UNKNOWN is asked for once more, or None for never.
            Defaults to None.
        clock (optional): function returning the time in seconds since the
            epoch, for the answers' dates. Defaults to time.time.

    Returns:
        dict: counts of looked_up, cached, known, unknown, failed, retried
            and set_aside. looked_up counts each indicator and feed once and
            is the sum of known, unknown and failed; retried is how many of
            them were asked a second time; set_aside is how many feeds were
            left alone part of the way, so the table is not whole.
    """
    counts = {
        "looked_up": 0,
        "cached": 0,
        "known": 0,
        "unknown": 0,
        "failed": 0,
        "retried": 0,
        "set_aside": 0,
    }
    aside = set()  # feeds left alone for the rest of the run
    checked = set()  # feeds whose key check has been made
    again = []  # (indicator, feed) of the lookups to try once more
    streak = {}  # feed to (kind of failure, how many lookups in a row ended in it)

    def set_aside(feed: str, why: str) -> None:
        aside.add(feed)
        counts["set_aside"] += 1
        log(f"{feed}: {why}")

    def ask(indicator: Row, feed: str, second_try: bool) -> None:
        lookup = client.lookup(feed, indicator["kind"], indicator["value"])
        if not second_try:
            counts["looked_up"] += 1
        if lookup.verdict is not Verdict.FAILED:
            streak.pop(feed, None)
            if second_try:
                # It was counted as failed the first time and has an answer now
                counts["failed"] -= 1
            save_lookup(
                conn,
                indicator["id"],
                feed,
                lookup.verdict.name,
                lookup.detail,
                clock(),
            )
            if lookup.verdict is Verdict.KNOWN:
                counts["known"] += 1
                log(f"{indicator['value']}: known to {feed} ({lookup.detail})")
            else:
                counts["unknown"] += 1
            return
        if not second_try:
            counts["failed"] += 1
        kind = failure_kind(lookup.status)
        if kind == "quota":
            set_aside(feed, "quota spent, left for the next run")
            return
        # Any other failure is about this one lookup until the next ones end the same way
        before = streak.get(feed, (kind, 0))
        running = before[1] + 1 if before[0] == kind else 1
        streak[feed] = (kind, running)
        if second_try:
            log(f"{feed} {indicator['value']}: {lookup.detail} again, left for the next run")
        else:
            log(f"{feed} {indicator['value']}: {lookup.detail}")
            if kind == "transient":
                again.append((indicator, feed))
        if kind == "refused" and running >= REFUSED_LIMIT:
            set_aside(
                feed,
                f"refused {running} lookups running, its key ({KEY_NAMES[feed]}) "
                "or this address is not accepted; not asked in this run",
            )
        elif kind == "transient" and running >= NO_ANSWER_LIMIT:
            set_aside(feed, f"no answer to {running} lookups running, left for the next run")

    try:
        for indicator in indicator_rows(conn):
            cached = set() if refresh else cached_feeds(conn, indicator["id"], recheck_s, clock())
            for feed in client.feeds():
                if feed in cached:
                    counts["cached"] += 1
                    continue
                if feed in aside:
                    continue
                if feed not in checked:
                    # Before the feed's first lookup and not before: a run
                    # with nothing to ask sends nothing
                    checked.add(feed)
                    key = client.check_key(feed)
                    if key is KeyCheck.REFUSED:
                        set_aside(feed, f"key refused ({KEY_NAMES[feed]}), not asked in this run")
                        continue
                    if key is KeyCheck.FAILED:
                        log(f"{feed}: the key check gave no clear answer, the key is not verified")
                ask(indicator, feed, second_try=False)
        for indicator, feed in again:
            if feed in aside:
                continue
            ask(indicator, feed, second_try=True)
            counts["retried"] += 1
    except BudgetExceeded:
        log("budget exceeded")
    return counts


def keyed_feeds(path: Path) -> tuple[str, ...]:
    """The feeds the config file has a key for, for the novelty table

    The table is printed from what is stored and needs no key. It reads the
    config only to learn which feeds are in use, so that a feed with a key
    and no answer yet is waited for. With no config file it goes by the
    answers alone.

    Args:
        path (Path): Path to the config.env file

    Returns:
        tuple[str, ...]: feed names in FEEDS order, or none if the file
            cannot be read
    """
    try:
        keys = feed_keys(load_config(path))
    except OSError:
        return ()
    return tuple(feed for feed in FEEDS if feed in keys)


# How many requests are under way at once. A request takes about 150 ms from
# the VPS (146 to 149 ms at the median over the nights of 22 and 23 November
# 2026), so 8 a second needs one or two under way; four leaves room for a
# slow answer without ever going past --rate.
WORKERS = 4
WORKERS_HELP = "requests under way at once; they reach --rate, never pass it"


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
    crowd.add_argument("--workers", type=int, default=WORKERS, help=WORKERS_HELP)
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
    sweep.add_argument("--workers", type=int, default=WORKERS, help=WORKERS_HELP)
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
    meta.add_argument("--workers", type=int, default=WORKERS, help=WORKERS_HELP)
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
    enrich = sub.add_parser("enrich", help="look indicators up in the public feeds")
    enrich.add_argument("--db", type=Path, default=Path("data/graphwatch.sqlite"))
    enrich.add_argument(
        "--file", type=Path, default=None, help="TSV of more indicators: kind, value"
    )
    enrich.add_argument(
        "--refresh", action="store_true", help="ask again for stored answers"
    )
    enrich.add_argument("--budget", type=int, default=None)
    enrich.add_argument(
        "--recheck-days",
        type=float,
        default=14.0,
        help="ask once more for an UNKNOWN whose first answer is this many days old; 0 for never",
    )
    enrich.add_argument(
        "--table", action="store_true", help="print the novelty table and exit"
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
    if getattr(args, "workers", 1) < 1:
        raise SystemExit("--workers has to be 1 or more")
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
    if args.command == "enrich":
        conn = connect(args.db)
        if args.table:
            # No client is built: the table is read from what is stored.
            table = render_novelty_table(novelty_rows(conn), in_use=keyed_feeds(args.config))
            print(table, end="", flush=True)
            return
        try:
            keys = feed_keys(load_config(args.config))
        except FileNotFoundError:
            raise SystemExit(f"Config file not found: {args.config}")
        if not keys:
            names = ", ".join(sorted(set(KEY_NAMES.values())))
            raise SystemExit(f"no feed key set in {args.config}: {names}")
        out = lambda s: print(s, flush=True)  # noqa: E731
        for feed in FEEDS:
            if feed not in keys:
                out(f"no key for {feed} ({KEY_NAMES[feed]}), skipped")
        found = collect_indicators(conn)
        for seen in found:
            upsert_indicator(
                conn,
                seen.kind,
                seen.value,
                "pages",
                seen.first_seen,
                seen.last_seen,
                seen.pages,
                dict(seen.titles),
            )
        listed = []
        if args.file is not None:
            listed, skipped = read_indicator_file(args.file)
            for seen in listed:
                upsert_indicator(conn, seen.kind, seen.value, args.file.name)
            if skipped:
                out(f"{skipped} rows of {args.file.name} are not an ip, host or url, skipped")
        # A file's indicator that a flagged page once held and holds no more
        # is the file's again
        on_pages = {(seen.kind, seen.value) for seen in found}
        for seen in listed:
            if (seen.kind, seen.value) not in on_pages:
                release_indicator_to_file(conn, seen.kind, seen.value, args.file.name)
        # What an earlier run found on pages that are no longer flagged, or
        # that the extractor no longer reports, leaves the table
        current = {(seen.kind, seen.value) for seen in (*found, *listed)}
        dropped = delete_stale_indicators(conn, current)
        if dropped:
            out(f"{dropped} indicators are on no flagged page any more, dropped")
        out(
            f"{len(found)} indicators from flagged pages, {len(listed)} from the file, "
            f"feeds: {', '.join(feed for feed in FEEDS if feed in keys)}"
        )
        client = FeedClient(keys, budget=args.budget, log=http_logger(conn))
        started = time.time()
        recheck_s = args.recheck_days * 86400 if args.recheck_days > 0 else None
        counts = run_enrich(conn, client, args.refresh, log=out, recheck_s=recheck_s)
        out(
            f"looked up {counts['looked_up']:,}, cached {counts['cached']:,}, "
            f"known {counts['known']:,}, unknown {counts['unknown']:,}, "
            f"failed {counts['failed']:,}, retried {counts['retried']:,}, "
            f"{client.requests_made:,} requests, {time.time() - started:.0f}s"
        )
        verdicts = count_verdicts(novelty_rows(conn), in_use=client.feeds())
        out(
            f"{sum(verdicts.values())} indicators: {verdicts['novel']} novel, "
            f"{verdicts['known']} known, {verdicts['unchecked']} unchecked"
        )
        if counts["set_aside"]:
            # Everything that was answered is stored. The status is for cron:
            # a feed that was left alone means the table is not whole
            feeds_left = "1 feed was" if counts["set_aside"] == 1 else f"{counts['set_aside']} feeds were"
            raise SystemExit(f"{feeds_left} left alone part of the way, see above; run enrich again")
        return
    if args.command == "sweep":
        key = require_key(args.config)
    resweep = args.command == "sweep" and args.resweep
    # A re-sweep walks stored pages, not titles, so it reads no word list
    if args.command in ("crowd", "sweep") and not resweep:
        entries = load_frozen(args.wordlists, args.unfrozen)
    conn = connect(args.db)
    client = TelegraphClient(
        rate_per_s=args.rate, budget=args.budget, log=http_logger(conn), workers=args.workers
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
