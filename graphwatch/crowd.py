"""Crowd check: how many Telegraph pages each candidate title gets per day."""

from dataclasses import dataclass
from datetime import date, timedelta
from sqlite3 import Connection

from graphwatch.telegraph import Outcome, build_path


@dataclass(frozen=True)
class DayCount:
    """The result of counting one title's pages on one calendar day"""

    slug: str  # the slug as probed, from slugify
    month: int  # 1 to 12
    day: int  # 1 to 31
    highest: int  # highest counter confirmed to exist; 0 means no pages
    requests: int  # probes spent on this day
    failures: int  # probes that came back FAILED, counted as not found
    paths: list[str]  # paths probed and found, in counter order; not every page


def recent_days(today: date, n: int) -> list[tuple[int, int]]:
    """The n calendar days ending on today, oldest first, as (month, day)

    Telegraph paths carry no year, so a day is just its month and day.
    timedelta handles month and year boundaries.

    Args:
        today (date): the last day of the window, usually date.today()
        n (int): how many days, including today

    Returns:
        list[tuple[int, int]]: n (month, day) pairs, oldest first
    """
    collect = []
    for i in range(n - 1, -1, -1):
        delta = today - timedelta(days=i)
        collect.append((delta.month, delta.day))
    return collect


def count_day(
    probe, slug: str, month: int, day: int, gap: int = 2, max_n: int = 4096
) -> DayCount:
    """Count one title's pages on one day with a doubling probe and bisection

    Args:
        probe: callable taking a path string and returning an Outcome; in
            production a wrapper around client.get_page(path, content=False)
        slug (str): the slug to probe, already through slugify
        month (int): 1 to 12
        day (int): 1 to 31
        gap (int, optional): how many consecutive missing counters to
            tolerate before declaring the end. Defaults to 2.
        max_n (int, optional): never confirm a counter above this; caps the
            cost of a pathological title. Defaults to 4096.

    Returns:
        DayCount: highest counter found, probes spent, failures, found paths
    """
    # Set of every probe made for this day
    seen = {}

    def look(n):
        # Ask whether page number n exists, probing at most once per n.
        if n not in seen:
            # Counter 1 has no suffix (there is no "-1" page), so pass None.
            path = build_path(slug, month, day, None if n == 1 else n)
            # The probe hits the network; remember its answer so we don't repeat it.
            seen[n] = probe(path)
        # True only for a confirmed page. NOT_FOUND and FAILED both give False.
        return seen[n] is Outcome.FOUND

    def alive(n):
        # Is there a page at n, or within the next `gap` counters after it?
        for candidate in range(n, n + gap + 1):
            if look(candidate):
                # Stop at the first hit and say where it was.
                return candidate
        # The whole window was empty: treat this as the end of the day's pages.
        return None

    # Start at the bare path. If nothing exists at 1 (or in its gap window),
    # the day has no pages and there is nothing more to probe.
    first = alive(1)
    if first is None:
        highest = 0
    else:
        # Doubling phase. `last_hit` is always a counter we have confirmed exists.
        last_hit = first
        # Next counter to try. Goes doubles until we overshoot.
        n = 2
        # `first_miss` will be the first counter whose whole window was empty.
        first_miss = None
        while n <= max_n:
            found = alive(n)
            if found is None:
                # Overshot: nothing at n or just after it. Remember and stop.
                first_miss = n
                break
            # Still finding pages; move the floor up and double the step.
            last_hit = found
            n *= 2
        if first_miss is None:
            # The loop ended because n passed max_n, not because of a miss,
            # so cap the search just above the limit.
            first_miss = max_n + 1

        # Bisection phase. The highest page is at `last_hit` or somewhere
        # between it and `first_miss`. Halve that bracket until it closes.
        while first_miss - last_hit > 1:
            # // is integer division, so middle is a whole counter.
            middle = (last_hit + first_miss) // 2
            found = alive(middle)
            if found is None:
                # Empty at middle: the answer is below it.
                first_miss = middle
            else:
                # A page exists at `found` (middle or just after it): the
                # answer is there or above, so raise the floor.
                last_hit = found
        # Adjacent last_hit and first_miss means last_hit is the last confirmed page.
        highest = last_hit

    # One probe per entry in the memo, so its size is the request count.
    requests = len(seen)
    # Count how many of those probes came back FAILED (network or API error).
    failures = sum(1 for o in seen.values() if o is Outcome.FAILED)
    # Rebuild the path for every counter we probed and found, in order.
    # This lists only what we touched, not every page the day has.
    paths = [
        build_path(slug, month, day, None if n == 1 else n)
        for n in sorted(seen)
        if seen[n] is Outcome.FOUND
    ]
    return DayCount(slug, month, day, highest, requests, failures, paths)


def crowd_check(
    probe, slugs: list[str], days: list[tuple[int, int]], gap: int = 2, done=frozenset()
):
    """Run count_day over every slug and day, skipping days already done

    Args:
        probe: callable taking a path and returning an Outcome
        slugs (list[str]): slugs to check, outer loop
        days (list[tuple[int, int]]): (month, day) pairs to check, inner loop
        gap (int, optional): passed through to count_day. Defaults to 2.
        done (optional): set of (slug, month, day) already recorded, from
            load_done. Defaults to an empty frozenset.

    Yields:
        DayCount: one per (slug, day) not in done, slugs outer, days inner
    """
    for slug in slugs:
        for month, day in days:
            if (slug, month, day) in done:
                continue
            yield count_day(probe, slug, month, day, gap=gap)


def save_day_count(conn: Connection, dc: DayCount, ts: float):
    """Upsert one DayCount into the crowd table

    Args:
        conn (Connection): database connection from db.connect
        dc (DayCount): the result to store; paths are not stored
        ts (float): when the check ran, stored as checked_at
    """
    sql = """
    INSERT INTO crowd (slug, month, day, highest, requests, failures, checked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(slug, month, day) DO UPDATE SET
    highest    = excluded.highest,
    requests   = excluded.requests,
    failures   = excluded.failures,
    checked_at = excluded.checked_at
    """
    params = (dc.slug, dc.month, dc.day, dc.highest, dc.requests, dc.failures, ts)
    conn.execute(sql, params)
    conn.commit()


def load_done(conn: Connection) -> set[tuple[str, int, int]]:
    """Load the (slug, month, day) tuples already in the crowd table

    Args:
        conn (Connection): database connection from db.connect

    Returns:
        set[tuple[str, int, int]]: every recorded (slug, month, day)
    """
    sql = "SELECT slug, month, day FROM crowd"
    rows = conn.execute(sql).fetchall()
    return {(row["slug"], row["month"], row["day"]) for row in rows}
