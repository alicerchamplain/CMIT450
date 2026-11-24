"""Sweep functionality to get data from Telegraph"""

from collections.abc import Iterator
from dataclasses import dataclass

from graphwatch.telegraph import Fetch, Outcome, build_path


@dataclass(frozen=True)
class DaySweep:
    """The result of a slug swept on one calendar day"""

    slug: str  # the slug as probed, from slugify
    month: int  # 1 to 12
    day: int  # 1 to 31
    next_n: int  # next counter to check; after a tail of failures, the first counter that failed
    done: bool  # if the day has been swept already
    requests: int  # probes spent on this day
    failures: int  # probes that came back FAILED
    found: list[str]  # paths probed and found


def sweep_day(
    fetch,
    slug: str,
    month: int,
    day: int,
    start: int,
    expected: int,
    gap: int,
    cap: int | None = None,
    hint=None,
) -> Iterator[Fetch]:
    """Walks the counters of one slug on one day, from start until the day has ended

    Counters up to expected, the crowd count, are fetched whatever they
    hold. Past it the walk ends at the first run of more than gap counters
    with no page. A run that is all failures leaves the day not done, to be
    walked again from the first counter that failed.

    Args:
        fetch: callable taking a path and returning a Fetch
        slug (str): the slug to walk, already through slugify
        month (int): 1 to 12
        day (int): 1 to 31
        start (int): the first counter to fetch; 1 is the bare path
        expected (int): the highest counter the crowd check confirmed
        gap (int): how many consecutive missing counters to tolerate past expected
        cap (int | None, optional): the last counter to fetch. Defaults to None.
        hint (optional): callable taking an iterable of the paths the walk is
            certain to fetch next, so that they can be fetched ahead of it;
            see telegraph.Ahead. Defaults to None.

    Returns:
        DaySweep: where the walk stopped, whether the day is done, and what it cost

    Yields:
        Iterator[Fetch]: each page found, in counter order
    """

    def path_of(counter: int) -> str:
        return build_path(slug, month, day, None if counter == 1 else counter)

    n = start
    miss = 0
    miss_failed = 0
    requests = 0
    failures = 0
    found = []
    done = False
    while True:
        if hint is not None:
            # How far the walk goes whatever the next answers are. Up to
            # expected nothing stops it, and past it a run of gap + 1 misses
            # does, so it reads on until the run it is in could be that long.
            sure = expected + gap + 1 if n <= expected else n + gap - miss
            if cap is not None:
                sure = min(sure, cap)
            hint(path_of(counter) for counter in range(n, sure + 1))
        path = path_of(n)
        result = fetch(path)
        requests += 1
        if result.outcome is Outcome.FOUND:
            yield result
            miss = 0
            miss_failed = 0
            found.append(result.page["path"])
        elif result.outcome is Outcome.FAILED:
            miss += 1
            failures += 1
            miss_failed += 1
        elif result.outcome is Outcome.NOT_FOUND:
            miss += 1

        n += 1
        if n == expected + 1:
            miss = 0
            miss_failed = 0

        if cap is not None and n > cap:
            done = True
            break
        if n <= expected:
            continue
        if miss > gap:
            if miss_failed == miss:
                # Every counter of this run failed: nothing says the day is
                # over, only that Telegraph did not answer. The day stays
                # open, and the next walk starts at the first of them, not
                # after the last: a page behind a failure is still to fetch.
                done = False
                n -= miss
            else:
                done = True
            break
    return DaySweep(slug, month, day, n, done, requests, failures, found)
