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
    next_n: int  # next counter to check
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
) -> Iterator[Fetch]:
    """_summary_

    Args:
        fetch (_type_): _description_
        slug (str): _description_
        month (int): _description_
        day (int): _description_
        start (int): _description_
        expected (int): _description_
        gap (int): _description_
        cap (int | None, optional): _description_. Defaults to None.

    Returns:
        _type_: _description_

    Yields:
        Iterator[Fetch]: _description_
    """
    n = start
    miss = 0
    miss_failed = 0
    requests = 0
    failures = 0
    found = []
    done = False
    while True:
        path = build_path(slug, month, day, None if n == 1 else n)
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
                done = False
            else:
                done = True
            break
    return DaySweep(slug, month, day, n, done, requests, failures, found)
