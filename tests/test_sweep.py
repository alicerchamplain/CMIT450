"""Tests for graphwatch.sweep.

sweep_day is driven by a fake fetch that answers from a set of counters that
exist for one slug and day, records every path it was asked for, and never
touches the network. The generator's DaySweep summary is read from
StopIteration.value, the way the cli will read it.
"""

import pytest

from graphwatch.sweep import DaySweep, sweep_day
from graphwatch.telegraph import Fetch, Outcome, build_path

SLUG, MONTH, DAY = "Hello", 10, 17


def counter(path: str) -> int:
    """The counter a path was built with; the bare path is counter 1."""
    prefix = build_path(SLUG, MONTH, DAY)
    assert path.startswith(prefix)
    rest = path[len(prefix):]
    return int(rest[1:]) if rest else 1


def make_fetch(existing, failed=()):
    """A fetch over the counters in `existing`; `failed` counters FAIL instead."""
    asked = []

    def fetch(path: str) -> Fetch:
        n = counter(path)
        asked.append(n)
        if n in failed:
            return Fetch(path, Outcome.FAILED, None, "request error", None, 1)
        if n in existing:
            return Fetch(path, Outcome.FOUND, {"path": path, "content": []}, None, 200, 1)
        return Fetch(path, Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND", 200, 1)

    return fetch, asked


def drive(gen) -> tuple[list[Fetch], DaySweep]:
    """Exhaust a sweep_day generator, returning what it yielded and its summary."""
    yielded = []
    while True:
        try:
            yielded.append(next(gen))
        except StopIteration as stop:
            return yielded, stop.value


def sweep(existing, failed=(), start=1, expected=0, gap=2, cap=None):
    fetch, asked = make_fetch(existing, failed)
    yielded, summary = drive(sweep_day(fetch, SLUG, MONTH, DAY, start, expected, gap, cap))
    return yielded, summary, asked


# --- DaySweep ------------------------------------------------------------------


def test_daysweep_is_frozen():
    ds = DaySweep(SLUG, MONTH, DAY, 1, False, 0, 0, [])
    with pytest.raises(AttributeError):
        ds.next_n = 2


def test_summary_carries_the_slug_and_day():
    _, s, _ = sweep(existing=set())
    assert (s.slug, s.month, s.day) == (SLUG, MONTH, DAY)


# --- the walk ---------------------------------------------------------------------


def test_bare_path_is_counter_one():
    fetch, asked = make_fetch({1})
    drive(sweep_day(fetch, SLUG, MONTH, DAY, 1, 0, 2))
    assert asked[0] == 1
    # and the path actually requested had no suffix
    fetch, _ = make_fetch({1})
    paths = []
    drive(sweep_day(lambda p: paths.append(p) or fetch(p), SLUG, MONTH, DAY, 1, 0, 2))
    assert paths[0] == "Hello-10-17"
    assert paths[1] == "Hello-10-17-2"


def test_found_pages_are_yielded_in_counter_order():
    yielded, s, _ = sweep(existing={1, 2, 3})
    assert [counter(f.path) for f in yielded] == [1, 2, 3]
    assert s.found == ["Hello-10-17", "Hello-10-17-2", "Hello-10-17-3"]


def test_found_records_the_api_path_not_the_requested_one():
    # The API may spell the path differently (case); store what it says.
    def fetch(path):
        return Fetch(path, Outcome.FOUND, {"path": path.upper()}, None, 200, 1) if counter(path) == 1 \
            else Fetch(path, Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND", 200, 1)
    _, s = drive(sweep_day(fetch, SLUG, MONTH, DAY, 1, 0, 1))
    assert s.found == ["HELLO-10-17"]


def test_gap_tolerates_up_to_gap_consecutive_misses():
    # Pages at 1, 2, 4, 5. Miss at 3 is inside the gap; 6, 7, 8 are three in a row.
    yielded, s, asked = sweep(existing={1, 2, 4, 5}, gap=2)
    assert asked == [1, 2, 3, 4, 5, 6, 7, 8]
    assert len(yielded) == 4
    assert s.next_n == 9
    assert s.done is True
    assert s.requests == 8
    assert s.failures == 0


def test_gap_zero_stops_at_the_first_miss():
    _, s, asked = sweep(existing={1, 2, 4}, gap=0)
    assert asked == [1, 2, 3]
    assert s.found == ["Hello-10-17", "Hello-10-17-2"]
    assert s.done is True


def test_a_hit_resets_the_miss_run():
    # 1, miss, miss, 4, miss, miss, 7: with gap 2 every run of two is tolerated.
    _, s, asked = sweep(existing={1, 4, 7}, gap=2)
    assert asked == list(range(1, 11))
    assert len(s.found) == 3
    assert s.next_n == 11


def test_empty_day_costs_gap_plus_one_requests():
    yielded, s, asked = sweep(existing=set(), gap=2)
    assert yielded == []
    assert asked == [1, 2, 3]
    assert s.requests == 3
    assert s.done is True
    assert s.next_n == 4


# --- expected, from the crowd table -------------------------------------------------


def test_misses_below_expected_never_stop_the_walk():
    # Counters 3 to 6 were deleted; the crowd table says the day reaches 10.
    _, s, asked = sweep(existing={1, 2, 7, 8, 9, 10}, expected=10, gap=2)
    assert asked == list(range(1, 14))  # walks to 10, then 11, 12, 13 miss
    assert len(s.found) == 6
    assert s.done is True


def test_pages_above_expected_are_still_found():
    # The crowd check counted 3; two more were posted since.
    _, s, asked = sweep(existing={1, 2, 3, 4, 5}, expected=3, gap=2)
    assert len(s.found) == 5
    assert s.next_n == 9


def test_expected_larger_than_reality_walks_to_expected_then_gap():
    _, s, asked = sweep(existing={1}, expected=5, gap=2)
    assert asked == [1, 2, 3, 4, 5, 6, 7, 8]
    assert s.found == ["Hello-10-17"]
    assert s.done is True


# --- resume ------------------------------------------------------------------------------


def test_resume_starts_at_start_and_never_looks_below_it():
    _, s, asked = sweep(existing={1, 2, 3, 4, 5, 6}, start=5, gap=2)
    assert asked == [5, 6, 7, 8, 9]
    assert min(asked) == 5
    assert s.found == ["Hello-10-17-5", "Hello-10-17-6"]
    assert s.next_n == 10


def test_resume_from_the_summary_of_a_previous_run_continues_cleanly():
    # First run stops by budget after counter 3 (simulated by capping at 3).
    _, first, _ = sweep(existing={1, 2, 3, 4, 5}, cap=3)
    assert first.next_n == 4
    _, second, asked = sweep(existing={1, 2, 3, 4, 5}, start=first.next_n, gap=2)
    assert asked == [4, 5, 6, 7, 8]
    assert second.found == ["Hello-10-17-4", "Hello-10-17-5"]


def test_resume_counts_only_this_runs_requests():
    _, s, _ = sweep(existing={1, 2, 3}, start=3, gap=1)
    assert s.requests == 3  # 3 found, 4 and 5 miss


# --- failures ------------------------------------------------------------------------------


def test_failed_probes_are_counted_and_treated_as_misses():
    _, s, asked = sweep(existing={1, 2, 5}, failed={3}, gap=2)
    # 3 FAILED and 4 NOT_FOUND are two misses, 5 is found, then 6, 7, 8 miss.
    assert asked == [1, 2, 3, 4, 5, 6, 7, 8]
    assert s.failures == 1
    assert len(s.found) == 3
    assert s.done is True


def test_a_tail_of_only_failures_leaves_the_day_not_done():
    _, s, asked = sweep(existing={1, 2}, failed={3, 4, 5}, gap=2)
    assert asked == [1, 2, 3, 4, 5]
    assert s.failures == 3
    assert s.done is False
    assert s.next_n == 6  # the next run retries from here


def test_a_mixed_tail_still_ends_the_day():
    # Two failures and one real not-found: the not-found is evidence the day is over.
    _, s, _ = sweep(existing={1}, failed={2, 3}, gap=2)
    assert s.failures == 2
    assert s.done is True


def test_failures_below_expected_do_not_stop_the_walk():
    _, s, asked = sweep(existing={1, 5}, failed={2, 3, 4}, expected=5, gap=1)
    assert 5 in asked
    assert len(s.found) == 2
    assert s.failures == 3


# --- cap ---------------------------------------------------------------------------------------


def test_cap_stops_after_cap_counters_and_marks_the_day_done():
    _, s, asked = sweep(existing=set(range(1, 100)), expected=99, cap=3)
    assert asked == [1, 2, 3]
    assert s.next_n == 4
    assert s.done is True
    assert s.requests == 3


def test_cap_applies_even_below_expected():
    _, s, asked = sweep(existing=set(range(1, 100)), expected=99, gap=2, cap=10)
    assert max(asked) == 10


def test_cap_larger_than_the_day_changes_nothing():
    _, with_cap, asked_cap = sweep(existing={1, 2}, gap=2, cap=1000)
    _, no_cap, asked_none = sweep(existing={1, 2}, gap=2)
    assert asked_cap == asked_none
    assert with_cap == no_cap


def test_cap_with_resume_is_an_absolute_counter_not_a_count():
    # start=8, cap=10: only counters 8, 9, 10 are fetched.
    _, s, asked = sweep(existing=set(range(1, 100)), start=8, expected=99, cap=10)
    assert asked == [8, 9, 10]
    assert s.next_n == 11


# --- generator behaviour -------------------------------------------------------------------------


def test_sweep_day_is_lazy_the_caller_can_stop_early():
    fetch, asked = make_fetch(set(range(1, 100)), ())
    gen = sweep_day(fetch, SLUG, MONTH, DAY, 1, 99, 2)
    next(gen)
    next(gen)
    gen.close()
    assert asked == [1, 2]  # nothing fetched beyond what was consumed


def test_summary_is_the_generator_return_value():
    fetch, _ = make_fetch({1})
    gen = sweep_day(fetch, SLUG, MONTH, DAY, 1, 0, 1)
    with pytest.raises(StopIteration) as stop:
        while True:
            next(gen)
    assert isinstance(stop.value.value, DaySweep)
