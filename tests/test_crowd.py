"""Tests for graphwatch.crowd.

The crowd check never sees the network here. Each test builds a fake probe
from a set of counters that "exist" for one slug and day, and the check is
judged on what it concludes and on how many probes it spent getting there.
"""

from datetime import date

import pytest

from graphwatch.crowd import (
    DayCount,
    count_day,
    count_only_slugs,
    crowd_check,
    fit_window,
    load_done,
    load_expected,
    recent_days,
    save_day_count,
    sweep_cost,
)
from graphwatch.db import connect
from graphwatch.telegraph import Outcome, build_path

T0 = 1_700_000_000.0


class FakeProbe:
    """probe(path) -> Outcome, backed by a set of existing counters.

    Counter 1 is the bare path (finding 5: there is no "-1" page), counter n
    for n >= 2 is the path with "-n". Records every path asked for.
    """

    def __init__(self, slug="Hello", month=10, day=24, existing=(), failing=()):
        self.slug, self.month, self.day = slug, month, day
        self.existing = {self._path(n) for n in existing}
        self.failing = {self._path(n) for n in failing}
        self.calls = []

    def _path(self, n):
        return build_path(self.slug, self.month, self.day, None if n == 1 else n)

    def __call__(self, path):
        self.calls.append(path)
        if path in self.failing:
            return Outcome.FAILED
        return Outcome.FOUND if path in self.existing else Outcome.NOT_FOUND


def check(existing, gap=2, failing=(), **kw):
    probe = FakeProbe(existing=existing, failing=failing)
    result = count_day(probe, probe.slug, probe.month, probe.day, gap=gap, **kw)
    return result, probe


# --------------------------------------------------------------------------
# count_day: what it concludes
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "existing, gap, highest",
    [
        ([], 2, 0),  # no pages
        ([1], 2, 1),  # only the bare page
        ([1, 2, 3], 2, 3),  # a run with no holes
        ([2, 3], 1, 3),  # a deleted bare page does not make the day empty
        ([1, 2, 3, 5], 1, 5),  # a hole no wider than the gap is stepped over
        ([1, 2, 3, 6], 1, 3),  # 4 and 5 missing is two in a row; gap=1 stops at 3
        ([1, 2, 3, 5], 0, 3),  # gap 0 stops at the first miss
        (range(1, 155), 2, 154),  # a busy day like the known actor's Hello-10-17-154
    ],
)
def test_count_day_finds_the_highest_counter(existing, gap, highest):
    result, _ = check(existing=existing, gap=gap)
    assert result.highest == highest


def test_paths_are_the_found_ones_in_counter_order():
    result, _ = check(existing=[1, 2, 3], gap=0)
    assert result.paths == ["Hello-10-24", "Hello-10-24-2", "Hello-10-24-3"]


def test_paths_only_lists_pages_the_check_actually_probed():
    # Doubling skips counters: 1, 2, then 4 (miss) and 5 (hit). Counter 3
    # exists but was never asked about. The sweep walks every slot; the
    # crowd check only reports what it touched.
    result, probe = check(existing=[1, 2, 3, 5], gap=1)
    assert result.highest == 5
    assert "Hello-10-24-3" not in probe.calls
    assert result.paths == ["Hello-10-24", "Hello-10-24-2", "Hello-10-24-5"]


def test_highest_is_capped_by_max_n():
    # Doubling lands on the cap itself (1, 2, 4, ... 512) and nothing is asked
    # after it: no bisection up to the cap, no look past it.
    result, _ = check(existing=range(1, 5000), max_n=512)
    assert result.highest == 512
    assert result.requests == 10


def test_gap_window_cannot_look_past_max_n():
    # Seen on the droplet: Kristina 10-04 reported 4098 with max_n=4096. The
    # page at the cap was missing but one inside the gap window existed, and
    # alive() returned that later counter. The cap is a promise: no counter
    # above it is ever confirmed, and no probe is spent above it either.
    existing = set(range(1, 5000)) - {512}
    result, probe = check(existing=existing, max_n=512)
    assert result.highest == 511
    assert "Hello-10-24-513" not in probe.calls
    assert "Hello-10-24-514" not in probe.calls


def test_default_max_n_is_two_to_the_twenty():
    # A probe that says FOUND to everything must still terminate, and must
    # stop at the default cap. Doubling then bisecting means a cap of 2**20
    # costs only a few dozen probes, so a large default is nearly free.
    always_found = lambda path: Outcome.FOUND
    result = count_day(always_found, "Hello", 10, 24)
    assert result.highest == 2**20
    assert result.requests == 21  # 1, 2, 4, ... 2**20 and nothing after


# --------------------------------------------------------------------------
# count_day: how it probes
# --------------------------------------------------------------------------


def test_first_probe_is_the_bare_path():
    _, probe = check(existing=[1, 2])
    assert probe.calls[0] == "Hello-10-24"


def test_never_probes_a_dash_one_path():
    _, probe = check(existing=range(1, 20))
    assert not any(p.endswith("-10-24-1") for p in probe.calls)


def test_busy_day_costs_far_fewer_probes_than_pages():
    # Exponential probe then bisection, then a look past the end that is
    # capped at 32 counters: 154 pages in well under 154 requests.
    result, probe = check(existing=range(1, 155), gap=2)
    assert result.requests <= 60
    assert check(existing=range(1, 155), gap=2, lookahead=0)[0].requests <= 40


# --------------------------------------------------------------------------
# Looking past the end: a hole wider than the gap must not end the count
# --------------------------------------------------------------------------

# Hello on 3 November 2026: counters 128 to 130 were gone and the doubling
# probe landed exactly on them, so the count came back as 127 of 160.
HELLO_11_03 = [*range(1, 128), *range(131, 161)]


def test_a_hole_at_a_doubling_probe_does_not_end_the_count():
    result, _ = check(existing=HELLO_11_03, gap=2)
    assert result.highest == 160


def test_lookahead_zero_is_the_old_rule_and_stops_at_the_hole():
    result, _ = check(existing=HELLO_11_03, gap=2, lookahead=0)
    assert result.highest == 127


def test_a_hole_at_a_bisection_probe_does_not_end_the_count():
    # Doubling passes 128 and misses at 256; the first midpoint is 192, which
    # sits in a hole of three with pages on both sides.
    existing = [*range(1, 192), *range(195, 221)]
    assert check(existing=existing, gap=2, lookahead=0)[0].highest == 191
    assert check(existing=existing, gap=2)[0].highest == 220


def test_the_count_carries_on_past_several_holes():
    # The first look finds 131 and the count settles at 160; only a second
    # look, from there, reaches 170.
    existing = [*range(1, 128), *range(131, 161), *range(170, 181)]
    result, _ = check(existing=existing, gap=2)
    assert result.highest == 180


def test_a_hole_longer_than_the_look_still_ends_the_count():
    # 40 pages earn a look of 40 // 4 = 10 counters past the gap window (44 to
    # 53), so a hole of 14 is the end of the day as far as the count can tell.
    # The far pages stop at 62 so the doubling probe at 64 does not find them.
    existing = [*range(1, 41), *range(55, 63)]
    result, _ = check(existing=existing, gap=2)
    assert result.highest == 40


def test_the_look_grows_with_the_day_and_is_capped_by_lookahead():
    # After 40 the gap window covers 41 to 43 and the look covers 44 to 53.
    assert check(existing=[*range(1, 41), 53], gap=2)[0].highest == 53
    assert check(existing=[*range(1, 41), 54], gap=2)[0].highest == 40
    # A cap of 4 shortens it to 44 to 47. (48 to 50 is a bisection window, so
    # the page just outside the look is put at 51.)
    assert check(existing=[*range(1, 41), 47], gap=2, lookahead=4)[0].highest == 47
    assert check(existing=[*range(1, 41), 51], gap=2, lookahead=4)[0].highest == 40
    # Left alone the cap is 32: after 200 the look covers 204 to 235, not the
    # 50 counters a quarter of the day would earn.
    assert check(existing=[*range(1, 201), 235], gap=2)[0].highest == 235
    assert check(existing=[*range(1, 201), 236], gap=2)[0].highest == 200


def test_the_look_past_the_end_is_at_most_lookahead_probes():
    # Fewer than 32 here: bisection already asked about some of those counters.
    plain, _ = check(existing=range(1, 1001), gap=2, lookahead=0)
    looked, _ = check(existing=range(1, 1001), gap=2)
    assert looked.highest == plain.highest == 1000
    assert plain.requests < looked.requests <= plain.requests + 32


def test_small_days_cost_exactly_what_they_did_before():
    # Under four pages the look is 0 counters, so nothing extra is asked.
    for pages in (0, 1, 2, 3):
        plain, _ = check(existing=range(1, pages + 1), gap=2, lookahead=0)
        looked, _ = check(existing=range(1, pages + 1), gap=2)
        assert looked.requests == plain.requests


def test_the_look_past_the_end_stops_at_max_n():
    result, probe = check(existing=range(1, 101), gap=2, max_n=100)
    assert result.highest == 100
    assert not any(path.endswith(("-101", "-102", "-110")) for path in probe.calls)


@pytest.mark.parametrize("existing", [range(1, 155), HELLO_11_03])
def test_every_path_is_probed_once_and_every_probe_is_counted(existing):
    # With and without a look past the end.
    result, probe = check(existing=existing, gap=2)
    assert len(probe.calls) == len(set(probe.calls)) == result.requests
    assert result.failures == 0


@pytest.mark.parametrize("gap, probes", [(2, 3), (0, 1)])
def test_empty_day_costs_only_the_gap_window(gap, probes):
    # bare, then gap more; nothing else to look at.
    result, probe = check(existing=[], gap=gap)
    assert (result.highest, result.paths) == (0, [])
    assert result.requests == probes == len(probe.calls)


def test_the_default_gap_is_two():
    # The same empty day, asked without a gap: by count_day and through crowd_check.
    assert count_day(FakeProbe(), "Hello", 10, 24).requests == 3
    assert next(crowd_check(FakeProbe(), ["Hello"], [(10, 24)])).requests == 3


def test_probes_go_up_by_doubling_before_bisecting():
    _, probe = check(existing=range(1, 100), gap=0)
    counters = [
        1 if p == "Hello-10-24" else int(p.rsplit("-", 1)[1]) for p in probe.calls
    ]
    assert counters[:7] == [1, 2, 4, 8, 16, 32, 64]
    assert 128 in counters  # first miss
    assert all(64 < c < 128 for c in counters[8:])  # bisection stays in the bracket


def test_builds_paths_with_build_path_format():
    probe = FakeProbe(slug="Povіstka", month=3, day=7, existing=[1, 2])
    result = count_day(probe, "Povіstka", 3, 7)
    assert result.paths == ["Povіstka-03-07", "Povіstka-03-07-2"]


# --------------------------------------------------------------------------
# count_day: failures
# --------------------------------------------------------------------------


def test_failed_probe_is_counted_and_treated_as_not_found():
    result, _ = check(existing=[1, 2, 3], failing=[3], gap=0)
    assert result.failures == 1
    assert result.highest == 2  # 3 could not be confirmed
    assert result.paths == ["Hello-10-24", "Hello-10-24-2"]  # nor listed as found


def test_failed_probe_inside_gap_window_does_not_hide_later_pages():
    # 2 fails on the wire; with gap=1 the check looks at 3, finds it, and
    # carries on, so the failure costs nothing but an honest count.
    result, _ = check(existing=[1, 2, 3, 4, 5], failing=[2], gap=1)
    assert result.highest == 5
    assert result.failures == 1


# --------------------------------------------------------------------------
# recent_days
# --------------------------------------------------------------------------


def test_recent_days_ends_today_oldest_first():
    assert recent_days(date(2026, 11, 1), 3) == [(10, 30), (10, 31), (11, 1)]


def test_recent_days_one_is_just_today():
    assert recent_days(date(2026, 10, 31), 1) == [(10, 31)]


def test_recent_days_crosses_a_year_boundary():
    assert recent_days(date(2026, 1, 2), 3) == [(12, 31), (1, 1), (1, 2)]


def test_recent_days_fourteen_has_fourteen_distinct_days():
    days = recent_days(date(2026, 10, 31), 14)
    assert len(days) == 14 == len(set(days))
    assert days[0] == (10, 18)


# --------------------------------------------------------------------------
# crowd_check: many slugs, many days, resumable
# --------------------------------------------------------------------------


class MultiProbe:
    """One fake probe over several slugs and days: {(slug, month, day): [counters]}."""

    def __init__(self, world):
        self.existing = set()
        for (slug, month, day), counters in world.items():
            for n in counters:
                self.existing.add(build_path(slug, month, day, None if n == 1 else n))
        self.calls = []

    def __call__(self, path):
        self.calls.append(path)
        return Outcome.FOUND if path in self.existing else Outcome.NOT_FOUND


def test_crowd_check_yields_one_daycount_per_slug_per_day():
    probe = MultiProbe({("Hello", 10, 24): [1, 2], ("Test", 10, 23): [1]})
    results = list(crowd_check(probe, ["Hello", "Test"], [(10, 23), (10, 24)], gap=0))
    assert [(r.slug, r.month, r.day, r.highest) for r in results] == [
        ("Hello", 10, 23, 0),
        ("Hello", 10, 24, 2),
        ("Test", 10, 23, 1),
        ("Test", 10, 24, 0),
    ]


def test_crowd_check_is_lazy():
    # A generator: nothing is probed until the caller asks for a result.
    probe = MultiProbe({})
    gen = crowd_check(probe, ["Hello"], [(10, 24)])
    assert probe.calls == []
    next(gen)
    assert probe.calls != []


@pytest.mark.parametrize("slug, key", [("Hello", "hello"), ("Hİ", "hi")])
def test_crowd_check_skips_done_pairs(slug, key):
    # done holds normalized keys, as load_done returns them, and the raw word
    # list slug has to match its key. For Hİ a casefold is not enough: the dot
    # it leaves above the i goes too.
    probe = MultiProbe({(slug, 10, 24): [1]})
    done = {(key, 10, 23)}
    results = list(crowd_check(probe, [slug], [(10, 23), (10, 24)], done=done))
    assert [(r.month, r.day) for r in results] == [(10, 24)]
    assert not any("10-23" in p for p in probe.calls)


def test_crowd_check_passes_gap_through():
    probe = MultiProbe({("Hello", 10, 24): [2]})
    assert next(crowd_check(probe, ["Hello"], [(10, 24)], gap=0)).highest == 0
    assert next(crowd_check(probe, ["Hello"], [(10, 24)], gap=1)).highest == 2


# --------------------------------------------------------------------------
# save_day_count / load_done
# --------------------------------------------------------------------------


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def test_save_and_load_roundtrip(conn):
    save_day_count(conn, DayCount("Hello", 10, 24, 3, 7, 0, []), T0)
    save_day_count(conn, DayCount("Test", 10, 23, 0, 3, 1, []), T0)
    assert load_done(conn) == {("hello", 10, 24), ("test", 10, 23)}


def test_save_stores_the_numbers(conn):
    save_day_count(conn, DayCount("Hello", 10, 24, 3, 7, 1, []), T0)
    row = conn.execute("SELECT * FROM crowd").fetchone()
    assert (row["slug"], row["month"], row["day"]) == ("hello", 10, 24)
    assert (row["highest"], row["requests"], row["failures"], row["checked_at"]) == (
        3,
        7,
        1,
        T0,
    )


def test_save_same_day_again_replaces_not_duplicates(conn):
    save_day_count(conn, DayCount("Hello", 10, 24, 3, 7, 0, []), T0)
    save_day_count(conn, DayCount("Hello", 10, 24, 4, 9, 2, []), T0 + 1)
    rows = conn.execute(
        "SELECT highest, requests, failures, checked_at FROM crowd"
    ).fetchall()
    assert [tuple(r) for r in rows] == [(4, 9, 2, T0 + 1)]


def test_save_commits(tmp_path):
    db = tmp_path / "g.sqlite"
    c1 = connect(db)
    save_day_count(c1, DayCount("Hello", 10, 24, 1, 1, 0, []), T0)
    c2 = connect(db)
    assert load_done(c2) == {("hello", 10, 24)}
    c1.close()
    c2.close()


def test_resume_end_to_end(conn):
    # Night one did Hello 10-23; night two must only do 10-24.
    save_day_count(conn, DayCount("Hello", 10, 23, 1, 1, 0, []), T0)
    probe = MultiProbe({("Hello", 10, 24): [1]})
    for dc in crowd_check(probe, ["Hello"], [(10, 23), (10, 24)], done=load_done(conn)):
        save_day_count(conn, dc, T0 + 1)
    assert load_done(conn) == {("hello", 10, 23), ("hello", 10, 24)}
    assert all("10-24" in p for p in probe.calls)


# --------------------------------------------------------------------------
# planning the sweep from the crowd table (issue #19)
# --------------------------------------------------------------------------

TODAY = date(2026, 11, 1)


def seed(conn, rows):
    """rows: (slug, month, day, highest). Requests and failures are irrelevant here."""
    for slug, month, day, highest in rows:
        save_day_count(conn, DayCount(slug, month, day, highest, 1, 0, []), 0.0)


def test_count_only_slugs_averages_pages_per_counted_day(conn):
    # Big averages 800 a day over two days; Small never gets near it.
    seed(conn, [("Big", 10, 31, 1_000), ("Big", 11, 1, 600), ("Small", 11, 1, 699)])
    assert count_only_slugs(conn, 700) == {"big"}


def test_count_only_slugs_does_not_grow_with_the_number_of_days(conn):
    # 184 pages a day for 60 days is 11,040 in total, which a sum over the
    # table would exclude at 10,000. This is Hello; it must stay swept.
    seed(conn, [("Hello", 10, d, 184) for d in range(1, 31)])
    seed(conn, [("Hello", 11, d, 184) for d in range(1, 31)])
    assert count_only_slugs(conn, 700) == set()


def test_count_only_slugs_one_burst_day_does_not_exclude_a_quiet_title(conn):
    # 9,200 pages on one day out of 42 averages about 240 a day.
    seed(conn, [("Free", 10, d, 20) for d in range(1, 32)])
    seed(conn, [("Free", 11, d, 20) for d in range(1, 11)])
    seed(conn, [("Free", 11, 11, 9_200)])
    assert count_only_slugs(conn, 700) == set()


def test_count_only_slugs_empty_days_pull_the_average_down(conn):
    # A counted day with no pages is still a day: (2,000 + 0 + 0) / 3 is under 700.
    seed(conn, [("Burst", 11, 1, 2_000), ("Burst", 11, 2, 0), ("Burst", 11, 3, 0)])
    assert count_only_slugs(conn, 700) == set()


def test_count_only_slugs_threshold_is_inclusive(conn):
    seed(conn, [("Exact", 10, 31, 600), ("Exact", 11, 1, 800)])
    assert count_only_slugs(conn, 700) == {"exact"}


def test_count_only_slugs_empty_table(conn):
    assert count_only_slugs(conn, 1) == set()


def test_count_only_slugs_zero_threshold_returns_everything(conn):
    # 0 is a threshold like any other, not "off": every counted title is at
    # or above it, one with no pages too.
    seed(conn, [("A", 11, 1, 0), ("B", 11, 1, 3)])
    assert count_only_slugs(conn, 0) == {"a", "b"}


def test_sweep_cost_is_pages_plus_gap_plus_one_per_title_day(conn):
    seed(conn, [("A", 11, 1, 10), ("B", 11, 1, 0)])
    # A: 10 + 2 + 1 = 13; B: an empty day still costs the gap probes, 0 + 2 + 1 = 3
    assert sweep_cost(conn, [(11, 1)], 2, set()) == 16


def test_sweep_cost_gap_changes_the_overhead(conn):
    seed(conn, [("A", 11, 1, 10)])
    assert sweep_cost(conn, [(11, 1)], 0, set()) == 11
    assert sweep_cost(conn, [(11, 1)], 5, set()) == 16


def test_sweep_cost_only_counts_days_in_the_window(conn):
    # A day is its month and its day: the first of October is not in a
    # window that holds the first of November.
    seed(conn, [("A", 10, 1, 100), ("A", 11, 1, 10)])
    assert sweep_cost(conn, [(11, 1)], 2, set()) == 13
    assert sweep_cost(conn, [(10, 1), (11, 1)], 2, set()) == 116
    assert sweep_cost(conn, [], 2, set()) == 0


def test_sweep_cost_excludes_count_only_slugs(conn):
    seed(conn, [("Links", 11, 1, 100_000), ("A", 11, 1, 10)])
    assert sweep_cost(conn, [(11, 1)], 2, {"links"}) == 13


def test_sweep_cost_cap_bounds_each_title_day(conn):
    # Spike is cut to the cap; A, under it, costs what it did without one.
    seed(conn, [("Spike", 11, 1, 88_651), ("A", 11, 1, 10)])
    assert sweep_cost(conn, [(11, 1)], 2, set(), cap=500) == 503 + 13


def test_fit_window_returns_the_largest_window_within_budget(conn):
    # Each day costs 13 (10 pages + gap 2 + 1). Three days cost 39: a budget of
    # exactly 39 fits them, one request less does not, and 40 does not buy a fourth.
    seed(conn, [("A", 10, d, 10) for d in range(25, 32)] + [("A", 11, 1, 10)])
    assert fit_window(conn, TODAY, 38, 2, set()) == 2
    assert fit_window(conn, TODAY, 39, 2, set()) == 3
    assert fit_window(conn, TODAY, 40, 2, set()) == 3


def test_fit_window_zero_when_one_day_does_not_fit(conn):
    seed(conn, [("A", 11, 1, 1_000)])
    assert fit_window(conn, TODAY, 100, 2, set()) == 0


def test_fit_window_caps_at_max_days(conn):
    seed(conn, [("A", 11, 1, 1)])
    assert fit_window(conn, TODAY, 10**9, 2, set()) == 30
    assert fit_window(conn, TODAY, 10**9, 2, set(), max_days=7) == 7


def test_fit_window_counts_the_newest_days_first(conn):
    # Oct 31 is expensive, Nov 1 is cheap. Budget 20 fits Nov 1 alone (13),
    # not Nov 1 + Oct 31 (13 + 1003).
    seed(conn, [("A", 10, 31, 1_000), ("A", 11, 1, 10)])
    assert fit_window(conn, TODAY, 20, 2, set()) == 1


def test_fit_window_respects_exclusions_and_cap(conn):
    seed(conn, [("Links", 11, 1, 100_000), ("Spike", 11, 1, 5_000), ("A", 11, 1, 10)])
    # Uncapped, Spike alone (5,003) breaks a 1,000 budget: nothing fits.
    assert fit_window(conn, TODAY, 1_000, 2, {"links"}) == 0
    # Capped at 500, the day costs 503 + 13 = 516 and fits; days absent from
    # the table cost nothing, so the window runs to max_days.
    assert fit_window(conn, TODAY, 1_000, 2, {"links"}, cap=500, max_days=1) == 1


def test_fit_window_crosses_the_year_boundary(conn):
    # recent_days handles Dec -> Jan; the window must price Dec 31 when today is Jan 1.
    seed(conn, [("A", 12, 31, 10), ("A", 1, 1, 10)])
    jan1 = date(2027, 1, 1)
    assert fit_window(conn, jan1, 13, 2, set(), max_days=2) == 1  # Jan 1 only
    assert fit_window(conn, jan1, 26, 2, set(), max_days=2) == 2  # Dec 31 priced too


def test_load_expected_keys_are_normalized(conn):
    save_day_count(conn, DayCount("MOBІLІZACІYA", 10, 19, 4, 1, 0, []), T0)
    assert load_expected(conn) == {("mobіlіzacіya", 10, 19): 4}


def test_sweep_cost_exclusion_matches_across_unicode_case(conn):
    seed(conn, [("Hİ", 11, 1, 100_000), ("A", 11, 1, 10)])
    assert sweep_cost(conn, [(11, 1)], 2, {"hi"}) == 13
