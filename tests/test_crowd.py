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
    crowd_check,
    load_done,
    recent_days,
    save_day_count,
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
# DayCount
# --------------------------------------------------------------------------


def test_daycount_fields():
    dc = DayCount("Hello", 10, 24, 3, 5, 0, ["Hello-10-24", "Hello-10-24-2", "Hello-10-24-3"])
    assert (dc.slug, dc.month, dc.day) == ("Hello", 10, 24)
    assert dc.highest == 3
    assert dc.requests == 5
    assert dc.failures == 0
    assert dc.paths == ["Hello-10-24", "Hello-10-24-2", "Hello-10-24-3"]


# --------------------------------------------------------------------------
# count_day: what it concludes
# --------------------------------------------------------------------------


def test_no_pages_gives_zero():
    result, probe = check(existing=[])
    assert result.highest == 0
    assert result.paths == []
    assert result.requests == len(probe.calls)


def test_one_bare_page():
    result, _ = check(existing=[1])
    assert result.highest == 1
    assert result.paths == ["Hello-10-24"]


def test_three_pages():
    result, _ = check(existing=[1, 2, 3])
    assert result.highest == 3


def test_bare_page_deleted_but_second_exists():
    # Gap tolerance: a missing bare page does not mean the day is empty.
    result, _ = check(existing=[2, 3], gap=1)
    assert result.highest == 3


def test_gap_inside_the_run_is_tolerated_within_gap():
    result, _ = check(existing=[1, 2, 3, 5], gap=1)
    assert result.highest == 5


def test_gap_wider_than_tolerance_ends_the_run():
    # 4 and 5 missing is two in a row; gap=1 stops at 3.
    result, _ = check(existing=[1, 2, 3, 6], gap=1)
    assert result.highest == 3


def test_gap_zero_stops_at_the_first_miss():
    result, _ = check(existing=[1, 2, 3, 5], gap=0)
    assert result.highest == 3


def test_a_busy_day_like_the_known_actor():
    result, _ = check(existing=range(1, 155))  # Hello-10-17-154 exists
    assert result.highest == 154


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
    result, _ = check(existing=range(1, 5000), max_n=512)
    assert result.highest <= 512
    assert result.requests < 60


# --------------------------------------------------------------------------
# count_day: how it probes
# --------------------------------------------------------------------------


def test_first_probe_is_the_bare_path():
    _, probe = check(existing=[1, 2])
    assert probe.calls[0] == "Hello-10-24"


def test_never_probes_a_dash_one_path():
    _, probe = check(existing=range(1, 20))
    assert not any(p.endswith("-10-24-1") for p in probe.calls)


def test_never_probes_the_same_path_twice():
    _, probe = check(existing=range(1, 155))
    assert len(probe.calls) == len(set(probe.calls))


def test_requests_equals_probe_calls():
    result, probe = check(existing=range(1, 155))
    assert result.requests == len(probe.calls)


def test_busy_day_costs_far_fewer_probes_than_pages():
    # Exponential probe then bisection: 154 pages in well under 154 requests.
    result, probe = check(existing=range(1, 155), gap=2)
    assert result.requests <= 40


def test_empty_day_costs_only_the_gap_window():
    # bare, then gap more; nothing else to look at.
    result, _ = check(existing=[], gap=2)
    assert result.requests == 3


def test_empty_day_with_gap_zero_is_one_probe():
    result, _ = check(existing=[], gap=0)
    assert result.requests == 1


def test_probes_go_up_by_doubling_before_bisecting():
    _, probe = check(existing=range(1, 100), gap=0)
    counters = [1 if p == "Hello-10-24" else int(p.rsplit("-", 1)[1]) for p in probe.calls]
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


def test_failed_probe_inside_gap_window_does_not_hide_later_pages():
    # 2 fails on the wire; with gap=1 the check looks at 3, finds it, and
    # carries on, so the failure costs nothing but an honest count.
    result, _ = check(existing=[1, 2, 3, 4, 5], failing=[2], gap=1)
    assert result.highest == 5
    assert result.failures == 1


def test_no_failures_is_zero():
    result, _ = check(existing=[1])
    assert result.failures == 0


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


def test_crowd_check_skips_done_pairs():
    probe = MultiProbe({("Hello", 10, 24): [1]})
    done = {("Hello", 10, 23)}
    results = list(crowd_check(probe, ["Hello"], [(10, 23), (10, 24)], done=done))
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


def test_schema_has_a_crowd_table(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(crowd)").fetchall()}
    assert {"slug", "month", "day", "highest", "requests", "failures", "checked_at"} <= cols


def test_save_and_load_roundtrip(conn):
    save_day_count(conn, DayCount("Hello", 10, 24, 3, 7, 0, []), T0)
    save_day_count(conn, DayCount("Test", 10, 23, 0, 3, 1, []), T0)
    assert load_done(conn) == {("Hello", 10, 24), ("Test", 10, 23)}


def test_save_stores_the_numbers(conn):
    save_day_count(conn, DayCount("Hello", 10, 24, 3, 7, 1, []), T0)
    row = conn.execute("SELECT * FROM crowd").fetchone()
    assert (row["slug"], row["month"], row["day"]) == ("Hello", 10, 24)
    assert (row["highest"], row["requests"], row["failures"], row["checked_at"]) == (3, 7, 1, T0)


def test_save_same_day_again_replaces_not_duplicates(conn):
    save_day_count(conn, DayCount("Hello", 10, 24, 3, 7, 0, []), T0)
    save_day_count(conn, DayCount("Hello", 10, 24, 4, 9, 0, []), T0 + 1)
    rows = conn.execute("SELECT highest, checked_at FROM crowd").fetchall()
    assert len(rows) == 1
    assert (rows[0]["highest"], rows[0]["checked_at"]) == (4, T0 + 1)


def test_save_commits(tmp_path):
    db = tmp_path / "g.sqlite"
    c1 = connect(db)
    save_day_count(c1, DayCount("Hello", 10, 24, 1, 1, 0, []), T0)
    c2 = connect(db)
    assert load_done(c2) == {("Hello", 10, 24)}
    c1.close()
    c2.close()


def test_load_done_empty(conn):
    assert load_done(conn) == set()


def test_resume_end_to_end(conn):
    # Night one did Hello 10-23; night two must only do 10-24.
    save_day_count(conn, DayCount("Hello", 10, 23, 1, 1, 0, []), T0)
    probe = MultiProbe({("Hello", 10, 24): [1]})
    for dc in crowd_check(probe, ["Hello"], [(10, 23), (10, 24)], done=load_done(conn)):
        save_day_count(conn, dc, T0 + 1)
    assert load_done(conn) == {("Hello", 10, 23), ("Hello", 10, 24)}
    assert all("10-24" in p for p in probe.calls)
