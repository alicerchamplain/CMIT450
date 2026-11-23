"""Shared by every test module: a clock for the tests that time a pattern.

A page is up to 64 KB and whoever posts it chooses every character, so the
suite holds tests that a pattern stays quick on a long run. Their limit is one
second, chosen on the laptop, where a good pattern takes a tenth of that and a
bad one took 4 to 54 seconds.

A wall clock and a fixed second do not travel. The VPS has one CPU, slower
than the laptop's, and on 23 November the slowest of these tests took 1.0 to
1.2 seconds there while the re-redaction pass was running beside them: half
of that was time spent waiting for the CPU. Nothing was slow; the second was
the laptop's. (The slowest, a test of the JWT pattern, was removed that
night; the tests of a crafted page were the next.)

So the clock here counts CPU time, which another process cannot add to, and
divides it by how many times slower than the laptop this machine is: 5 to 7
on the VPS. "Under a second" then means what it meant where the limit was
chosen.
"""

import re
import time

import pytest

# The yardstick: one pattern over one text, both fixed. The pattern never
# matches: from every letter it reads up to 400 more, finds no digit and gives
# them back, which is the kind of work the timed patterns do on a long run.
# YARDSTICK_S is the CPU time it took on the laptop (22 November 2026, Python
# 3.14, quickest of three). The VPS took 0.36 to 0.51 s the same night
YARDSTICK_PATTERN = re.compile(r"[a-z]{2,400}\d")
YARDSTICK_TEXT = "abcdefgh" * 4000
YARDSTICK_S = 0.070
YARDSTICK_RUNS = 3


def cpu_seconds(work) -> float:
    """Function to time one piece of work in CPU seconds of this process

    Args:
        work: a function of no arguments

    Returns:
        float: the CPU time work() took; time spent waiting for another
            process to leave the CPU is not counted
    """
    started = time.process_time()
    work()
    return time.process_time() - started


def read_yardstick() -> None:
    for _match in YARDSTICK_PATTERN.finditer(YARDSTICK_TEXT):
        pass


@pytest.fixture(scope="session")
def slowdown() -> float:
    """How many times slower than the laptop this machine is, and never under 1

    The quickest of a few runs, measured once per session. A machine quicker
    than the laptop keeps the plain second.
    """
    quickest = min(cpu_seconds(read_yardstick) for _ in range(YARDSTICK_RUNS))
    return max(1.0, quickest / YARDSTICK_S)


@pytest.fixture
def laptop_seconds(slowdown):
    """A clock: laptop_seconds(work) runs work() and gives the seconds it would
    have taken on the laptop, so a test can say `< 1.0` and mean the same thing
    on every machine
    """

    def clock(work) -> float:
        return cpu_seconds(work) / slowdown

    return clock
