"""Which pages would gain or lose the resolver flag under the rules in this checkout?

  .venv/bin/python plan/analysis/flag_diff.py DB

Run this on the machine that holds the full database BEFORE deploying a change
to the resolver rules. It scores the newest snapshot of every page in memory
with the rule table of the code it is run from and compares the result with
the flag stored by the last classify. It writes nothing and makes no request;
the database is opened read-only.

It prints the paths that lose the flag and the paths that gain it, with the
old and new score, and for the pages that keep the flag how many changed
score. Held-out pages are counted and never named. A page whose newest
snapshot has no stored score is compared against the newest snapshot that has
one, which is what "flagged" means to the re-poll.

The rules of 22 November are meant to drop the email and version-number false
positives and nothing else. This is how to see that on the full table: every
path under "lose the flag" should be one of those, and none should be Hello.
"""

import argparse
import sqlite3
from collections import Counter
from pathlib import Path

from graphwatch.classify import body_hash, classify_page, computed_rules, templated_hashes
from graphwatch.rules import RULES, THRESHOLD, body_of, score

# The flag is the resolver score, so only the resolver rules are run. All 55
# rules took 71 minutes over 711,352 pages on the VPS; these eleven take a
# fraction of that.
RESOLVER_RULES = tuple(rule for rule in RULES if rule.category == "resolver")

BATCH = 1000

# One batch of pages with their newest snapshot, by page id
LATEST = """
    SELECT p.id, p.path, p.held_out, s.title, s.description, s.text
    FROM pages p
    JOIN snapshots s ON s.id = (
        SELECT id FROM snapshots WHERE page_id = p.id
        ORDER BY fetched_at DESC, id DESC LIMIT 1
    )
    WHERE p.id > ?
    ORDER BY p.id
    LIMIT ?
"""

STORED = """
    SELECT sc.page_id, sc.score, sc.flagged FROM scores sc
    JOIN snapshots s ON s.id = sc.snapshot_id
    ORDER BY s.fetched_at, s.id
"""


def newest_snapshots(conn):
    """Every page with its newest snapshot, read a batch at a time

    Each batch is read whole before it is handed out. A cursor left open
    over the whole table would hold a read lock for as long as the scoring
    takes, and the nightly job or the re-poll could not commit meanwhile.
    """
    after = 0
    while True:
        rows = conn.execute(LATEST, (after, BATCH)).fetchall()
        if not rows:
            return
        yield from rows
        after = rows[-1][0]


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db", type=Path)
    parser.add_argument("--threshold", type=int, default=THRESHOLD)
    args = parser.parse_args(argv)
    conn = sqlite3.connect(args.db.resolve().as_uri() + "?mode=ro", uri=True)

    # The newest stored score of each page: later rows overwrite earlier ones
    stored = {}
    for page_id, old_score, old_flag in conn.execute(STORED).fetchall():
        stored[page_id] = (old_score, bool(old_flag))

    def digest_of(row) -> str | None:
        return body_hash(body_of(row[3], row[4], row[5]))

    templated = templated_hashes((digest_of(row), row[3]) for row in newest_snapshots(conn))

    lose, gain = [], []
    counts = Counter()
    for row in newest_snapshots(conn):
        page_id, path, held_out, title, description, text = row
        if page_id not in stored:
            counts["never classified"] += 1
            continue
        old_score, old_flag = stored[page_id]
        body = body_of(title, description, text)
        digest = body_hash(body)
        computed = computed_rules(body, digest if digest in templated else None)
        new_score = score(classify_page(title, description, text, computed, RESOLVER_RULES))
        new_flag = new_score >= args.threshold
        who = "held-out" if held_out else "sweep"
        counts[f"{who} pages"] += 1
        counts[f"{who} flagged before"] += old_flag
        counts[f"{who} flagged after"] += new_flag
        if old_flag and new_flag and old_score != new_score:
            counts[f"{who} keep the flag with another score"] += 1
        if old_flag == new_flag:
            continue
        counts[f"{who} {'lose' if old_flag else 'gain'} the flag"] += 1
        if not held_out:
            (lose if old_flag else gain).append((path, old_score, new_score))

    for name in sorted(counts):
        print(f"{name}: {counts[name]:,}")
    for title, pages in (("lose the flag", lose), ("gain the flag", gain)):
        print(f"\n{title}: {len(pages)} sweep pages (path, stored score, new score)")
        for path, old_score, new_score in sorted(pages):
            print(f"  {path}\t{old_score:+d}\t{new_score:+d}")


if __name__ == "__main__":
    main()
