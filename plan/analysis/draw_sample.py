"""Draw the development and test samples for the classification plan (#35).

Run from the repo root, on the machine that holds the full database:

  .venv/bin/python plan/analysis/draw_sample.py dev  DB data/sample-dev
  .venv/bin/python plan/analysis/draw_sample.py test DB data/sample-test --exclude data/sample-dev.tsv

Each run writes three files next to each other:

  NAME.txt      path, title and the first 1,500 characters of the redacted
                text of each sampled page, for reading. Stays in data/, never
                in git.
  NAME.tsv      path, sample, label, sentence. The first two columns are
                filled in; label and sentence are for the hand label. The
                filled-in rows are what goes into
                plan/reports/labels-YYYY-MM-DD.tsv.
  NAME-key.tsv  path, stratum: the group each page was drawn from. Not for
                reading while labelling: it says what the classifier called
                the page. precision.py takes it with --key, so the table is
                counted by the label a page had on the day it was drawn and
                not by whatever later nights have made of it.

A run refuses to write over a NAME.tsv that exists, because that is the file
the labels are typed into. Pass --force to replace it.

Both samples are distinct bodies: never two pages with the same body. Held-out
pages are never sampled. The order is the snapshot's sha256, which is as good
as random and gives the same sample every time. The database is opened
read-only.

dev   200 bodies by the survey's provisional groups (shape_survey.py): 65
      from the pages with a URL and no other feature, 35 from the pages with
      no feature at all, and 100 across the named groups, about 8 each. The
      flagged pages are left out because they are already read. Rules are
      written from these pages.

test  drawn after the rule freeze, from the stored labels: up to 15 pages per
      category by primary label, 50 unlabelled pages and 30 resolver near
      misses. The flagged resolver pages are left out because they are read
      in full. Bodies in the --exclude file's pages are never drawn, so a
      page used to write a rule is never used to judge one.
"""

import argparse
import hashlib
import sqlite3
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shape_survey import features, provisional  # noqa: E402

from graphwatch.rules import CATEGORIES, THRESHOLD, body_of  # noqa: E402

EXCERPT_CHARS = 1500
DEV_WITH_URL = 65
DEV_NO_FEATURE = 35
DEV_NAMED = 100
TEST_PER_CATEGORY = 15
TEST_UNLABELLED = 50
TEST_NEAR_MISS = 30

LATEST = """
    JOIN snapshots s ON s.id = (
        SELECT id FROM snapshots WHERE page_id = p.id
        ORDER BY fetched_at DESC, id DESC LIMIT 1
    )
"""


def body_digest(title, description, text) -> str:
    """The key that makes two pages the same body"""
    body = body_of(title, description, text).strip()
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def excluded_bodies(conn, tsv: Path | None) -> set[str]:
    """The bodies of every page named in an earlier sample's TSV"""
    if tsv is None:
        return set()
    paths = [
        line.split("\t")[0]
        for line in tsv.read_text(encoding="utf-8").splitlines()[1:]
        if line.strip()
    ]
    bodies = set()
    for path in paths:
        row = conn.execute(
            f"SELECT s.title, s.description, s.text FROM pages p {LATEST} WHERE p.path = ?",
            (path,),
        ).fetchone()
        if row is not None:
            bodies.add(body_digest(*row))
    return bodies


def take(candidates, quota: int, seen: set[str]) -> list[tuple]:
    """The first `quota` candidates whose body has not been taken yet

    Args:
        candidates: (sha256, body digest, path, stratum) tuples, sorted by sha256
        quota (int): how many to take
        seen (set[str]): body digests already taken; added to as pages are taken

    Returns:
        list[tuple]: the pages taken, in sha256 order
    """
    taken = []
    for candidate in candidates:
        if len(taken) >= quota:
            break
        if candidate[1] in seen:
            continue
        seen.add(candidate[1])
        taken.append(candidate)
    return taken


def draw_dev(conn) -> list[tuple]:
    """The development sample: strata are the survey's provisional groups"""
    # Flagged on any snapshot, not only the newest: a re-poll adds a
    # snapshot that has no score until the next classify
    sql = f"""
    SELECT s.sha256, p.path, s.title, s.description, s.text,
           EXISTS (SELECT 1 FROM scores sc WHERE sc.page_id = p.id AND sc.flagged = 1)
    FROM pages p {LATEST}
    WHERE p.held_out = 0
    """
    by_group = {}
    for sha, path, title, description, text, flagged in conn.execute(sql):
        if flagged:
            continue
        bits = features(title, description, text, flagged)[0]
        group = provisional(bits)
        digest = body_digest(title, description, text)
        by_group.setdefault(group, []).append((sha, digest, path, group))
    for pages in by_group.values():
        pages.sort()
    seen = set()
    sample = take(by_group.pop("other_with_url", []), DEV_WITH_URL, seen)
    sample += take(by_group.pop("other", []), DEV_NO_FEATURE, seen)
    # About 8 from each named group: one page from each group in turn, so a
    # group with only a few bodies gives what it has and the rest make it up.
    named = sorted(by_group)
    taken = 0
    progress = True
    while taken < DEV_NAMED and progress:
        progress = False
        for group in named:
            if taken >= DEV_NAMED:
                break
            picked = take(by_group[group], 1, seen)
            if picked:
                by_group[group] = [c for c in by_group[group] if c[0] > picked[0][0]]
                sample += picked
                taken += 1
                progress = True
    return sample


def draw_test(conn, excluded: set[str]) -> list[tuple]:
    """The test sample: strata are the classifier's own primary labels"""
    sql = f"""
    SELECT s.sha256, p.path, s.title, s.description, s.text, sc.score,
           (SELECT l.category FROM labels l
            WHERE l.snapshot_id = s.id AND l.is_primary = 1)
    FROM pages p {LATEST}
    JOIN scores sc ON sc.snapshot_id = s.id
    WHERE p.held_out = 0
      AND NOT EXISTS (SELECT 1 FROM scores f WHERE f.page_id = p.id AND f.flagged = 1)
    """
    by_stratum = {}
    for sha, path, title, description, text, score, primary in conn.execute(sql):
        if primary == "resolver":
            continue
        digest = body_digest(title, description, text)
        if digest in excluded:
            continue
        stratum = primary or "unlabelled"
        by_stratum.setdefault(stratum, []).append((sha, digest, path, stratum))
        if 0 < score < THRESHOLD:
            by_stratum.setdefault("near-miss", []).append((sha, digest, path, "near-miss"))
    for pages in by_stratum.values():
        pages.sort()
    seen = set()
    sample = []
    for category in CATEGORIES:
        sample += take(by_stratum.get(category, []), TEST_PER_CATEGORY, seen)
    sample += take(by_stratum.get("unlabelled", []), TEST_UNLABELLED, seen)
    sample += take(by_stratum.get("near-miss", []), TEST_NEAR_MISS, seen)
    return sample


def write_sample(conn, sample: list[tuple], name: str, out: Path) -> None:
    """Write the reading file, the TSV to fill in, and the key of strata"""
    sample = sorted(sample)
    with open(f"{out}.txt", "w", encoding="utf-8") as reading, open(
        f"{out}.tsv", "w", encoding="utf-8"
    ) as table, open(f"{out}-key.tsv", "w", encoding="utf-8") as key:
        table.write("path\tsample\tlabel\tsentence\n")
        key.write("path\tstratum\n")
        for number, (_sha, _digest, path, stratum) in enumerate(sample, start=1):
            key.write(f"{path}\t{stratum}\n")
            title, text = conn.execute(
                f"SELECT s.title, s.text FROM pages p {LATEST} WHERE p.path = ?", (path,)
            ).fetchone()
            kind = "test-near-miss" if stratum == "near-miss" else name
            table.write(f"{path}\t{kind}\t\t\n")
            reading.write(f"===== {number} of {len(sample)}: {path}\n")
            reading.write(f"title: {title}\n")
            reading.write((text or "")[:EXCERPT_CHARS] + "\n\n")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sample", choices=["dev", "test"])
    parser.add_argument("db", type=Path)
    parser.add_argument("out", type=Path, help="output path without an extension")
    parser.add_argument("--exclude", type=Path, help="TSV of an earlier sample")
    parser.add_argument("--force", action="store_true", help="replace an existing NAME.tsv")
    args = parser.parse_args(argv)
    if args.sample == "test" and args.exclude is None:
        raise SystemExit("the test sample needs --exclude with the development sample's TSV")
    if Path(f"{args.out}.tsv").exists() and not args.force:
        raise SystemExit(
            f"{args.out}.tsv exists and may hold hand labels; pass --force to replace it"
        )
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    if args.sample == "dev":
        sample = draw_dev(conn)
    else:
        sample = draw_test(conn, excluded_bodies(conn, args.exclude))
    write_sample(conn, sample, args.sample, args.out)
    print(f"{len(sample)} pages written to {args.out}.txt, {args.out}.tsv and {args.out}-key.tsv")
    # Stratum sizes only: nothing from a page is printed.
    for stratum, pages in sorted(Counter(c[3] for c in sample).items()):
        print(f"  {stratum:<22}{pages:>4}")


if __name__ == "__main__":
    main()
