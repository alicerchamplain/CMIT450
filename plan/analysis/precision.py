"""Precision per category from the hand labels (#35).

  .venv/bin/python plan/analysis/precision.py DB plan/reports/labels-2026-11-22.tsv \\
      --key data/sample-test-key.tsv

The TSV has four columns: path, sample, label, sentence. A label is one of
the fourteen category names, or benign, or unsure. Rows of the development
sample are skipped: those pages were read to write the rules, so they cannot
judge them.

--key is the NAME-key.tsv that draw_sample.py wrote with the test sample. It
says which category the classifier gave each page on the day it was drawn,
and the table is counted by that. Without it each page's category is read
from the database as it is now, and a later night can have changed it: a
body that has since turned up under a third title is template_spam today.
The last line says how many pages have moved.

For each category the table gives how many of the test pages the classifier
put there (by primary label) carry the same hand label, as counts: with 15
pages a percentage alone would hide how coarse the figure is. The unlabelled
row estimates what the classifier misses: how many of the pages it gave no
label were hand-labelled as one of the nine intelligence categories. The
near-miss row is the resolver's near-threshold pages.

Prints Markdown and counts only. The database is opened read-only.
"""

import argparse
import sqlite3
from collections import Counter
from pathlib import Path

from graphwatch.rules import CATEGORIES, INTELLIGENCE

HAND_LABELS = frozenset([*CATEGORIES, "benign", "unsure"])


def read_labels(tsv: Path) -> list[tuple[str, str, str]]:
    """The (path, sample, label) of every labelled row

    Raises:
        SystemExit: on a label that is not one of HAND_LABELS, or a row with
            no label, naming the line
    """
    rows = []
    lines = tsv.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 3:
            # An editor that trims trailing whitespace eats the empty columns
            raise SystemExit(f"{tsv}:{number}: no label column on this line")
        path, sample, label = fields[0], fields[1].strip(), fields[2].strip()
        if label not in HAND_LABELS:
            raise SystemExit(f"{tsv}:{number}: {label!r} is not a label")
        rows.append((path, sample, label))
    return rows


def predicted(conn, path: str) -> str | None:
    """The classifier's primary label for a page: a category, "unlabelled", or
    None if the page is unknown or was never classified"""
    row = conn.execute(
        """
        SELECT sc.snapshot_id,
               (SELECT l.category FROM labels l
                WHERE l.snapshot_id = sc.snapshot_id AND l.is_primary = 1)
        FROM pages p JOIN scores sc ON sc.page_id = p.id
        WHERE p.path = ? AND p.held_out = 0
        ORDER BY sc.snapshot_id DESC LIMIT 1
        """,
        (path,),
    ).fetchone()
    if row is None:
        return None
    return row[1] or "unlabelled"


def read_key(tsv: Path | None) -> dict[str, str]:
    """The stratum each sampled page was drawn from, by path"""
    if tsv is None:
        return {}
    strata = {}
    for line in tsv.read_text(encoding="utf-8").splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) >= 2 and fields[0]:
            strata[fields[0]] = fields[1].strip()
    return strata


def precision_table(conn, rows: list[tuple[str, str, str]], strata=None) -> str:
    """The precision table as Markdown

    Args:
        conn: read-only connection to the classified database
        rows: (path, sample, label) from read_labels
        strata (optional): path to the stratum it was drawn from, from
            read_key. Defaults to None, which reads every category from the
            database as it is now.

    Returns:
        str: the table, one line per category, then the unlabelled and
            near-miss lines and a line of what was skipped
    """
    pages = Counter()
    agree = Counter()
    unsure = Counter()
    missed = Counter()
    near_miss = Counter()
    skipped = Counter()
    strata = strata or {}
    moved = 0
    for path, sample, label in rows:
        if sample == "dev":
            skipped["development sample"] += 1
            continue
        if sample == "test-near-miss":
            near_miss["pages"] += 1
            near_miss["resolver"] += label == "resolver"
            near_miss["unsure"] += label == "unsure"
            continue
        now = predicted(conn, path)
        category = strata.get(path, now)
        if category is None:
            skipped["not in the database"] += 1
            continue
        moved += path in strata and now is not None and now != category
        pages[category] += 1
        unsure[category] += label == "unsure"
        if category == "unlabelled":
            if label in INTELLIGENCE:
                missed[label] += 1
        else:
            agree[category] += label == category
    lines = [
        "| Category | Kind | Test pages | Hand label agrees | Unsure |",
        "|---|---|---|---|---|",
    ]
    for category in CATEGORIES:
        kind = "intelligence" if category in INTELLIGENCE else "noise"
        if pages[category]:
            share = f"{agree[category]} of {pages[category]}"
        else:
            share = "none sampled"
        lines.append(
            f"| `{category}` | {kind} | {pages[category]} | {share} | {unsure[category]} |"
        )
    lines.append("")
    total_missed = sum(missed.values())
    detail = ", ".join(f"{label} {count}" for label, count in sorted(missed.items()))
    lines.append(
        f"Unlabelled test pages: {pages['unlabelled']}, of which {total_missed} were "
        f"hand-labelled as intelligence{' (' + detail + ')' if detail else ''} "
        f"and {unsure['unlabelled']} unsure."
    )
    lines.append(
        f"Resolver near misses: {near_miss['pages']}, of which {near_miss['resolver']} "
        f"were hand-labelled resolver and {near_miss['unsure']} unsure."
    )
    if skipped:
        detail = ", ".join(f"{count} {reason}" for reason, count in sorted(skipped.items()))
        lines.append(f"Skipped rows: {detail}.")
    if strata:
        lines.append(
            f"Counted by the category on the day of the draw; {moved} of those pages "
            "carry another primary label in the database now."
        )
    else:
        lines.append(
            "No key file given: each category is the page's primary label in the "
            "database as it is now."
        )
    return "\n".join(lines) + "\n"


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("--key", type=Path, help="NAME-key.tsv from draw_sample.py test")
    args = parser.parse_args(argv)
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    table = precision_table(conn, read_labels(args.labels), read_key(args.key))
    print(table, end="")


if __name__ == "__main__":
    main()
