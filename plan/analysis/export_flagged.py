"""Export the flagged pages and their indicators for labelling and enrichment.

  .venv/bin/python plan/analysis/export_flagged.py DB data/flagged

Writes two files, for reading on a machine that does not hold the full
database (week5_schedule.md, Thursday):

  NAME.txt             every page that has ever been flagged: path, title,
                       resolver score, labels, the rule hits and the first
                       1,500 characters of the redacted text
  NAME-indicators.tsv  path, kind, value, source for every indicator the
                       extractor finds on any snapshot of a flagged page,
                       decoys included

No author fields are read. Held-out pages are never exported. Both files
stay in data/, never in git. The database is opened read-only.
"""

import argparse
import sqlite3
from pathlib import Path

from graphwatch.extract import extract

EXCERPT_CHARS = 1500


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db", type=Path)
    parser.add_argument("out", type=Path, help="output path without an extension")
    args = parser.parse_args(argv)
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    # Flagged on any snapshot: a re-poll adds a snapshot that has no score
    # until the next classify, and the page is still a flagged page
    pages = conn.execute(
        """
        SELECT p.id, p.path, s.title, s.text
        FROM pages p
        JOIN snapshots s ON s.id = (
            SELECT id FROM snapshots WHERE page_id = p.id
            ORDER BY fetched_at DESC, id DESC LIMIT 1
        )
        WHERE p.held_out = 0
          AND EXISTS (SELECT 1 FROM scores sc WHERE sc.page_id = p.id AND sc.flagged = 1)
        ORDER BY p.path
        """
    ).fetchall()
    indicators = 0
    with open(f"{args.out}.txt", "w", encoding="utf-8") as reading, open(
        f"{args.out}-indicators.tsv", "w", encoding="utf-8"
    ) as table:
        table.write("path\tkind\tvalue\tsource\n")
        for number, page in enumerate(pages, start=1):
            # The score, labels and hits of the newest snapshot that has them
            scored = conn.execute(
                """
                SELECT sc.snapshot_id, sc.score FROM scores sc
                JOIN snapshots s ON s.id = sc.snapshot_id
                WHERE sc.page_id = ? ORDER BY s.fetched_at DESC, s.id DESC LIMIT 1
                """,
                (page["id"],),
            ).fetchone()
            labels = conn.execute(
                "SELECT category FROM labels WHERE snapshot_id = ? AND assigned = 1 ORDER BY rowid",
                (scored["snapshot_id"],),
            ).fetchall()
            hits = conn.execute(
                "SELECT rule, weight, evidence, matches FROM hits WHERE snapshot_id = ? ORDER BY id",
                (scored["snapshot_id"],),
            ).fetchall()
            reading.write(f"===== {number} of {len(pages)}: {page['path']}\n")
            reading.write(f"title: {page['title']}\n")
            reading.write(f"score: {scored['score']}\n")
            reading.write(f"labels: {', '.join(row['category'] for row in labels) or 'none'}\n")
            for hit in hits:
                times = f" x{hit['matches']}" if hit["matches"] > 1 else ""
                reading.write(f"  {hit['weight']:+d} {hit['rule']:<22} {hit['evidence']}{times}\n")
            reading.write((page["text"] or "")[:EXCERPT_CHARS] + "\n\n")
            # Indicators of every snapshot: an edited page held another address before
            seen = set()
            snapshots = conn.execute(
                "SELECT title, text FROM snapshots WHERE page_id = ? ORDER BY fetched_at, id",
                (page["id"],),
            )
            for snapshot in snapshots:
                for indicator in extract(snapshot["title"], snapshot["text"]):
                    # A tab or a newline in a value would break the row
                    value = indicator.value.replace("\t", " ").replace("\n", " ")
                    if (indicator.kind, value) in seen:
                        continue
                    seen.add((indicator.kind, value))
                    table.write(f"{page['path']}\t{indicator.kind}\t{value}\t{indicator.source}\n")
                    indicators += 1
    print(f"{len(pages)} flagged pages and {indicators} indicators written to {args.out}.txt "
          f"and {args.out}-indicators.tsv")


if __name__ == "__main__":
    main()
