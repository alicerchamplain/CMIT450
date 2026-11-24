"""One-time pass: run today's redaction over every stored snapshot.

Usage: python -m graphwatch.reredact <db> [--dry-run] [--config PATH]

Redaction happens at ingest, so a snapshot only has the patterns that existed
on the night it was fetched. The 2026-11-15 survey found secret shapes with no
pattern at all (plan/classification-plan-2026-11-15.md, "Redaction gaps"). The
patterns exist now; this script brings the stored rows into line.

For each snapshot the stored title, description and content go through
redact_page again. Where that changes anything, the row's title, description,
content, text and sha256 are rewritten. No content_changed event is written:
the page did not change, only how much of it is hashed.

One thing is undone first. From 6 to 22 November the bare login:password
pattern hashed the scheme of a URL that follows a label, so link:https://site/...
is stored as link:SECRET{...}://site/... and no URL pattern can see the link.
A scheme is not a secret and its hash is known, so the hash is put back to the
scheme before the snapshot is redacted again; the pattern no longer takes a
scheme for a password. What comes out is what a fresh fetch of the same page
would store.

A second thing is undone the same way. A proxy listed as host:port:user:password
was stored as host:SECRET{...}:user:password: the same pattern took the host
for a login and hashed the port, and nothing hashed the password. The pattern
for that line needs to see the port, and a port is one of 111,110 strings of
one to five digits, so its hash is put back to the port first.

The hits and labels of a rewritten snapshot are deleted, because a stored hit
quotes the old text as evidence (all but the templated-body hit, which quotes
a hash). Its score row is kept, so a page that was
flagged stays on the re-poll's list. Run classify afterwards: this pass clears
classify's mark, so that run scores every page again.

It needs the same HMAC_KEY the sweep used, or a secret hashed tonight would
not match the same secret hashed in October. Back up the database first (#41).
"""

import argparse
import functools
import json
import re
import sqlite3
import sys
from pathlib import Path

from graphwatch.classify import TEMPLATED_RULE
from graphwatch.config import CONFIG, hmac_key, load_config
from graphwatch.db import connect, fingerprint, set_classify_mark
from graphwatch.redact import hash_secret, redact_page
from graphwatch.telegraph import page_text

BATCH = 1000

# The schemes whose hash is put back before a snapshot is redacted again
SCHEMES = (
    "http",
    "https",
    "ftp",
    "ftps",
    "sftp",
    "ssh",
    "ws",
    "wss",
    "rtmp",
    "rtsp",
    "tg",
    "magnet",
    "s3",
    "vless",
    "vmess",
    "ss",
    "ssr",
    "trojan",
    "socks",
    "socks4",
    "socks5",
    "socks5h",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "mongodb",
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "amqp",
)

# Regex for a scheme that is still hashed after the known ones were put back
# SECRET\{[0-9a-f]{64}\} : a hash
# ://                      : where a scheme stands
HASHED_SCHEME_PATTERN = re.compile(r"SECRET\{[0-9a-f]{64}\}://")

# Regex for the hashed port of a proxy line, host:SECRET{...}:user:password
# (?<![\w.:-])                             : negative lookbehind, this is the first char of the host
# ((?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}:) : group 1, the host and the colon after it
# (SECRET\{[0-9a-f]{64}\})                 : group 2, a hash where the port stood
# (?=:[^\s:]+:[^\s:])                      : positive lookahead, a user and the start of a password
#                                            follow. In content, which is JSON here, that can
#                                            run past the end of a text node; a port put back
#                                            where it was not needed is hashed again as it was
# re.IGNORECASE                            : tells the python regex to ignore upper vs lowercase
HASHED_PORT_PATTERN = re.compile(
    r"(?<![\w.:-])((?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}:)(SECRET\{[0-9a-f]{64}\})"
    r"(?=:[^\s:]+:[^\s:])",
    re.IGNORECASE,
)

# A port as redact.py's proxy line pattern reads one: one to five digits
PORT_DIGITS = 5


def scheme_hashes(key: bytes) -> dict[str, str]:
    """Function to work out what each scheme looks like after the old pattern hashed it

    Args:
        key (bytes): The hmac key for redactions

    Returns:
        dict[str, str]: "SECRET{...}://" to "scheme://", for every scheme in
            SCHEMES as written in lower case, upper case and with a capital
    """
    hashes = {}
    for scheme in SCHEMES:
        for spelling in (scheme, scheme.upper(), scheme.capitalize()):
            hashes[hash_secret(spelling, key) + "://"] = spelling + "://"
    return hashes


def restore_schemes(s: str | None, hashes: dict[str, str]) -> str | None:
    """Function to put a hashed URL scheme back

    Args:
        s (str | None): stored text: a title, a description, or content as JSON
        hashes (dict[str, str]): the replacements from scheme_hashes

    Returns:
        str | None: the text with link:SECRET{...}://site read link:https://site again
    """
    if s is None or "}://" not in s:
        return s
    for hashed, scheme in hashes.items():
        s = s.replace(hashed, scheme)
    return s


@functools.lru_cache(maxsize=1)
def port_hashes(key: bytes) -> dict[str, str]:
    """Function to work out what every port looks like after it was hashed

    Worked out once for a key and kept: it is 111,110 hashes.

    Args:
        key (bytes): The hmac key for redactions

    Returns:
        dict[str, str]: "SECRET{...}" to the digits, for every string of one
            to PORT_DIGITS digits, 0 and 00080 included
    """
    hashes = {}
    for width in range(1, PORT_DIGITS + 1):
        for number in range(10**width):
            digits = f"{number:0{width}d}"
            hashes[hash_secret(digits, key)] = digits
    return hashes


def restore_ports(s: str | None, key: bytes) -> str | None:
    """Function to put the hashed port of a proxy line back

    Only in host:SECRET{...}:user:password, and only when the hash is the
    hash of one to five digits. A hash of anything else stays: it is a
    password, as in first.last:SECRET{...}:First:Last.

    Args:
        s (str | None): stored text: a title, a description, or content as JSON
        key (bytes): The hmac key for redactions

    Returns:
        str | None: the text with host:SECRET{...}:user:password read host:8080:user:password again
    """
    if s is None or HASHED_PORT_PATTERN.search(s) is None:
        return s
    ports = port_hashes(key)
    return HASHED_PORT_PATTERN.sub(
        lambda m: m.group(1) + ports.get(m.group(2), m.group(2)), s
    )


def reredact_snapshot(
    row: sqlite3.Row, key: bytes, hashes: dict[str, str] | None = None
) -> dict | None:
    """Function to redact one stored snapshot again

    Args:
        row (sqlite3.Row): a snapshots row with title, description and content
        key (bytes): The hmac key for redactions
        hashes (dict[str, str] | None, optional): the replacements from
            scheme_hashes, or None to work them out. Defaults to None.

    Returns:
        dict | None: the new title, description, content, text and sha256, or
            None if redaction changed nothing
    """
    if hashes is None:
        hashes = scheme_hashes(key)
    stored = {
        "title": row["title"],
        "description": row["description"],
        "content": json.loads(row["content"]),
    }
    restored = {
        "title": restore_ports(restore_schemes(row["title"], hashes), key),
        "description": restore_ports(restore_schemes(row["description"], hashes), key),
        "content": json.loads(restore_ports(restore_schemes(row["content"], hashes), key)),
    }
    page = redact_page(restored, key)
    if page == stored:
        return None
    # A stored title or description can be NULL; page_text joins strings
    text = page_text(
        {**page, "title": page["title"] or "", "description": page["description"] or ""}
    )
    return {
        "title": page["title"],
        "description": page["description"],
        "content": json.dumps(page["content"], ensure_ascii=False),
        "text": text,
        "sha256": fingerprint(page["title"], page["description"], page["content"]),
    }


def reredact(
    conn: sqlite3.Connection, key: bytes, dry_run: bool = False, log=print
) -> dict:
    """Function to redact every stored snapshot again, a batch at a time

    Snapshots are read in id order, BATCH rows per query, and each batch is
    committed before the next is read. A run that is stopped can be started
    again: a snapshot that is already redacted comes back unchanged. The
    hits and labels of a snapshot that is rewritten are deleted.

    Args:
        conn (sqlite3.Connection): SQL db connection, with row_factory set
        key (bytes): The hmac key for redactions
        dry_run (bool, optional): Count what would change and write nothing.
            Defaults to False.
        log (optional): Logging function. Defaults to print.

    Returns:
        dict: snapshots read, snapshots changed, pages changed, and
            hashed_schemes: snapshots that still hold a hashed scheme this
            pass could not put back, because the word in front of :// was
            not one of SCHEMES. Such a page reads differently when it is
            fetched again, which shows up once as a content_changed.
    """
    select = """
    SELECT id, page_id, title, description, content FROM snapshots
    WHERE id > ? ORDER BY id LIMIT ?
    """
    update = """
    UPDATE snapshots SET title = ?, description = ?, content = ?, text = ?, sha256 = ?
    WHERE id = ?
    """
    counts = {"snapshots": 0, "changed": 0, "hashed_schemes": 0}
    pages = set()
    hashes = scheme_hashes(key)
    last_id = 0
    while True:
        rows = conn.execute(select, (last_id, BATCH)).fetchall()
        if not rows:
            break
        for row in rows:
            last_id = row["id"]
            counts["snapshots"] += 1
            if HASHED_SCHEME_PATTERN.search(restore_schemes(row["content"], hashes)):
                counts["hashed_schemes"] += 1
            new = reredact_snapshot(row, key, hashes)
            if new is None:
                continue
            counts["changed"] += 1
            pages.add(row["page_id"])
            if not dry_run:
                params = (
                    new["title"],
                    new["description"],
                    new["content"],
                    new["text"],
                    new["sha256"],
                    row["id"],
                )
                conn.execute(update, params)
                # A stored hit quotes the old text as its evidence. The score
                # row stays: "has this page ever been flagged" is read from
                # it, and classify scores a flagged older snapshot again
                # The templated-body hit quotes nothing but a hash, and it
                # is how classify finds an older snapshot whose penalty may
                # have to come off again, so that one hit stays
                conn.execute(
                    "DELETE FROM hits WHERE snapshot_id = ? AND rule != ?",
                    (row["id"], TEMPLATED_RULE),
                )
                conn.execute("DELETE FROM labels WHERE snapshot_id = ?", (row["id"],))
                # The scores were made from the old text. classify only
                # scores a page again when its mark is gone, so the mark
                # goes in the same transaction as the first rewrite
                set_classify_mark(conn, None)
        conn.commit()
        log(f"{counts['snapshots']:,} snapshots read, {counts['changed']:,} changed")
    counts["pages"] = len(pages)
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args(argv)
    if not args.db.is_file():
        print(f"no such file: {args.db}", file=sys.stderr)
        return 2
    try:
        key = hmac_key(load_config(args.config))
    except FileNotFoundError:
        print(f"Config file not found: {args.config}", file=sys.stderr)
        return 2
    except KeyError:
        print(f"HMAC_KEY not set in {args.config}", file=sys.stderr)
        return 2
    except ValueError as too_short:
        print(f"{too_short}: {args.config}", file=sys.stderr)
        return 2
    if args.dry_run:
        # Read-only: a dry run must not even add the tables a real run would
        # as_uri quotes the path: a # or a ? in it would otherwise cut the URI short
        conn = sqlite3.connect(args.db.resolve().as_uri() + "?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    else:
        # connect, not sqlite3.connect: it adds the tables this version expects
        conn = connect(args.db)
    try:
        counts = reredact(
            conn, key, dry_run=args.dry_run, log=lambda s: print(s, flush=True)
        )
    finally:
        conn.close()
    verb = "would change" if args.dry_run else "changed"
    print(
        f"{verb} {counts['changed']:,} of {counts['snapshots']:,} snapshots "
        f"on {counts['pages']:,} pages"
    )
    if counts["hashed_schemes"]:
        print(
            f"{counts['hashed_schemes']:,} snapshots still hold a hashed URL scheme "
            "that is not in SCHEMES; they will read as changed when fetched again"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
