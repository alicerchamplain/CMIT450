"""Enrichment: which indicators to look up and what the answers add up to (issue #38)

Nothing here touches the network; feeds.py does the lookups. This module
decides what is an indicator worth looking up, turns the feeds' answers into
one novelty verdict, and renders the novelty table (issue #39).
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from sqlite3 import Connection
from urllib.parse import urlsplit

from graphwatch.db import flagged_page_snapshots, indicator_rows, lookup_rows
from graphwatch.extract import extract
from graphwatch.feeds import FEEDS
from graphwatch.rules import is_public_ip

# The kinds that are addresses. A decoy is bait and a token is an opaque run;
# neither is ever sent to a feed.
LOOKUP_KINDS = frozenset(["ip", "host", "url"])

# The two feeds the proposal names first. Novelty needs an answer from both.
PRIMARY_FEEDS = ("threatfox", "otx")

FEED_TITLES = {
    "threatfox": "ThreatFox",
    "urlhaus": "URLhaus",
    "otx": "OTX",
    "virustotal": "VirusTotal",
}


@dataclass(frozen=True)
class Seen:
    """An indicator and where the sweep saw it

    first_seen and last_seen are fetch times of the snapshots that held it,
    and pages is how many pages did. An indicator read from a file has no
    times and no pages.
    """

    kind: str
    value: str
    first_seen: float | None = None
    last_seen: float | None = None
    pages: int = 0


def host_of_url(url: str) -> tuple[str, str] | None:
    """The server a URL points at, as an indicator of its own

    A feed that has never seen this exact URL may well know its host, under
    another path or as a plain domain. So a URL's host is looked up beside
    the URL, and the table shows both.

    Args:
        url (str): a url indicator

    Returns:
        tuple[str, str] | None: ("ip", address) or ("host", name), or None if
            the URL has no host that can be read
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    return ("ip" if is_public_ip(host) else "host", host)


def collect_indicators(conn: Connection) -> list[Seen]:
    """Function to pull the indicators out of every snapshot of every flagged page

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[Seen]: one entry per ip, host or url, in order of first
            appearance, and after each url its host. Decoys and tokens are
            left out, and so is a host that is a decoy on any flagged page
            and a url on such a host.
    """
    first = {}
    last = {}
    pages = {}
    decoys = set()
    for row in flagged_page_snapshots(conn):
        for indicator in extract(row["title"], row["text"]):
            if indicator.kind == "decoy":
                decoys.add(indicator.value)
            if indicator.kind not in LOOKUP_KINDS:
                continue
            keys = [(indicator.kind, indicator.value)]
            if indicator.kind == "url":
                host = host_of_url(indicator.value)
                if host is not None:
                    keys.append(host)
            for key in keys:
                # Snapshots arrive oldest first, so the first time is the earliest
                first.setdefault(key, row["fetched_at"])
                last[key] = row["fetched_at"]
                pages.setdefault(key, set()).add(row["page_id"])

    def on_a_decoy(kind: str, value: str) -> bool:
        # A decoy is somebody else's site, named as bait. That holds on every
        # page and for every address on the site, so none of it is the
        # actor's and none of it is sent to a feed
        if kind == "url":
            host = host_of_url(value)
            return host is not None and host[1] in decoys
        return value in decoys

    return [
        Seen(kind, value, first[(kind, value)], last[(kind, value)], len(pages[(kind, value)]))
        for kind, value in first
        if not on_a_decoy(kind, value)
    ]


def read_indicator_file(path: Path) -> tuple[list[Seen], int]:
    """Function to read indicators from a TSV file with kind and value columns

    The first line names the columns. Other columns are ignored, so the file
    can carry notes beside each indicator.

    Args:
        path (Path): Path to the TSV file

    Raises:
        ValueError: if the header has no kind or no value column

    Returns:
        tuple[list[Seen], int]: the ip, host and url rows without repeats, and
            how many rows were skipped for being another kind
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t") if lines else []
    if "kind" not in header or "value" not in header:
        raise ValueError(f"{path}: the first line has to name a kind and a value column")
    kind_at = header.index("kind")
    value_at = header.index("value")
    found = []
    seen = set()
    skipped = 0
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) <= max(kind_at, value_at):
            continue
        kind = fields[kind_at].strip()
        value = fields[value_at].strip()
        if not value:
            continue
        if kind not in LOOKUP_KINDS:
            skipped += 1
            continue
        rows = [(kind, value)]
        if kind == "url":
            host = host_of_url(value)
            if host is not None:
                rows.append(host)
        for row in rows:
            if row not in seen:
                seen.add(row)
                found.append(Seen(*row))
    return found, skipped


def novelty_rows(conn: Connection) -> list[dict]:
    """Function to load every stored indicator with what each feed said about it

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[dict]: one dict per indicator with kind, value, first_seen,
            pages, and lookups: feed name to (verdict, detail)
    """
    rows = []
    for indicator in indicator_rows(conn):
        lookups = {
            lookup["feed"]: (lookup["verdict"], lookup["detail"])
            for lookup in lookup_rows(conn, indicator["id"])
        }
        rows.append(
            {
                "kind": indicator["kind"],
                "value": indicator["value"],
                "first_seen": indicator["first_seen"],
                "pages": indicator["pages"],
                "lookups": lookups,
            }
        )
    return rows


def novelty(verdicts: dict[str, str]) -> str:
    """The novelty verdict for one indicator from what each feed said

    Args:
        verdicts (dict[str, str]): feed name to KNOWN or UNKNOWN, for the
            feeds that answered

    Returns:
        str: "known" if any feed knows it; "novel" if none does and both
            primary feeds answered; "unchecked" if a primary feed is missing,
            because a feed that was never asked cannot vouch for novelty
    """
    if "KNOWN" in verdicts.values():
        return "known"
    if all(feed in verdicts for feed in PRIMARY_FEEDS):
        return "novel"
    return "unchecked"


def defang(kind: str, value: str) -> str:
    """An indicator written so that nothing turns it into a link

    Args:
        kind (str): ip, host or url
        value (str): the indicator

    Returns:
        str: 1.2.3[.]4, example[.]com, hxxp://example[.]com/path or
            2001[:]db8::1
    """
    scheme = ""
    rest = value
    if kind == "url" and "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = scheme.lower().replace("http", "hxxp") + "://"
    # Only the host is defanged: the dots in a path are not what a browser
    # follows. The host ends at the first / ? or #.
    end = min((rest.index(c) for c in "/?#" if c in rest), default=len(rest))
    host, tail = rest[:end], rest[end:]
    # A URL's host can have userinfo in front of it, and that is a name too
    parts = [_defang_name(part) for part in host.split("@")]
    return scheme + "@".join(parts) + tail


def _defang_name(name: str) -> str:
    """One hostname or address with a bracket in it, so it is not a link"""
    if name.count(":") > 1:
        # An IPv6 address has no dot to bracket
        return name.replace(":", "[:]", 1)
    head, dot, last = name.rpartition(".")
    if dot:
        return f"{head}[.]{last}"
    return name


def _cell(text: str) -> str:
    """Text from a page or a feed made safe for one cell of a Markdown table

    A pipe would end the cell and a backtick would end the code span around
    an indicator; either lets what follows be read as Markdown, and what
    follows was written by whoever posted the page.
    """
    text = text.replace("\n", " ").replace("\r", " ")
    return text.replace("|", "%7C").replace("`", "%60")


def _day(ts: float | None) -> str:
    """A UTC date for the table, or a dash for an indicator with no time"""
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d")


def render_novelty_table(rows: list[dict], feeds=FEEDS) -> str:
    """The novelty table as Markdown, with the shares under it

    Args:
        rows (list[dict]): one dict per indicator with kind, value,
            first_seen, pages, and lookups: feed name to (verdict, detail)
        feeds (optional): the feed columns, in order. Defaults to FEEDS.

    Returns:
        str: a line per indicator, defanged, then the counts the Novelty
            measure is read from
    """
    titles = " | ".join(FEED_TITLES[feed] for feed in feeds)
    lines = [
        f"| Indicator | Kind | First seen | Pages | {titles} | Verdict |",
        "|---|---|---|---|" + "---|" * len(feeds) + "---|",
    ]
    counts = {"novel": 0, "known": 0, "unchecked": 0}
    primary_checked = 0
    primary_absent = 0
    for row in rows:
        lookups = row["lookups"]
        cells = []
        for feed in feeds:
            if feed not in lookups:
                cells.append("not checked")
            elif lookups[feed][0] == "KNOWN":
                cells.append(_cell(lookups[feed][1] or "known"))
            else:
                cells.append("-")
        verdicts = {feed: verdict for feed, (verdict, _detail) in lookups.items()}
        verdict = novelty(verdicts)
        counts[verdict] += 1
        if all(feed in verdicts for feed in PRIMARY_FEEDS):
            primary_checked += 1
            primary_absent += all(verdicts[feed] == "UNKNOWN" for feed in PRIMARY_FEEDS)
        lines.append(
            f"| `{_cell(defang(row['kind'], row['value']))}` | {row['kind']} | {_day(row['first_seen'])} "
            f"| {row['pages']} | {' | '.join(cells)} | {verdict} |"
        )
    checked = counts["novel"] + counts["known"]
    lines.append("")
    lines.append(
        f"{len(rows)} indicators: {counts['novel']} novel, {counts['known']} known, "
        f"{counts['unchecked']} unchecked."
    )
    lines.append(f"Novel, of the indicators with a verdict: {counts['novel']} of {checked}.")
    lines.append(
        f"Absent from ThreatFox and OTX, of the indicators both answered for: "
        f"{primary_absent} of {primary_checked}."
    )
    return "\n".join(lines) + "\n"
