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

from graphwatch.db import flagged_pages, indicator_rows, lookup_rows, page_snapshots, title_rows
from graphwatch.extract import extract
from graphwatch.feeds import FEEDS
from graphwatch.rules import is_public_ip

# The kinds that are addresses. A decoy is bait and a token is an opaque run;
# neither is ever sent to a feed.
LOOKUP_KINDS = frozenset(["ip", "host", "url"])

# The two feeds the proposal names first. Novelty needs an answer from both,
# and from any other feed that is in use: see required_feeds.
PRIMARY_FEEDS = ("threatfox", "otx")

# The names in the table's count by title for an indicator that no flagged page
# holds, which is one that only a file names, and for one that pages hold
# whose titles were not stored: a row from before the titles were kept, until
# the next enrich run fills them in
NO_PAGE = "no page"
NOT_RECORDED = "title not recorded"

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
    and pages is how many pages did. titles says whose pages: the slug of
    each title with how many of its pages hold the indicator, the title on
    most pages first. An indicator read from a file has no times, no pages
    and no titles.
    """

    kind: str
    value: str
    first_seen: float | None = None
    last_seen: float | None = None
    pages: int = 0
    titles: tuple[tuple[str, int], ...] = ()


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


def lookup_rows_for(kind: str, value: str) -> list[tuple[str, str]]:
    """The indicators one address becomes in the table

    An ip or a host is itself. A url is itself and, after it, its host. A
    url that names nothing but a host (http://8.8.8.8, https://name/) is
    only that host, so that the table does not count one server twice.

    That gives something up. ThreatFox and URLhaus answer for a host with
    the URLs on it, but OTX and VirusTotal keep a record of the URL apart
    from the record of the host, and that record is no longer asked for: a
    server whose bare URL one of them knows, and whose host neither does,
    reads as unknown to them.

    Args:
        kind (str): ip, host or url
        value (str): the address

    Returns:
        list[tuple[str, str]]: (kind, value) pairs, one or two
    """
    if kind != "url":
        return [(kind, value)]
    host = host_of_url(value)
    if host is None:
        return [(kind, value)]
    try:
        parts = urlsplit(value)
        only_a_host = (
            parts.path in ("", "/")
            and not parts.query
            and not parts.fragment
            and parts.port is None
            and parts.username is None
            and parts.password is None
        )
    except ValueError:
        # A port that is no number: keep the url as it was written
        only_a_host = False
    if only_a_host:
        return [host]
    return [(kind, value), host]


def collect_indicators(conn: Connection) -> list[Seen]:
    """Function to pull the indicators out of every snapshot of every flagged page

    The snapshots are read a page at a time and no read is left open while
    the indicators are pulled out, so a nightly job or a re-poll that wants
    to write is never kept waiting for longer than one short read. The actor
    writes the same few lines onto many pages, so each different title and
    text is searched once, however many snapshots hold it.

    Args:
        conn (Connection): SQL db connection

    Returns:
        list[Seen]: one entry per ip, host or url, in order of first
            appearance, and after each url its host (see lookup_rows_for).
            Decoys and tokens are left out, and so is a host that is a decoy
            on any flagged page and a url on such a host.
    """
    first = {}  # where each indicator first appears: (fetched_at, snapshot id, place in the snapshot)
    last = {}
    pages = {}
    slugs = {}  # indicator to the page ids under each title that hold it
    decoys = set()
    extracted = {}  # (title, text) to its indicators
    for page in flagged_pages(conn):
        page_id = page["id"]
        for row in page_snapshots(conn, page_id):
            content = (row["title"], row["text"])
            if content not in extracted:
                extracted[content] = extract(*content)
            place = 0
            for indicator in extracted[content]:
                if indicator.kind == "decoy":
                    decoys.add(indicator.value)
                if indicator.kind not in LOOKUP_KINDS:
                    continue
                for key in lookup_rows_for(indicator.kind, indicator.value):
                    # Pages are read one after another, not in order of
                    # time, so the earliest sighting is kept by comparing
                    seen_at = (row["fetched_at"], row["id"], place)
                    place += 1
                    if key not in first or seen_at < first[key]:
                        first[key] = seen_at
                    if key not in last or row["fetched_at"] > last[key]:
                        last[key] = row["fetched_at"]
                    pages.setdefault(key, set()).add(page_id)
                    slugs.setdefault(key, {}).setdefault(page["slug"], set()).add(page_id)

    def titles_of(key: tuple[str, str]) -> tuple[tuple[str, int], ...]:
        counted = [(slug, len(ids)) for slug, ids in slugs[key].items()]
        return tuple(sorted(counted, key=lambda title: (-title[1], title[0])))

    def on_a_decoy(kind: str, value: str) -> bool:
        # A decoy is somebody else's site, named as bait. That holds on every
        # page and for every address on the site, so none of it is the
        # actor's and none of it is sent to a feed
        if kind == "url":
            host = host_of_url(value)
            return host is not None and host[1] in decoys
        return value in decoys

    return [
        Seen(
            kind,
            value,
            first[(kind, value)][0],
            last[(kind, value)],
            len(pages[(kind, value)]),
            titles_of((kind, value)),
        )
        for kind, value in sorted(first, key=first.get)
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
        for row in lookup_rows_for(kind, value):
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
            pages, titles (slug to how many flagged pages of that title
            hold it), and three dicts keyed by feed name: lookups, (verdict,
            detail) as each feed last said; first, the verdict each feed
            gave the first time; and asked, when each last answered
    """
    rows = []
    for indicator in indicator_rows(conn):
        stored = lookup_rows(conn, indicator["id"])
        rows.append(
            {
                "kind": indicator["kind"],
                "value": indicator["value"],
                "first_seen": indicator["first_seen"],
                "pages": indicator["pages"],
                "titles": {title["slug"]: title["pages"] for title in title_rows(conn, indicator["id"])},
                "lookups": {lookup["feed"]: (lookup["verdict"], lookup["detail"]) for lookup in stored},
                "first": {lookup["feed"]: lookup["first_verdict"] for lookup in stored},
                "asked": {lookup["feed"]: lookup["checked_at"] for lookup in stored},
            }
        )
    return rows


def required_feeds(rows: list[dict], in_use=()) -> tuple[str, ...]:
    """The feeds an indicator needs an answer from before it can be called novel

    The two primary feeds, always. Any other feed too if it is in use: it
    has a key, or it has answered for one indicator in the table. A feed
    that is in use and was not asked about this indicator (its quota ran
    out, its key was refused, the run was cut short) cannot vouch for it. A
    feed with no key that has never answered is not waited for.

    Args:
        rows (list[dict]): the indicators from novelty_rows
        in_use (optional): the feeds that have a key. Defaults to none, which
            leaves the answers in the table to say which feeds are in use.

    Returns:
        tuple[str, ...]: feed names, in FEEDS order
    """
    answered = {feed for row in rows for feed in row["lookups"]}
    return tuple(
        feed for feed in FEEDS if feed in PRIMARY_FEEDS or feed in answered or feed in in_use
    )


def novelty(verdicts: dict[str, str], required=PRIMARY_FEEDS) -> str:
    """The novelty verdict for one indicator from what each feed said

    Args:
        verdicts (dict[str, str]): feed name to KNOWN or UNKNOWN, for the
            feeds that answered
        required (optional): the feeds that all have to answer before an
            indicator is novel, from required_feeds. Defaults to PRIMARY_FEEDS.

    Returns:
        str: "known" if any feed knows it; "novel" if none does and every
            required feed answered; "unchecked" if a required feed is
            missing, because a feed that was never asked cannot vouch for
            novelty
    """
    if "KNOWN" in verdicts.values():
        return "known"
    if all(feed in verdicts for feed in required):
        return "novel"
    return "unchecked"


def count_verdicts(rows: list[dict], in_use=()) -> dict[str, int]:
    """How many of the stored indicators are novel, known and unchecked

    Args:
        rows (list[dict]): the indicators from novelty_rows
        in_use (optional): the feeds that have a key, for required_feeds.
            Defaults to none.

    Returns:
        dict[str, int]: counts under "novel", "known" and "unchecked"
    """
    required = required_feeds(rows, in_use)
    counts = {"novel": 0, "known": 0, "unchecked": 0}
    for row in rows:
        verdicts = {feed: verdict for feed, (verdict, _detail) in row["lookups"].items()}
        counts[novelty(verdicts, required)] += 1
    return counts


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


def render_novelty_table(rows: list[dict], feeds=FEEDS, in_use=()) -> str:
    """The novelty table as Markdown, with the shares under it

    Args:
        rows (list[dict]): one dict per indicator with kind, value,
            first_seen, pages, and lookups: feed name to (verdict, detail);
            and, where known, titles: slug to pages (see novelty_rows)
        feeds (optional): the feed columns, in order. Defaults to FEEDS.
        in_use (optional): the feeds that have a key, for required_feeds.
            Defaults to none.

    Returns:
        str: a line per indicator, defanged, then the counts the Novelty
            measure is read from, the same counts for each title, the feeds
            a novel verdict rests on and the ones the unchecked indicators
            wait for, the days the answers are from, and how many indicators
            a feed has come to know since it was first asked
    """
    required = required_feeds(rows, in_use)
    feed_columns = " | ".join(FEED_TITLES[feed] for feed in feeds)
    lines = [
        f"| Indicator | Kind | First seen | Pages | Titles | {feed_columns} | Verdict |",
        "|---|---|---|---|---|" + "---|" * len(feeds) + "---|",
    ]
    counts = {"novel": 0, "known": 0, "unchecked": 0}
    by_title = {}  # title to its own novel, known and unchecked
    several_titles = False  # whether any indicator is on pages of more than one title
    waiting = dict.fromkeys(required, 0)  # feed to the unchecked indicators it has not answered for
    primary_checked = 0
    primary_absent = 0
    novel_at_first = 0
    known_since = 0
    asked = []
    for row in rows:
        lookups = row["lookups"]
        asked.extend(row.get("asked", {}).values())
        # What each feed said the first time; the same answers, for a row
        # that has not been asked about again
        first = row.get("first") or {feed: verdict for feed, (verdict, _detail) in lookups.items()}
        if novelty(first, required) == "novel":
            novel_at_first += 1
            known_since += "KNOWN" in (verdict for verdict, _detail in lookups.values())
        cells = []
        for feed in feeds:
            if feed not in lookups:
                cells.append("not checked")
            elif lookups[feed][0] == "KNOWN":
                cells.append(_cell(lookups[feed][1] or "known"))
            else:
                cells.append("-")
        verdicts = {feed: verdict for feed, (verdict, _detail) in lookups.items()}
        verdict = novelty(verdicts, required)
        counts[verdict] += 1
        # An indicator on pages of two titles counts under each of them, and
        # one that only a file names under neither. The page count decides
        # which it is: a title left on a row that no page holds is not shown.
        held_by = list(row.get("titles") or {}) if row["pages"] else []
        several_titles = several_titles or len(held_by) > 1
        if held_by:
            title_cell = _cell(", ".join(held_by))
        elif row["pages"]:
            title_cell = "?"
        else:
            title_cell = "-"
        for title in held_by or [NOT_RECORDED if row["pages"] else NO_PAGE]:
            by_title.setdefault(title, {"novel": 0, "known": 0, "unchecked": 0})[verdict] += 1
        if verdict == "unchecked":
            for feed in required:
                waiting[feed] += feed not in verdicts
        if all(feed in verdicts for feed in PRIMARY_FEEDS):
            primary_checked += 1
            primary_absent += all(verdicts[feed] == "UNKNOWN" for feed in PRIMARY_FEEDS)
        lines.append(
            f"| `{_cell(defang(row['kind'], row['value']))}` | {row['kind']} | {_day(row['first_seen'])} "
            f"| {row['pages']} | {title_cell} | {' | '.join(cells)} | {verdict} |"
        )
    checked = counts["novel"] + counts["known"]
    lines.append("")
    lines.append(
        f"{len(rows)} indicators: {counts['novel']} novel, {counts['known']} known, "
        f"{counts['unchecked']} unchecked."
    )
    lines.append(f"Novel, of the indicators with a verdict: {counts['novel']} of {checked}.")
    # The classifier flags what looks like a resolver, whoever posted it. The
    # title says whose pages an indicator is on: the actor's are Hello pages.
    # The title on most indicators first, and the ones no page holds last.
    order = sorted(
        by_title,
        key=lambda title: (title == NO_PAGE, title == NOT_RECORDED, -sum(by_title[title].values()), title),
    )
    shares = [
        f"{_cell(title)}: {by_title[title]['novel']} novel, {by_title[title]['known']} known, "
        f"{by_title[title]['unchecked']} unchecked"
        for title in order
    ]
    # The shares then add up to more than the indicators there are
    twice = " (an indicator on pages of several titles counts under each)" if several_titles else ""
    lines.append(f"By the title of the pages that hold them: {'; '.join(shares) or 'none'}{twice}.")
    lines.append(
        f"Novel means unknown to every one of: {', '.join(FEED_TITLES[feed] for feed in required)}."
    )
    late = [f"{count} for {FEED_TITLES[feed]}" for feed, count in waiting.items() if count]
    lines.append(f"Unchecked indicators wait: {', '.join(late) or 'none'}.")
    lines.append(
        f"Absent from ThreatFox and OTX, of the indicators both answered for: "
        f"{primary_absent} of {primary_checked}."
    )
    # A verdict is as old as its answers. An UNKNOWN is asked for once more
    # after some days (see cli's --recheck-days), and the second line is what
    # that found: indicators the feeds learned of after the sweep had them.
    if asked:
        lines.append(f"Answers given from {_day(min(asked))} to {_day(max(asked))} (UTC).")
    else:
        lines.append("Answers given: none.")
    lines.append(
        f"Unknown to every one of them when first asked: {novel_at_first}; "
        f"known to a feed since: {known_since}."
    )
    return "\n".join(lines) + "\n"
