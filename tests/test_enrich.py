"""Tests for graphwatch.enrich: what gets looked up and what the answers add up to (#38, #39).

Nothing here touches the network. Pages are synthetic, in the actor's two
shapes with made-up addresses; nothing reads a held-out page from known.txt.
"""

import sqlite3

import pytest

from graphwatch import enrich
from graphwatch.cli import run_classify
from graphwatch.db import add_snapshot, connect, save_lookup, upsert_indicator, upsert_page
from graphwatch.enrich import (
    Seen,
    collect_indicators,
    count_verdicts,
    defang,
    host_of_url,
    lookup_rows_for,
    novelty,
    novelty_rows,
    read_indicator_file,
    render_novelty_table,
    required_feeds,
)
from graphwatch.extract import extract

T0 = 1_700_000_000.0  # 2023-11-14 22:13 UTC
DAY = 86400.0
KEY = b"test-key"
API_SAMPLE = "Hello,+world!"
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"
OTHER_SPOOF_TITLE = "www.juniper.net@second.example-tunnel.workers.dev/"
# A spoof only as a title: the decoy does not end in a TLD the text pattern knows
AG_TITLE = "primewire.ag@agfc.harper18.workers.dev/"


def put(conn, path, title, body=API_SAMPLE, ts=T0, held_out=False) -> int:
    page_id = upsert_page(conn, path, ts, held_out=held_out)
    page = {"title": title, "description": body, "content": [body]}
    add_snapshot(conn, page_id, page, ts, KEY)
    return page_id


def quiet(_line):
    pass


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def collected(conn) -> dict:
    return {(seen.kind, seen.value): seen for seen in collect_indicators(conn)}


# --------------------------------------------------------------------------
# collect_indicators
# --------------------------------------------------------------------------


@pytest.mark.parametrize("title", [SPOOF_TITLE, AG_TITLE])
def test_collect_takes_the_destination_of_a_flagged_spoof_page_and_never_the_decoy(conn, title):
    # The left side of the spoof is bait: it must never be sent to a feed.
    put(conn, "Hello-10-17-9", title)
    run_classify(conn, log=quiet)
    assert list(collected(conn)) == [("host", "agfc.harper18.workers.dev")]


@pytest.mark.parametrize(
    "body",
    [
        "see https://www.tenable.com/plugins for more",
        "see https://WWW.Tenable.com:8443/plugins for more",  # the host of a URL, whatever its case and port
        "see www.tenable.com for more",
    ],
)
def test_a_url_on_the_decoys_own_site_is_not_collected_and_neither_is_its_host(conn, body):
    # The decoy is a real vendor's site. Its pages are no more the actor's
    # than its name is, and absent from the feeds they would count as novel.
    put(conn, "Hello-10-17-9", SPOOF_TITLE, body=body)
    run_classify(conn, log=quiet)
    assert list(collected(conn)) == [("host", "agfc.harper18.workers.dev")]


def test_a_decoy_on_one_flagged_page_is_not_collected_from_another(conn):
    put(conn, "Hello-10-17-9", SPOOF_TITLE)
    put(conn, "Hello-10-17-10", OTHER_SPOOF_TITLE, body="mirror of www.tenable.com and https://www.tenable.com/plugins")
    run_classify(conn, log=quiet)
    assert list(collected(conn)) == [
        ("host", "agfc.harper18.workers.dev"),
        ("host", "second.example-tunnel.workers.dev"),
    ]


def test_a_url_on_another_site_is_still_collected_from_a_spoof_page(conn):
    put(conn, "Hello-10-17-9", SPOOF_TITLE, body="get https://docs.tenable.com.example.org/x now")
    run_classify(conn, log=quiet)
    assert ("url", "https://docs.tenable.com.example.org/x") in collected(conn)
    assert ("host", "docs.tenable.com.example.org") in collected(conn)


def test_a_token_is_never_collected(conn):
    put(conn, "Hello-10-17-9", SPOOF_TITLE, body="dGViaQ== " + API_SAMPLE)
    run_classify(conn, log=quiet)
    # The run is in the stored text and extract does report it, as a token
    stored = conn.execute("SELECT title, text FROM snapshots").fetchone()
    assert ("token", "dGViaQ==") in {(i.kind, i.value) for i in extract(stored["title"], stored["text"])}
    assert list(collected(conn)) == [("host", "agfc.harper18.workers.dev")]


def test_a_page_that_was_never_flagged_gives_nothing(conn):
    put(conn, "Notes-10-17", "Notes", body="see 8.8.8.8 and c2.example.org")
    run_classify(conn, log=quiet)
    assert collect_indicators(conn) == []


def test_a_held_out_page_gives_nothing(conn):
    # Synthetic held-out row: real held-out content is never a test input.
    put(conn, "Known-01-02", SPOOF_TITLE, held_out=True)
    run_classify(conn, log=quiet)
    assert collect_indicators(conn) == []


def test_every_snapshot_is_read_and_first_and_last_seen_are_their_fetch_times(conn):
    # The actor edits in place: last week's address is in an older snapshot.
    page_id = put(conn, "Hello-10-17-9", SPOOF_TITLE, ts=T0)
    run_classify(conn, log=quiet)
    same = {"title": SPOOF_TITLE, "description": API_SAMPLE, "content": [API_SAMPLE], "views": 9}
    add_snapshot(conn, page_id, same, T0 + DAY, KEY)
    rotated = {"title": OTHER_SPOOF_TITLE, "description": API_SAMPLE, "content": [API_SAMPLE]}
    add_snapshot(conn, page_id, rotated, T0 + 2 * DAY, KEY)
    found = collected(conn)
    old = found[("host", "agfc.harper18.workers.dev")]
    new = found[("host", "second.example-tunnel.workers.dev")]
    assert (old.first_seen, old.last_seen) == (T0, T0 + DAY)
    assert (new.first_seen, new.last_seen) == (T0 + 2 * DAY, T0 + 2 * DAY)


def test_pages_counts_distinct_pages_not_snapshots(conn):
    first = put(conn, "Hello-10-17-9", SPOOF_TITLE, ts=T0)
    put(conn, "Hello-10-18-4", SPOOF_TITLE, ts=T0 + DAY)
    run_classify(conn, log=quiet)
    same = {"title": SPOOF_TITLE, "description": API_SAMPLE, "content": [API_SAMPLE], "views": 9}
    add_snapshot(conn, first, same, T0 + 2 * DAY, KEY)
    assert collected(conn)[("host", "agfc.harper18.workers.dev")].pages == 2


def test_an_indicator_is_collected_once_in_order_of_first_appearance(conn):
    put(conn, "Hello-10-17-9", OTHER_SPOOF_TITLE, ts=T0)
    put(conn, "Hello-10-18-4", SPOOF_TITLE, ts=T0 + DAY)
    put(conn, "Hello-10-19-2", OTHER_SPOOF_TITLE, ts=T0 + 2 * DAY)
    run_classify(conn, log=quiet)
    hosts = [seen.value for seen in collect_indicators(conn) if seen.kind == "host"]
    assert hosts == ["second.example-tunnel.workers.dev", "agfc.harper18.workers.dev"]


def test_the_order_and_the_times_do_not_depend_on_which_page_was_stored_first(conn):
    # The pages are read one after another by id. The page stored first here
    # was fetched last, and the indicator it shares was seen earlier elsewhere.
    put(conn, "Hello-10-19-2", OTHER_SPOOF_TITLE, ts=T0 + 2 * DAY)
    put(conn, "Hello-10-18-4", SPOOF_TITLE, ts=T0 + DAY)
    put(conn, "Hello-10-17-9", OTHER_SPOOF_TITLE, ts=T0)
    run_classify(conn, log=quiet)
    found = collect_indicators(conn)
    hosts = [seen.value for seen in found if seen.kind == "host"]
    assert hosts == ["second.example-tunnel.workers.dev", "agfc.harper18.workers.dev"]
    other = collected(conn)[("host", "second.example-tunnel.workers.dev")]
    assert (other.first_seen, other.last_seen, other.pages) == (T0, T0 + 2 * DAY, 2)

    # a url comes before its host, whatever else the page holds
    conn = connect(":memory:")
    body = "http://8.8.4.4/m2/file.exe and http://9.9.9.9/x"
    put(conn, "Hello-10-17-9", SPOOF_TITLE, body=body)
    run_classify(conn, log=quiet)
    found = [(seen.kind, seen.value) for seen in collect_indicators(conn)]
    assert found.index(("url", "http://8.8.4.4/m2/file.exe")) + 1 == found.index(("ip", "8.8.4.4"))
    assert found.index(("url", "http://9.9.9.9/x")) + 1 == found.index(("ip", "9.9.9.9"))
    assert found.index(("ip", "8.8.4.4")) < found.index(("url", "http://9.9.9.9/x"))


def test_two_snapshots_of_one_moment_are_ordered_by_which_was_stored_first_not_by_page(conn):
    # The first page's second snapshot was stored after the second page's
    # only one, in the same second. The old single read went by snapshot.
    first = put(conn, "Hello-10-17-9", AG_TITLE.replace("agfc.harper18", "third.example"), ts=T0)
    put(conn, "Hello-10-17-8", OTHER_SPOOF_TITLE, ts=T0 + 60)
    rotated = {"title": SPOOF_TITLE, "description": API_SAMPLE, "content": [API_SAMPLE]}
    add_snapshot(conn, first, rotated, T0 + 60, KEY)
    run_classify(conn, log=quiet)
    hosts = [seen.value for seen in collect_indicators(conn) if seen.kind == "host"]
    assert hosts == [
        "third.example.workers.dev",
        "second.example-tunnel.workers.dev",
        "agfc.harper18.workers.dev",
    ]


def test_the_order_inside_one_snapshot_holds_when_a_later_page_was_read_first(conn):
    # The page read first (it was stored first) was fetched later and holds
    # only the second of the two hosts that the earlier snapshot names.
    put(conn, "Hello-10-18-4", SPOOF_TITLE, ts=T0 + DAY)
    put(conn, "Hello-10-17-9", OTHER_SPOOF_TITLE, body="see agfc.harper18.workers.dev", ts=T0)
    run_classify(conn, log=quiet)
    found = collect_indicators(conn)
    assert [seen.value for seen in found if seen.kind == "host"] == [
        "second.example-tunnel.workers.dev",
        "agfc.harper18.workers.dev",
    ]
    assert {seen.first_seen for seen in found} == {T0}


def test_the_same_title_and_text_is_searched_once_however_many_snapshots_hold_it(conn, monkeypatch):
    # The actor writes its current addresses onto every earlier page, and the
    # re-poll stores each rewrite: thousands of snapshots, a handful of texts.
    searched = []

    def counting(title, text):
        searched.append((title, text))
        return extract(title, text)

    monkeypatch.setattr(enrich, "extract", counting)
    for day in range(1, 6):
        page_id = put(conn, f"Hello-10-{day:02d}-1", SPOOF_TITLE, ts=T0 + day * DAY)
        rotated = {"title": OTHER_SPOOF_TITLE, "description": API_SAMPLE, "content": [API_SAMPLE]}
        add_snapshot(conn, page_id, rotated, T0 + day * DAY + 60, KEY)
    run_classify(conn, log=quiet)
    found = collected(conn)
    assert len(searched) == 2
    assert len(set(searched)) == 2
    # and nothing is lost by it: every page and both ends of the time span count
    seen = found[("host", "agfc.harper18.workers.dev")]
    assert (seen.first_seen, seen.last_seen, seen.pages) == (T0 + DAY, T0 + 5 * DAY, 5)

    put(conn, "Hello-10-17-9", SPOOF_TITLE, body="http://8.8.4.4/m2/file.exe")
    put(conn, "Hello-10-18-4", SPOOF_TITLE, body="http://9.9.9.9/x", ts=T0 + DAY)
    run_classify(conn, log=quiet)
    assert {("ip", "8.8.4.4"), ("ip", "9.9.9.9")} <= set(collected(conn))


def test_collect_leaves_no_read_open_while_it_pulls_the_indicators_out(tmp_path, monkeypatch):
    # The database is in rollback-journal mode, where a read left open makes
    # every other writer's commit wait, and fail after the busy timeout. The
    # re-poll writes every ten minutes, so it has to be able to commit at any
    # point of this. The second connection does not wait at all.
    path = tmp_path / "g.sqlite"
    conn = connect(path)
    # Two pages with two snapshots each, every one a different text: a read
    # that hands its rows out one at a time is still open at each of them
    for path_name, titles in (("Hello-10-17-9", (SPOOF_TITLE, AG_TITLE)), ("Hello-10-18-4", (OTHER_SPOOF_TITLE, SPOOF_TITLE))):
        page_id = put(conn, path_name, titles[0])
        later = {"title": titles[1], "description": "rotated", "content": ["rotated " + path_name]}
        add_snapshot(conn, page_id, later, T0 + DAY, KEY)
    run_classify(conn, log=quiet)
    conn.commit()
    other_job = sqlite3.connect(path, timeout=0)
    wrote = []

    def extract_while_another_job_writes(title, text):
        other_job.execute("UPDATE pages SET last_seen = last_seen + 1")
        other_job.commit()
        wrote.append(title)
        return extract(title, text)

    monkeypatch.setattr(enrich, "extract", extract_while_another_job_writes)
    found = collect_indicators(conn)
    other_job.close()
    conn.close()
    assert len(wrote) == 4
    assert {seen.value for seen in found} == {"agfc.harper18.workers.dev", "second.example-tunnel.workers.dev"}


def test_collect_reads_the_database_and_writes_nothing(conn):
    # It is given no client, so it has nothing to make a request with. What
    # it could do is write, and no table gains or changes a row.
    put(conn, "Hello-10-17-9", SPOOF_TITLE)
    run_classify(conn, log=quiet)
    before = conn.total_changes
    assert collect_indicators(conn)
    assert conn.total_changes == before


# --------------------------------------------------------------------------
# read_indicator_file
# --------------------------------------------------------------------------

FILE = (
    "kind\tvalue\tset\tstatus\n"
    "host\tfirst.example-tunnel.workers.dev\tactor\tnew\n"
    "ip\t8.8.8.8\tactor\tnew\n"
    "url\thttp://8.8.4.4/m2/file.exe\tother\tnew\n"
    "decoy\twww.tenable.com\tactor\tnew\n"
    "token\tdGViaQ==\tactor\tnew\n"
    "ip \t 8.8.8.8 \tactor\tbefore\n"
    "ip\t\tactor\tno value\n"
    "\n"
    "host\n"
)


def write(tmp_path, text, name="indicators.tsv"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_the_file_reader_takes_the_addresses_once_and_counts_the_decoys_and_tokens_it_skips(tmp_path):
    found, skipped = read_indicator_file(write(tmp_path, FILE))
    assert found == [
        Seen("host", "first.example-tunnel.workers.dev"),
        Seen("ip", "8.8.8.8"),
        Seen("url", "http://8.8.4.4/m2/file.exe"),
        Seen("ip", "8.8.4.4"),  # the url's host, looked up beside it
    ]
    assert skipped == 2
    # An indicator read from a file has no times and no pages
    assert all((s.first_seen, s.last_seen, s.pages) == (None, None, 0) for s in found)


def test_the_file_reader_finds_the_columns_wherever_they_are(tmp_path):
    text = "note\tvalue\tkind\nseen once\t8.8.8.8\tip\n"
    assert read_indicator_file(write(tmp_path, text))[0] == [Seen("ip", "8.8.8.8")]


@pytest.mark.parametrize("text", ["", "value\tset\n8.8.8.8\tactor\n", "kind\tset\nip\tactor\n"])
def test_the_file_reader_refuses_a_file_without_both_columns(tmp_path, text):
    with pytest.raises(ValueError) as exc:
        read_indicator_file(write(tmp_path, text))
    assert "kind" in str(exc.value)


# --------------------------------------------------------------------------
# novelty
# --------------------------------------------------------------------------

ALL_UNKNOWN = {"threatfox": "UNKNOWN", "urlhaus": "UNKNOWN", "otx": "UNKNOWN", "virustotal": "UNKNOWN"}


def test_unknown_to_every_feed_is_novel():
    assert novelty(ALL_UNKNOWN) == "novel"


@pytest.mark.parametrize("feed", ["otx", "virustotal"])
def test_known_to_any_one_feed_is_known(feed):
    assert novelty({**ALL_UNKNOWN, feed: "KNOWN"}) == "known"


def test_the_two_primary_feeds_alone_can_say_novel():
    # The cut line: ThreatFox and OTX only, VirusTotal and URLhaus added later.
    assert novelty({"threatfox": "UNKNOWN", "otx": "UNKNOWN"}) == "novel"


def test_a_feed_that_is_in_use_has_to_answer_before_an_indicator_is_novel():
    # VirusTotal's quota ran out before this one: what it would have said is
    # not known, and seven of the first table's known rows were its alone.
    primary_only = {"threatfox": "UNKNOWN", "otx": "UNKNOWN"}
    every_feed = ("threatfox", "urlhaus", "otx", "virustotal")
    assert novelty(primary_only, every_feed) == "unchecked"
    assert novelty({**primary_only, "urlhaus": "UNKNOWN"}, every_feed) == "unchecked"
    assert novelty(ALL_UNKNOWN, every_feed) == "novel"

    assert novelty({"urlhaus": "KNOWN"}, ("threatfox", "urlhaus", "otx", "virustotal")) == "known"


def answers(*feeds, known=()) -> dict:
    return {feed: ("KNOWN" if feed in known else "UNKNOWN", None) for feed in feeds}


def test_the_required_feeds_are_the_primary_two_until_another_feed_has_answered():
    assert required_feeds([]) == ("threatfox", "otx")
    assert required_feeds([row("ip", "8.8.8.8", {})]) == ("threatfox", "otx")
    assert required_feeds([row("ip", "8.8.8.8", answers("threatfox"))]) == ("threatfox", "otx")

    rows = [
        row("ip", "8.8.8.8", answers("threatfox", "otx")),
        row("ip", "9.9.9.9", answers("virustotal", known=("virustotal",))),
    ]
    assert required_feeds(rows) == ("threatfox", "otx", "virustotal")
    rows.append(row("ip", "1.1.1.1", answers("urlhaus")))
    assert required_feeds(rows) == ("threatfox", "urlhaus", "otx", "virustotal")


def test_a_run_cut_short_does_not_count_more_novel_indicators_than_a_whole_one():
    # Two indicators. VirusTotal alone knows the second.
    whole = [
        row("ip", "8.8.8.8", answers("threatfox", "urlhaus", "otx", "virustotal")),
        row("ip", "9.9.9.9", answers("threatfox", "urlhaus", "otx", "virustotal", known=("virustotal",))),
    ]
    assert count_verdicts(whole) == {"novel": 1, "known": 1, "unchecked": 0}
    # The same run with VirusTotal's quota spent after the first indicator
    cut = [whole[0], row("ip", "9.9.9.9", answers("threatfox", "urlhaus", "otx"))]
    assert count_verdicts(cut) == {"novel": 1, "known": 0, "unchecked": 1}

    # A feed that never answered is not waited for: enrich skips a feed with no key
    rows = [
        row("ip", "8.8.8.8", answers("threatfox", "urlhaus", "otx")),
        row("ip", "9.9.9.9", answers("threatfox", "urlhaus", "otx", known=("urlhaus",))),
    ]
    assert count_verdicts(rows) == {"novel": 1, "known": 1, "unchecked": 0}
    assert count_verdicts([]) == {"novel": 0, "known": 0, "unchecked": 0}


def test_a_feed_with_a_key_is_required_before_it_has_answered_anything():
    # VirusTotal's quota was spent, or its key refused, from its first lookup
    # on: nothing of its is stored, and it still has to answer.
    rows = [
        row("ip", "8.8.8.8", answers("threatfox", "urlhaus", "otx")),
        row("ip", "9.9.9.9", answers("threatfox", "urlhaus", "otx", known=("otx",))),
    ]
    assert required_feeds(rows) == ("threatfox", "urlhaus", "otx")
    keyed = ("threatfox", "urlhaus", "otx", "virustotal")
    assert required_feeds(rows, keyed) == keyed
    assert required_feeds([], ("virustotal",)) == ("threatfox", "otx", "virustotal")
    assert count_verdicts(rows, keyed) == {"novel": 0, "known": 1, "unchecked": 1}
    lines = render_novelty_table(rows, in_use=keyed).splitlines()
    assert lines[2].endswith("| not checked | unchecked |")
    assert lines[-8] == "2 indicators: 0 novel, 1 known, 1 unchecked."
    assert lines[-5] == "Novel means unknown to every one of: ThreatFox, URLhaus, OTX, VirusTotal."
    # and the table says which feed the unchecked one waits for
    assert lines[-4] == "Unchecked indicators wait: 1 for VirusTotal."

    rows = [
        row("ip", "8.8.8.8", answers("threatfox", "urlhaus", "otx", "virustotal")),
        row("ip", "9.9.9.9", answers("threatfox", "urlhaus", "otx")),
    ]
    assert count_verdicts(rows, ("threatfox", "urlhaus", "otx")) == {"novel": 1, "known": 0, "unchecked": 1}


@pytest.mark.parametrize("missing", ["threatfox", "otx"])
def test_a_missing_primary_feed_leaves_the_indicator_unchecked(missing):
    verdicts = {feed: verdict for feed, verdict in ALL_UNKNOWN.items() if feed != missing}
    assert novelty(verdicts) == "unchecked"


def test_no_answer_at_all_is_unchecked_never_novel():
    assert novelty({}) == "unchecked"


def test_one_known_is_enough_even_with_a_primary_feed_missing():
    assert novelty({"virustotal": "KNOWN"}) == "known"


# --------------------------------------------------------------------------
# defang and the table
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,value,safe",
    [
        ("ip", "8.8.8.8", "8.8.8[.]8"),
        ("ip", "8.8.8.8:8443", "8.8.8[.]8:8443"),
        ("host", "localhost", "localhost"),
        ("url", "https://c2.example.org/a.b/c", "hxxps://c2.example[.]org/a.b/c"),
        ("url", "HTTP://c2.example.org", "hxxp://c2.example[.]org"),
        # A hand-written file can hold a url with no scheme
        ("url", "c2.example.org/a.b", "c2.example[.]org/a.b"),
        # What the review of 22 November found: only the host is bracketed, whatever follows it
        ("url", "http://evil.example.com?u=file.php", "hxxp://evil.example[.]com?u=file.php"),
        ("url", "https://evil.example.com#a.b", "hxxps://evil.example[.]com#a.b"),
        ("url", "http://good.example.org@evil.example.com/x", "hxxp://good.example[.]org@evil.example[.]com/x"),
        ("url", "http://evil.example.com:8080/a.b", "hxxp://evil.example[.]com:8080/a.b"),
        ("ip", "2a00::1", "2a00[:]:1"),
        ("url", "http://[2001:db8::1]:80/x", "hxxp://[2001[:]db8::1]:80/x"),
    ],
)
def test_defang(kind, value, safe):
    assert defang(kind, value) == safe


def row(kind, value, lookups, first_seen=T0, pages=1) -> dict:
    return {"kind": kind, "value": value, "first_seen": first_seen, "pages": pages, "lookups": lookups}


ROWS = [
    row("ip", "8.8.8.8", {feed: ("UNKNOWN", None) for feed in ALL_UNKNOWN}, pages=4),
    row(
        "host",
        "c2.example.org",
        {
            "threatfox": ("KNOWN", "2 IOCs, Made-up RAT"),
            "urlhaus": ("UNKNOWN", None),
            "otx": ("KNOWN", "4 pulses"),
            "virustotal": ("UNKNOWN", None),
        },
    ),
    row("host", "late.example.org", {"threatfox": ("UNKNOWN", None)}, first_seen=None, pages=0),
    row("url", "http://8.8.4.4/a.exe", {"threatfox": ("UNKNOWN", None), "otx": ("UNKNOWN", None)}),
    # Known, yet absent from the two primary feeds. First seen at 00:13 UTC the next day.
    row(
        "host",
        "old.example.org",
        {"threatfox": ("UNKNOWN", None), "otx": ("UNKNOWN", None), "virustotal": ("KNOWN", "malicious on 5 of 95 engines")},
        first_seen=T0 + 7200,
    ),
    # Known, with one of the primary feeds never asked
    row("host", "half.example.org", {"threatfox": ("UNKNOWN", None), "urlhaus": ("KNOWN", "3 URLs")}),
]


def table_lines() -> list[str]:
    return render_novelty_table(ROWS).splitlines()


def test_the_table_prints_every_indicator_defanged():
    out = render_novelty_table(ROWS)
    assert "`8.8.8[.]8`" in out
    assert "`c2.example[.]org`" in out
    assert "`hxxp://8.8.4[.]4/a.exe`" in out
    for plain in ("8.8.8.8", "c2.example.org", "http://"):
        assert plain not in out


def test_a_novel_row_shows_a_dash_for_every_feed():
    line = table_lines()[2]
    # these rows are on pages and built without titles, which prints as ?
    assert line == "| `8.8.8[.]8` | ip | 2023-11-14 | 4 | ? | - | - | - | - | novel |"


def test_a_known_row_shows_what_each_feed_holds():
    line = table_lines()[3]
    assert line == (
        "| `c2.example[.]org` | host | 2023-11-14 | 1 | ? "
        "| 2 IOCs, Made-up RAT | - | 4 pulses | - | known |"
    )


def test_a_feed_that_was_not_asked_says_so_and_the_row_is_unchecked():
    line = table_lines()[4]
    assert line == (
        "| `late.example[.]org` | host | - | 0 | - | - | not checked | not checked | not checked | unchecked |"
    )


def test_a_row_the_other_feeds_were_not_asked_about_is_unchecked_once_they_are_in_use():
    # URLhaus and VirusTotal answered for other rows of this table
    line = table_lines()[5]
    assert line == "| `hxxp://8.8.4[.]4/a.exe` | url | 2023-11-14 | 1 | ? | - | not checked | - | not checked | unchecked |"

    lines = render_novelty_table([ROWS[3]]).splitlines()
    assert lines[2] == "| `hxxp://8.8.4[.]4/a.exe` | url | 2023-11-14 | 1 | ? | - | not checked | - | not checked | novel |"
    assert lines[-5] == "Novel means unknown to every one of: ThreatFox, OTX."
    assert lines[-4] == "Unchecked indicators wait: none."


def test_the_table_and_the_count_give_the_same_verdicts():
    lines = table_lines()
    printed = [line.rsplit("|", 2)[1].strip() for line in lines[2 : 2 + len(ROWS)]]
    counts = count_verdicts(ROWS)
    assert {verdict: printed.count(verdict) for verdict in counts} == counts


def test_a_row_known_to_another_feed_only_is_known_and_its_day_is_utc():
    assert table_lines()[6:8] == [
        "| `old.example[.]org` | host | 2023-11-15 | 1 | ? | - | not checked | - | malicious on 5 of 95 engines | known |",
        "| `half.example[.]org` | host | 2023-11-14 | 1 | ? | - | 3 URLs | not checked | not checked | known |",
    ]


def test_the_shares_under_the_table():
    # The unchecked row is in neither share. The second share is not the
    # first: it counts old.example.org as absent and leaves half.example.org out.
    lines = table_lines()
    assert len(lines) == 2 + len(ROWS) + 9
    assert lines[-9] == ""
    assert lines[-8] == "6 indicators: 1 novel, 3 known, 2 unchecked."
    assert lines[-7] == "Novel, of the indicators with a verdict: 1 of 4."
    # Rows built by hand name no title. The five that are on pages count
    # apart from the one that no page holds, late.example.org
    assert lines[-6] == (
        "By the title of the pages that hold them: title not recorded: 1 novel, 3 known, 1 unchecked; "
        "no page: 0 novel, 0 known, 1 unchecked."
    )
    # every feed that has answered for a row of the table, in feed order
    assert lines[-5] == "Novel means unknown to every one of: ThreatFox, URLhaus, OTX, VirusTotal."
    # late.example.org has only ThreatFox's answer; the url has ThreatFox's and OTX's
    assert lines[-4] == "Unchecked indicators wait: 2 for URLhaus, 1 for OTX, 2 for VirusTotal."
    assert lines[-3] == (
        "Absent from ThreatFox and OTX, of the indicators both answered for: 3 of 4."
    )
    # rows built by hand carry no dates, and none was asked about twice
    assert lines[-2] == "Answers given: none."
    assert lines[-1] == "Unknown to every one of them when first asked: 1; known to a feed since: 0."


def test_the_table_of_nothing_is_a_header_and_zero_counts():
    assert render_novelty_table([]) == (
        "| Indicator | Kind | First seen | Pages | Titles | ThreatFox | URLhaus | OTX | VirusTotal | Verdict |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "\n"
        "0 indicators: 0 novel, 0 known, 0 unchecked.\n"
        "Novel, of the indicators with a verdict: 0 of 0.\n"
        "By the title of the pages that hold them: none.\n"
        "Novel means unknown to every one of: ThreatFox, OTX.\n"
        "Unchecked indicators wait: none.\n"
        "Absent from ThreatFox and OTX, of the indicators both answered for: 0 of 0.\n"
        "Answers given: none.\n"
        "Unknown to every one of them when first asked: 0; known to a feed since: 0.\n"
    )


# --------------------------------------------------------------------------
# novelty_rows: the stored indicators with their stored answers
# --------------------------------------------------------------------------


def test_novelty_rows_joins_each_indicator_with_its_lookups(conn):
    a = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + DAY, 4, {"botnet": 1, "hello": 3})
    upsert_indicator(conn, "host", "late.example.org", "indicators.tsv")
    save_lookup(conn, a, "threatfox", "UNKNOWN", None, T0)
    save_lookup(conn, a, "otx", "KNOWN", "4 pulses", T0)
    rows = novelty_rows(conn)
    assert rows == [
        {
            "kind": "host",
            "value": "late.example.org",
            "first_seen": None,
            "pages": 0,
            "titles": {},
            "lookups": {},
            "first": {},
            "asked": {},
        },
        {
            "kind": "ip",
            "value": "8.8.8.8",
            "first_seen": T0,
            "pages": 4,
            "titles": {"hello": 3, "botnet": 1},
            "lookups": {"otx": ("KNOWN", "4 pulses"), "threatfox": ("UNKNOWN", None)},
            "first": {"otx": "KNOWN", "threatfox": "UNKNOWN"},
            "asked": {"otx": T0, "threatfox": T0},
        },
    ]
    # the titles as stored, the one on most pages first, and so into the table
    assert list(rows[1]["titles"]) == ["hello", "botnet"]
    lines = render_novelty_table(rows).splitlines()
    assert [line.split("|")[5].strip() for line in lines[2:4]] == ["-", "hello, botnet"]
    assert "botnet: 0 novel, 1 known, 0 unchecked; hello: 0 novel, 1 known, 0 unchecked; no page: " in lines[-6]

    # what a feed said first is kept beside what it says now
    conn = connect(":memory:")
    a = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0, 1)
    save_lookup(conn, a, "threatfox", "UNKNOWN", None, T0)
    save_lookup(conn, a, "threatfox", "KNOWN", "1 IOCs, Made-up RAT", T0 + 14 * DAY)
    (found,) = novelty_rows(conn)
    assert found["lookups"] == {"threatfox": ("KNOWN", "1 IOCs, Made-up RAT")}
    assert found["first"] == {"threatfox": "UNKNOWN"}
    assert found["asked"] == {"threatfox": T0 + 14 * DAY}


def test_the_table_says_when_its_answers_were_given_and_what_the_feeds_learned_since(conn):
    # Three indicators nobody knew on the day. Two weeks on, ThreatFox lists one.
    for n, value in enumerate(["8.8.8.8", "9.9.9.9", "1.1.1.1"]):
        indicator_id = upsert_indicator(conn, "ip", value, "pages", T0, T0, 1)
        save_lookup(conn, indicator_id, "threatfox", "UNKNOWN", None, T0 + n)
        save_lookup(conn, indicator_id, "otx", "UNKNOWN", None, T0 + n)
    learned = conn.execute("SELECT id FROM indicators WHERE value = '9.9.9.9'").fetchone()[0]
    save_lookup(conn, learned, "threatfox", "KNOWN", "1 IOCs, Made-up RAT", T0 + 14 * DAY)
    lines = render_novelty_table(novelty_rows(conn)).splitlines()
    assert lines[-8] == "3 indicators: 2 novel, 1 known, 0 unchecked."
    assert lines[-2] == "Answers given from 2023-11-14 to 2023-11-28 (UTC)."
    assert lines[-1] == "Unknown to every one of them when first asked: 3; known to a feed since: 1."

    known = row("ip", "8.8.8.8", answers("threatfox", "otx", known=("otx",)))
    lines = render_novelty_table([known]).splitlines()
    assert lines[-1] == "Unknown to every one of them when first asked: 0; known to a feed since: 0."


# --------------------------------------------------------------------------
# what the review of 22 November found
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,host",
    [
        ("http://c2.example.org:8080/gate.php", ("host", "c2.example.org")),
        ("http://8.8.4.4/m2/file.exe", ("ip", "8.8.4.4")),
        ("https://user@C2.Example.org/x", ("host", "c2.example.org")),
        ("http://[broken", None),
        ("http:///nohost", None),
    ],
)
def test_host_of_url(url, host):
    assert host_of_url(url) == host


@pytest.mark.parametrize(
    "kind,value,rows",
    [
        ("ip", "8.8.8.8", [("ip", "8.8.8.8")]),
        ("host", "c2.example.org", [("host", "c2.example.org")]),
        # a url and, after it, its host
        ("url", "http://8.8.4.4/m2/file.exe", [("url", "http://8.8.4.4/m2/file.exe"), ("ip", "8.8.4.4")]),
        ("url", "https://c2.example.org/?id=1", [("url", "https://c2.example.org/?id=1"), ("host", "c2.example.org")]),
        ("url", "http://c2.example.org/#top", [("url", "http://c2.example.org/#top"), ("host", "c2.example.org")]),
        # a port or a user is something the host row would not show
        ("url", "http://8.8.4.4:8080", [("url", "http://8.8.4.4:8080"), ("ip", "8.8.4.4")]),
        ("url", "http://user@c2.example.org/", [("url", "http://user@c2.example.org/"), ("host", "c2.example.org")]),
        ("url", "http://8.8.4.4:port/", [("url", "http://8.8.4.4:port/"), ("ip", "8.8.4.4")]),
        # a url that names nothing but a host is that host, once
        ("url", "http://8.8.4.4", [("ip", "8.8.4.4")]),
        ("url", "http://8.8.4.4/", [("ip", "8.8.4.4")]),
        ("url", "HTTPS://C2.Example.org", [("host", "c2.example.org")]),
        # no host that can be read: the url as it was written
        ("url", "http:///nohost", [("url", "http:///nohost")]),
    ],
)
def test_lookup_rows_for(kind, value, rows):
    assert lookup_rows_for(kind, value) == rows


def test_a_url_that_names_only_a_host_is_collected_as_that_host_once(conn, tmp_path):
    # One server on one page was two rows of the first table, and both novel
    put(conn, "Hello-10-17-9", SPOOF_TITLE, body="http://8.8.4.4 and http://9.9.9.9/x")
    run_classify(conn, log=quiet)
    found = [(seen.kind, seen.value) for seen in collect_indicators(conn)]
    assert ("ip", "8.8.4.4") in found
    assert ("url", "http://8.8.4.4") not in found
    assert found.count(("ip", "8.8.4.4")) == 1
    assert ("url", "http://9.9.9.9/x") in found and ("ip", "9.9.9.9") in found

    # and the file reader does the same
    path = write(tmp_path, "kind\tvalue\nurl\thttp://8.8.4.4\nip\t8.8.4.4\nurl\thttp://8.8.4.4/a.exe\n")
    found, skipped = read_indicator_file(path)
    assert [(seen.kind, seen.value) for seen in found] == [("ip", "8.8.4.4"), ("url", "http://8.8.4.4/a.exe")]
    assert skipped == 0


def test_the_host_of_a_collected_url_is_collected_beside_it(conn):
    # A feed that has never seen this exact URL may know its host. Looking
    # only the URL up counted every url on a known server as novel.
    put(conn, "Hello-10-17-9", SPOOF_TITLE, body="get http://c2.example.org:8080/gate.php now")
    run_classify(conn, log=quiet)
    found = collected(conn)
    assert ("url", "http://c2.example.org:8080/gate.php") in found
    host = found[("host", "c2.example.org")]
    assert (host.first_seen, host.pages) == (T0, 1)


def test_a_file_url_whose_host_is_also_listed_gives_the_host_once(tmp_path):
    text = "kind\tvalue\nurl\thttp://8.8.4.4/a.exe\nip\t8.8.4.4\nurl\thttp://8.8.4.4/b.exe\n"
    found, _skipped = read_indicator_file(write(tmp_path, text))
    assert [(s.kind, s.value) for s in found] == [
        ("url", "http://8.8.4.4/a.exe"),
        ("ip", "8.8.4.4"),
        ("url", "http://8.8.4.4/b.exe"),
    ]


def test_a_backtick_or_pipe_in_an_indicator_cannot_break_out_of_its_cell():
    # The value is text from a page. A backtick would close the code span and
    # let what follows be read as Markdown: a live link in a committed report.
    tick = chr(96)
    value = f"http://evil.example.com/a{tick}[click-here](https://evil.example.com/b){tick}c|d|e"
    out = render_novelty_table([row("url", value, {})])
    line = next(l for l in out.splitlines() if l.startswith("| `"))
    assert line.count("`") == 2
    assert len(line.split("|")) == len(out.splitlines()[0].split("|"))
    assert "%60" in line and "%7C" in line


def test_a_pipe_or_line_break_in_what_a_feed_says_cannot_break_the_row():
    lookups = {"threatfox": ("KNOWN", "2 IOCs, Some|Name\r\nwith `ticks`"), "otx": ("UNKNOWN", None)}
    out = render_novelty_table([row("ip", "8.8.8.8", lookups)])
    assert out.splitlines()[2] == (
        "| `8.8.8[.]8` | ip | 2023-11-14 | 1 | ? "
        "| 2 IOCs, Some%7CName  with %60ticks%60 | not checked | - | not checked | known |"
    )


# --------------------------------------------------------------------------
# whose pages an indicator is on (24 November): the classifier flags what
# looks like a resolver whoever posted it, and the actor's pages are Hello
# --------------------------------------------------------------------------


def test_collect_says_under_which_titles_the_flagged_pages_hold_an_indicator(conn):
    first = put(conn, "Hello-10-17-9", SPOOF_TITLE, ts=T0)
    put(conn, "Hello-10-18-4", SPOOF_TITLE, ts=T0 + DAY)
    again = {"title": SPOOF_TITLE, "description": API_SAMPLE, "content": [API_SAMPLE], "views": 9}
    add_snapshot(conn, first, again, T0 + 4 * DAY, KEY)  # a second snapshot of the same page
    put(conn, "botnet-11-20", SPOOF_TITLE, body="http://8.8.4.4/m2/file.exe", ts=T0 + 2 * DAY)
    put(conn, "botnet-11-21", OTHER_SPOOF_TITLE, ts=T0 + 3 * DAY)
    run_classify(conn, log=quiet)
    found = collected(conn)
    # the title on most pages first; a title is counted in pages, not snapshots
    assert found[("host", "agfc.harper18.workers.dev")].titles == (("hello", 2), ("botnet", 1))
    assert found[("host", "second.example-tunnel.workers.dev")].titles == (("botnet", 1),)
    assert found[("url", "http://8.8.4.4/m2/file.exe")].titles == (("botnet", 1),)
    assert found[("ip", "8.8.4.4")].titles == (("botnet", 1),)
    # an indicator a file names is on no page
    assert Seen("ip", "9.9.9.9").titles == ()


def test_the_table_names_the_titles_and_counts_the_verdicts_under_each():
    def titled(value, titles, **known):
        lookups = answers("threatfox", "otx", known=tuple(known))
        return {**row("ip", value, lookups), "titles": titles}

    both = answers("threatfox", "otx")
    rows = [
        titled("8.8.8.8", {"hello": 61}),
        titled("9.9.9.9", {"hello": 3, "botnet": 1}, otx=True),
        titled("8.8.4.4", {"botnet": 1}),
        {**row("ip", "1.1.1.1", both, pages=0), "titles": {}},  # only a file names it
        {**row("ip", "1.0.0.1", answers("threatfox")), "titles": {"hello": 2}},
        {**row("ip", "9.9.9.10", answers("otx")), "titles": {"with|pipe": 1}},
        # on three pages, stored before the titles were kept
        {**row("ip", "9.9.9.11", both, pages=3), "titles": {}},
        # given back to its file by code that did not know of the titles: no page holds it
        {**row("ip", "9.9.9.12", both, pages=0), "titles": {"hello": 2}},
    ]
    lines = render_novelty_table(rows).splitlines()
    assert lines[0].startswith("| Indicator | Kind | First seen | Pages | Titles | ThreatFox |")
    assert [line.split("|")[5].strip() for line in lines[2:10]] == [
        "hello", "hello, botnet", "botnet", "-", "hello", "with%7Cpipe", "?", "-",
    ]
    # An indicator on pages of two titles counts under each, and the line
    # says so, because its shares then add up to more than the indicators
    # there are. The title on most indicators comes first; what has no title
    # stored and what no page holds come last.
    assert lines[-6] == (
        "By the title of the pages that hold them: hello: 1 novel, 1 known, 1 unchecked; "
        "botnet: 1 novel, 1 known, 0 unchecked; with%7Cpipe: 0 novel, 0 known, 1 unchecked; "
        "title not recorded: 1 novel, 0 known, 0 unchecked; no page: 2 novel, 0 known, 0 unchecked "
        "(an indicator on pages of several titles counts under each)."
    )
    assert lines[-4] == "Unchecked indicators wait: 1 for ThreatFox, 1 for OTX."
    # with every indicator under one title the shares add up, and nothing is said
    assert "counts under each" not in render_novelty_table(rows[:1] + rows[2:])
