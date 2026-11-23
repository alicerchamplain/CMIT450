"""Tests for graphwatch.enrich: what gets looked up and what the answers add up to (#38, #39).

Nothing here touches the network. Pages are synthetic, in the actor's two
shapes with made-up addresses; nothing reads a held-out page from known.txt.
"""

import pytest

from graphwatch.cli import run_classify
from graphwatch.db import add_snapshot, connect, save_lookup, upsert_indicator, upsert_page
from graphwatch.enrich import (
    Seen,
    collect_indicators,
    defang,
    host_of_url,
    novelty,
    novelty_rows,
    read_indicator_file,
    render_novelty_table,
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
    assert line == "| `8.8.8[.]8` | ip | 2023-11-14 | 4 | - | - | - | - | novel |"


def test_a_known_row_shows_what_each_feed_holds():
    line = table_lines()[3]
    assert line == (
        "| `c2.example[.]org` | host | 2023-11-14 | 1 "
        "| 2 IOCs, Made-up RAT | - | 4 pulses | - | known |"
    )


def test_a_feed_that_was_not_asked_says_so_and_the_row_is_unchecked():
    line = table_lines()[4]
    assert line == (
        "| `late.example[.]org` | host | - | 0 | - | not checked | not checked | not checked | unchecked |"
    )


def test_the_two_primary_feeds_make_a_row_novel_with_the_others_not_checked():
    line = table_lines()[5]
    assert line == "| `hxxp://8.8.4[.]4/a.exe` | url | 2023-11-14 | 1 | - | not checked | - | not checked | novel |"


def test_a_row_known_to_another_feed_only_is_known_and_its_day_is_utc():
    assert table_lines()[6:8] == [
        "| `old.example[.]org` | host | 2023-11-15 | 1 | - | not checked | - | malicious on 5 of 95 engines | known |",
        "| `half.example[.]org` | host | 2023-11-14 | 1 | - | 3 URLs | not checked | not checked | known |",
    ]


def test_the_shares_under_the_table():
    # The unchecked row is in neither share. The second share is not the
    # first: it counts old.example.org as absent and leaves half.example.org out.
    lines = table_lines()
    assert len(lines) == 2 + len(ROWS) + 4
    assert lines[-4] == ""
    assert lines[-3] == "6 indicators: 2 novel, 3 known, 1 unchecked."
    assert lines[-2] == "Novel, of the indicators with a verdict: 2 of 5."
    assert lines[-1] == (
        "Absent from ThreatFox and OTX, of the indicators both answered for: 3 of 4."
    )


def test_the_table_of_nothing_is_a_header_and_zero_counts():
    assert render_novelty_table([]) == (
        "| Indicator | Kind | First seen | Pages | ThreatFox | URLhaus | OTX | VirusTotal | Verdict |\n"
        "|---|---|---|---|---|---|---|---|---|\n"
        "\n"
        "0 indicators: 0 novel, 0 known, 0 unchecked.\n"
        "Novel, of the indicators with a verdict: 0 of 0.\n"
        "Absent from ThreatFox and OTX, of the indicators both answered for: 0 of 0.\n"
    )


# --------------------------------------------------------------------------
# novelty_rows: the stored indicators with their stored answers
# --------------------------------------------------------------------------


def test_novelty_rows_joins_each_indicator_with_its_lookups(conn):
    a = upsert_indicator(conn, "ip", "8.8.8.8", "pages", T0, T0 + DAY, 4)
    upsert_indicator(conn, "host", "late.example.org", "indicators.tsv")
    save_lookup(conn, a, "threatfox", "UNKNOWN", None, T0)
    save_lookup(conn, a, "otx", "KNOWN", "4 pulses", T0)
    rows = novelty_rows(conn)
    assert rows == [
        {"kind": "host", "value": "late.example.org", "first_seen": None, "pages": 0, "lookups": {}},
        {
            "kind": "ip",
            "value": "8.8.8.8",
            "first_seen": T0,
            "pages": 4,
            "lookups": {"otx": ("KNOWN", "4 pulses"), "threatfox": ("UNKNOWN", None)},
        },
    ]


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
        "| `8.8.8[.]8` | ip | 2023-11-14 | 1 "
        "| 2 IOCs, Some%7CName  with %60ticks%60 | not checked | - | not checked | known |"
    )
