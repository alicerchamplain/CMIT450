"""Tests for graphwatch.telegraph.

Every test here runs offline. The HTTP-facing tests hand the client a stub
session, so nothing in this file can reach the network.
"""

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
import requests

from graphwatch.telegraph import (
    _node_links,
    _node_text,
    Ahead,
    ALLOWED_HOSTS,
    BLOCK_TAGS,
    BudgetExceeded,
    build_path,
    Fetch,
    Outcome,
    page_links,
    page_text,
    parse_envelope,
    parse_html_meta,
    Pool,
    TelegraphClient,
)

FIXTURES = Path(__file__).resolve().parents[1] / "plan" / "fixtures"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / f"{name}.json").read_bytes()


def fixture_page(name: str) -> dict:
    return json.loads(fixture_bytes(name))["result"]


# --------------------------------------------------------------------------
# build_path
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "slug, month, day, n, expected",
    [
        ("Vizit", 12, 28, None, "Vizit-12-28"),  # no counter, padded month
        ("ki06", 5, 2, None, "ki06-05-02"),  # single-digit month and day
        ("Hello", 10, 17, 154, "Hello-10-17-154"),  # counter appended
        # A counter of 0 is a value, not "no counter"; `if n:` would drop it.
        ("x", 1, 1, 0, "x-01-01-0"),
    ],
)
def test_build_path_matches_known_paths(slug, month, day, n, expected):
    assert build_path(slug, month, day, n) == expected


# --------------------------------------------------------------------------
# parse_envelope
# --------------------------------------------------------------------------


def test_parse_envelope_found_fixture():
    outcome, page, error = parse_envelope(200, fixture_bytes("Vizit-12-28"))
    assert outcome is Outcome.FOUND
    assert page["path"] == "Vizit-12-28"
    assert error is None


def test_parse_envelope_not_found_fixture():
    outcome, page, error = parse_envelope(200, fixture_bytes("not-found"))
    assert outcome is Outcome.NOT_FOUND
    assert page is None
    assert error == "PAGE_NOT_FOUND"


@pytest.mark.parametrize(
    "status, body",
    [
        (502, b"<html>Bad Gateway</html>"),  # not JSON
        (200, b"\xff\xfe"),  # not UTF-8
        (200, b"[1, 2, 3]"),  # JSON but not an object
        (200, b'{"ok": true}'),  # ok without a result
        (200, b'{"ok": true, "result": "x"}'),  # result not a dict
        (200, b'{"ok": 1, "result": {}}'),  # 1 is not the boolean true
        (200, b'{"ok": false, "error": "FLOOD_WAIT"}'),  # other API error
        (200, b'{"ok": false}'),  # error missing
        (200, b'{"error": "PAGE_NOT_FOUND"}'),  # not found, but ok is missing
    ],
)
def test_parse_envelope_failed_shapes(status, body):
    # Everything that is not the exact good shape or the exact not-found
    # shape is FAILED, so it is retried and never closes a day.
    outcome, page, error = parse_envelope(status, body)
    assert outcome is Outcome.FAILED
    assert page is None
    assert isinstance(error, str) and error


def test_parse_envelope_a_not_found_body_is_not_found_whatever_the_status():
    # The body is the authority, not the status line.
    outcome, page, error = parse_envelope(
        429, b'{"ok": false, "error": "PAGE_NOT_FOUND"}'
    )
    assert (outcome, page, error) == (Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND")


def test_parse_envelope_failed_error_mentions_status_for_bad_body():
    _, _, error = parse_envelope(502, b"<html>")
    assert "502" in error


def test_parse_envelope_keeps_api_error_text():
    _, _, error = parse_envelope(200, b'{"ok": false, "error": "FLOOD_WAIT"}')
    assert error == "FLOOD_WAIT"


def test_parse_envelope_never_echoes_the_body():
    # The error string ends up in the logs unhashed, so neither shape that is
    # parsed and then refused (a wrong envelope, a JSON value that is not an
    # object) may dump the page into it.
    secret = "user:hunter2@example"
    envelope = {"ok": "maybe", "result": {"content": [secret]}}
    for data in (envelope, [envelope]):
        outcome, _, error = parse_envelope(200, json.dumps(data).encode())
        assert outcome is Outcome.FAILED
        assert secret not in error


# --------------------------------------------------------------------------
# content walkers
# --------------------------------------------------------------------------


def test_block_tags_are_the_nine_that_end_a_line():
    # page_text is what the classifier reads, so which tags end a line changes
    # its input. Telegraph's other tags (a, b, i, em, strong, u, s, code) are
    # inline.
    assert BLOCK_TAGS == frozenset(
        {"p", "br", "li", "h3", "h4", "blockquote", "pre", "figcaption", "hr"}
    )


@pytest.mark.parametrize(
    "node, text",
    [
        ("hello", "hello"),  # a string is its own text
        ({"tag": "p", "children": ["ab"]}, "ab\n"),  # a block ends the line
        ({"tag": "b", "children": ["ab"]}, "ab"),  # an inline tag does not
        ({"tag": "p"}, "\n"),  # an empty block is just the line end
        (  # the text of inline children is read through
            {"tag": "p", "children": ["see ", {"tag": "a", "children": ["here"]}]},
            "see here\n",
        ),
        # a br inside a paragraph breaks the line
        ({"tag": "p", "children": ["one", {"tag": "br"}, "two"]}, "one\ntwo\n"),
        (None, ""),  # an unknown shape contributes nothing
        (42, ""),
    ],
)
def test_node_text_is_the_text_with_a_line_end_after_each_block(node, text):
    assert _node_text(node) == text


@pytest.mark.parametrize(
    "node, links",
    [
        ("hi", []),  # a string has no links
        ({"tag": "a", "attrs": {"href": "https://x.test/y"}}, ["https://x.test/y"]),
        (  # an image's src is a link too
            {"tag": "img", "attrs": {"src": "https://x.test/i.png"}},
            ["https://x.test/i.png"],
        ),
        ({"tag": "a", "attrs": {"href": ""}}, []),  # an empty target is no link
        (None, []),  # an unknown shape contributes nothing
    ],
)
def test_node_links_are_the_href_and_src_targets(node, links):
    assert _node_links(node) == links


def test_node_links_is_flat_not_nested():
    node = {
        "tag": "p",
        "children": [
            "see ",
            {"tag": "a", "attrs": {"href": "https://x.test/1"}, "children": ["one"]},
            {"tag": "a", "attrs": {"href": "https://x.test/2"}, "children": ["two"]},
        ],
    }
    assert _node_links(node) == ["https://x.test/1", "https://x.test/2"]


# --------------------------------------------------------------------------
# page_text / page_links on recorded pages
# --------------------------------------------------------------------------


def test_page_text_starts_with_title_then_description_then_body():
    page = {
        "title": "T",
        "description": "D",
        "content": [{"tag": "p", "children": ["B"]}],
    }
    assert page_text(page) == "T\nD\nB\n"


def test_page_text_without_content_key_does_not_crash():
    assert page_text({"title": "a", "description": "b"}) == "a\nb\n"


def test_page_text_hello_pointer_is_in_the_title():
    text = page_text(fixture_page("Hello-10-17-154"))
    assert text.startswith("198.13.32.106")
    assert text.count("\n") == 3  # title, description, one paragraph


def test_page_text_test_fixture_has_every_line():
    # 21 paragraphs and 6 <br> inside them, the two joins after the title and
    # the description, and 6 line ends the description itself holds. Exact, so
    # a tag that stops ending its line shows on a real page.
    text = page_text(fixture_page("Test-10-16"))
    assert text.count("\n") == 35


def test_page_text_vizit_pointer_is_in_the_text():
    text = page_text(fixture_page("Vizit-12-28"))
    assert "workers.dev" in text


def test_page_links_collects_from_content_only():
    page = {
        "title": "https://not-a-link-in-the-title.test",
        "content": [
            {
                "tag": "p",
                "children": [{"tag": "a", "attrs": {"href": "https://x.test/y"}}],
            }
        ],
    }
    assert page_links(page) == ["https://x.test/y"]


def test_page_links_without_content_key_is_empty():
    assert page_links({"title": "a"}) == []


def test_page_links_vizit_plain_text_pointer_is_not_a_link():
    # The pointer is in the text, not an href. page_text sees it, page_links
    # must not; that is why they are two functions.
    assert page_links(fixture_page("Vizit-12-28")) == []


# --------------------------------------------------------------------------
# TelegraphClient: stubs for the network
# --------------------------------------------------------------------------


@dataclass
class FakeResponse:
    status_code: int
    content: bytes


class FakeSession:
    """Records every call and returns canned responses in order."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_client(responses, **kwargs):
    # retries=0 unless a test says otherwise, so each canned response is one call
    kwargs.setdefault("retries", 0)
    session = FakeSession(responses)
    rows = []
    client = TelegraphClient(
        session=session,
        sleep=lambda s: None,  # never actually wait
        log=rows.append,
        **kwargs,
    )
    return client, session, rows


LOG_KEYS = {
    "ts",
    "path",
    "attempt",
    "status",
    "outcome",
    "error",
    "elapsed_ms",
    "bytes",
}


def test_allowed_hosts_is_the_api_and_the_page_host():
    assert ALLOWED_HOSTS == frozenset({"api.telegra.ph", "telegra.ph"})


def test_check_host_accepts_the_api_and_the_page_host():
    client = TelegraphClient(session=FakeSession([]))
    client._check_host("https://api.telegra.ph/getPage/x")
    client._check_host("https://telegra.ph/x")  # the page host, for get_html


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.test/x",
        "https://telegra.ph.evil.test/x",  # an allowed name in front is not enough
        "https://www.telegra.ph/x",  # nor at the end
        "https://api.telegra.ph@evil.test/x",  # nor before an @: the host follows it
        "https://evil.test/api.telegra.ph",  # nor in the path
    ],
)
def test_check_host_refuses_every_other_host(url):
    client = TelegraphClient(session=FakeSession([]))
    with pytest.raises(ValueError):
        client._check_host(url)


@pytest.mark.parametrize(
    "method, other_host", [("get_page", "telegra.ph"), ("get_html", "api.telegra.ph")]
)
def test_a_url_off_the_allowlist_is_refused_before_anything_is_sent(
    monkeypatch, method, other_host
):
    # Each method checks the URL it built. With only the other method's host
    # left on the list, the request has to be refused, and refused unsent.
    monkeypatch.setattr("graphwatch.telegraph.ALLOWED_HOSTS", frozenset({other_host}))
    client, session, rows = make_client([FakeResponse(200, b"")])
    with pytest.raises(ValueError):
        getattr(client, method)("Hello-10-17")
    assert session.calls == []
    assert rows == []
    assert client.requests_made == 0


def test_wait_turn_sleeps_only_when_the_slot_is_not_open():
    # No rate given: the default is 8 a second, a slot every 0.125 s. The clock
    # is read once a call, on arrival.
    slept = []
    times = iter([50.0, 50.0, 60.0])
    client = TelegraphClient(
        session=FakeSession([]), clock=lambda: next(times), sleep=slept.append
    )
    client._wait_turn()  # the first call never waits
    client._wait_turn()  # at once after it: waits out the slot
    assert slept == [0.125]
    assert client.next_allowed == 50.25
    client._wait_turn()  # long after the slot opened: no wait, and no slot saved up
    assert slept == [0.125]
    assert client.next_allowed == 60.125


def test_a_sleep_that_ran_late_does_not_push_the_later_slots_back():
    # Every sleep here runs 10 ms long. The slots stay 125 ms apart all the
    # same, so each later wait is 10 ms shorter: 8 a second, not 7.4.
    class LateClock:
        now = 100.0
        slept = []

        def sleep(self, seconds):
            self.slept.append(round(seconds, 3))
            self.now += seconds + 0.010

    clock = LateClock()
    client = TelegraphClient(session=FakeSession([]), clock=lambda: clock.now, sleep=clock.sleep)
    for _ in range(5):
        client._wait_turn()
    assert clock.slept == [0.125, 0.115, 0.115, 0.115]
    assert round(client.next_allowed, 3) == 100.0 + 5 * 0.125

    # Ten slots went by unused while a page was being stored. The requests
    # after it are a slot apart again, not ten at once.
    clock = SteppedClock()
    client = TelegraphClient(session=FakeSession([]), clock=clock, sleep=clock.sleep)
    client._wait_turn()
    clock.now += 10 * 0.125
    for _ in range(3):
        client._wait_turn()
    assert clock.sleeps == [0.125, 0.125]


def test_get_page_found():
    client, session, rows = make_client(
        [FakeResponse(200, fixture_bytes("Vizit-12-28"))]
    )
    fetch = client.get_page("Vizit-12-28")
    assert isinstance(fetch, Fetch)
    assert fetch.outcome is Outcome.FOUND
    assert fetch.path == "Vizit-12-28"
    assert fetch.page["path"] == "Vizit-12-28"
    assert fetch.status == 200
    assert fetch.error is None


def test_get_page_builds_the_documented_url():
    client, session, _ = make_client([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client.get_page("Vizit-12-28")
    url, kwargs = session.calls[0]
    assert url == "https://api.telegra.ph/getPage/Vizit-12-28?return_content=true"
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == 10
    # A bare product name and nothing else: no contact details go out.
    assert kwargs["headers"] == {"User-Agent": "graphwatch"}


def test_get_page_content_false_asks_only_for_existence():
    client, session, _ = make_client([FakeResponse(200, fixture_bytes("not-found"))])
    client.get_page("Vizit-12-28", content=False)
    # lowercase, as the API wants
    assert session.calls[0][0] == (
        "https://api.telegra.ph/getPage/Vizit-12-28?return_content=false"
    )


def test_get_page_not_found():
    client, _, rows = make_client([FakeResponse(200, fixture_bytes("not-found"))])
    fetch = client.get_page("Nope-01-01")
    assert fetch.outcome is Outcome.NOT_FOUND
    assert fetch.page is None
    assert fetch.error == "PAGE_NOT_FOUND"
    assert rows[0]["outcome"] == "NOT_FOUND"


def test_get_page_server_error_is_failed_not_not_found():
    client, _, _ = make_client([FakeResponse(502, b"<html>Bad Gateway</html>")])
    fetch = client.get_page("Vizit-12-28")
    assert fetch.outcome is Outcome.FAILED
    assert fetch.status == 502


def test_get_page_network_exception_is_failed_with_no_status():
    client, _, rows = make_client([requests.ConnectionError("down")])
    fetch = client.get_page("Vizit-12-28")
    assert fetch.outcome is Outcome.FAILED
    assert fetch.status is None
    assert fetch.page is None
    assert fetch.error == "request error: down"
    assert rows[0]["status"] is None
    assert rows[0]["outcome"] == "FAILED"
    assert rows[0]["error"] == "request error: down"
    assert rows[0]["bytes"] == 0


def test_get_page_logs_one_row_per_request_with_expected_keys():
    client, _, rows = make_client([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client.get_page("Vizit-12-28")
    assert len(rows) == 1
    assert set(rows[0]) == LOG_KEYS
    assert rows[0]["path"] == "Vizit-12-28"
    assert rows[0]["outcome"] == "FOUND"
    assert rows[0]["attempt"] == 1
    assert rows[0]["bytes"] == len(fixture_bytes("Vizit-12-28"))


def test_get_page_log_is_optional():
    session = FakeSession([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client = TelegraphClient(session=session, sleep=lambda s: None)
    assert client.get_page("Vizit-12-28").outcome is Outcome.FOUND


def test_elapsed_ms_is_the_time_the_request_took():
    # The clock is read once by the pacer, then before and after the request.
    times = iter([0.0, 10.0, 12.5])
    client, _, rows = make_client(
        [FakeResponse(200, fixture_bytes("not-found"))], clock=lambda: next(times)
    )
    fetch = client.get_page("x-01-01")
    assert fetch.elapsed_ms == 2500
    assert rows[0]["elapsed_ms"] == 2500


# --------------------------------------------------------------------------
# HTML metadata: parse_html_meta and get_html (plan/page-meta-plan-2026-11-04.md)
# --------------------------------------------------------------------------

# Modeled on the head of a real telegra.ph page as fetched on 4 Nov 2026.
# Note the double space before content= on the modified tag: the plan shows
# it that way and the parser must not care.
HTML_HEAD = (
    '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hello</title>'
    '<meta property="og:type" content="article">'
    '<meta property="og:title" content="Hello, world&#33;">'
    '<meta property="og:site_name" content="Telegraph">'
    '<meta property="article:published_time" content="2026-10-19T03:00:08+0000">'
    '<meta property="article:modified_time"  content="2026-11-04T15:06:39+0000">'
    '<meta property="article:author" content="">'
    "</head><body><article>Hello, world!</article></body></html>"
)
HTML_BODY = HTML_HEAD.encode("utf-8")
HTML_PUB = 1792378808.0  # 2026-10-19T03:00:08Z
HTML_MOD = 1793804799.0  # 2026-11-04T15:06:39Z
HTML_NOT_FOUND = b"<!DOCTYPE html><html><head><title>Telegraph</title></head><body></body></html>"


def test_parse_html_meta_found():
    outcome, page, error = parse_html_meta(200, HTML_BODY)
    assert outcome is Outcome.FOUND
    assert error is None
    assert page == {"published_at": HTML_PUB, "modified_at": HTML_MOD}
    assert isinstance(page["published_at"], float)
    assert isinstance(page["modified_at"], float)


def test_parse_html_meta_404_is_not_found():
    # telegra.ph answers a missing page with a plain 404 (checked 4 Nov 2026).
    outcome, page, error = parse_html_meta(404, HTML_NOT_FOUND)
    assert outcome is Outcome.NOT_FOUND
    assert page is None


def test_parse_html_meta_200_without_tags_is_failed_not_a_crash():
    outcome, page, error = parse_html_meta(200, HTML_NOT_FOUND)
    assert outcome is Outcome.FAILED
    assert page is None
    assert error


def test_parse_html_meta_one_tag_missing_is_failed():
    body = HTML_HEAD.replace(
        '<meta property="article:modified_time"  content="2026-11-04T15:06:39+0000">', ""
    ).encode()
    outcome, page, _ = parse_html_meta(200, body)
    assert outcome is Outcome.FAILED
    assert page is None


@pytest.mark.parametrize(
    "status, body",
    [
        (503, b"<html>busy</html>"),
        (302, HTML_BODY),  # only a 200 is read, whatever the body holds
    ],
)
def test_parse_html_meta_any_other_status_is_failed_and_names_the_status(status, body):
    outcome, page, error = parse_html_meta(status, body)
    assert outcome is Outcome.FAILED
    assert page is None
    assert str(status) in error


def test_parse_html_meta_bad_timestamp_is_failed_not_a_crash():
    body = HTML_HEAD.replace("2026-11-04T15:06:39+0000", "yesterday").encode()
    outcome, page, error = parse_html_meta(200, body)
    assert outcome is Outcome.FAILED
    assert page is None
    assert error


def test_parse_html_meta_undecodable_body_is_failed():
    outcome, page, error = parse_html_meta(200, b"\xff\xfe\xfa")
    assert outcome is Outcome.FAILED
    assert page is None


def test_parse_html_meta_never_echoes_the_body():
    # A FAILED reason may name the status or the missing tag, never page text,
    # which can carry unredacted storage keys.
    body = b"<html><head><title>SECRETKEYTEXT</title></head></html>"
    _, _, error = parse_html_meta(200, body)
    assert "SECRETKEYTEXT" not in error


def test_get_html_builds_the_page_url():
    client, session, _ = make_client([FakeResponse(200, HTML_BODY)])
    client.get_html("Hello-10-19-130")
    url, kwargs = session.calls[0]
    assert url == "https://telegra.ph/Hello-10-19-130"
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == 10
    assert kwargs["headers"] == {"User-Agent": "graphwatch"}


def test_get_html_found():
    client, _, _ = make_client([FakeResponse(200, HTML_BODY)])
    fetch = client.get_html("Hello-10-19-130")
    assert isinstance(fetch, Fetch)
    assert fetch.outcome is Outcome.FOUND
    assert fetch.path == "Hello-10-19-130"  # the plain path, no prefix
    assert fetch.page == {"published_at": HTML_PUB, "modified_at": HTML_MOD}
    assert fetch.status == 200
    assert fetch.error is None


def test_get_html_not_found():
    client, _, _ = make_client([FakeResponse(404, HTML_NOT_FOUND)])
    fetch = client.get_html("zz-01-01-99999")
    assert fetch.outcome is Outcome.NOT_FOUND
    assert fetch.page is None
    assert fetch.status == 404


def test_get_html_logs_one_row_with_an_html_prefixed_path():
    client, _, rows = make_client([FakeResponse(200, HTML_BODY)])
    client.get_html("Hello-10-19-130")
    assert len(rows) == 1
    assert rows[0]["path"] == "html:Hello-10-19-130"
    assert rows[0]["outcome"] == "FOUND"
    assert rows[0]["status"] == 200
    assert rows[0]["bytes"] == len(HTML_BODY)
    assert set(rows[0]) == LOG_KEYS


def test_get_page_still_parses_json_not_html():
    # Adding an HTML parser must not change how the API path is read.
    client, _, _ = make_client([FakeResponse(200, HTML_BODY)])
    fetch = client.get_page("Hello-10-19-130")
    assert fetch.outcome is Outcome.FAILED


# --------------------------------------------------------------------------
# quoting, retries, budget and pacing: the same for get_page and get_html
# --------------------------------------------------------------------------

both_methods = pytest.mark.parametrize("method", ["get_page", "get_html"])

# The reply each method reads as a page and as a missing page. A 502 is
# FAILED to both.
FOUND_REPLY = {
    "get_page": FakeResponse(200, fixture_bytes("Vizit-12-28")),
    "get_html": FakeResponse(200, HTML_BODY),
}
NOT_FOUND_REPLY = {
    "get_page": FakeResponse(200, fixture_bytes("not-found")),
    "get_html": FakeResponse(404, HTML_NOT_FOUND),
}
BAD_GATEWAY = FakeResponse(502, b"<html>Bad Gateway</html>")


def retrying_client(responses, **kwargs):
    """A client on a clock that only moves when the client sleeps, so every
    sleep it asks for is exact. After a backoff wait the pacer's 0.125 s slot
    (the default 8 a second) has long been open, so only the backoffs show."""
    session = FakeSession(responses)
    clock, rows = SteppedClock(), []
    client = TelegraphClient(
        session=session, clock=clock, sleep=clock.sleep, log=rows.append, **kwargs
    )
    return client, session, clock.sleeps, rows


@pytest.mark.parametrize(
    "path, quoted",
    [
        ("Повістка-10-25", "%D0%9F%D0%BE%D0%B2%D1%96%D1%81%D1%82%D0%BA%D0%B0-10-25"),
        # A path cannot add a segment, a query or a fragment to the URL.
        ("a/b?c=d#e", "a%2Fb%3Fc%3Dd%23e"),
    ],
)
def test_paths_are_percent_encoded_whole(path, quoted):
    client, session, _ = make_client(
        [NOT_FOUND_REPLY["get_page"], NOT_FOUND_REPLY["get_html"]]
    )
    client.get_page(path)
    client.get_html(path)
    assert [url for url, _ in session.calls] == [
        f"https://api.telegra.ph/getPage/{quoted}?return_content=true",
        f"https://telegra.ph/{quoted}",
    ]


@both_methods
def test_a_failed_attempt_is_retried_and_the_success_returned(method):
    # A 502 body is FAILED, so it is retried like a network error.
    client, session, slept, rows = retrying_client(
        [BAD_GATEWAY, FOUND_REPLY[method]], retries=2
    )
    fetch = getattr(client, method)("Vizit-12-28")
    assert fetch.outcome is Outcome.FOUND
    assert len(session.calls) == 2
    assert [r["attempt"] for r in rows] == [1, 2]
    # one backoff, and the retry still waits for its slot
    assert slept == [1.0]


@both_methods
def test_the_default_is_two_retries_then_the_last_failure(method):
    client, session, slept, rows = retrying_client(
        [requests.Timeout(e) for e in "abcd"]
    )
    fetch = getattr(client, method)("Vizit-12-28")
    assert fetch.outcome is Outcome.FAILED
    assert fetch.error == "request error: c"  # the last attempt's, not the first
    assert len(session.calls) == 3  # one try plus two retries, never four
    assert [r["attempt"] for r in rows] == [1, 2, 3]
    # 1 s then 2 s of backoff, and no sleep after the last attempt
    assert slept == [1.0, 2.0]


@both_methods
def test_backoff_doubles_each_time_from_backoff_s(method):
    # Three retries, because two cannot tell doubling from adding.
    client, _, slept, _ = retrying_client(
        [requests.Timeout(e) for e in "abcd"], retries=3, backoff_s=5.0
    )
    getattr(client, method)("Vizit-12-28")
    assert slept == [5.0, 10.0, 20.0]


@both_methods
def test_a_retry_waits_for_its_slot_like_any_request(method):
    # A backoff shorter than a slot: the rest of the slot is still waited out
    client, _, slept, _ = retrying_client(
        [requests.Timeout("a"), requests.Timeout("b")], retries=1, backoff_s=0.025
    )
    getattr(client, method)("Vizit-12-28")
    assert [round(seconds, 3) for seconds in slept] == [0.025, 0.1]


@both_methods
def test_a_missing_page_is_not_retried(method):
    client, session, slept, _ = retrying_client(
        [NOT_FOUND_REPLY[method], FOUND_REPLY[method]], retries=2
    )
    fetch = getattr(client, method)("Nope-01-01")
    assert fetch.outcome is Outcome.NOT_FOUND
    assert len(session.calls) == 1
    assert slept == []


@both_methods
def test_retries_zero_means_a_single_attempt(method):
    client, session, slept, _ = retrying_client(
        [requests.Timeout("a"), FOUND_REPLY[method]], retries=0
    )
    assert getattr(client, method)("Vizit-12-28").outcome is Outcome.FAILED
    assert len(session.calls) == 1
    assert slept == []


@both_methods
def test_budget_is_enforced_per_attempt(method):
    # Budget of 2 with a client that would retry twice: the third attempt is
    # refused. A failed request is charged like any other.
    client, session, _, _ = retrying_client(
        [requests.Timeout(e) for e in "abc"], retries=2, budget=2
    )
    with pytest.raises(BudgetExceeded):
        getattr(client, method)("Vizit-12-28")
    assert len(session.calls) == 2
    assert client.requests_made == 2


def test_get_page_counts_requests_including_failures():
    # Whatever the answer was, the request went out: a missing page and a
    # network error are charged like a page. The crowd check is nearly all
    # missing pages, so a budget that did not count them would not hold it.
    client, _, _ = make_client(
        [
            FakeResponse(200, fixture_bytes("not-found")),
            requests.ConnectionError("down"),
        ]
    )
    client.get_page("a-01-01")
    client.get_page("b-01-01")
    assert client.requests_made == 2


def test_get_page_budget_raises_before_sending():
    client, session, _ = make_client(
        [FakeResponse(200, fixture_bytes("Vizit-12-28"))], budget=1
    )
    client.get_page("Vizit-12-28")
    with pytest.raises(BudgetExceeded):
        client.get_page("Vizit-12-28")
    assert len(session.calls) == 1  # the refused request never hit the session


def test_a_budget_of_zero_sends_nothing():
    # 0 is a budget, not "no budget"; `if self.budget:` would let everything through.
    client, session, _ = make_client([FOUND_REPLY["get_page"]], budget=0)
    with pytest.raises(BudgetExceeded):
        client.get_page("Vizit-12-28")
    assert session.calls == []


def test_get_html_charges_the_budget_exactly_once():
    client, _, _ = make_client([FakeResponse(200, HTML_BODY)] * 2, budget=1)
    client.get_html("Hello-10-19-130")
    assert client.requests_made == 1
    with pytest.raises(BudgetExceeded):
        client.get_html("Hello-10-19-131")
    assert client.requests_made == 1


def test_get_page_paces_requests():
    clock = SteppedClock()
    session = FakeSession([FakeResponse(200, fixture_bytes("not-found"))] * 3)
    client = TelegraphClient(rate_per_s=4.0, session=session, clock=clock, sleep=clock.sleep)
    for _ in range(3):
        client.get_page("x-01-01")
    # The first request goes immediately; each later one waits a 0.25 s slot.
    assert clock.sleeps == [0.25, 0.25]


def test_get_html_shares_the_pacer_with_get_page():
    clock = SteppedClock()
    session = FakeSession(
        [FakeResponse(200, fixture_bytes("not-found")), FakeResponse(200, HTML_BODY)]
    )
    client = TelegraphClient(rate_per_s=4.0, session=session, clock=clock, sleep=clock.sleep)
    client.get_page("x-01-01")
    client.get_html("x-01-01")
    assert clock.sleeps == [0.25]


# --------------------------------------------------------------------------
# several requests under way at once: the client's lock, Pool and Ahead
# (23 November: one request at a time reached 6.3 to 6.5 a second of the 8)
# --------------------------------------------------------------------------


class SlowSession:
    """Answers every path as missing, or as the Vizit fixture for the paths
    in `found`, after `delay` seconds. Records the paths, the threads that
    asked and the most requests that were under way at once. `delays` gives
    single paths a delay of their own."""

    def __init__(self, delay=0.0, found=(), delays=None):
        self.delay = delay
        self.found = set(found)
        self.delays = dict(delays or {})
        self.lock = threading.Lock()
        self.paths = []
        self.threads = set()
        self.under_way = 0
        self.most = 0

    def get(self, url, **kwargs):
        path = url.rsplit("/", 1)[1].split("?", 1)[0]
        with self.lock:
            self.paths.append(path)
            self.threads.add(threading.current_thread())
            self.under_way += 1
            self.most = max(self.most, self.under_way)
        time.sleep(self.delays.get(path, self.delay))
        with self.lock:
            self.under_way -= 1
        return FakeResponse(200, fixture_bytes("Vizit-12-28" if path in self.found else "not-found"))


def pooled(workers, delay=0.0, log=None, **kwargs):
    kwargs.setdefault("retries", 0)
    kwargs.setdefault("sleep", lambda s: None)
    session = SlowSession(delay, kwargs.pop("found", ()), kwargs.pop("delays", None))
    client = TelegraphClient(session=session, workers=workers, log=log, **kwargs)
    return client, session


PATHS = [f"x-01-01-{n}" for n in range(2, 26)]


def test_one_worker_is_the_default_and_starts_no_thread():
    for workers in (0, -1):
        with pytest.raises(ValueError):
            TelegraphClient(session=FakeSession([]), workers=workers)
    client, session = pooled(1)
    assert TelegraphClient(session=FakeSession([])).workers == 1
    with Pool(client) as pool:
        tickets = [pool.submit(client.get_page, path) for path in PATHS[:3]]
        # nothing is sent until a result is asked for, and then in that order
        assert session.paths == []
        assert pool.result(tickets[1]).path == PATHS[1]
        assert pool.result(tickets[0]).path == PATHS[0]
        assert session.paths == [PATHS[1], PATHS[0]]
    # the one that was never asked for was never sent
    assert session.paths == [PATHS[1], PATHS[0]]
    assert session.threads == {threading.current_thread()}

    client, session = pooled(1)
    with Pool(client) as pool:
        seen = []
        for path, fetch in pool.map(client.get_page, PATHS):
            # each request is made only when the one before it has been handed out
            seen.append(list(session.paths))
            assert fetch.path == path
    assert seen == [PATHS[: n + 1] for n in range(len(PATHS))]


def test_a_pool_has_several_requests_under_way_at_once_and_never_more_than_its_workers():
    client, session = pooled(4, delay=0.02)
    with Pool(client) as pool:
        fetched = [fetch.path for _path, fetch in pool.map(client.get_page, PATHS)]
    assert fetched == PATHS
    assert 2 <= session.most <= 4
    assert sorted(session.paths) == sorted(PATHS)
    # the requests left the calling thread, on threads the pool named
    assert threading.current_thread() not in session.threads
    assert all(thread.name.startswith("graphwatch") for thread in session.threads)

    # The first path is the slowest: its answer arrives after the others
    client, session = pooled(4, delays={PATHS[0]: 0.05}, found={PATHS[3]})
    with Pool(client) as pool:
        got = list(pool.map(client.get_page, PATHS[:8]))
    assert [path for path, _fetch in got] == PATHS[:8]
    assert [fetch.path for _path, fetch in got] == PATHS[:8]
    assert [fetch.outcome for _path, fetch in got][3] is Outcome.FOUND
    assert session.paths[0] == PATHS[0] and session.paths != PATHS[:8] or session.most > 1


def test_log_rows_are_written_on_the_calling_thread_one_for_each_request():
    wrote = []
    client, session = pooled(4, delay=0.005, log=lambda row: wrote.append((threading.current_thread(), row)))
    with Pool(client) as pool:
        for _path, _fetch in pool.map(client.get_page, PATHS):
            pass
    assert {thread for thread, _row in wrote} == {threading.current_thread()}
    assert sorted(row["path"] for _thread, row in wrote) == sorted(PATHS)
    assert len(wrote) == client.requests_made == len(PATHS)

    # A connection refuses to be used on any thread but the one that opened it
    from graphwatch.db import connect, http_logger

    conn = connect(":memory:")
    client, _ = pooled(4, delay=0.005, log=http_logger(conn))
    with Pool(client) as pool:
        assert len(list(pool.map(client.get_page, PATHS))) == len(PATHS)
    assert conn.execute("SELECT COUNT(*) FROM http_log").fetchone()[0] == len(PATHS)
    conn.close()

    wrote = []
    client, _ = pooled(4, log=wrote.append)
    with Pool(client):
        client.get_page("x-01-01")
        assert [row["path"] for row in wrote] == ["x-01-01"]


class SteppedClock:
    """A clock that only moves when something sleeps on it."""

    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.mark.parametrize("workers", [1, 4, 8])
def test_requests_start_a_slot_apart_however_many_threads_ask(workers):
    # The rate is the promise made to Telegraph: more workers reach it, none passes it
    clock = SteppedClock()
    client, session = pooled(workers, rate_per_s=8.0, clock=clock, sleep=clock.sleep)
    with Pool(client) as pool:
        assert len(list(pool.map(client.get_page, PATHS))) == len(PATHS)
    assert clock.sleeps == [0.125] * (len(PATHS) - 1)


@pytest.mark.parametrize("workers", [1, 4, 8])
def test_a_pool_never_sends_more_requests_than_the_budget(workers):
    # Every request has to wait for its slot here, and a thread that waits
    # lets the others run. Each has to wait and be counted before the next
    # may look at the budget, or several see the last request still unspent.
    client, session = pooled(workers, delay=0.002, budget=10, sleep=lambda s: time.sleep(0.001))
    got = []
    with Pool(client) as pool:
        with pytest.raises(BudgetExceeded):
            for path, fetch in pool.map(client.get_page, PATHS):
                got.append(path)
    assert len(session.paths) == client.requests_made == 10
    # every answer that was paid for is handed out before the stop, in the order asked
    assert sorted(got) == sorted(session.paths)
    assert got == [path for path in PATHS if path in set(got)]


def test_an_answer_that_was_paid_for_is_handed_out_though_an_earlier_item_met_the_budget():
    # The two slow items come to the budget after the two quick ones spent it
    client, session = pooled(4, budget=2)

    def fetch(path):
        if path.startswith("slow"):
            time.sleep(0.05)
        return client.get_page(path)

    got = []
    with Pool(client) as pool:
        with pytest.raises(BudgetExceeded):
            for path, _fetch in pool.map(fetch, ["slow-01-01", "x-01-01", "slow-01-02", "x-01-02"]):
                got.append(path)
    assert got == ["x-01-01", "x-01-02"]
    assert sorted(session.paths) == ["x-01-01", "x-01-02"]


def test_no_call_is_started_once_the_budget_is_known_to_be_spent():
    client, session = pooled(2, budget=1)
    asked = []

    def items():
        for path in PATHS:
            asked.append(path)
            yield path

    with Pool(client) as pool:
        with pytest.raises(BudgetExceeded):
            list(pool.map(client.get_page, items()))
    assert len(session.paths) == 1
    assert len(asked) <= 2 * 2 + 1  # not the whole list


def test_map_starts_only_a_little_ahead_of_what_it_hands_out():
    client, session = pooled(3, delay=0.002)
    asked = []

    def items():
        for path in PATHS:
            asked.append(path)
            yield path

    with Pool(client) as pool:
        results = pool.map(client.get_page, items())
        assert next(results)[0] == PATHS[0]
        results.close()
        assert len(asked) == 2 * 3
    # what was under way is waited for and is in the count; nothing new was started
    assert len(session.paths) == client.requests_made <= 2 * 3


def test_closing_a_pool_logs_every_request_that_was_sent_and_starts_no_other():
    wrote = []
    client, session = pooled(2, delay=0.02, log=wrote.append)
    pool = Pool(client)
    for path in PATHS:
        pool.submit(client.get_page, path)
    pool.close()
    assert sorted(row["path"] for row in wrote) == sorted(session.paths)
    # only what the two threads had already taken up was sent; the rest was dropped
    assert 1 <= len(session.paths) <= 4
    assert client.requests_made == len(session.paths)


def test_an_interrupted_wait_still_gets_the_calls_requests_into_the_log():
    # Ctrl-C arrives while the calling thread waits for a result, which is
    # where it spends most of a run. The call is under way all the same.
    class Interrupted:
        def __init__(self, future):
            self.future = future
            self.waits = 0

        def result(self):
            self.waits += 1
            if self.waits == 1:
                raise KeyboardInterrupt
            return self.future.result()

        def cancel(self):
            return self.future.cancel()

    wrote = []
    client, session = pooled(2, delay=0.02, log=wrote.append)
    pool = Pool(client)
    ticket = pool.submit(client.get_page, "x-01-01")
    ticket.future = Interrupted(ticket.future)
    with pytest.raises(KeyboardInterrupt):
        pool.result(ticket)
    pool.close()
    assert [row["path"] for row in wrote] == session.paths == ["x-01-01"]


def test_closing_a_pool_ends_a_call_of_many_requests_at_its_next_one():
    # A crowd count is dozens of requests in one call. After Ctrl-C or an
    # error it must not go on asking Telegraph to its end.
    wrote = []
    client, session = pooled(2, delay=0.005, log=wrote.append)

    def count(_unit):
        return [client.get_page(path) for path in PATHS]

    pool = Pool(client)
    pool.submit(count, 1)
    pool.submit(count, 2)
    deadline = time.monotonic() + 5
    while len(session.paths) < 2 and time.monotonic() < deadline:
        time.sleep(0.001)
    pool.close()
    sent = len(session.paths)
    assert 2 <= sent <= 6  # not the 48 the two calls had to make
    assert len(wrote) == client.requests_made == sent
    # the client itself is not closed: the calling thread goes on, and so
    # does the same pool if it is used again
    assert client.get_page("x-01-01").outcome is Outcome.NOT_FOUND
    assert [fetch.outcome for _path, fetch in pool.map(client.get_page, PATHS[:4])] == [Outcome.NOT_FOUND] * 4
    pool.close()


def test_what_a_call_raises_is_raised_where_its_result_is_asked_for():
    client, _ = pooled(3)

    def broken(path):
        raise KeyError(path)

    with Pool(client) as pool:
        ticket = pool.submit(broken, "x-01-01")
        fine = pool.submit(client.get_page, "x-01-01")
        with pytest.raises(KeyError):
            pool.result(ticket)
        assert pool.result(fine).outcome is Outcome.NOT_FOUND


def test_a_failed_attempt_is_retried_on_the_thread_that_made_it():
    wrote = []
    session = FakeSession(
        [FakeResponse(500, b"busy"), FakeResponse(200, fixture_bytes("not-found"))]
    )
    client = TelegraphClient(session=session, sleep=lambda s: None, log=wrote.append, workers=3, retries=2)
    with Pool(client) as pool:
        fetch = pool.result(pool.submit(client.get_page, "x-01-01"))
    assert fetch.outcome is Outcome.NOT_FOUND
    assert [row["attempt"] for row in wrote] == [1, 2]
    assert client.requests_made == 2


# --- Ahead ---


def test_ahead_fetches_what_was_hinted_before_it_is_asked_for():
    client, session = pooled(4, delay=0.01, found={PATHS[1]})
    with Pool(client) as pool:
        ahead = Ahead(pool, client.get_page)
        ahead.hint(PATHS[:4])
        deadline = time.monotonic() + 5
        while len(session.paths) < 4 and time.monotonic() < deadline:
            time.sleep(0.001)
        assert sorted(session.paths) == PATHS[:4]  # sent before any was asked for
        fetches = [ahead.fetch(path) for path in PATHS[:4]]
    assert [fetch.path for fetch in fetches] == PATHS[:4]
    assert fetches[1].outcome is Outcome.FOUND
    assert len(session.paths) == 4  # and not sent again
    assert ahead.tickets == {}


def test_ahead_takes_a_hint_only_while_it_has_room_and_never_twice():
    client, session = pooled(2, delay=0.001)
    with Pool(client) as pool:
        ahead = Ahead(pool, client.get_page)
        read = []

        def paths():
            for path in PATHS:
                read.append(path)
                yield path

        ahead.hint(paths())
        ahead.hint(PATHS)  # the same paths again
        assert list(ahead.tickets) == PATHS[:4]  # twice the workers
        assert len(read) == 5  # and the list is not read past the room
        assert ahead.fetch(PATHS[0]).path == PATHS[0]
        ahead.hint(PATHS[1:])  # what is still to come
        assert list(ahead.tickets) == PATHS[1:5]
    assert len(session.paths) == client.requests_made <= 5


def test_ahead_with_one_worker_fetches_only_when_asked():
    client, session = pooled(1)
    with Pool(client) as pool:
        ahead = Ahead(pool, client.get_page)
        ahead.hint(PATHS)
        assert (ahead.tickets, session.paths) == ({}, [])
        ahead.fetch(PATHS[2])
    assert session.paths == [PATHS[2]]

    client, session = pooled(4)
    with Pool(client) as pool:
        ahead = Ahead(pool, client.get_page)
        assert ahead.fetch("x-01-01").outcome is Outcome.NOT_FOUND
    assert session.threads == {threading.current_thread()}


def test_ahead_raises_budget_exceeded_at_the_path_that_did_not_get_a_request():
    client, session = pooled(4, budget=2)
    with Pool(client) as pool:
        ahead = Ahead(pool, client.get_page)
        ahead.hint(PATHS[:4])
        outcomes = []
        for path in PATHS[:4]:
            try:
                outcomes.append(ahead.fetch(path).outcome)
            except BudgetExceeded:
                outcomes.append(None)
    # Only as many are fetched ahead as the budget can pay for, so it is the
    # first two that get their request, whichever thread takes its turn first
    assert outcomes == [Outcome.NOT_FOUND, Outcome.NOT_FOUND, None, None]
    assert session.paths == PATHS[:2] or sorted(session.paths) == PATHS[:2]
