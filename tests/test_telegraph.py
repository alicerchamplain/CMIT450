"""Tests for graphwatch.telegraph.

Every test here runs offline. The HTTP-facing tests hand the client a stub
session, so nothing in this file can reach the network.
"""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
import requests

from graphwatch.telegraph import (
    ALLOWED_HOSTS,
    BLOCK_TAGS,
    BudgetExceeded,
    Fetch,
    Outcome,
    TelegraphClient,
    _node_links,
    _node_text,
    build_path,
    page_links,
    page_text,
    parse_envelope,
    parse_html_meta,
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
    # is read twice a call: on arrival, and again to book the next slot.
    slept = []
    times = iter([50.0, 50.0, 50.0, 50.125, 60.0, 60.0])
    client = TelegraphClient(
        session=FakeSession([]), clock=lambda: next(times), sleep=slept.append
    )
    client._wait_turn()  # the first call never waits
    client._wait_turn()  # at once after it: waits out the slot
    assert slept == [0.125]
    assert client.next_allowed == 50.25
    client._wait_turn()  # long after the slot opened: no wait
    assert slept == [0.125]
    assert client.next_allowed == 60.125


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
    # The clock is read twice by the pacer, then before and after the request.
    times = iter([0.0, 0.0, 10.0, 12.5])
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
    """A client whose clock stands still, so every sleep it asks for is exact:
    a backoff wait after a failure, then the pacer's 0.125 s slot before the
    next attempt (the default 8 a second)."""
    session = FakeSession(responses)
    slept, rows = [], []
    client = TelegraphClient(
        session=session, clock=lambda: 100.0, sleep=slept.append, log=rows.append, **kwargs
    )
    return client, session, slept, rows


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
    assert slept == [1.0, 0.125]


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
    assert slept == [1.0, 0.125, 2.0, 0.125]


@both_methods
def test_backoff_doubles_each_time_from_backoff_s(method):
    # Three retries, because two cannot tell doubling from adding.
    client, _, slept, _ = retrying_client(
        [requests.Timeout(e) for e in "abcd"], retries=3, backoff_s=5.0
    )
    getattr(client, method)("Vizit-12-28")
    assert slept == [5.0, 0.125, 10.0, 0.125, 20.0, 0.125]


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
    slept = []
    times = iter([0.0] * 20)
    session = FakeSession([FakeResponse(200, fixture_bytes("not-found"))] * 3)
    client = TelegraphClient(
        rate_per_s=4.0, session=session, clock=lambda: next(times), sleep=slept.append
    )
    for _ in range(3):
        client.get_page("x-01-01")
    # The first request goes immediately; each later one waits a 0.25 s slot.
    assert slept == [0.25, 0.25]


def test_get_html_shares_the_pacer_with_get_page():
    slept = []
    times = iter([0.0] * 20)
    session = FakeSession(
        [FakeResponse(200, fixture_bytes("not-found")), FakeResponse(200, HTML_BODY)]
    )
    client = TelegraphClient(
        rate_per_s=4.0, session=session, clock=lambda: next(times), sleep=slept.append
    )
    client.get_page("x-01-01")
    client.get_html("x-01-01")
    assert slept == [0.25]
