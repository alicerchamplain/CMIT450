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
        ("mark", 1, 20, 5, "mark-01-20-5"),  # lowercase slug preserved
    ],
)
def test_build_path_matches_known_paths(slug, month, day, n, expected):
    assert build_path(slug, month, day, n) == expected


def test_build_path_keeps_zero_counter():
    # A counter of 0 is a value, not "no counter"; `if n:` would drop it.
    assert build_path("x", 1, 1, 0) == "x-01-01-0"


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
        (429, b'{"ok": false, "error": "PAGE_NOT_FOUND"}'),  # body says gap...
    ],
)
def test_parse_envelope_failed_shapes(status, body):
    outcome, page, error = parse_envelope(status, body)
    # The last case is the one exception: the body is the authority, so a
    # PAGE_NOT_FOUND body is NOT_FOUND regardless of status. Everything else
    # that is not the exact good shape or the exact not-found shape is FAILED.
    if body == b'{"ok": false, "error": "PAGE_NOT_FOUND"}':
        assert outcome is Outcome.NOT_FOUND
    else:
        assert outcome is Outcome.FAILED
        assert page is None
        assert isinstance(error, str) and error


def test_parse_envelope_failed_error_mentions_status_for_bad_body():
    _, _, error = parse_envelope(502, b"<html>")
    assert "502" in error


def test_parse_envelope_keeps_api_error_text():
    _, _, error = parse_envelope(200, b'{"ok": false, "error": "FLOOD_WAIT"}')
    assert error == "FLOOD_WAIT"


def test_parse_envelope_never_echoes_body_on_unexpected_shape():
    # An unexpected envelope must not dump the page into the error string,
    # because the error string ends up in logs unhashed.
    secret = "user:hunter2@example"
    body = json.dumps({"ok": "maybe", "result": {"content": [secret]}}).encode()
    outcome, _, error = parse_envelope(200, body)
    assert outcome is Outcome.FAILED
    assert secret not in error


# --------------------------------------------------------------------------
# content walkers
# --------------------------------------------------------------------------


def test_block_tags_has_the_line_ending_tags():
    assert {"p", "br", "li"} <= BLOCK_TAGS


def test_node_text_string_is_returned_as_is():
    assert _node_text("hello") == "hello"


def test_node_text_block_adds_newline_inline_does_not():
    assert _node_text({"tag": "p", "children": ["ab"]}) == "ab\n"
    assert _node_text({"tag": "b", "children": ["ab"]}) == "ab"


def test_node_text_empty_block_is_just_a_newline():
    assert _node_text({"tag": "p"}) == "\n"


def test_node_text_recurses_into_inline_children():
    node = {"tag": "p", "children": ["see ", {"tag": "a", "children": ["here"]}]}
    assert _node_text(node) == "see here\n"


def test_node_text_br_inside_paragraph_breaks_the_line():
    node = {"tag": "p", "children": ["one", {"tag": "br"}, "two"]}
    assert _node_text(node) == "one\ntwo\n"


def test_node_text_unknown_shape_contributes_nothing():
    assert _node_text(None) == ""
    assert _node_text(42) == ""


def test_node_links_string_has_no_links():
    assert _node_links("hi") == []


def test_node_links_reads_href_and_src():
    assert _node_links({"tag": "a", "attrs": {"href": "https://x.test/y"}}) == [
        "https://x.test/y"
    ]
    assert _node_links({"tag": "img", "attrs": {"src": "https://x.test/i.png"}}) == [
        "https://x.test/i.png"
    ]


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


def test_node_links_unknown_shape_contributes_nothing():
    assert _node_links(None) == []


# --------------------------------------------------------------------------
# page_text / page_links on recorded pages
# --------------------------------------------------------------------------


def test_page_text_starts_with_title_then_description_then_body():
    page = {"title": "T", "description": "D", "content": [{"tag": "p", "children": ["B"]}]}
    assert page_text(page) == "T\nD\nB\n"


def test_page_text_without_content_key_does_not_crash():
    assert page_text({"title": "a", "description": "b"}) == "a\nb\n"


def test_page_text_hello_pointer_is_in_the_title():
    text = page_text(fixture_page("Hello-10-17-154"))
    assert text.startswith("208.76.222.152")
    assert text.count("\n") == 3  # title, description, one paragraph


def test_page_text_test_fixture_has_all_paragraphs():
    text = page_text(fixture_page("Test-10-16"))
    assert text.count("\n") >= 21


def test_page_text_vizit_pointer_is_in_the_text():
    text = page_text(fixture_page("Vizit-12-28"))
    assert "workers.dev" in text


def test_page_links_collects_from_content_only():
    page = {
        "title": "https://not-a-link-in-the-title.test",
        "content": [
            {"tag": "p", "children": [{"tag": "a", "attrs": {"href": "https://x.test/y"}}]}
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


def test_allowed_hosts_is_only_the_api_host():
    assert ALLOWED_HOSTS == frozenset({"api.telegra.ph"})


def test_check_host_accepts_api_and_refuses_others():
    client = TelegraphClient(session=FakeSession([]))
    client._check_host("https://api.telegra.ph/getPage/x")
    with pytest.raises(ValueError):
        client._check_host("https://evil.test/x")
    with pytest.raises(ValueError):
        client._check_host("https://telegra.ph/x")  # the page host, not the API


def test_wait_turn_sleeps_only_when_the_slot_is_not_open():
    slept = []
    times = iter([0.0, 0.0, 0.0, 0.125])
    client = TelegraphClient(
        rate_per_s=8.0,
        session=FakeSession([]),
        clock=lambda: next(times),
        sleep=slept.append,
    )
    client._wait_turn()
    client._wait_turn()
    assert slept == [0.125]
    assert client.next_allowed == 0.25


def test_get_page_found():
    client, session, rows = make_client([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    fetch = client.get_page("Vizit-12-28")
    assert isinstance(fetch, Fetch)
    assert fetch.outcome is Outcome.FOUND
    assert fetch.path == "Vizit-12-28"
    assert fetch.page["path"] == "Vizit-12-28"
    assert fetch.status == 200
    assert fetch.error is None
    assert fetch.elapsed_ms >= 0


def test_get_page_builds_the_documented_url():
    client, session, _ = make_client([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client.get_page("Vizit-12-28")
    url, kwargs = session.calls[0]
    assert url == "https://api.telegra.ph/getPage/Vizit-12-28?return_content=true"
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] is not None
    assert "User-Agent" in kwargs["headers"]


def test_get_page_percent_encodes_non_ascii_paths():
    client, session, _ = make_client([FakeResponse(200, fixture_bytes("not-found"))])
    client.get_page("Повістка-10-25")
    url, _ = session.calls[0]
    assert "Повістка" not in url
    assert "%D0%9F" in url  # first byte of П


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
    assert fetch.error.startswith("request error")
    assert rows[0]["status"] is None
    assert rows[0]["bytes"] == 0


def test_get_page_timeout_is_a_request_exception():
    client, _, _ = make_client([requests.Timeout("slow")])
    assert client.get_page("Vizit-12-28").outcome is Outcome.FAILED


def test_get_page_logs_one_row_per_request_with_expected_keys():
    client, _, rows = make_client([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client.get_page("Vizit-12-28")
    assert len(rows) == 1
    assert set(rows[0]) == {
        "ts", "path", "attempt", "status", "outcome", "error", "elapsed_ms", "bytes"
    }
    assert rows[0]["outcome"] == "FOUND"
    assert rows[0]["attempt"] == 1
    assert rows[0]["bytes"] == len(fixture_bytes("Vizit-12-28"))


def test_get_page_log_is_optional():
    session = FakeSession([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client = TelegraphClient(session=session, sleep=lambda s: None)
    assert client.get_page("Vizit-12-28").outcome is Outcome.FOUND


# --------------------------------------------------------------------------
# content flag
# --------------------------------------------------------------------------


def test_get_page_asks_for_content_by_default():
    client, session, _ = make_client([FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client.get_page("Vizit-12-28")
    assert session.calls[0][0].endswith("?return_content=true")


def test_get_page_content_false_asks_only_for_existence():
    client, session, _ = make_client([FakeResponse(200, fixture_bytes("not-found"))])
    client.get_page("Vizit-12-28", content=False)
    url = session.calls[0][0]
    assert url.endswith("?return_content=false")
    assert "True" not in url and "False" not in url  # lowercase, as the API wants


# --------------------------------------------------------------------------
# retries
# --------------------------------------------------------------------------


def backoff_sleeps(slept):
    """The pacer also calls sleep with tiny values; keep only the backoff waits."""
    return [s for s in slept if s >= 1.0]


def test_get_page_retries_a_failed_attempt_and_returns_the_success():
    slept = []
    session = FakeSession([requests.Timeout("slow"), FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    rows = []
    client = TelegraphClient(session=session, sleep=slept.append, log=rows.append, retries=2)
    fetch = client.get_page("Vizit-12-28")
    assert fetch.outcome is Outcome.FOUND
    assert len(session.calls) == 2
    assert [r["attempt"] for r in rows] == [1, 2]
    assert backoff_sleeps(slept) == [1.0]


def test_get_page_gives_up_after_retries_and_returns_the_last_failure():
    slept = []
    session = FakeSession([requests.Timeout("a"), requests.Timeout("b"), requests.Timeout("c")])
    rows = []
    client = TelegraphClient(session=session, sleep=slept.append, log=rows.append, retries=2)
    fetch = client.get_page("Vizit-12-28")
    assert fetch.outcome is Outcome.FAILED
    assert "c" in fetch.error  # the last attempt's error, not the first
    assert len(session.calls) == 3  # one try plus two retries, never four
    assert [r["attempt"] for r in rows] == [1, 2, 3]
    assert backoff_sleeps(slept) == [1.0, 2.0]  # doubling, and no sleep after the last attempt


def test_get_page_backoff_scales_with_backoff_s():
    slept = []
    session = FakeSession([requests.Timeout("a"), requests.Timeout("b"), requests.Timeout("c")])
    client = TelegraphClient(session=session, sleep=slept.append, retries=2, backoff_s=5.0)
    client.get_page("Vizit-12-28")
    assert backoff_sleeps(slept) == [5.0, 10.0]


def test_get_page_does_not_retry_not_found():
    slept = []
    session = FakeSession([FakeResponse(200, fixture_bytes("not-found"))])
    client = TelegraphClient(session=session, sleep=slept.append, retries=2)
    fetch = client.get_page("Nope-01-01")
    assert fetch.outcome is Outcome.NOT_FOUND
    assert len(session.calls) == 1
    assert backoff_sleeps(slept) == []


def test_get_page_retries_a_server_error_body_too():
    # A 502 HTML body is FAILED, so it is retried like a network error.
    session = FakeSession(
        [FakeResponse(502, b"<html>Bad Gateway</html>"), FakeResponse(200, fixture_bytes("Vizit-12-28"))]
    )
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=1)
    assert client.get_page("Vizit-12-28").outcome is Outcome.FOUND
    assert len(session.calls) == 2


def test_get_page_retries_zero_means_a_single_attempt():
    session = FakeSession([requests.Timeout("a"), FakeResponse(200, fixture_bytes("Vizit-12-28"))])
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=0)
    assert client.get_page("Vizit-12-28").outcome is Outcome.FAILED
    assert len(session.calls) == 1


def test_get_page_budget_is_enforced_per_attempt():
    # Budget of 2 with a client that would retry twice: the third attempt is refused.
    session = FakeSession([requests.Timeout("a"), requests.Timeout("b"), requests.Timeout("c")])
    client = TelegraphClient(session=session, sleep=lambda s: None, retries=2, budget=2)
    with pytest.raises(BudgetExceeded):
        client.get_page("Vizit-12-28")
    assert len(session.calls) == 2
    assert client.requests_made == 2


def test_get_page_counts_requests_including_failures():
    client, _, _ = make_client(
        [FakeResponse(200, fixture_bytes("not-found")), requests.ConnectionError("down")]
    )
    client.get_page("a-01-01")
    client.get_page("b-01-01")
    assert client.requests_made == 2


def test_get_page_budget_raises_before_sending():
    client, session, _ = make_client([FakeResponse(200, fixture_bytes("Vizit-12-28"))], budget=1)
    client.get_page("Vizit-12-28")
    with pytest.raises(BudgetExceeded):
        client.get_page("Vizit-12-28")
    assert len(session.calls) == 1  # the refused request never hit the session


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
