"""Tests for graphwatch.feeds, the lookup-only client for the public feeds (issue #38).

No test here touches the network: the session is a fake that records what it
was asked to send. Every answer is made up in the shape the feed's
documentation shows, and every key is a made-up string.
"""

import base64
import json

import pytest
import requests

from graphwatch.feeds import (
    ALLOWED_HOSTS,
    FEED_FUNCTIONS,
    FEEDS,
    KEY_NAMES,
    PACE_S,
    FeedClient,
    Lookup,
    Verdict,
    bare_host,
    feed_keys,
    ioc_is,
    otx_requests,
    parse_otx,
    parse_threatfox,
    parse_urlhaus,
    parse_virustotal,
    threatfox_requests,
    urlhaus_requests,
    virustotal_requests,
)
from graphwatch.telegraph import BudgetExceeded

KEYS = {
    "threatfox": "abuse-key-made-up",
    "urlhaus": "abuse-key-made-up",
    "otx": "otx-key-made-up",
    "virustotal": "vt-key-made-up",
}
IP = "8.8.8.8"
HOST = "c2.example.org"
URL = "http://c2.example.org/gate.php?id=1"


def body(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


THREATFOX_HIT = body(
    {
        "query_status": "ok",
        "data": [
            {"ioc": "8.8.8.8:443", "malware_printable": "Made-up RAT"},
            {"ioc": "8.8.8.8:8080", "malware_printable": "Made-up RAT"},
        ],
    }
)
THREATFOX_MISS = body({"query_status": "no_result", "data": "Your search did not yield any results"})
URLHAUS_HOST_HIT = body({"query_status": "ok", "url_count": "3", "urls": []})
URLHAUS_URL_HIT = body({"query_status": "ok", "threat": "malware_download"})
URLHAUS_MISS = body({"query_status": "no_results"})
OTX_HIT = body({"indicator": IP, "pulse_info": {"count": 4, "pulses": []}})
OTX_MISS = body({"indicator": IP, "pulse_info": {"count": 0, "pulses": []}})


def vt(malicious: int, harmless: int = 60) -> bytes:
    stats = {"harmless": harmless, "malicious": malicious, "suspicious": 0, "timeout": 0, "undetected": 30}
    return body({"data": {"attributes": {"last_analysis_stats": stats}}})


VT_NOT_FOUND = body({"error": {"code": "NotFoundError", "message": "not found"}})
VT_QUOTA = body({"error": {"code": "QuotaExceededError", "message": "quota"}})

MISS = {
    "threatfox": (200, THREATFOX_MISS),
    "urlhaus": (200, URLHAUS_MISS),
    "otx": (200, OTX_MISS),
    "virustotal": (200, vt(0)),
}
HIT = {
    "threatfox": (200, THREATFOX_HIT),
    "urlhaus": (200, URLHAUS_HOST_HIT),
    "otx": (200, OTX_HIT),
    "virustotal": (200, vt(5)),
}


class Resp:
    def __init__(self, status, content):
        self.status_code = status
        self.content = content


class FeedSession:
    """Records every request and answers by host from `answers`: a dict of
    host substring to (status, body), or to a list of them used in turn."""

    def __init__(self, answers=None, error=None):
        self.answers = answers or {}
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if self.error is not None:
            raise self.error
        for needle, answer in self.answers.items():
            if needle in url:
                if isinstance(answer, list):
                    answer = answer.pop(0)
                return Resp(*answer)
        return Resp(500, b"no answer set up for this url")


def by_feed(per_feed: dict) -> dict:
    """Answers keyed by feed name, turned into answers keyed by host."""
    hosts = {
        "threatfox": "threatfox-api.abuse.ch",
        "urlhaus": "urlhaus-api.abuse.ch",
        "otx": "otx.alienvault.com",
        "virustotal": "www.virustotal.com",
    }
    return {hosts[feed]: answer for feed, answer in per_feed.items()}


def make_client(per_feed=None, keys=KEYS, error=None, **kwargs):
    session = FeedSession(by_feed(per_feed or MISS), error)
    client = FeedClient(keys, session=session, sleep=lambda s: None, **kwargs)
    return client, session


# --------------------------------------------------------------------------
# keys and names
# --------------------------------------------------------------------------


def test_the_four_feeds_and_their_hosts():
    assert FEEDS == ("threatfox", "urlhaus", "otx", "virustotal")
    assert ALLOWED_HOSTS == {
        "threatfox-api.abuse.ch",
        "urlhaus-api.abuse.ch",
        "otx.alienvault.com",
        "www.virustotal.com",
    }
    assert set(FEED_FUNCTIONS) == set(FEEDS)


def test_the_feed_allowlist_shares_no_host_with_telegraph():
    from graphwatch import telegraph

    assert not ALLOWED_HOSTS & telegraph.ALLOWED_HOSTS


def test_key_names_are_the_ones_agreed_for_the_config_file():
    assert KEY_NAMES == {
        "threatfox": "ABUSE_CH_KEY",
        "urlhaus": "ABUSE_CH_KEY",
        "otx": "OTX_KEY",
        "virustotal": "VT_KEY",
    }


def test_feed_keys_gives_both_abuse_ch_feeds_the_one_key():
    keys = feed_keys({"ABUSE_CH_KEY": "a", "OTX_KEY": "o", "VT_KEY": "v", "HMAC_KEY": "h"})
    assert keys == {"threatfox": "a", "urlhaus": "a", "otx": "o", "virustotal": "v"}


def test_feed_keys_leaves_out_a_feed_whose_key_is_missing_or_empty():
    assert feed_keys({"OTX_KEY": "o", "VT_KEY": ""}) == {"otx": "o"}
    assert feed_keys({}) == {}


def test_bare_host_drops_a_port_and_nothing_else():
    assert bare_host("8.8.8.8:8443") == "8.8.8.8"
    assert bare_host("c2.example.org:443") == "c2.example.org"
    assert bare_host("c2.example.org") == "c2.example.org"


# --------------------------------------------------------------------------
# request builders
# --------------------------------------------------------------------------


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("kind,value", [("ip", IP), ("host", HOST), ("url", URL)])
def test_every_request_is_to_an_allowed_host_over_https(feed, kind, value):
    build, _parse = FEED_FUNCTIONS[feed]
    built = build(kind, value, KEYS[feed])
    assert built
    for request in built:
        assert request.url.startswith("https://")
        assert request.url.split("/")[2] in ALLOWED_HOSTS


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("kind,value", [("ip", IP), ("host", HOST), ("url", URL)])
def test_the_key_travels_in_a_header_and_never_in_the_url_or_body(feed, kind, value):
    build, _parse = FEED_FUNCTIONS[feed]
    for request in build(kind, value, KEYS[feed]):
        assert KEYS[feed] in request.headers.values()
        assert KEYS[feed] not in request.url
        assert KEYS[feed] not in json.dumps([request.json, request.data])


def test_threatfox_searches_for_the_value_with_a_wildcard_search():
    (request,) = threatfox_requests("ip", IP, "k")
    assert (request.method, request.url) == ("POST", "https://threatfox-api.abuse.ch/api/v1/")
    assert request.json == {"query": "search_ioc", "search_term": IP}
    assert request.headers == {"Auth-Key": "k"}
    assert request.term == IP


def test_threatfox_searches_for_an_address_without_its_port():
    (request,) = threatfox_requests("ip", "8.8.8.8:8443", "k")
    assert request.json["search_term"] == "8.8.8.8"


def test_threatfox_searches_for_a_url_whole():
    (request,) = threatfox_requests("url", URL, "k")
    assert request.json["search_term"] == URL


@pytest.mark.parametrize("kind,value", [("ip", IP), ("host", HOST), ("ip", "8.8.8.8:8443")])
def test_urlhaus_asks_the_host_endpoint_for_an_ip_or_a_host(kind, value):
    (request,) = urlhaus_requests(kind, value, "k")
    assert (request.method, request.url) == ("POST", "https://urlhaus-api.abuse.ch/v1/host/")
    assert request.data == {"host": bare_host(value)}
    assert request.headers == {"Auth-Key": "k"}


def test_urlhaus_asks_the_url_endpoint_for_a_url():
    (request,) = urlhaus_requests("url", URL, "k")
    assert request.url == "https://urlhaus-api.abuse.ch/v1/url/"
    assert request.data == {"url": URL}


def test_otx_asks_for_an_ip_once():
    (request,) = otx_requests("ip", IP, "k")
    assert request.method == "GET"
    assert request.url == "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
    assert request.headers == {"X-OTX-API-KEY": "k"}


def test_otx_asks_for_a_host_as_a_hostname_and_then_as_a_domain():
    # The wrong one answers with no pulses, not an error, so both are asked.
    first, second = otx_requests("host", HOST, "k")
    assert first.url == "https://otx.alienvault.com/api/v1/indicators/hostname/c2.example.org/general"
    assert second.url == "https://otx.alienvault.com/api/v1/indicators/domain/c2.example.org/general"


def test_otx_quotes_a_url_so_its_query_does_not_end_the_path():
    (request,) = otx_requests("url", URL, "k")
    assert request.url == (
        "https://otx.alienvault.com/api/v1/indicators/url/"
        "http%3A%2F%2Fc2.example.org%2Fgate.php%3Fid%3D1/general"
    )


def test_virustotal_asks_for_the_stored_report_of_each_kind():
    (ip,) = virustotal_requests("ip", IP, "k")
    (host,) = virustotal_requests("host", HOST, "k")
    assert ip.url == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    assert host.url == "https://www.virustotal.com/api/v3/domains/c2.example.org"
    assert ip.headers == {"x-apikey": "k"}


def test_virustotal_asks_for_a_url_by_its_unpadded_base64_id():
    (request,) = virustotal_requests("url", URL, "k")
    url_id = request.url.rsplit("/", 1)[1]
    assert "=" not in url_id
    padded = url_id + "=" * (-len(url_id) % 4)
    assert base64.urlsafe_b64decode(padded).decode("utf-8") == URL


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("kind,value", [("ip", IP), ("host", HOST), ("url", URL)])
def test_no_request_submits_anything_for_scanning(feed, kind, value):
    # Passive only. VirusTotal and OTX are read with GET. The two abuse.ch
    # feeds take their lookups by POST, to a query endpoint and nothing else.
    build, _parse = FEED_FUNCTIONS[feed]
    for request in build(kind, value, KEYS[feed]):
        if feed in ("virustotal", "otx"):
            assert request.method == "GET"
            assert request.json is None and request.data is None
        elif feed == "threatfox":
            assert request.json["query"] == "search_ioc"
        else:
            assert request.url.rsplit("/", 2)[1] in ("host", "url")
        for word in ("scan", "submit", "analyse", "analyze", "rescan"):
            assert word not in request.url


# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------


def test_threatfox_hit_is_known_with_the_ioc_count_and_malware_name():
    assert parse_threatfox(200, THREATFOX_HIT, IP) == (Verdict.KNOWN, "2 IOCs, Made-up RAT")


def test_threatfox_no_result_is_unknown():
    assert parse_threatfox(200, THREATFOX_MISS, IP) == (Verdict.UNKNOWN, None)


def test_threatfox_hits_on_longer_values_only_are_unknown():
    # A wildcard search for 8.8.8.8 also returns 8.8.8.80 and 18.8.8.8.
    answer = body({"query_status": "ok", "data": [{"ioc": "8.8.8.80:443"}, {"ioc": "18.8.8.8:80"}]})
    assert parse_threatfox(200, answer, IP) == (Verdict.UNKNOWN, None)


def test_threatfox_counts_only_the_iocs_that_are_the_value():
    answer = body({"query_status": "ok", "data": [{"ioc": "8.8.8.80:443"}, {"ioc": "8.8.8.8:443"}]})
    assert parse_threatfox(200, answer, IP) == (Verdict.KNOWN, "1 IOCs")


@pytest.mark.parametrize(
    "ioc,term,same",
    [
        ("8.8.8.8", "8.8.8.8", True),
        ("8.8.8.8:443", "8.8.8.8", True),
        ("8.8.8.80:443", "8.8.8.8", False),
        ("18.8.8.8", "8.8.8.8", False),
        ("C2.Example.org", "c2.example.org", True),
        ("evil-c2.example.org", "c2.example.org", False),
        ("http://c2.example.org/gate.php", "c2.example.org", True),
        ("http://c2.example.org.evil.test/", "c2.example.org", False),
        ("http://c2.example.org/gate.php?id=1", "http://c2.example.org/gate.php?id=1", True),
        ("http://[broken", "c2.example.org", False),
    ],
)
def test_ioc_is(ioc, term, same):
    assert ioc_is(ioc, term) is same


@pytest.mark.parametrize(
    "status,answer",
    [
        (200, body({"query_status": "illegal_search_term"})),
        (200, body({"query_status": "ok", "data": "not a list"})),
        (401, body({"error": "Unauthorized"})),
        (200, b"<html>not json</html>"),
        (200, body(["a", "list"])),
        (502, b""),
    ],
)
def test_threatfox_anything_else_is_failed_never_unknown(status, answer):
    verdict, detail = parse_threatfox(status, answer, IP)
    assert verdict is Verdict.FAILED
    assert detail


def test_urlhaus_host_hit_is_known_with_the_url_count():
    assert parse_urlhaus(200, URLHAUS_HOST_HIT, HOST) == (Verdict.KNOWN, "3 URLs")


def test_urlhaus_url_hit_is_known_with_the_threat():
    assert parse_urlhaus(200, URLHAUS_URL_HIT, URL) == (Verdict.KNOWN, "malware_download")


def test_urlhaus_no_results_is_unknown():
    assert parse_urlhaus(200, URLHAUS_MISS, HOST) == (Verdict.UNKNOWN, None)


def test_urlhaus_reads_the_status_key_as_the_documentation_misspells_it():
    answer = body({"query_staus": "ok", "url_count": "1"})
    assert parse_urlhaus(200, answer, HOST) == (Verdict.KNOWN, "1 URLs")


@pytest.mark.parametrize(
    "status,answer",
    [
        (200, body({"query_status": "invalid_host"})),
        (200, body({"query_status": "invalid_url"})),
        (200, body({"query_status": "http_post_expected"})),
        (401, body({"error": "Unauthorized"})),
        (200, b"not json"),
    ],
)
def test_urlhaus_anything_else_is_failed(status, answer):
    assert parse_urlhaus(status, answer, HOST)[0] is Verdict.FAILED


def test_otx_is_known_only_when_the_indicator_is_in_a_pulse():
    assert parse_otx(200, OTX_HIT, IP) == (Verdict.KNOWN, "4 pulses")
    assert parse_otx(200, OTX_MISS, IP) == (Verdict.UNKNOWN, None)


@pytest.mark.parametrize("answer", [b"", body({"detail": "endpoint not found"}), b"<html>404</html>"])
def test_otx_not_found_is_failed_not_unknown(answer):
    # OTX answers 200 with a count of 0 for an address it has never seen. A
    # 404 is a path it could not route, and must not make an indicator novel.
    verdict, detail = parse_otx(404, answer, IP)
    assert verdict is Verdict.FAILED
    assert detail


@pytest.mark.parametrize(
    "status,answer",
    [
        (400, body({"detail": "Invalid IP (8.8.8.8)"})),
        (403, body({"detail": "Authentication required"})),
        (200, body({"indicator": IP})),
        (200, b"not json"),
    ],
)
def test_otx_anything_else_is_failed_and_does_not_quote_the_feed(status, answer):
    verdict, detail = parse_otx(status, answer, IP)
    assert verdict is Verdict.FAILED
    assert "Invalid IP" not in detail


def test_virustotal_is_known_only_when_an_engine_says_malicious():
    assert parse_virustotal(200, vt(5), IP) == (Verdict.KNOWN, "malicious on 5 of 95 engines")
    assert parse_virustotal(200, vt(0), IP) == (Verdict.UNKNOWN, None)


def test_virustotal_no_report_is_unknown():
    assert parse_virustotal(404, VT_NOT_FOUND, IP) == (Verdict.UNKNOWN, None)


def test_virustotal_a_spent_quota_is_failed_and_names_the_error():
    assert parse_virustotal(429, VT_QUOTA, IP) == (Verdict.FAILED, "429: QuotaExceededError")


@pytest.mark.parametrize(
    "status,answer",
    [
        (401, body({"error": {"code": "WrongCredentialsError"}})),
        (200, body({"data": {"attributes": {}}})),
        (200, body({"data": None})),
        (200, b"not json"),
        (500, body({"error": "a string, not an object"})),
    ],
)
def test_virustotal_anything_else_is_failed(status, answer):
    assert parse_virustotal(status, answer, IP)[0] is Verdict.FAILED


# --------------------------------------------------------------------------
# FeedClient
# --------------------------------------------------------------------------


def test_feeds_lists_the_feeds_with_a_key_in_feed_order():
    client, _ = make_client(keys={"virustotal": "v", "threatfox": "a"})
    assert client.feeds() == ["threatfox", "virustotal"]


@pytest.mark.parametrize("feed", FEEDS)
def test_lookup_returns_unknown_for_a_miss(feed):
    client, _ = make_client(MISS)
    lookup = client.lookup(feed, "ip", IP)
    assert isinstance(lookup, Lookup)
    assert (lookup.feed, lookup.kind, lookup.value) == (feed, "ip", IP)
    assert (lookup.verdict, lookup.detail, lookup.status) == (Verdict.UNKNOWN, None, 200)


@pytest.mark.parametrize("feed", FEEDS)
def test_lookup_returns_known_for_a_hit(feed):
    client, _ = make_client(HIT)
    lookup = client.lookup(feed, "ip", IP)
    assert lookup.verdict is Verdict.KNOWN
    assert lookup.detail


def test_lookup_sends_what_the_builder_built():
    client, session = make_client(MISS)
    client.lookup("threatfox", "ip", IP)
    (call,) = session.calls
    assert call["method"] == "POST"
    assert call["url"] == "https://threatfox-api.abuse.ch/api/v1/"
    assert call["json"] == {"query": "search_ioc", "search_term": IP}
    assert call["headers"]["Auth-Key"] == KEYS["threatfox"]
    assert call["headers"]["User-Agent"] == "graphwatch"
    assert call["allow_redirects"] is False
    assert call["timeout"] > 0


def test_the_user_agent_is_a_bare_product_name():
    client, session = make_client(MISS)
    client.lookup("otx", "ip", IP)
    agent = session.calls[0]["headers"]["User-Agent"]
    assert agent == "graphwatch"
    assert "@" not in agent


def test_an_otx_host_lookup_asks_the_second_section_only_after_a_miss():
    client, session = make_client({"otx": [(200, OTX_MISS), (200, OTX_HIT)]})
    lookup = client.lookup("otx", "host", HOST)
    assert [call["url"].split("/")[6] for call in session.calls] == ["hostname", "domain"]
    assert (lookup.verdict, lookup.detail) == (Verdict.KNOWN, "4 pulses")
    assert client.requests_made == 2


def test_an_otx_host_lookup_stops_at_the_first_hit():
    client, session = make_client({"otx": [(200, OTX_HIT), (200, OTX_MISS)]})
    assert client.lookup("otx", "host", HOST).verdict is Verdict.KNOWN
    assert len(session.calls) == 1


def test_an_otx_host_is_unknown_only_when_both_sections_say_so():
    client, session = make_client({"otx": [(200, OTX_MISS), (200, OTX_MISS)]})
    assert client.lookup("otx", "host", HOST).verdict is Verdict.UNKNOWN
    assert len(session.calls) == 2


def test_an_otx_host_lookup_that_fails_halfway_is_failed_not_unknown():
    client, _ = make_client({"otx": [(200, OTX_MISS), (500, b"")]})
    assert client.lookup("otx", "host", HOST).verdict is Verdict.FAILED


def test_a_network_error_is_a_failed_lookup_not_an_exception():
    error = requests.ConnectionError(f"could not reach host with key {KEYS['otx']}")
    client, _ = make_client(error=error)
    lookup = client.lookup("otx", "ip", IP)
    assert (lookup.verdict, lookup.status) == (Verdict.FAILED, None)
    assert lookup.detail == "request error: ConnectionError"


def test_lookup_refuses_a_feed_it_has_no_key_for():
    client, session = make_client(keys={"otx": "o"})
    with pytest.raises(KeyError):
        client.lookup("virustotal", "ip", IP)
    assert session.calls == []


def test_lookup_refuses_a_url_off_the_allowlist(monkeypatch):
    from graphwatch import feeds

    def stray(kind, value, key):
        return [feeds.Request("GET", f"http://{value}/", {}, value)]

    monkeypatch.setitem(feeds.FEED_FUNCTIONS, "otx", (stray, parse_otx))
    client, session = make_client()
    with pytest.raises(ValueError):
        client.lookup("otx", "host", HOST)
    assert session.calls == []
    assert client.requests_made == 0


def test_no_lookup_ever_sends_a_request_to_the_indicator_itself():
    client, session = make_client(MISS)
    for feed in FEEDS:
        for kind, value in (("ip", IP), ("host", HOST), ("url", URL)):
            client.lookup(feed, kind, value)
    hosts = {call["url"].split("/")[2] for call in session.calls}
    assert hosts <= ALLOWED_HOSTS
    assert len(hosts) == 4


def test_budget_exceeded_is_raised_before_anything_is_sent():
    client, session = make_client(MISS, budget=1)
    client.lookup("threatfox", "ip", IP)
    with pytest.raises(BudgetExceeded):
        client.lookup("urlhaus", "ip", IP)
    assert len(session.calls) == 1
    assert client.requests_made == 1


def test_budget_counts_requests_not_lookups():
    client, session = make_client({"otx": [(200, OTX_MISS), (200, OTX_MISS)]}, budget=1)
    with pytest.raises(BudgetExceeded):
        client.lookup("otx", "host", HOST)
    assert len(session.calls) == 1


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def test_virustotal_is_paced_at_four_requests_a_minute():
    assert PACE_S["virustotal"] == 15.0
    clock = Clock()
    session = FeedSession(by_feed(MISS))
    client = FeedClient(KEYS, session=session, clock=clock, sleep=clock.sleep)
    for _ in range(3):
        client.lookup("virustotal", "ip", IP)
    assert clock.sleeps == [15.0, 15.0]


def test_each_feed_has_its_own_pace():
    clock = Clock()
    session = FeedSession(by_feed(MISS))
    client = FeedClient(KEYS, session=session, clock=clock, sleep=clock.sleep)
    client.lookup("virustotal", "ip", IP)
    client.lookup("threatfox", "ip", IP)  # another feed: no wait for VirusTotal's slot
    assert clock.sleeps == []
    client.lookup("threatfox", "ip", IP)
    assert clock.sleeps == [PACE_S["threatfox"]]


def test_the_first_lookup_never_waits():
    clock = Clock()
    client = FeedClient(KEYS, session=FeedSession(by_feed(MISS)), clock=clock, sleep=clock.sleep)
    client.lookup("otx", "ip", IP)
    assert clock.sleeps == []


def test_every_request_writes_one_log_row_in_the_http_log_shape():
    rows = []
    client, _ = make_client({"otx": [(200, OTX_MISS), (200, OTX_HIT)]}, log=rows.append)
    client.lookup("otx", "host", HOST)
    assert len(rows) == 2
    assert set(rows[0]) == {"ts", "path", "attempt", "status", "outcome", "error", "elapsed_ms", "bytes"}
    assert [row["attempt"] for row in rows] == [1, 2]
    assert [row["outcome"] for row in rows] == ["UNKNOWN", "KNOWN"]
    assert rows[0]["path"] == "otx:c2.example.org"
    assert rows[0]["error"] is None


def test_a_failed_request_logs_its_reason():
    rows = []
    client, _ = make_client({"virustotal": (429, VT_QUOTA)}, log=rows.append)
    client.lookup("virustotal", "ip", IP)
    assert (rows[0]["status"], rows[0]["outcome"]) == (429, "FAILED")
    assert rows[0]["error"] == "429: QuotaExceededError"


def test_the_log_rows_fit_the_http_log_table():
    from graphwatch.db import connect, http_logger

    conn = connect(":memory:")
    client, _ = make_client(MISS, log=http_logger(conn))
    client.lookup("threatfox", "ip", IP)
    row = conn.execute("SELECT path, outcome FROM http_log").fetchone()
    assert tuple(row) == ("threatfox:8.8.8.8", "UNKNOWN")
    conn.close()


@pytest.mark.parametrize("error", [None, requests.ConnectionError("boom")])
def test_a_key_never_appears_in_a_log_row_or_a_lookup(error):
    rows = []
    looked = []
    client, _ = make_client(MISS, error=error, log=rows.append)
    for feed in FEEDS:
        for kind, value in (("ip", IP), ("host", HOST), ("url", URL)):
            looked.append(client.lookup(feed, kind, value))
    written = json.dumps(rows) + repr(looked)
    for key in set(KEYS.values()):
        assert key not in written


# --------------------------------------------------------------------------
# what the review of 22 November found
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "answer",
    [
        {"pulse_info": {}},
        {"pulse_info": {"count": None}},
        {"pulse_info": {"pulses": [{"name": "x"}]}},
        {"pulse_info": {"count": "3"}},
        {"pulse_info": {"count": True}},
        {"pulse_info": {"count": 2.0}},
    ],
)
def test_otx_without_a_whole_number_count_is_failed(answer):
    # A missing count read as 0 would store UNKNOWN, and UNKNOWN from OTX is
    # half of what makes an indicator novel.
    assert parse_otx(200, body(answer), IP)[0] is Verdict.FAILED


def test_a_parser_that_raises_is_a_failed_lookup_and_is_still_logged(monkeypatch):
    from graphwatch import feeds

    def broken(status, content, term):
        raise TypeError("a shape no parser foresaw")

    monkeypatch.setitem(feeds.FEED_FUNCTIONS, "otx", (otx_requests, broken))
    rows = []
    client, _ = make_client(MISS, log=rows.append)
    lookup = client.lookup("otx", "ip", IP)
    assert lookup.verdict is Verdict.FAILED
    assert lookup.detail == "200: unexpected answer (TypeError)"
    assert [(row["outcome"], row["status"]) for row in rows] == [("FAILED", 200)]


@pytest.mark.parametrize(
    "value,bare",
    [
        ("2a00:1450:4001::81b:2004", "2a00:1450:4001::81b:2004"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("8.8.8.8:8443", "8.8.8.8"),
        ("c2.example.org:443", "c2.example.org"),
    ],
)
def test_bare_host_does_not_cut_the_last_group_off_an_ipv6_address(value, bare):
    assert bare_host(value) == bare


def test_an_ipv6_address_is_asked_for_whole_and_under_its_own_otx_section():
    address = "2a00:1450:4001::81b:2004"
    (otx,) = otx_requests("ip", address, "k")
    assert otx.url == (
        "https://otx.alienvault.com/api/v1/indicators/IPv6/2a00%3A1450%3A4001%3A%3A81b%3A2004/general"
    )
    assert threatfox_requests("ip", address, "k")[0].json["search_term"] == address
    assert urlhaus_requests("ip", address, "k")[0].data == {"host": address}
    assert virustotal_requests("ip", address, "k")[0].url.endswith("/ip_addresses/2a00%3A1450%3A4001%3A%3A81b%3A2004")


def test_ioc_is_reads_a_bracketed_ipv6_ioc():
    assert ioc_is("[2a00::1]:443", "2a00::1") is True
    assert ioc_is("[2a00::12]:443", "2a00::1") is False


@pytest.mark.parametrize("threat", [{"kind": "malware"}, ["a", "b"], 7, "", None])
def test_urlhaus_gives_a_text_detail_whatever_the_feed_put_in_threat(threat):
    # A dict as the detail could not be stored, and ended the whole run.
    verdict, detail = parse_urlhaus(200, body({"query_status": "ok", "threat": threat}), URL)
    assert (verdict, detail) == (Verdict.KNOWN, "listed")


def test_a_detail_that_is_not_text_is_made_text_before_it_leaves_the_client(monkeypatch):
    from graphwatch import feeds

    monkeypatch.setitem(feeds.FEED_FUNCTIONS, "otx", (otx_requests, lambda status, content, term: (Verdict.KNOWN, {"n": 3})))
    client, _ = make_client(MISS)
    assert client.lookup("otx", "ip", IP).detail == "{'n': 3}"
