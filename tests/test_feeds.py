"""Tests for graphwatch.feeds, the lookup-only client for the public feeds (issue #38).

No test here touches the network: the session is a fake that records what it
was asked to send. Every answer is made up in the shape the feed's
documentation shows, and every key is a made-up string.
"""

import itertools
import json

import pytest
import requests

from graphwatch.feeds import (
    ALLOWED_HOSTS,
    FEED_FUNCTIONS,
    FEEDS,
    FeedClient,
    KeyCheck,
    Lookup,
    Request,
    Verdict,
    bare_host,
    failure_kind,
    feed_keys,
    ioc_is,
    otx_key_request,
    otx_requests,
    parse_key_check,
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
EVERY_KIND = [("ip", IP), ("host", HOST), ("url", URL)]


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
OTX_ERROR = body({"detail": "server error"})


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
    from graphwatch import telegraph

    assert FEEDS == ("threatfox", "urlhaus", "otx", "virustotal")
    assert ALLOWED_HOSTS == {
        "threatfox-api.abuse.ch",
        "urlhaus-api.abuse.ch",
        "otx.alienvault.com",
        "www.virustotal.com",
    }
    assert set(FEED_FUNCTIONS) == set(FEEDS)
    # This module talks to the feeds and telegraph.py to Telegraph, and neither to both
    assert not ALLOWED_HOSTS & telegraph.ALLOWED_HOSTS


def test_feed_keys_gives_both_abuse_ch_feeds_the_one_key():
    keys = feed_keys({"ABUSE_CH_KEY": "a", "OTX_KEY": "o", "VT_KEY": "v", "HMAC_KEY": "h"})
    assert keys == {"threatfox": "a", "urlhaus": "a", "otx": "o", "virustotal": "v"}


def test_feed_keys_leaves_out_a_feed_whose_key_is_missing_or_empty():
    assert feed_keys({"OTX_KEY": "o", "VT_KEY": ""}) == {"otx": "o"}
    assert feed_keys({}) == {}


@pytest.mark.parametrize(
    "value,bare",
    [
        ("c2.example.org", "c2.example.org"),
        ("c2.example.org:443", "c2.example.org"),
        ("8.8.8.8:8443", "8.8.8.8"),
        ("8.8.8.8:50000", "8.8.8.8"),
        # An IPv6 address is colons and digits all the way: its last group is not a port
        ("2a00:1450:4001::81b:2004", "2a00:1450:4001::81b:2004"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_bare_host_drops_a_port_and_never_the_last_group_of_an_ipv6_address(value, bare):
    assert bare_host(value) == bare


# --------------------------------------------------------------------------
# request builders
# --------------------------------------------------------------------------


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("kind,value", EVERY_KIND)
def test_every_request_is_to_an_allowed_host_over_https(feed, kind, value):
    build, _parse = FEED_FUNCTIONS[feed]
    built = build(kind, value, KEYS[feed])
    assert built
    for request in built:
        assert request.url.startswith("https://")
        assert request.url.split("/")[2] in ALLOWED_HOSTS


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("kind,value", EVERY_KIND)
def test_the_key_travels_in_a_header_and_never_in_the_url_or_body(feed, kind, value):
    build, _parse = FEED_FUNCTIONS[feed]
    for request in build(kind, value, KEYS[feed]):
        assert KEYS[feed] in request.headers.values()
        assert KEYS[feed] not in request.url
        assert KEYS[feed] not in json.dumps([request.json, request.data])


@pytest.mark.parametrize(
    "kind,value,term",
    [
        ("host", HOST, HOST),
        ("ip", "8.8.8.8:8443", IP),
        ("url", URL, URL),
        # A URL is searched for whole, and a port on the end of it is part of it
        ("url", "http://c2.example.org:8080", "http://c2.example.org:8080"),
    ],
)
def test_threatfox_searches_for_an_address_without_its_port_and_a_url_whole(kind, value, term):
    (request,) = threatfox_requests(kind, value, "k")
    assert request == Request(
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        {"Auth-Key": "k"},
        term,
        json={"query": "search_ioc", "search_term": term},
    )


@pytest.mark.parametrize(
    "kind,value,endpoint,term",
    [("host", HOST, "host", HOST), ("ip", "8.8.8.8:8443", "host", IP), ("url", URL, "url", URL)],
)
def test_urlhaus_asks_the_host_endpoint_for_an_address_and_the_url_endpoint_for_a_url(kind, value, endpoint, term):
    (request,) = urlhaus_requests(kind, value, "k")
    assert request == Request(
        "POST", f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", {"Auth-Key": "k"}, term, data={endpoint: term}
    )


@pytest.mark.parametrize("value", [IP, "8.8.8.8:8443"])
def test_otx_asks_for_an_ip_once_and_without_its_port(value):
    (request,) = otx_requests("ip", value, "k")
    assert request == Request(
        "GET", "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general", {"X-OTX-API-KEY": "k"}, IP
    )


@pytest.mark.parametrize("value", [HOST, "c2.example.org:443"])
def test_otx_asks_for_a_host_as_a_hostname_and_then_as_a_domain(value):
    # The wrong one answers with no pulses, not an error, so both are asked.
    first, second = otx_requests("host", value, "k")
    assert first.url == "https://otx.alienvault.com/api/v1/indicators/hostname/c2.example.org/general"
    assert second.url == "https://otx.alienvault.com/api/v1/indicators/domain/c2.example.org/general"
    assert first.term == second.term == HOST


def test_otx_quotes_a_url_so_its_query_does_not_end_the_path():
    (request,) = otx_requests("url", URL, "k")
    assert request.url == (
        "https://otx.alienvault.com/api/v1/indicators/url/"
        "http%3A%2F%2Fc2.example.org%2Fgate.php%3Fid%3D1/general"
    )


@pytest.mark.parametrize(
    "kind,value,path,term",
    [
        ("ip", "8.8.8.8:8443", "ip_addresses/8.8.8.8", IP),
        ("host", "c2.example.org:443", "domains/c2.example.org", HOST),
        # A URL is asked for by its id, the unpadded URL-safe base64 of it. The
        # plain alphabet would put a / in this one and the padding two = after it.
        (
            "url",
            "http://c2.example.org/gate?id=1",
            "urls/aHR0cDovL2MyLmV4YW1wbGUub3JnL2dhdGU_aWQ9MQ",
            "http://c2.example.org/gate?id=1",
        ),
    ],
)
def test_virustotal_asks_for_the_stored_report_of_each_kind(kind, value, path, term):
    (request,) = virustotal_requests(kind, value, "k")
    assert request == Request("GET", "https://www.virustotal.com/api/v3/" + path, {"x-apikey": "k"}, term)


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("kind,value", EVERY_KIND)
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


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("answer", [b"<html>not json</html>", b""])
def test_an_answer_that_is_not_json_is_failed_by_every_parser(feed, answer):
    # An error page, or nothing at all: neither says the feed does not know the value
    _build, parse = FEED_FUNCTIONS[feed]
    verdict, detail = parse(200, answer, IP)
    assert verdict is Verdict.FAILED
    assert detail.startswith("200: ")


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
        ("http://c2.example.org/gate.php", "c2.example.org", True),
        ("http://c2.example.org.evil.test/", "c2.example.org", False),
        ("http://evil-c2.example.org/gate.php", "c2.example.org", False),
        ("http://c2.example.org/gate.php?id=1", "http://c2.example.org/gate.php?id=1", True),
        # A URL is sent as the page wrote it, and a host is the same host in capitals
        ("http://c2.example.org/gate.php", "http://C2.Example.org/gate.php", True),
        ("http://[broken", "c2.example.org", False),
        ("[2a00::1]:443", "2a00::1", True),
        ("[2a00::12]:443", "2a00::1", False),
    ],
)
def test_ioc_is(ioc, term, same):
    assert ioc_is(ioc, term) is same


@pytest.mark.parametrize(
    "status,answer,detail",
    [
        (200, body({"query_status": "illegal_search_term"}), "200: illegal_search_term"),
        (401, body({"error": "Unauthorized"}), "401: unexpected answer"),
        (200, body(["a", "list"]), "200: answer is not a JSON object"),
        # What abuse.ch sends for a key it does not know (seen 23 November 2026)
        (403, body({"query_status": "unknown_auth_key"}), "403: unknown_auth_key"),
        # A refusal or an error is not an answer, whatever its body says:
        # read as UNKNOWN it would be stored and count towards novel
        (401, body({"query_status": "no_result"}), "401: no_result"),
        (403, body({"query_status": "no_result"}), "403: no_result"),
        (429, body({"query_status": "no_result"}), "429: no_result"),
        (500, body({"query_status": "no_result"}), "500: no_result"),
        (403, body({"query_status": "ok", "data": [{"ioc": "8.8.8.8:443"}]}), "403: ok"),
        (204, body({"query_status": "no_result"}), "204: no_result"),
    ],
)
def test_threatfox_anything_else_is_failed_never_unknown(status, answer, detail):
    assert parse_threatfox(status, answer, IP) == (Verdict.FAILED, detail)


def test_threatfox_ok_without_a_list_of_iocs_is_failed_never_unknown():
    # Text where the IOCs should be holds no IOC that is the value, and that must not read as a miss
    answer = body({"query_status": "ok", "data": "not a list"})
    assert parse_threatfox(200, answer, IP)[0] is Verdict.FAILED


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
    "status,answer,detail",
    [
        (200, body({"query_status": "invalid_url"}), "200: invalid_url"),
        (401, body({"error": "Unauthorized"}), "401: unexpected answer"),
        (403, body({"query_status": "unknown_auth_key"}), "403: unknown_auth_key"),
        # As for ThreatFox: only a 200 is an answer
        (401, body({"query_status": "no_results"}), "401: no_results"),
        (403, body({"query_status": "no_results"}), "403: no_results"),
        (429, body({"query_status": "no_results"}), "429: no_results"),
        (500, body({"query_status": "ok", "url_count": "2"}), "500: ok"),
        (403, body({"query_staus": "ok", "url_count": "2"}), "403: ok"),
    ],
)
def test_urlhaus_anything_else_is_failed(status, answer, detail):
    assert parse_urlhaus(status, answer, HOST) == (Verdict.FAILED, detail)


def test_otx_is_known_only_when_the_indicator_is_in_a_pulse():
    assert parse_otx(200, OTX_HIT, IP) == (Verdict.KNOWN, "4 pulses")
    assert parse_otx(200, body({"pulse_info": {"count": 1}}), IP) == (Verdict.KNOWN, "1 pulses")
    assert parse_otx(200, OTX_MISS, IP) == (Verdict.UNKNOWN, None)


@pytest.mark.parametrize("answer", [OTX_MISS, body({"detail": "endpoint not found"}), b"<html>404</html>"])
def test_otx_not_found_is_failed_not_unknown(answer):
    # OTX answers 200 with a count of 0 for an address it has never seen. A
    # 404 is a path it could not route, and must not make an indicator novel,
    # not even when there is a count of 0 in it.
    verdict, detail = parse_otx(404, answer, IP)
    assert verdict is Verdict.FAILED
    assert detail.startswith("404: ")


@pytest.mark.parametrize(
    "status,answer",
    [
        (400, body({"detail": "Invalid IP (8.8.8.8)"})),
        (200, body({"indicator": IP})),
    ],
)
def test_otx_anything_else_is_failed_and_does_not_quote_the_feed(status, answer):
    assert parse_otx(status, answer, IP) == (Verdict.FAILED, f"{status}: unexpected answer")


def test_virustotal_is_known_only_when_an_engine_says_malicious():
    assert parse_virustotal(200, vt(5), IP) == (Verdict.KNOWN, "malicious on 5 of 95 engines")
    assert parse_virustotal(200, vt(1), IP) == (Verdict.KNOWN, "malicious on 1 of 91 engines")
    assert parse_virustotal(200, vt(0), IP) == (Verdict.UNKNOWN, None)


def test_virustotal_no_report_is_unknown():
    assert parse_virustotal(404, VT_NOT_FOUND, IP) == (Verdict.UNKNOWN, None)


def test_virustotal_a_spent_quota_is_failed_and_names_the_error():
    assert parse_virustotal(429, VT_QUOTA, IP) == (Verdict.FAILED, "429: QuotaExceededError")


@pytest.mark.parametrize(
    "status,answer,detail",
    [
        (200, body({"data": {"attributes": {}}}), "200: no analysis stats in the answer"),
        (200, body({"data": None}), "200: no analysis stats in the answer"),
        # A 404 is "no report"; a wrong key must not be read the same way
        (401, body({"error": {"code": "WrongCredentialsError"}}), "401: WrongCredentialsError"),
        (500, body({"error": "a string, not an object"}), "500: unexpected answer"),
    ],
)
def test_virustotal_anything_else_is_failed(status, answer, detail):
    assert parse_virustotal(status, answer, IP) == (Verdict.FAILED, detail)


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


@pytest.mark.parametrize(
    "feed,detail",
    [
        ("threatfox", "2 IOCs, Made-up RAT"),
        ("urlhaus", "3 URLs"),
        ("otx", "4 pulses"),
        ("virustotal", "malicious on 5 of 95 engines"),
    ],
)
def test_lookup_returns_known_for_a_hit(feed, detail):
    client, _ = make_client(HIT)
    lookup = client.lookup(feed, "ip", IP)
    assert (lookup.verdict, lookup.detail, lookup.status) == (Verdict.KNOWN, detail, 200)


@pytest.mark.parametrize("feed", FEEDS)
def test_lookup_sends_what_the_builder_built(feed):
    client, session = make_client(MISS)
    client.lookup(feed, "url", URL)
    (built,) = FEED_FUNCTIONS[feed][0]("url", URL, KEYS[feed])
    (call,) = session.calls
    assert (call["method"], call["url"]) == (built.method, built.url)
    assert (call["json"], call["data"]) == (built.json, built.data)
    # The User-Agent is a bare product name, with no contact address in it
    assert call["headers"] == {"User-Agent": "graphwatch", **built.headers}
    assert call["allow_redirects"] is False
    assert call["timeout"] > 0


@pytest.mark.parametrize(
    "answers,verdict,detail,asked",
    [
        ([(200, OTX_MISS), (200, OTX_HIT)], Verdict.KNOWN, "4 pulses", 2),
        ([(200, OTX_HIT), (200, OTX_MISS)], Verdict.KNOWN, "4 pulses", 1),
        ([(200, OTX_MISS), (200, OTX_MISS)], Verdict.UNKNOWN, None, 2),
        ([(200, OTX_MISS), (500, OTX_ERROR)], Verdict.FAILED, "500: unexpected answer", 2),
        ([(500, OTX_ERROR), (200, OTX_MISS)], Verdict.FAILED, "500: unexpected answer", 1),
    ],
)
def test_an_otx_host_is_unknown_only_when_both_sections_say_so(answers, verdict, detail, asked):
    # The second section is asked only after the first said UNKNOWN. A hit
    # ends the lookup, and so does a failure: half an answer is not UNKNOWN.
    client, session = make_client({"otx": answers})
    lookup = client.lookup("otx", "host", HOST)
    assert (lookup.verdict, lookup.detail) == (verdict, detail)
    assert [call["url"].split("/")[6] for call in session.calls] == ["hostname", "domain"][:asked]
    assert client.requests_made == asked


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectionError(f"could not reach host with key {KEYS['otx']}"),
        requests.Timeout("timed out"),
    ],
)
def test_a_network_error_is_a_failed_lookup_not_an_exception(error):
    client, _ = make_client(error=error)
    lookup = client.lookup("otx", "ip", IP)
    assert (lookup.verdict, lookup.status) == (Verdict.FAILED, None)
    # Only the kind of error: its text can quote the request
    assert lookup.detail == f"request error: {type(error).__name__}"
    # The request was made, so the budget has one fewer
    assert client.requests_made == 1


def test_lookup_refuses_a_feed_it_has_no_key_for():
    client, session = make_client(keys={"otx": "o"})
    with pytest.raises(KeyError):
        client.lookup("virustotal", "ip", IP)
    assert session.calls == []


@pytest.mark.parametrize(
    "stray_url",
    [
        "http://c2.example.org/",
        "https://not-otx.alienvault.com/",
        "https://otx.alienvault.com.evil.test/",
        "https://otx.alienvault.com@evil.test/",
    ],
)
def test_lookup_refuses_a_url_off_the_allowlist(monkeypatch, stray_url):
    from graphwatch import feeds

    def stray(kind, value, key):
        # A good request first: every URL is checked before anything is sent
        return [*otx_requests(kind, value, key), Request("GET", stray_url, {}, value)]

    monkeypatch.setitem(feeds.FEED_FUNCTIONS, "otx", (stray, parse_otx))
    client, session = make_client()
    with pytest.raises(ValueError):
        client.lookup("otx", "ip", IP)
    assert session.calls == []
    assert client.requests_made == 0


def test_no_lookup_ever_sends_a_request_to_the_indicator_itself():
    client, session = make_client(MISS)
    for feed in FEEDS:
        for kind, value in EVERY_KIND:
            client.lookup(feed, kind, value)
    hosts = {call["url"].split("/")[2] for call in session.calls}
    assert hosts <= ALLOWED_HOSTS
    assert len(hosts) == 4


@pytest.mark.parametrize("budget", [0, 1])
def test_budget_exceeded_is_raised_before_anything_is_sent(budget):
    client, session = make_client(MISS, budget=budget)
    for _ in range(budget):
        client.lookup("threatfox", "ip", IP)
    with pytest.raises(BudgetExceeded):
        client.lookup("urlhaus", "ip", IP)
    assert len(session.calls) == budget
    assert client.requests_made == budget


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


def paced_client():
    clock = Clock()
    return clock, FeedClient(KEYS, session=FeedSession(by_feed(MISS)), clock=clock, sleep=clock.sleep)


@pytest.mark.parametrize("feed,pace", [("threatfox", 1.0), ("urlhaus", 1.0), ("otx", 1.0), ("virustotal", 15.0)])
def test_each_feed_is_paced_at_its_own_rate(feed, pace):
    # VirusTotal's free tier allows 4 requests a minute. The first lookup never waits.
    clock, client = paced_client()
    for _ in range(3):
        client.lookup(feed, "ip", IP)
    assert clock.sleeps == [pace, pace]


def test_a_lookup_waits_only_for_what_is_left_of_its_own_feeds_pace():
    clock, client = paced_client()
    client.lookup("virustotal", "ip", IP)
    client.lookup("threatfox", "ip", IP)  # another feed: no wait for VirusTotal's slot
    assert clock.sleeps == []
    clock.now += 5.0  # spent on the other feeds
    client.lookup("virustotal", "ip", IP)
    assert clock.sleeps == [10.0]
    clock.now += 60.0
    client.lookup("virustotal", "ip", IP)
    assert clock.sleeps == [10.0]


def test_a_lookup_is_timed_over_all_of_its_requests():
    # Every reading of this clock is one second after the last, so each request takes one second
    ticks = itertools.count()
    rows = []
    answers = {"otx": [(200, OTX_MISS), (200, OTX_MISS)]}
    client, _ = make_client(answers, clock=lambda: float(next(ticks)), log=rows.append)
    lookup = client.lookup("otx", "host", HOST)
    assert [row["elapsed_ms"] for row in rows] == [1000, 1000]
    assert lookup.elapsed_ms == 2000


def test_every_request_writes_one_log_row_in_the_http_log_shape():
    rows = []
    client, _ = make_client({"otx": [(200, OTX_MISS), (200, OTX_HIT)]}, log=rows.append)
    client.lookup("otx", "host", HOST)
    assert len(rows) == 2
    assert set(rows[0]) == {"ts", "path", "attempt", "status", "outcome", "error", "elapsed_ms", "bytes"}
    assert [row["attempt"] for row in rows] == [1, 2]
    assert [row["outcome"] for row in rows] == ["UNKNOWN", "KNOWN"]
    assert [row["bytes"] for row in rows] == [len(OTX_MISS), len(OTX_HIT)]
    assert rows[0]["path"] == "otx:c2.example.org"
    # What a feed holds about the value is not an error
    assert [row["error"] for row in rows] == [None, None]


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


@pytest.mark.parametrize("error", [None, requests.ConnectionError("no route, sent " + " ".join(KEYS.values()))])
def test_a_key_never_appears_in_a_log_row_or_a_lookup(error):
    rows = []
    looked = []
    client, _ = make_client(MISS, error=error, log=rows.append)
    for feed in FEEDS:
        for kind, value in EVERY_KIND:
            looked.append(client.lookup(feed, kind, value))
    assert len(rows) >= len(looked) == 12
    written = json.dumps(rows) + repr(looked)
    for key in set(KEYS.values()):
        assert key not in written


# --------------------------------------------------------------------------
# what the review of 22 November found
# --------------------------------------------------------------------------


@pytest.mark.parametrize("pulse_info", [{}, {"count": "3"}, {"count": True}, {"count": 2.0}])
def test_otx_without_a_whole_number_count_is_failed(pulse_info):
    # A missing count read as 0 would store UNKNOWN, and UNKNOWN from OTX is
    # half of what makes an indicator novel.
    answer = body({"pulse_info": pulse_info})
    assert parse_otx(200, answer, IP) == (Verdict.FAILED, "200: no pulse count in the answer")


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


def test_an_ipv6_address_is_asked_for_whole_and_under_its_own_otx_section():
    address = "2a00:1450:4001::81b:2004"
    (otx,) = otx_requests("ip", address, "k")
    assert otx.url == (
        "https://otx.alienvault.com/api/v1/indicators/IPv6/2a00%3A1450%3A4001%3A%3A81b%3A2004/general"
    )
    assert threatfox_requests("ip", address, "k")[0].json["search_term"] == address
    assert urlhaus_requests("ip", address, "k")[0].data == {"host": address}
    assert virustotal_requests("ip", address, "k")[0].url.endswith("/ip_addresses/2a00%3A1450%3A4001%3A%3A81b%3A2004")


@pytest.mark.parametrize("threat", [{"kind": "malware"}, ["a", "b"], "", None])
def test_urlhaus_gives_a_text_detail_whatever_the_feed_put_in_threat(threat):
    # A dict as the detail could not be stored, and ended the whole run.
    verdict, detail = parse_urlhaus(200, body({"query_status": "ok", "threat": threat}), URL)
    assert (verdict, detail) == (Verdict.KNOWN, "listed")


def test_a_detail_that_is_not_text_is_made_text_before_it_leaves_the_client(monkeypatch):
    from graphwatch import feeds

    monkeypatch.setitem(feeds.FEED_FUNCTIONS, "otx", (otx_requests, lambda status, content, term: (Verdict.KNOWN, {"n": 3})))
    client, _ = make_client(MISS)
    assert client.lookup("otx", "ip", IP).detail == "{'n': 3}"


# --------------------------------------------------------------------------
# the key check (23 November): OTX answers a lookup whatever the key
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,outcome,detail",
    [
        (200, KeyCheck.ACCEPTED, None),
        (401, KeyCheck.REFUSED, None),
        (403, KeyCheck.REFUSED, None),
        (404, KeyCheck.FAILED, "404: unexpected answer"),
        (429, KeyCheck.FAILED, "429: unexpected answer"),
        (500, KeyCheck.FAILED, "500: unexpected answer"),
        # Only a plain 200 is a yes: not another 2xx, and not a redirect to a login page
        (204, KeyCheck.FAILED, "204: unexpected answer"),
        (302, KeyCheck.FAILED, "302: unexpected answer"),
    ],
)
def test_a_key_check_is_read_from_the_status_alone(status, outcome, detail):
    # The body describes the account and is never read, kept or logged
    assert parse_key_check(status, b"not json, and not looked at", "key check") == (outcome, detail)


@pytest.mark.parametrize(
    "status,outcome",
    [
        (200, KeyCheck.ACCEPTED),
        (403, KeyCheck.REFUSED),
        (401, KeyCheck.REFUSED),
        (500, KeyCheck.FAILED),
        (429, KeyCheck.FAILED),
        (302, KeyCheck.FAILED),
    ],
)
def test_check_key_says_whether_otx_accepted_the_key(status, outcome):
    client, session = make_client({"otx": (status, b"{}")})
    assert client.check_key("otx") is outcome
    (call,) = session.calls
    assert (call["method"], call["url"]) == ("GET", "https://otx.alienvault.com/api/v1/user/me")
    # a GET to an allowed host, with the key in a header and nowhere else
    assert call["url"].split("/")[2] in ALLOWED_HOSTS
    assert call["headers"] == {"User-Agent": "graphwatch", "X-OTX-API-KEY": KEYS["otx"]}
    assert (call["json"], call["data"]) == (None, None)
    assert call["allow_redirects"] is False
    assert client.requests_made == 1
    # the term goes into the log, so it says what was asked and nothing else
    assert otx_key_request(KEYS["otx"]).term == "key check"


def test_check_key_cannot_tell_when_the_feed_does_not_answer_or_cannot_be_read(monkeypatch):
    # Not None: that is the answer for a feed with no check, and the caller tells the two apart
    from graphwatch import feeds

    for error in (requests.Timeout("timed out"), requests.ConnectionError("reset")):
        client, _ = make_client(error=error)
        assert client.check_key("otx") is KeyCheck.FAILED

    def broken(status, content, term):
        raise TypeError("a shape no parser foresaw")

    monkeypatch.setattr(feeds, "parse_key_check", broken)
    client, _ = make_client({"otx": (200, b"{}")})
    assert client.check_key("otx") is KeyCheck.FAILED


def test_check_key_sends_nothing_where_it_has_no_check_no_key_or_no_budget():
    # The other three refuse a lookup made with a wrong key, so they need no check
    client, session = make_client()
    for feed in ("threatfox", "urlhaus", "virustotal"):
        assert client.check_key(feed) is None
    assert (session.calls, client.requests_made) == ([], 0)
    keyless, session = make_client(keys={"threatfox": "a"})
    with pytest.raises(KeyError):
        keyless.check_key("otx")
    assert session.calls == []
    spent, session = make_client(budget=0)
    with pytest.raises(BudgetExceeded):
        spent.check_key("otx")
    assert session.calls == []


@pytest.mark.parametrize(
    "stray_url",
    [
        "http://c2.example.org/",
        "https://not-otx.alienvault.com/",
        "https://otx.alienvault.com.evil.test/",
        "https://otx.alienvault.com@evil.test/",
    ],
)
def test_check_key_refuses_a_url_off_the_allowlist(monkeypatch, stray_url):
    # The key travels with this request, so it is checked like any lookup
    from graphwatch import feeds

    def stray(key):
        return Request("GET", stray_url, {"X-OTX-API-KEY": key}, "key check")

    monkeypatch.setitem(feeds.KEY_CHECKS, "otx", stray)
    client, session = make_client()
    with pytest.raises(ValueError) as refused:
        client.check_key("otx")
    assert session.calls == []
    assert client.requests_made == 0
    assert KEYS["otx"] not in str(refused.value)


@pytest.mark.parametrize(
    "status,kind",
    [
        (429, "quota"),
        (401, "refused"),
        (403, "refused"),
        (None, "transient"),
        (500, "transient"),
        (502, "transient"),
        (503, "transient"),
        (200, "other"),
        (400, "other"),
        (404, "other"),
        (499, "other"),
    ],
)
def test_failure_kind_reads_why_a_lookup_failed_from_its_status(status, kind):
    assert failure_kind(status) == kind


@pytest.mark.parametrize("status,outcome,error", [(200, "ACCEPTED", None), (403, "REFUSED", None), (500, "FAILED", "500: unexpected answer")])
def test_a_key_check_writes_one_log_row_that_names_no_key(status, outcome, error):
    rows = []
    client, _ = make_client({"otx": (status, b'{"username": "someone"}')}, log=rows.append)
    client.check_key("otx")
    (row,) = rows
    assert (row["path"], row["attempt"], row["status"]) == ("otx:key check", 1, status)
    assert (row["outcome"], row["error"]) == (outcome, error)
    assert KEYS["otx"] not in json.dumps(rows)
    # and the row fits the table the request log is kept in
    from graphwatch.db import connect, http_logger

    conn = connect(":memory:")
    http_logger(conn)(row)
    assert tuple(conn.execute("SELECT path, outcome, error FROM http_log").fetchone()) == ("otx:key check", outcome, error)
    conn.close()


