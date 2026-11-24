"""Read-only client for the public threat intelligence feeds (issue #38)

Every request here asks a feed what it already holds about one value, or
whether it accepts the key it is asked with. Nothing
is ever submitted for scanning: a scan would make the feed fetch the actor's
server on our behalf, and the project is passive only. This is the second
module that touches the network. It talks to the four feed hosts and nothing
else; telegraph.py talks to Telegraph and nothing else.
"""

import base64
import ipaddress
import json
import re
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum, auto

import requests

from graphwatch.telegraph import BudgetExceeded

FEEDS = ("threatfox", "urlhaus", "otx", "virustotal")

ALLOWED_HOSTS = frozenset(
    [
        "threatfox-api.abuse.ch",
        "urlhaus-api.abuse.ch",
        "otx.alienvault.com",
        "www.virustotal.com",
    ]
)

# The config.env variable that holds each feed's API key. abuse.ch gives one
# key for all of its services.
KEY_NAMES = {
    "threatfox": "ABUSE_CH_KEY",
    "urlhaus": "ABUSE_CH_KEY",
    "otx": "OTX_KEY",
    "virustotal": "VT_KEY",
}

# Seconds between two requests to the same feed. VirusTotal's free tier
# allows 4 requests a minute.
PACE_S = {"threatfox": 1.0, "urlhaus": 1.0, "otx": 1.0, "virustotal": 15.0}

# Regex for a port number on the end of a host or IP
# :       : the separator
# \d{1,5} : one to five digits
# $       : at the very end
PORT_PATTERN = re.compile(r":\d{1,5}$")


class Verdict(Enum):
    """The three ways a feed lookup can end"""

    KNOWN = auto()
    UNKNOWN = auto()
    FAILED = auto()


class KeyCheck(Enum):
    """The three ways a key check can end"""

    ACCEPTED = auto()
    REFUSED = auto()
    FAILED = auto()


# The HTTP statuses a feed answers a key it does not accept with: 401 from
# VirusTotal, 403 from abuse.ch and OTX (seen 23 November 2026)
KEY_REFUSED_STATUSES = frozenset([401, 403])


def failure_kind(status: int | None) -> str:
    """Why a lookup failed, as far as its HTTP status says

    Args:
        status (int | None): HTTP status of the failed lookup, or None if the
            feed gave no answer at all (a timeout, a dropped connection)

    Returns:
        str: "quota" for a 429; "refused" for a 401 or 403, which is a key
            the feed does not accept or a block on this address or this one
            value; "transient" for no answer or a 5xx, which may well be
            answered a minute later; "other" for an answer that will be the
            same however often it is asked for
    """
    if status == 429:
        return "quota"
    if status in KEY_REFUSED_STATUSES:
        return "refused"
    if status is None or status >= 500:
        return "transient"
    return "other"


@dataclass
class Lookup:
    """
    Class for storing the result of one feed lookup
    """

    feed: str  # the feed that was asked
    kind: str  # ip, host or url
    value: str  # the indicator that was looked up
    verdict: Verdict  # what the feed said
    detail: str | None  # what the feed holds, or why the lookup failed
    status: int | None  # HTTP status code
    elapsed_ms: int  # How long the lookup took


@dataclass(frozen=True)
class Request:
    """One HTTP request to a feed, built but not sent"""

    method: str
    url: str
    headers: dict
    term: str  # the value the feed is asked about, as it is sent
    json: dict | None = None  # a JSON body, for ThreatFox
    data: dict | None = None  # a form body, for URLhaus


def feed_keys(config: dict) -> dict[str, str]:
    """Picks the feed API keys out of the config dictionary

    Args:
        config (dict): The config dictionary from load_config

    Returns:
        dict[str, str]: feed name to key, for the feeds whose key is set
    """
    keys = {}
    for feed in FEEDS:
        value = config.get(KEY_NAMES[feed], "")
        if value:
            keys[feed] = value
    return keys


def bare_host(value: str) -> str:
    """An IP or hostname without the port that may follow it

    An IPv6 address is colons and digits all the way, so its last group is
    not a port: 2001:db8::1 is returned whole, and [2001:db8::1]:443, the
    form that does carry a port, gives the address between the brackets.
    """
    if value.startswith("["):
        return value[1:].partition("]")[0]
    try:
        if ipaddress.ip_address(value).version == 6:
            return value
    except ValueError:
        pass
    return PORT_PATTERN.sub("", value)


def threatfox_requests(kind: str, value: str, key: str) -> list[Request]:
    """Builds the ThreatFox IOC search for one indicator

    The search is a wildcard one: ThreatFox stores an address with its port,
    like 1.2.3.4:443, and the bare address has to find it. parse_threatfox
    then keeps only the IOCs that really are the address asked for.

    Args:
        kind (str): ip, host or url
        value (str): the indicator
        key (str): the abuse.ch API key

    Returns:
        list[Request]: the one request to send
    """
    term = value if kind == "url" else bare_host(value)
    return [
        Request(
            "POST",
            "https://threatfox-api.abuse.ch/api/v1/",
            {"Auth-Key": key},
            term,
            json={"query": "search_ioc", "search_term": term},
        )
    ]


def urlhaus_requests(kind: str, value: str, key: str) -> list[Request]:
    """Builds the URLhaus host or URL lookup for one indicator

    Args:
        kind (str): ip, host or url
        value (str): the indicator
        key (str): the abuse.ch API key

    Returns:
        list[Request]: the one request to send
    """
    if kind == "url":
        return [
            Request(
                "POST",
                "https://urlhaus-api.abuse.ch/v1/url/",
                {"Auth-Key": key},
                value,
                data={"url": value},
            )
        ]
    host = bare_host(value)
    return [
        Request(
            "POST",
            "https://urlhaus-api.abuse.ch/v1/host/",
            {"Auth-Key": key},
            host,
            data={"host": host},
        )
    ]


def otx_requests(kind: str, value: str, key: str) -> list[Request]:
    """Builds the OTX general lookups for one indicator

    OTX files a name under "domain" if it is a registered domain and under
    "hostname" if it is a subdomain, and the wrong one answers with no pulses
    instead of an error (checked 22 November 2026). Telling the two apart
    takes the public suffix list, so a host is asked for under both.

    Args:
        kind (str): ip, host or url
        value (str): the indicator
        key (str): the OTX API key

    Returns:
        list[Request]: the requests to try in order: one for an ip or a url,
            two for a host
    """
    if kind == "url":
        sections, term = ["url"], value
    elif kind == "ip":
        term = bare_host(value)
        sections = ["IPv6"] if ":" in term else ["IPv4"]
    else:
        sections, term = ["hostname", "domain"], bare_host(value)
    # Quoted whole: a URL with a ? in it would otherwise end the path early
    quoted = urllib.parse.quote(term, safe="")
    return [
        Request(
            "GET",
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{quoted}/general",
            {"X-OTX-API-KEY": key},
            term,
        )
        for section in sections
    ]


def virustotal_requests(kind: str, value: str, key: str) -> list[Request]:
    """Builds the VirusTotal report lookup for one indicator

    Only GET requests for a stored report. A URL is asked for by its id, the
    unpadded URL-safe base64 of the URL, which reads the report VirusTotal
    already has and does not submit the URL for a scan.

    Args:
        kind (str): ip, host or url
        value (str): the indicator
        key (str): the VirusTotal API key

    Returns:
        list[Request]: the one request to send
    """
    if kind == "url":
        url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
        term = value
        path = "urls/" + url_id.rstrip("=")
    elif kind == "ip":
        term = bare_host(value)
        path = "ip_addresses/" + urllib.parse.quote(term, safe="")
    else:
        term = bare_host(value)
        path = "domains/" + urllib.parse.quote(term, safe="")
    return [
        Request(
            "GET", f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": key}, term
        )
    ]


def otx_key_request(key: str) -> Request:
    """Builds the request that shows whether OTX accepts a key

    OTX answers a lookup with any key or none, at a lower rate limit (a 429
    after about 100 requests in an hour, seen 23 November 2026), so a wrong
    key never shows in a lookup. Its own-account endpoint answers 200 with a
    valid key and 403 without one.

    Args:
        key (str): the OTX API key

    Returns:
        Request: the one request to send
    """
    return Request(
        "GET", "https://otx.alienvault.com/api/v1/user/me", {"X-OTX-API-KEY": key}, "key check"
    )


def parse_key_check(status: int, body: bytes, term: str) -> tuple[KeyCheck, str | None]:
    """Reads the answer to a key check from its HTTP status alone

    Args:
        status (int): HTTP response status
        body (bytes): HTTP response body; not read, it describes the account
        term (str): not needed here

    Returns:
        tuple[KeyCheck, str | None]: ACCEPTED for a 200, REFUSED for a 401
            or 403, FAILED with the status for anything else
    """
    if status == 200:
        return KeyCheck.ACCEPTED, None
    if status in KEY_REFUSED_STATUSES:
        return KeyCheck.REFUSED, None
    return KeyCheck.FAILED, f"{status}: unexpected answer"


# The feeds whose key has to be checked by a request of its own, because a
# lookup does not show a wrong one. feed name: request builder
KEY_CHECKS = {"otx": otx_key_request}


def _load(status: int, body: bytes) -> tuple[dict | None, str | None]:
    """Decodes a feed's JSON answer

    Returns:
        tuple[dict | None, str | None]: the JSON object, or None and the reason
    """
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return None, f"{status}: {e}"
    if not isinstance(data, dict):
        return None, f"{status}: answer is not a JSON object"
    return data, None


def ioc_is(ioc: str, term: str) -> bool:
    """Checks if an IOC a wildcard search returned is the address that was asked for

    Searching for 1.2.3.4 also returns 1.2.3.40:443 and 11.2.3.4. An IOC is
    the address when it is the term itself, the term with a port, or a URL
    on that host.

    Args:
        ioc (str): the IOC as ThreatFox stores it
        term (str): the search term that was sent

    Returns:
        bool: True if the IOC is about the term and not a longer value
    """
    ioc = ioc.lower()
    term = term.lower()
    if ioc == term or bare_host(ioc) == term:
        return True
    if "://" in ioc:
        try:
            return urllib.parse.urlsplit(ioc).hostname == term
        except ValueError:
            return False
    return False


def parse_threatfox(status: int, body: bytes, term: str) -> tuple[Verdict, str | None]:
    """Parses a ThreatFox search answer

    The no-hit status, "no_result", is not in the API's documentation. If
    ThreatFox words it differently the lookup comes back FAILED and is not
    stored, so a wrong guess here can never count an indicator as novel.

    Args:
        status (int): HTTP response status
        body (bytes): HTTP response body
        term (str): the search term that was sent

    Returns:
        tuple[Verdict, str | None]: KNOWN with the number of matching IOCs
            and the first one's malware name, UNKNOWN for no result or only
            longer values, FAILED with the reason for anything else
    """
    data, error = _load(status, body)
    if data is None:
        return Verdict.FAILED, error
    query_status = data.get("query_status")
    if status != 200:
        # ThreatFox answers a hit and a miss with 200 (seen 23 November 2026).
        # Anything else is a refusal or an error, whatever its body says
        return Verdict.FAILED, f"{status}: {query_status or 'unexpected answer'}"
    if query_status == "no_result":
        return Verdict.UNKNOWN, None
    iocs = data.get("data")
    if query_status != "ok" or not isinstance(iocs, list):
        return Verdict.FAILED, f"{status}: {query_status or 'unexpected answer'}"
    matching = [
        ioc
        for ioc in iocs
        if isinstance(ioc, dict) and ioc_is(str(ioc.get("ioc", "")), term)
    ]
    if not matching:
        return Verdict.UNKNOWN, None
    detail = f"{len(matching)} IOCs"
    if matching[0].get("malware_printable"):
        detail += f", {matching[0]['malware_printable']}"
    return Verdict.KNOWN, detail


def parse_urlhaus(status: int, body: bytes, term: str) -> tuple[Verdict, str | None]:
    """Parses a URLhaus host or URL answer

    Args:
        status (int): HTTP response status
        body (bytes): HTTP response body
        term (str): the host or URL that was asked about; not needed here

    Returns:
        tuple[Verdict, str | None]: KNOWN with the number of URLs on the host
            or the URL's threat, UNKNOWN for no results, FAILED with the
            reason for anything else
    """
    data, error = _load(status, body)
    if data is None:
        return Verdict.FAILED, error
    # The documentation's sample host answer spells the key query_staus
    query_status = data.get("query_status") or data.get("query_staus")
    if status != 200:
        # As for ThreatFox: a hit and a miss are both a 200
        return Verdict.FAILED, f"{status}: {query_status or 'unexpected answer'}"
    if query_status == "no_results":
        return Verdict.UNKNOWN, None
    if query_status == "ok":
        if data.get("url_count") is not None:
            return Verdict.KNOWN, f"{data['url_count']} URLs"
        threat = data.get("threat")
        return Verdict.KNOWN, threat if isinstance(threat, str) and threat else "listed"
    return Verdict.FAILED, f"{status}: {query_status or 'unexpected answer'}"


def parse_otx(status: int, body: bytes, term: str) -> tuple[Verdict, str | None]:
    """Parses an OTX general answer

    OTX answers for almost any address, so the indicator is only known when
    someone put it in a pulse.

    Args:
        status (int): HTTP response status
        body (bytes): HTTP response body
        term (str): the address that was asked about; not needed here

    Returns:
        tuple[Verdict, str | None]: KNOWN with the number of pulses, UNKNOWN
            for a count of 0, FAILED with the reason for anything else, a
            404 included
    """
    data, error = _load(status, body)
    if data is None:
        return Verdict.FAILED, error
    pulse_info = data.get("pulse_info")
    # OTX answers 200 with a pulse count of 0 for an address it has never
    # seen (checked 22 November 2026). A 404 is a path it could not route,
    # not an answer about the address, so it is FAILED like anything else
    # that is not a 200 with a count in it.
    if status != 200 or not isinstance(pulse_info, dict):
        # OTX's own error text quotes the value, so only the status is kept
        return Verdict.FAILED, f"{status}: unexpected answer"
    count = pulse_info.get("count")
    if isinstance(count, bool) or not isinstance(count, int):
        return Verdict.FAILED, f"{status}: no pulse count in the answer"
    if count > 0:
        return Verdict.KNOWN, f"{count} pulses"
    return Verdict.UNKNOWN, None


def parse_virustotal(status: int, body: bytes, term: str) -> tuple[Verdict, str | None]:
    """Parses a VirusTotal report answer

    VirusTotal has a report for almost any address, so the indicator is only
    known when at least one engine calls it malicious.

    Args:
        status (int): HTTP response status
        body (bytes): HTTP response body
        term (str): the address that was asked about; not needed here

    Returns:
        tuple[Verdict, str | None]: KNOWN with the engine count, UNKNOWN for
            a clean report or no report, FAILED with the reason for anything
            else, a spent quota (429) included
    """
    if status == 404:
        return Verdict.UNKNOWN, None
    data, error = _load(status, body)
    if data is None:
        return Verdict.FAILED, error
    if status != 200:
        code = (data.get("error") or {}).get("code") if isinstance(data.get("error"), dict) else None
        return Verdict.FAILED, f"{status}: {code or 'unexpected answer'}"
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        engines = sum(int(count) for count in stats.values())
    except (KeyError, TypeError, ValueError, AttributeError):
        return Verdict.FAILED, f"{status}: no analysis stats in the answer"
    if malicious > 0:
        return Verdict.KNOWN, f"malicious on {malicious} of {engines} engines"
    return Verdict.UNKNOWN, None


# feed name: (request builder, answer parser)
FEED_FUNCTIONS = {
    "threatfox": (threatfox_requests, parse_threatfox),
    "urlhaus": (urlhaus_requests, parse_urlhaus),
    "otx": (otx_requests, parse_otx),
    "virustotal": (virustotal_requests, parse_virustotal),
}


class FeedClient:
    """Paced, allowlisted client for the four feeds: it looks up, and it checks a key

    Every request goes through lookup or check_key, and then _send. The clock, sleep function,
    session and log sink are all injectable so tests can run without waiting
    or connecting.
    """

    def __init__(
        self,
        keys: dict[str, str],
        budget: int | None = None,
        session=None,
        clock=time.monotonic,
        sleep=time.sleep,
        log=None,
        user_agent: str = "graphwatch",
        pace_s: dict[str, float] | None = None,
    ):
        """Stores the client settings and creates a requests.Session if none was given

        Args:
            keys (dict[str, str]): feed name to API key, from feed_keys. A feed with no key is never asked.
            budget (int | None, optional): maximum requests this client may make, or None for no limit. Defaults to None.
            session (optional): object with a requests-style request() method. Defaults to a new requests.Session.
            clock (optional): function returning monotonic seconds, used for pacing and timing. Defaults to time.monotonic.
            sleep (optional): function that blocks for the given seconds. Defaults to time.sleep.
            log (optional): callable given one dict per request, or None to skip logging. Defaults to None.
            user_agent (str, optional): User-Agent header sent with every request. Defaults to "graphwatch".
            pace_s (dict[str, float] | None, optional): seconds between two requests to the same feed. Defaults to PACE_S.
        """
        self.keys = dict(keys)
        self.budget = budget
        self.session = session if session is not None else requests.Session()
        self.clock = clock
        self.sleep = sleep
        self.log = log
        self.user_agent = user_agent
        self.pace_s = dict(pace_s if pace_s is not None else PACE_S)
        self.requests_made = 0
        self.next_allowed = {}

    def feeds(self) -> list[str]:
        """The feeds this client can ask: the ones it has a key for, in FEEDS order"""
        return [feed for feed in FEEDS if feed in self.keys]

    def _wait_turn(self, feed: str):
        """Blocks until the feed's next request slot opens, then books the slot after it"""
        now = self.clock()
        wait = self.next_allowed.get(feed, 0.0) - now
        if wait > 0:
            self.sleep(wait)
        self.next_allowed[feed] = self.clock() + self.pace_s[feed]

    def _check_host(self, url: str) -> None:
        """Checks if url is in allowed hosts list

        Args:
            url (str): url to check

        Raises:
            ValueError: error if host not in allowed hosts
        """
        host = urllib.parse.urlparse(url).hostname
        if host not in ALLOWED_HOSTS:
            raise ValueError(f"Host {host} not in allowed hosts")

    def _send(
        self, feed: str, request: Request, parse, attempt: int
    ) -> tuple[Verdict | KeyCheck, str | None, int | None, int]:
        """Sends one built request and returns what the feed said

        Counts against the budget, waits for the feed's pacer, sends the
        request, parses the answer and writes one log row. Never raises for
        network or parse problems; those become a FAILED verdict.

        Args:
            feed (str): the feed being asked, for the pacer and the log row
            request (Request): the request to send, already host-checked
            parse (func): the feed's answer parser, or parse_key_check
            attempt (int): 1 for the first request of a lookup, counting up; logged

        Returns:
            tuple[Verdict | KeyCheck, str | None, int | None, int]: what the
                parser made of the answer (FAILED if there was none),
                detail, HTTP status and elapsed milliseconds

        Raises:
            BudgetExceeded: if requests_made has reached budget; nothing is sent
        """
        if self.budget is not None and self.requests_made >= self.budget:
            raise BudgetExceeded(
                f"Requests Made:{self.requests_made}, Budget:{self.budget}"
            )

        self._wait_turn(feed)
        self.requests_made += 1
        started = self.clock()
        try:
            resp = self.session.request(
                request.method,
                request.url,
                headers={"User-Agent": self.user_agent, **request.headers},
                json=request.json,
                data=request.data,
                timeout=20,
                allow_redirects=False,
            )
            status = resp.status_code
            body = resp.content
        except requests.RequestException as e:
            status = None
            body = b""
            verdict = Verdict.FAILED
            # Only the kind of error: its text can quote the request
            detail = f"request error: {type(e).__name__}"
        else:
            try:
                verdict, detail = parse(status, body, request.term)
            except Exception as e:  # noqa: BLE001  an answer no parser foresaw
                # A feed can change the shape of its answer. That must end
                # one lookup as FAILED, logged, not the whole run
                verdict = Verdict.FAILED
                detail = f"{status}: unexpected answer ({type(e).__name__})"
            if detail is not None and not isinstance(detail, str):
                # The detail is stored and printed; whatever a feed put there, it is text
                detail = str(detail)
        elapsed_ms = int((self.clock() - started) * 1000)
        if self.log is not None:
            self.log(
                {
                    "ts": time.time(),
                    "path": f"{feed}:{request.term}",
                    "attempt": attempt,
                    "status": status,
                    "outcome": verdict.name,
                    # FAILED by name: a key check has an outcome of its own kind
                    "error": detail if verdict.name == "FAILED" else None,
                    "elapsed_ms": elapsed_ms,
                    "bytes": len(body),
                }
            )
        return verdict, detail, status, elapsed_ms

    def check_key(self, feed: str) -> KeyCheck | None:
        """Asks a feed whether it accepts its key, where a lookup would not show it

        Only OTX needs this. The other feeds refuse a lookup made with a
        wrong key (see KEY_REFUSED_STATUSES), so for them nothing is sent.

        Args:
            feed (str): one of FEEDS

        Returns:
            KeyCheck | None: ACCEPTED or REFUSED as the feed said, FAILED if
                the check got no clear answer, and None for a feed that has
                no check of its own

        Raises:
            BudgetExceeded: if the budget is reached; nothing is sent
            KeyError: if the feed has a check and the client has no key for it
            ValueError: if the built URL is not on an allowed host
        """
        build = KEY_CHECKS.get(feed)
        if build is None:
            return None
        request = build(self.keys[feed])
        self._check_host(request.url)
        outcome, _detail, _status, _elapsed_ms = self._send(feed, request, parse_key_check, 1)
        if outcome in (KeyCheck.ACCEPTED, KeyCheck.REFUSED):
            return outcome
        # No answer, or one no parser foresaw: _send calls both FAILED
        return KeyCheck.FAILED

    def lookup(self, feed: str, kind: str, value: str) -> Lookup:
        """Asks one feed what it holds about one indicator

        Most lookups are one request. Where a feed files the same value under
        two names, the requests are sent in turn until one says KNOWN or one
        fails; the indicator is UNKNOWN only if every one said so.

        Args:
            feed (str): one of FEEDS, with a key in this client
            kind (str): ip, host or url
            value (str): the indicator

        Returns:
            Lookup: the feed's verdict with its detail, status and timing

        Raises:
            BudgetExceeded: if the budget is reached before any request, or
                between two; the refused request is never sent
            KeyError: if the client has no key for the feed
            ValueError: if a built URL is not on an allowed host
        """
        build, parse = FEED_FUNCTIONS[feed]
        built = build(kind, value, self.keys[feed])
        for request in built:
            self._check_host(request.url)
        total_ms = 0
        for attempt, request in enumerate(built, start=1):
            verdict, detail, status, elapsed_ms = self._send(feed, request, parse, attempt)
            total_ms += elapsed_ms
            if verdict is not Verdict.UNKNOWN:
                break
        return Lookup(feed, kind, value, verdict, detail, status, total_ms)
