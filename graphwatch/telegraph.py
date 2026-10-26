"""Read-only client for the Telegraph API (api.telegra.ph)."""

import json
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum, auto

import requests

BASE_URL = "https://api.telegra.ph"
ALLOWED_HOSTS = frozenset(["api.telegra.ph"])
BLOCK_TAGS = frozenset(
    ["p", "br", "li", "h3", "h4", "blockquote", "pre", "figcaption", "hr"]
)


class Outcome(Enum):
    """The three ways a page lookup can end"""

    FOUND = auto()
    NOT_FOUND = auto()
    FAILED = auto()


@dataclass
class Fetch:
    """
    Class for storing telegraph page fetch results
    """

    path: str  # the path to fetch
    outcome: Outcome  # the outcome of the fetch request
    page: dict | None  # the page result
    error: str | None  # API error strings
    status: int | None  # HTTP status codes
    elapsed_ms: int  # How long the fetch took


def build_path(slug: str, month: int, day: int, n: int | None = None) -> str:
    """Takes in the page slug, month, day, and post # and returns the path string like Vizit-12-28

    Args:
        slug (str): page slug
        month (int): month the post was made
        day (int): day the post was made
        n (int | None, optional): the number of the post if multiple posts with the same slug exist. Defaults to None.

    Returns:
        str: Built and padded path string like Vizit-12-28
    """
    path = f"{slug}-{month:02d}-{day:02d}"
    if n is not None:
        path = path + "-" + str(n)
    return path


def parse_envelope(status: int, body: bytes) -> tuple[Outcome, dict | None, str | None]:
    """Parses the HTTP response data and returns the outcome of the fetch

    Args:
        status (int): HTTP response status
        body (bytes): HTTP response body

    Returns:
        tuple[Outcome, dict | None, str | None]: Tuple with outcome result

    """
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return Outcome.FAILED, None, f"{status}: {e}"

    if not isinstance(data, dict):
        return Outcome.FAILED, None, "Data is not a dict"

    ok = data.get("ok")
    result = data.get("result")
    if ok is True and isinstance(result, dict):
        return Outcome.FOUND, result, None
    if ok is False and data.get("error") == "PAGE_NOT_FOUND":
        return Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND"

    return (
        Outcome.FAILED,
        None,
        data.get("error") or f"Unexpected response envelope. Status: {status}",
    )


def _node_text(node) -> str:
    """Walks DOM nodes for text, takes one node and returns a string

    Args:
        node (str | dict): Node to check for text

    Returns:
        str: found text as a string
    """

    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        pieces = []
        for child in node.get("children", []):
            pieces.append(_node_text(child))
        text = "".join(pieces)
        if node.get("tag") in BLOCK_TAGS:
            text = text + "\n"
        return text
    return ""


def _node_links(node) -> list[str]:
    """Walks DOM nodes for links, takes one node and returns a list of links in string format

    Args:
        node (str | dict): text node to check for links

    Returns:
        list[str]: list of links found in node
    """
    if isinstance(node, str):
        return []

    if isinstance(node, dict):
        links = []
        attrs = node.get("attrs", {})
        for key in ("href", "src"):
            value = attrs.get(key)
            if value:
                links.append(value)
        for child in node.get("children", []):
            links.extend(_node_links(child))
        return links
    return []


def page_text(page: dict) -> str:
    """Takes the page content as a dictionary and returns the page title, page description, and page body content as a string

    Args:
        page (dict): dictionary containing the page content

    Returns:
        str: page content in string format
    """
    pieces = []
    for block in page.get("content", []):
        pieces.append(_node_text(block))
    body = "".join(pieces)
    result = [page.get("title", ""), page.get("description", ""), body]
    return "\n".join(result)


def page_links(page: dict) -> list[str]:
    """Takes the page content as a dictionary and returns a list of the links in the page

    Args:
        page (dict): dictionary containing the page content

    Returns:
        list[str]: list of links found in page content
    """
    links = []
    for block in page.get("content", []):
        links.extend(_node_links(block))
    return links


class BudgetExceeded(Exception):
    """Raised by TelegraphClient.get_page when the request budget is spent"""


class TelegraphClient:
    """Paced, allowlisted, read-only client for Telegraph's getPage method

    Every request goes through get_page, which is the only place in the
    package that touches the network. The clock, sleep function, session and
    log sink are all injectable so tests can run without waiting or connecting.
    """

    def __init__(
        self,
        rate_per_s: float = 8.0,
        budget: int | None = None,
        session=None,
        clock=time.monotonic,
        sleep=time.sleep,
        log=None,
        user_agent: str = "graphwatch",
        retries: int = 2,
        backoff_s: float = 1.0
    ):
        """Stores the client settings and creates a requests.Session if none was given

        Args:
            rate_per_s (float, optional): maximum requests per second. Defaults to 8.0.
            budget (int | None, optional): maximum requests this client may make, or None for no limit. Defaults to None.
            session (optional): object with a requests-style get() method. Defaults to a new requests.Session.
            clock (optional): function returning monotonic seconds, used for pacing and timing. Defaults to time.monotonic.
            sleep (optional): function that blocks for the given seconds. Defaults to time.sleep.
            log (optional): callable given one dict per request attempt, or None to skip logging. Defaults to None.
            user_agent (str, optional): User-Agent header sent with every request. Defaults to "graphwatch".
            retries (int, optional): how many more attempts get_page makes after a FAILED outcome. Defaults to 2.
            backoff_s (float, optional): wait before the first retry, in seconds; doubles each retry. Defaults to 1.0.
        """
        self.rate_per_s = rate_per_s
        self.budget = budget
        self.session = session if session is not None else requests.Session()
        self.clock = clock
        self.sleep = sleep
        self.log = log
        self.user_agent = user_agent
        self.retries = retries
        self.backoff_s = backoff_s
        self.requests_made = 0
        self.next_allowed = 0.0

    def _wait_turn(self):
        """Blocks until the next request slot opens, then books the slot after it

        Slots are 1 / rate_per_s seconds apart. The first call never waits.
        """
        now = self.clock()
        wait = self.next_allowed - now
        if wait > 0:
            self.sleep(wait)
        self.next_allowed = self.clock() + 1.0 / self.rate_per_s

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

    def _attempt(self, path: str, url: str, attempt: int) -> Fetch:
        """Makes one request for an already-built URL and returns it as a Fetch

        Counts against the budget, waits for the pacer, performs the GET,
        parses the envelope and writes one log row. Never raises for network
        or parse problems; those become a FAILED Fetch.

        Args:
            path (str): the Telegraph path, for the Fetch and the log row
            url (str): the full URL, already percent-encoded and host-checked
            attempt (int): 1 for the first try, counting up on retries; logged

        Returns:
            Fetch: the result of this single attempt

        Raises:
            BudgetExceeded: if requests_made has reached budget; nothing is sent
        """
        if self.budget is not None and self.requests_made >= self.budget:
            raise BudgetExceeded(
                f"Requests Made:{self.requests_made}, Budget:{self.budget}"
            )

        self._wait_turn()
        self.requests_made += 1
        started = self.clock()
        try:
            resp = self.session.get(
                url,
                timeout=10,
                allow_redirects=False,
                headers={"User-Agent": self.user_agent},
            )
            status = resp.status_code
            body = resp.content
            outcome, page, error = parse_envelope(status, body)
        except requests.RequestException as e:
            status = None
            body = b""
            outcome = Outcome.FAILED
            page = None
            error = f"request error: {e}"
        elapsed_ms = int((self.clock() - started) * 1000)
        fetch = Fetch(path, outcome, page, error, status, elapsed_ms)
        if self.log is not None:
            self.log(
                {
                    "ts": time.time(),
                    "path": path,
                    "attempt": attempt,
                    "status": status,
                    "outcome": outcome.name,
                    "error": error,
                    "elapsed_ms": elapsed_ms,
                    "bytes": len(body),
                }
            )
        return fetch


    def get_page(self, path: str, content: bool = True) -> Fetch:
        """Fetches one Telegraph page by path and returns the outcome as a Fetch

        Builds and host-checks the URL, then calls _attempt up to retries + 1
        times. FOUND and NOT_FOUND are returned at once; a FAILED attempt is
        retried after backoff_s seconds, doubling each time, and the last
        FAILED Fetch is returned if every attempt fails. A missing page is a
        normal NOT_FOUND result; network errors and unexpected responses are
        FAILED, never exceptions. Each attempt writes its own log row.

        Args:
            path (str): Telegraph path such as Vizit-12-28, not percent-encoded
            content (bool, optional): if True, ask for the page body too. False
                only asks whether the page exists, which is cheaper and faster;
                the crowd check uses it. Defaults to True.

        Returns:
            Fetch: record of the request with outcome, page, error, status and timing

        Raises:
            BudgetExceeded: if the budget is reached before any attempt, or
                between retries; the refused attempt is never sent
            ValueError: if the built URL is not on an allowed host
        """
        url = f"{BASE_URL}/getPage/{urllib.parse.quote(path, safe='')}?return_content={'true' if content else 'false'}"
        self._check_host(url)
        for attempt in range(1, self.retries + 2):
            fetch =  self._attempt(path, url, attempt)
            if fetch.outcome is not Outcome.FAILED:
                return fetch
            if attempt <= self.retries:
                self.sleep(self.backoff_s * 2 ** (attempt - 1))
        return fetch

