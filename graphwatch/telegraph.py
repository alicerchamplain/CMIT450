"""Read-only client for the Telegraph API (api.telegra.ph)."""

import json
import re
import threading
import time
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto

import requests

BASE_URL = "https://api.telegra.ph"
ALLOWED_HOSTS = frozenset(["api.telegra.ph", "telegra.ph"])
BLOCK_TAGS = frozenset(
    ["p", "br", "li", "h3", "h4", "blockquote", "pre", "figcaption", "hr"]
)

# <meta\s+                     : the opening tag, then at least one whitespace char
# property="article:published_time" : the attribute that identifies the tag
# \s+                          : one or more whitespace chars (the modified tag has two spaces)
# content="([^"]+)"            : group 1, the timestamp: one or more chars that are not a quote
PUBLISHED_TIME_PATTERN = re.compile(
    r'<meta\s+property="article:published_time"\s+content="([^"]+)"'
)

# Same shape as PUBLISHED_TIME_PATTERN for the modified_time tag
MODIFIED_TIME_PATTERN = re.compile(
    r'<meta\s+property="article:modified_time"\s+content="([^"]+)"'
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


def parse_html_meta(
    status: int, body: bytes
) -> tuple[Outcome, dict | None, str | None]:
    """Parser to collect published_time and modified_time from telegraph pages

    Args:
        status (int): HTTP status code
        body (bytes): HTTP response body

    Returns:
        tuple[Outcome, dict | None, str | None]: Tuple with outcome result
    """

    if status == 404:
        return Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND"
    elif status != 200:
        return Outcome.FAILED, None, f"FAILED: {status}"

    try:
        html = body.decode("utf-8")
    except UnicodeDecodeError as e:
        return Outcome.FAILED, None, f"{status}: {e}"

    published_time = PUBLISHED_TIME_PATTERN.search(html)
    modified_time = MODIFIED_TIME_PATTERN.search(html)

    if published_time is None or modified_time is None:
        return Outcome.FAILED, None, "published time or modified time not found"
    else:
        published_time = published_time.group(1)
        modified_time = modified_time.group(1)
    try:
        published_time = datetime.fromisoformat(published_time).timestamp()
        modified_time = datetime.fromisoformat(modified_time).timestamp()
    except ValueError as e:
        return Outcome.FAILED, None, f"{status}: {e}"

    return (
        Outcome.FOUND,
        {"published_at": published_time, "modified_at": modified_time},
        None,
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


class PoolClosed(Exception):
    """Raised inside a call whose Pool was closed while it still had requests to make"""


class TelegraphClient:
    """Paced, allowlisted, read-only client for Telegraph's getPage method

    Every request goes through get_page, which is the only place in the
    package that touches the network. The clock, sleep function, session and
    log sink are all injectable so tests can run without waiting or connecting.

    The client may be used from several threads at once (see Pool). However
    many there are, requests start one after another, a slot apart, and the
    budget is counted once.
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
        backoff_s: float = 1.0,
        workers: int = 1,
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
            workers (int, optional): how many requests a Pool may have under way at once. With 1 nothing runs
                on another thread. More than 1 does not raise the rate: it lets the rate be reached when one
                request takes longer than a slot. Defaults to 1.
        """
        if workers < 1:
            raise ValueError("workers has to be 1 or more")
        self.rate_per_s = rate_per_s
        self.budget = budget
        if session is None:
            session = requests.Session()
            # One connection for each request that can be under way
            session.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=max(10, workers)))
        self.session = session
        self.workers = workers
        # Held while a request waits for its slot and is counted, so the
        # threads of a Pool start their requests one at a time
        self._turn = threading.Lock()
        # On a Pool's thread: the list its log rows are kept in until the
        # calling thread writes them. Not set on any other thread.
        self._held = threading.local()
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

        The next slot is counted from when this one opened, not from when
        the thread woke up: a sleep runs a little long, more so on a busy
        machine, and counting from the wake-up let every late start push all
        the later ones back (7.3 a second of 8 on the VPS, 24 November 2026).
        A slot that nobody took is not saved up: after a pause the next
        request goes at once and the slots are counted from there, so the
        requests never come faster than the rate for longer than one sleep
        ran late.
        """
        now = self.clock()
        opens = max(now, self.next_allowed)
        if opens > now:
            self.sleep(opens - now)
        self.next_allowed = opens + 1.0 / self.rate_per_s

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

    def _attempt(
        self,
        path: str,
        url: str,
        attempt: int,
        parse=parse_envelope,
        log_path: str | None = None,
    ) -> Fetch:
        """Makes one request for an already-built URL and returns it as a Fetch

        Counts against the budget, waits for the pacer, performs the GET,
        parses the envelope and writes one log row. Never raises for network
        or parse problems; those become a FAILED Fetch.

        Args:
            path (str): the Telegraph path, for the Fetch and the log row
            url (str): the full URL, already percent-encoded and host-checked
            attempt (int): 1 for the first try, counting up on retries; logged
            parse (func): parser function to use
            log_path (str): log path to use if non-default

        Returns:
            Fetch: the result of this single attempt

        Raises:
            BudgetExceeded: if requests_made has reached budget; nothing is sent
        """
        with self._turn:
            closing = getattr(self._held, "closing", None)
            if closing is not None and closing.is_set():
                # On a Pool's thread, and the caller has stopped: a call of
                # many requests, a whole crowd count, ends here and not at
                # its last one
                raise PoolClosed("the pool was closed")
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
            outcome, page, error = parse(status, body)
        except requests.RequestException as e:
            status = None
            body = b""
            outcome = Outcome.FAILED
            page = None
            error = f"request error: {e}"
        elapsed_ms = int((self.clock() - started) * 1000)
        fetch = Fetch(path, outcome, page, error, status, elapsed_ms)
        self._log_row(
            {
                "ts": time.time(),
                "path": log_path if log_path is not None else path,
                "attempt": attempt,
                "status": status,
                "outcome": outcome.name,
                "error": error,
                "elapsed_ms": elapsed_ms,
                "bytes": len(body),
            }
        )
        return fetch

    def _log_row(self, row: dict) -> None:
        """Writes one log row, or on a Pool's thread keeps it for the calling thread

        The log sink is a database connection in production, and a
        connection is only used on the thread that opened it.

        Args:
            row (dict): the log row of one request attempt
        """
        held = getattr(self._held, "rows", None)
        if held is not None:
            held.append(row)
        elif self.log is not None:
            self.log(row)

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
            fetch = self._attempt(path, url, attempt)
            if fetch.outcome is not Outcome.FAILED:
                return fetch
            if attempt <= self.retries:
                self.sleep(self.backoff_s * 2 ** (attempt - 1))
        return fetch

    def get_html(self, path: str) -> Fetch:
        """Fetches one Telegraph page's html by path and returns the outcome as a Fetch

        Args:
            path (str): Telegraph path such as Vizit-12-28, not percent-encoded

        Returns:
            Fetch: record of the request with outcome, page, error, status and timing

        Raises:
            BudgetExceeded: if the budget is reached before any attempt, or
                between retries; the refused attempt is never sent
            ValueError: if the built URL is not on an allowed host
        """
        url = f"https://telegra.ph/{urllib.parse.quote(path, safe='')}"
        self._check_host(url)
        for attempt in range(1, self.retries + 2):
            fetch = self._attempt(
                path, url, attempt, parse=parse_html_meta, log_path=f"html:{path}"
            )
            if fetch.outcome is not Outcome.FAILED:
                return fetch
            if attempt <= self.retries:
                self.sleep(self.backoff_s * 2 ** (attempt - 1))
        return fetch


class Ticket:
    """A call handed to a Pool, to be exchanged for its result"""

    def __init__(self, call, args, future=None):
        self.call = call
        self.args = args
        self.future = future  # None when the call runs on the calling thread


class Pool:
    """Runs calls that use one TelegraphClient, several at a time

    A request spends most of its time waiting for the answer, about 150 ms
    from the VPS, which is longer than the 125 ms slot of 8 requests a
    second: one request at a time cannot reach the rate. With a few under
    way at once it can. The client still starts them a slot apart and still
    counts the budget once, so a Pool reaches the rate and never passes it.

    Only the calls leave the calling thread. A call's result, the log rows
    of its requests and whatever it raised come back through result() on the
    calling thread, so the database behind the log, and everything a caller
    does with a result, stays on one thread. With a client of 1 worker no
    thread is started and each call runs when its result is asked for.
    """

    def __init__(self, client: TelegraphClient):
        """Stores the client; threads are started with the first call that needs one

        Args:
            client (TelegraphClient): the client the calls use; its workers
                attribute says how many calls may be under way at once
        """
        self.client = client
        self.workers = client.workers
        self._executor = None
        self._waiting = []  # tickets whose result has not been handed out
        self._closing = threading.Event()  # set while close() waits for what is under way

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _run(self, call, args) -> tuple[bool, object, list[dict]]:
        """On a thread of the pool: makes the call and keeps its log rows

        Returns:
            tuple[bool, object, list[dict]]: whether it returned, what it
                returned or raised, and the log rows of its requests
        """
        rows = []
        self.client._held.rows = rows
        self.client._held.closing = self._closing
        try:
            return True, call(*args), rows
        except Exception as raised:  # noqa: BLE001  raised again on the calling thread
            return False, raised, rows
        finally:
            self.client._held.rows = None
            self.client._held.closing = None

    def _write(self, rows: list[dict]) -> None:
        """On the calling thread: writes the log rows a call made"""
        if self.client.log is not None:
            for row in rows:
                self.client.log(row)

    def submit(self, call, *args) -> Ticket:
        """Hands a call to the pool

        Args:
            call: the function to call; it may use the client
            *args: its arguments

        Returns:
            Ticket: what result() takes
        """
        if self.workers == 1:
            ticket = Ticket(call, args)
        else:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(self.workers, thread_name_prefix="graphwatch")
            ticket = Ticket(call, args, self._executor.submit(self._run, call, args))
        self._waiting.append(ticket)
        return ticket

    def result(self, ticket: Ticket):
        """Waits for a call, writes its log rows and returns what it returned

        Args:
            ticket (Ticket): from submit, not yet used

        Returns:
            whatever the call returned

        Raises:
            whatever the call raised, BudgetExceeded included
        """
        if ticket.future is None:
            self._waiting.remove(ticket)
            return ticket.call(*ticket.args)
        # The ticket stays in the list until the call is back: if this wait
        # is interrupted, close() still knows the call and writes its rows
        returned, value, rows = ticket.future.result()
        self._waiting.remove(ticket)
        self._write(rows)
        if not returned:
            raise value
        return value

    def map(self, call, items):
        """Makes one call per item, several at a time, and gives the results in order

        A few items past the one being handed out are already under way,
        twice the workers at most, so a caller that stops early has asked
        for little it did not use. Every call's requests would have been made
        one by one as well.

        If a call finds the budget spent, no more are started. The results
        that were already obtained are still handed out, and BudgetExceeded
        is raised after the last of them.

        Args:
            call: function of one item
            items: iterable of items; read only as far as calls are started

        Yields:
            tuple: (item, result), in the order of items

        Raises:
            BudgetExceeded: after the last result, if any call raised it
        """
        ahead = 1 if self.workers == 1 else self.workers * 2
        window = deque()
        spent = None
        for item in items:
            window.append((item, self.submit(call, item)))
            if len(window) < ahead:
                continue
            item, ticket = window.popleft()
            try:
                value = self.result(ticket)
            except BudgetExceeded as raised:
                spent = raised
                break
            yield item, value
        for item, ticket in window:
            try:
                value = self.result(ticket)
            except BudgetExceeded as raised:
                spent = raised
                continue
            yield item, value
        if spent is not None:
            raise spent

    def close(self) -> None:
        """Ends the pool: nothing new starts, and what is under way is waited for

        A call that had not started is dropped and makes no request. One
        that had makes no further request (its next one raises PoolClosed
        inside it), is waited for, and its log rows are written, so every
        request that was sent is in the log; its result is not used.
        """
        self._closing.set()
        waiting, self._waiting = self._waiting, []
        # Everything that has not started is dropped first: while this
        # thread waited for one call, the pool's threads would start the next
        started = [
            ticket
            for ticket in waiting
            if ticket.future is not None and not ticket.future.cancel()
        ]
        for ticket in started:
            _returned, _value, rows = ticket.future.result()
            self._write(rows)
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None
        self._closing.clear()


class Ahead:
    """Fetches for a walk that knows some of the paths it is going to ask for

    A walk asks for one path at a time and decides from each answer what to
    do next, but part of what lies ahead does not depend on the answers.
    hint() takes those paths and starts fetching them; fetch() hands each
    one out when the walk gets to it. A path is only ever hinted when the
    walk is certain to ask for it, so no request is made that the walk
    would not have made.
    """

    def __init__(self, pool: Pool, call):
        """
        Args:
            pool (Pool): where the hinted paths are fetched
            call: function of a path returning a Fetch, such as client.get_page
        """
        self.pool = pool
        self.call = call
        self.tickets = {}  # path to the ticket of its fetch

    def hint(self, paths) -> None:
        """Starts fetching paths that fetch() is certain to be asked for

        Args:
            paths: iterable of paths, in the order they will be asked for;
                read only while there is room, twice the pool's workers
        """
        if self.pool.workers == 1:
            return
        room = self.pool.workers * 2 - len(self.tickets)
        client = self.pool.client
        if client.budget is not None:
            # Never more than the budget can still pay for. The threads take
            # their turns in no fixed order, and a later path must not get
            # the last request while an earlier one is refused: the walk
            # would stop at the earlier one and the later page be thrown away.
            room = min(room, client.budget - client.requests_made - len(self.tickets))
        for path in paths:
            if room <= 0:
                return
            if path not in self.tickets:
                self.tickets[path] = self.pool.submit(self.call, path)
                room -= 1

    def fetch(self, path: str) -> Fetch:
        """Fetches one path, or hands out the fetch a hint started

        Args:
            path (str): the path to fetch

        Returns:
            Fetch: as the call returns it

        Raises:
            BudgetExceeded: if the budget was spent before this path's request
        """
        ticket = self.tickets.pop(path, None)
        if ticket is None:
            return self.call(path)
        return self.pool.result(ticket)
