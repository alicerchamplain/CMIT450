"""Scoring engine: applies the rule table to a stored page (issue #29)"""

import hashlib
import json
import multiprocessing
import multiprocessing.connection
import os
import sys
import threading
import unicodedata
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

# The files of this package that a page's score is worked out by. A change to
# any of them can change a score, so their bytes are in the fingerprint
SCORING_FILES = ("classify.py", "decode.py", "rules.py", "telegraph.py")


def scoring_code(package: Path) -> str:
    """One hash of the scoring files as they are on disk in a package folder

    Args:
        package (Path): the folder that holds SCORING_FILES

    Returns:
        str: hex digest; it changes with any byte of any of the files
    """
    digest = hashlib.sha256()
    for name in SCORING_FILES:
        digest.update(name.encode("utf-8"))
        digest.update((package / name).read_bytes())
    return digest.hexdigest()


# The scoring code this process runs. It is read here, above the imports that
# load that code, and never again. A deploy that lands while the process is
# starting can then only leave this hash older than the code that was loaded,
# and an old hash is put right by the next run, which scores every page. Read
# after the imports it could be newer than the code, and old scores would be
# kept under the new code's name for good.
CODE = scoring_code(Path(__file__).parent)

from graphwatch.rules import (  # noqa: E402
    EMPTY_BODY_CHARS,
    LONG_TEXT_CHARS,
    RULES,
    URL_TRAILING,
    Hit,
    apply_rules,
    body_of,
    category_scores,
    labels_for,
    primary_label,
    score,
)
from graphwatch.telegraph import page_links  # noqa: E402

MIN_TEMPLATE_CHARS = 40
MIN_TEMPLATE_TITLES = 3

# The computed rules: what holds for a page is worked out here, not by a regex
TEMPLATED_RULE = "templated_body"
TEMPLATE_SPAM_RULE = "template_spam"
EMPTY_BODY_RULE = "empty_body"
LONG_TEXT_RULE = "long_text_no_link"

# Text that makes a long body a page of links, not prose
LINK_MARKERS = ("://", "t.me/")

# A batch smaller than this is scored in the calling process: starting the
# workers and passing the rows across costs more than it saves
POOL_MIN_ROWS = 200


def body_hash(body: str) -> str | None:
    """The sha256 of a body, used to spot one body posted under many titles

    Args:
        body (str): the body text from body_of

    Returns:
        str | None: hex digest, or None if the body is under MIN_TEMPLATE_CHARS
    """
    if len(body) < MIN_TEMPLATE_CHARS:
        return None
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def templated_hashes(
    pairs: Iterable[tuple[str | None, str | None]],
    min_titles: int = MIN_TEMPLATE_TITLES,
) -> set[str]:
    """Find the bodies that were posted under several different titles

    Args:
        pairs (Iterable[tuple[str | None, str | None]]): one (body hash, title)
            per page; pages whose hash is None are ignored
        min_titles (int, optional): how many distinct titles make a template.
            Defaults to MIN_TEMPLATE_TITLES.

    Returns:
        set[str]: the body hashes seen under min_titles or more titles
    """
    titles: dict[str, set[str | None]] = {}
    for digest, title in pairs:
        if digest is None:
            continue
        titles.setdefault(digest, set()).add(title)
    return {digest for digest, seen in titles.items() if len(seen) >= min_titles}


def link_targets(content: str | None, text: str | None) -> list[str]:
    """The link targets of a page that its text does not already show

    A link's target is stored with the content and is not in the text: the
    page says "Download here" and the address is in the href. Telegraph also
    turns a URL typed into the body into a link to itself; that one is in the
    text already and is left out, so nothing is counted twice. Only targets
    that go somewhere else are kept: /file/abc.jpg is a picture on the page.

    Args:
        content (str | None): snapshots.content, the page's nodes as JSON
        text (str | None): snapshots.text

    Returns:
        list[str]: the href and src values to show the rules, in page order,
            no repeats
    """
    if not content:
        return []
    try:
        nodes = json.loads(content)
    except json.JSONDecodeError:
        return []
    # A target is already shown only if the text has it as a whole word. A
    # plain "is it somewhere in the text" would also hide https://site/a
    # behind a visible https://site/abc.
    shown = set()
    for word in (text or "").split():
        shown.add(word)
        shown.add(word.rstrip(URL_TRAILING))
    targets = []
    for link in page_links({"content": nodes}):
        if not isinstance(link, str) or link in targets or link in shown:
            continue
        if any(marker in link for marker in LINK_MARKERS):
            targets.append(link)
    return targets


def computed_rules(body: str, templated: str | None = None, links=()) -> dict[str, str]:
    """The computed rules that hold for one page, each with its evidence

    Args:
        body (str): the body text from body_of
        templated (str | None, optional): the page's body hash if that body is
            a template, else None. Defaults to None.
        links (optional): the page's link targets from link_targets. A long
            text with a link behind its words is not prose. Defaults to none.

    Returns:
        dict[str, str]: rule name to evidence, for the rules that hold
    """
    held = {}
    if templated is not None:
        # One fact, two rules: a penalty for the resolver score and a label
        # of its own
        held[TEMPLATED_RULE] = f"body {templated[:12]}"
        held[TEMPLATE_SPAM_RULE] = f"body {templated[:12]}"
    stripped = body.strip()
    if len(stripped) < EMPTY_BODY_CHARS:
        held[EMPTY_BODY_RULE] = f"{len(stripped)} characters"
    has_link = bool(links) or any(m in body for m in LINK_MARKERS)
    if len(body) > LONG_TEXT_CHARS and not has_link:
        held[LONG_TEXT_RULE] = f"{len(body):,} characters"
    return held


def classify_page(
    title: str | None,
    description: str | None,
    text: str | None,
    computed: dict[str, str] | None = None,
    rules=RULES,
    links=(),
) -> list[Hit]:
    """Every rule hit for one page: the pattern rules plus the computed ones

    Args:
        title (str | None): snapshots.title
        description (str | None): snapshots.description
        text (str | None): snapshots.text
        computed (dict[str, str] | None, optional): the computed rules that
            hold for the page, name to evidence, from computed_rules.
            Defaults to None, which is none of them.
        rules (optional): the rules to apply. Defaults to RULES.
        links (optional): the page's link targets from link_targets, for the
            rules that read the page field. Defaults to none.

    Returns:
        list[Hit]: hits in table order; score() of this list is the resolver
            score and category_scores() gives every category's
    """
    hits = apply_rules(title, description, text, rules, links)
    if computed:
        for rule in rules:
            if rule.where == "computed" and rule.name in computed:
                hits.append(Hit(rule, computed[rule.name]))
        order = {rule.name: position for position, rule in enumerate(rules)}
        hits.sort(key=lambda hit: order[hit.rule.name])
    return hits


def fingerprint(threshold: int, code: str = CODE) -> str:
    """One hash of everything a stored score depends on besides its own page

    The scoring code this process loaded, the threshold, and the Python and
    Unicode versions, which decide what a pattern matches. cli.run_classify
    stores it when it has scored every page. While it stays the same, a page
    that has a score would get the same score again and is not scored again.
    An edit to a comment in one of the files changes it too; the cost is one
    night of scoring every page.

    Args:
        threshold (int): the score a page is flagged and a category is a
            label at
        code (str, optional): the hash of the scoring files. Defaults to
            CODE, the files this process loaded.

    Returns:
        str: hex digest
    """
    parts = f"code={code} threshold={threshold} python={sys.version} unicode={unicodedata.unidata_version}"
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


def score_snapshot(item: tuple, templated: frozenset[str], threshold: int) -> tuple:
    """Everything classify stores for one snapshot

    A function of its arguments and of the rule table only: it reads nothing
    else and writes nothing, so it gives the same answer in a worker process
    as in the caller.

    Args:
        item (tuple): snapshot id, page id, then the snapshot's title,
            description, text and content
        templated (frozenset[str]): tonight's templated body hashes, from
            templated_hashes
        threshold (int): flag at this score or above, and label a category
            at it

    Returns:
        tuple: snapshot id, page id, the resolver score, whether it is
            flagged, the body hash, the hits as (rule, weight, evidence,
            matches) and the labels as (category, score, assigned,
            is_primary). A category that scored 0 gets no label row, so a row
            with assigned False is a near miss or an excluded page.
    """
    snapshot_id, page_id, title, description, text, content = item
    body = body_of(title, description, text)
    digest = body_hash(body)
    # The addresses behind the page's links, which its text does not show
    links = link_targets(content, text)
    computed = computed_rules(body, digest if digest in templated else None, links)
    hits = classify_page(title, description, text, computed, links=links)
    # The resolver verdict, as before the categories existed
    total = score(hits)
    stored_hits = [
        (hit.rule.name, hit.rule.weight, hit.evidence, hit.matches) for hit in hits
    ]
    by_category = category_scores(hits)
    labels = labels_for(by_category, threshold)
    primary = primary_label(labels)
    stored_labels = [
        (category, value, category in labels, category == primary)
        for category, value in by_category.items()
        if value != 0
    ]
    return snapshot_id, page_id, total, total >= threshold, digest, stored_hits, stored_labels


# What a worker process was started with: see _start_worker
_WORKER: dict = {}


def _stop_with_the_parent() -> None:
    """Ends this worker when the process that started it is gone

    A worker waits on a pipe for its next batch. If the parent is killed
    (kill, or the kernel out of memory) nothing closes that pipe, and the
    worker would wait on it until the machine is restarted.
    """
    parent = multiprocessing.parent_process()
    if parent is None:
        return
    multiprocessing.connection.wait([parent.sentinel])
    os._exit(1)


def _start_worker(templated: frozenset[str], threshold: int, expected: str) -> None:
    """Runs once in each worker process, before it scores anything"""
    threading.Thread(target=_stop_with_the_parent, daemon=True).start()
    if fingerprint(threshold) != expected:
        # The worker loaded the code from disk after the caller did. If a
        # deploy landed in between, the two would score differently
        raise RuntimeError("a worker loaded other scoring code than the process that started it")
    _WORKER["templated"] = templated
    _WORKER["threshold"] = threshold


def _score_in_worker(item: tuple) -> tuple:
    return score_snapshot(item, _WORKER["templated"], _WORKER["threshold"])


class Scorer:
    """Scores batches of snapshots, in this process or spread over several

    Scoring is regex work and keeps one CPU busy; a second process uses a
    second CPU. The workers only score. Each is started as a fresh Python
    (spawn, the same on every Python version), imports the rules itself and
    is handed plain tuples, so none of them ever holds the database
    connection: reading and writing stay with the caller. The workers are
    started by the first batch big enough to be worth it.

    Use it in a with statement, which stops the workers at the end.
    """

    def __init__(self, templated: Iterable[str], threshold: int, workers: int = 1):
        self.templated = frozenset(templated)
        self.threshold = threshold
        self.workers = max(1, workers)
        self._pool: ProcessPoolExecutor | None = None

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)
            self._pool = None

    def score(self, items: list[tuple]) -> list[tuple]:
        """Score a batch

        Args:
            items (list[tuple]): one tuple per snapshot, as score_snapshot takes

        Returns:
            list[tuple]: what score_snapshot gives for each, in the same order
        """
        if self.workers == 1 or len(items) < POOL_MIN_ROWS:
            return [score_snapshot(item, self.templated, self.threshold) for item in items]
        if self._pool is None:
            self._pool = ProcessPoolExecutor(
                max_workers=self.workers,
                mp_context=multiprocessing.get_context("spawn"),
                initializer=_start_worker,
                initargs=(self.templated, self.threshold, fingerprint(self.threshold)),
            )
        # A few chunks per worker, so one slow page does not leave the others idle
        chunk = max(1, len(items) // (self.workers * 4))
        return list(self._pool.map(_score_in_worker, items, chunksize=chunk))
