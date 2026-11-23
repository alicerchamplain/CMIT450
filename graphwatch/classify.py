"""Scoring engine: applies the rule table to a stored page (issue #29)"""

import hashlib
import json
from collections.abc import Iterable

from graphwatch.rules import (
    EMPTY_BODY_CHARS,
    LONG_TEXT_CHARS,
    RULES,
    URL_TRAILING,
    Hit,
    apply_rules,
    body_of,
)
from graphwatch.telegraph import page_links

MIN_TEMPLATE_CHARS = 40
MIN_TEMPLATE_TITLES = 3

# The computed rules: what holds for a page is worked out here, not by a regex
TEMPLATED_RULE = "templated_body"
TEMPLATE_SPAM_RULE = "template_spam"
EMPTY_BODY_RULE = "empty_body"
LONG_TEXT_RULE = "long_text_no_link"

# Text that makes a long body a page of links, not prose
LINK_MARKERS = ("://", "t.me/")


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
