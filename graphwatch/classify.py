"""Scoring engine: applies the rule table to a stored page (issue #29)"""

import hashlib
from collections.abc import Iterable

from graphwatch.rules import RULES, Hit, apply_rules

MIN_TEMPLATE_CHARS = 40
MIN_TEMPLATE_TITLES = 3
TEMPLATED_RULE = "templated_body"


def body_of(title: str | None, description: str | None, text: str | None) -> str:
    """The page body: snapshots.text without its title and description lines

    page_text builds text as title, description and body joined by newlines,
    so the body is whatever follows that prefix.

    Args:
        title (str | None): snapshots.title
        description (str | None): snapshots.description
        text (str | None): snapshots.text

    Returns:
        str: the body text, or all of text if it does not start with the prefix
    """
    text = text or ""
    prefix = f"{title or ''}\n{description or ''}\n"
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


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


def classify_page(
    title: str | None,
    description: str | None,
    text: str | None,
    templated: str | None = None,
    rules=RULES,
) -> list[Hit]:
    """Every rule hit for one page: the pattern rules plus the computed one

    Args:
        title (str | None): snapshots.title
        description (str | None): snapshots.description
        text (str | None): snapshots.text
        templated (str | None, optional): the page's body hash if that body is
            a template, else None. Defaults to None.
        rules (optional): the rules to apply. Defaults to RULES.

    Returns:
        list[Hit]: hits in table order; score() of this list is the page score
    """
    hits = apply_rules(title, description, text, rules)
    if templated is not None:
        for rule in rules:
            if rule.name == TEMPLATED_RULE:
                hits.append(Hit(rule, f"body {templated[:12]}"))
    return hits
