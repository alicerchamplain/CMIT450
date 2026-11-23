"""Tests for graphwatch.classify, the scoring engine (issue #29, shapes for #32).

Known shapes flag, benign shapes do not. Positive examples are the actor's
Hello pages (the Hello-10-17-154 fixture and title shapes from the night-1
database, held_out = 0). Nothing here reads a held-out page from known.txt.
"""

import hashlib
import json
from pathlib import Path

import pytest

from graphwatch.classify import (
    body_hash,
    body_of,
    classify_page,
    computed_rules,
    link_targets,
    templated_hashes,
)
from graphwatch.rules import (
    RULES,
    THRESHOLD,
    Rule,
    apply_rules,
    category_scores,
    labels_for,
    score,
)
from graphwatch.telegraph import page_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plan" / "fixtures"
KNOWN = {
    line.strip()
    for line in (ROOT / "known.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
}

API_SAMPLE = "Hello,+world!"
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"
# Squatter B's ad, the shape from the shape notes: one invite link three times.
SQUATTER_BODY = (
    "https://t.me/+YztOEovieQIzZjY8 exploits, malware, RATs, steallers and other "
    "stuff https://t.me/+YztOEovieQIzZjY8 https://t.me/+YztOEovieQIzZjY8"
)


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def page_fields(page: dict) -> tuple[str, str, str]:
    """(title, description, text) as add_snapshot stores them."""
    return page.get("title"), page.get("description"), page_text(page)


def text_of(title: str, description: str, body: str) -> str:
    return page_text({"title": title, "description": description, "content": [body]})


def names(hits) -> list[str]:
    """The resolver rules that fired; the category rules have their own tests."""
    return [h.rule.name for h in hits if h.rule.category == "resolver"]


def all_names(hits) -> list[str]:
    return [h.rule.name for h in hits]


def templated(digest: str) -> dict[str, str]:
    """The computed rules for a page whose body is a template and nothing else."""
    return computed_rules("x" * 100, digest)


def test_fixtures_used_here_are_not_held_out():
    for name in ("Hello-10-17-154", "Hello-10-17-5", "Test-10-16"):
        assert name not in KNOWN


# --------------------------------------------------------------------------
# body_of
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title, description, text, body",
    [
        ("Hello", "desc", "Hello\ndesc\nline one\nline two", "line one\nline two"),
        ("t", "d", "t\nd\n", ""),
        (None, None, "\n\nbody", "body"),
        (None, None, None, ""),
        # Never guess: a row that was not built by page_text is hashed whole.
        ("Other", "d", "Hello\nd\nbody", "Hello\nd\nbody"),
    ],
)
def test_body_of_is_the_text_after_its_title_and_description_lines(title, description, text, body):
    assert body_of(title, description, text) == body


def test_body_of_matches_what_page_text_built():
    page = fixture_page("Hello-10-17-5")
    title, description, text = page_fields(page)
    assert title + "\n" + description + "\n" + body_of(title, description, text) == text


# --------------------------------------------------------------------------
# body_hash
# --------------------------------------------------------------------------


@pytest.mark.parametrize("body", ["x" * 40, "Привет, это шаблон объявления, длиннее сорока символов"])
def test_body_hash_is_the_sha256_of_a_body_of_forty_characters_or_more(body):
    assert body_hash(body) == hashlib.sha256(body.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("body", ["x" * 39, "я" * 39, API_SAMPLE, ""])
def test_body_hash_is_none_for_a_body_under_forty_characters(body):
    # The API sample is the actor's body. It also sits under other people's
    # API tests, so without the guard the actor would take the templated penalty.
    assert body_hash(body) is None


# --------------------------------------------------------------------------
# templated_hashes
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pairs, templates",
    [
        ([("h1", "Alpha"), ("h1", "Beta"), ("h1", "Gamma"), ("h2", "Alpha")], {"h1"}),
        ([("h1", "Alpha"), ("h1", "Beta")], set()),
        # Ten pages of one body under one title is a busy title, not a squatter.
        ([("h1", "Alpha")] * 10, set()),
        ([(None, "Alpha"), (None, "Beta"), (None, "Gamma")], set()),
    ],
)
def test_a_body_under_three_or_more_titles_is_a_template(pairs, templates):
    # iter(): the pairs come from a database cursor, which is read once
    assert templated_hashes(iter(pairs)) == templates


def test_the_number_of_titles_that_makes_a_template_can_be_changed():
    assert templated_hashes([("h1", "Alpha"), ("h1", "Beta")], min_titles=2) == {"h1"}


# --------------------------------------------------------------------------
# classify_page: known shapes flag, benign shapes do not
# --------------------------------------------------------------------------


def test_classify_page_without_computed_rules_is_apply_rules_and_the_pointer_fixture_flags():
    fields = page_fields(fixture_page("Hello-10-17-154"))
    hits = classify_page(*fields)
    assert hits == apply_rules(*fields)
    assert score(hits) >= THRESHOLD


@pytest.mark.parametrize("name", ["Hello-10-17-5", "Test-10-16"])
def test_benign_fixtures_do_not_flag(name):
    hits = classify_page(*page_fields(fixture_page(name)))
    assert score(hits) < THRESHOLD


def test_a_squatter_page_takes_the_template_penalty_and_the_template_label():
    text = text_of("Cobalt-Strike", "", SQUATTER_BODY)
    digest = body_hash(body_of("Cobalt-Strike", "", text))
    hits = classify_page("Cobalt-Strike", "", text, templated(digest))
    assert names(hits) == ["telegram_link", "templated_body"]
    scores = category_scores(hits)
    assert scores["resolver"] == score(hits) == -3  # as before the categories existed
    assert scores["template_spam"] == 4
    assert labels_for(scores)[0] == "template_spam"


def test_a_templated_spoof_page_still_flags():
    # 5 + 1 - 2: the penalty cannot hide the decisive shape.
    text = text_of(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    hits = classify_page(SPOOF_TITLE, API_SAMPLE, text, templated("ab" * 32))
    assert score(hits) >= THRESHOLD


def test_the_actors_api_sample_body_is_a_placeholder_and_still_a_resolver():
    # 13 characters: empty_body holds, and the resolver score does not move.
    text = text_of(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    hits = classify_page(SPOOF_TITLE, API_SAMPLE, text, computed_rules(API_SAMPLE))
    assert score(hits) == 6
    assert labels_for(category_scores(hits))[0] == "resolver"
    assert "placeholder" in labels_for(category_scores(hits))


@pytest.mark.parametrize(
    "computed, added",
    [
        ({}, []),
        ({"empty_body": "0 characters"}, ["empty_body"]),
        ({"no_such_rule": "x"}, []),
        # Only rules whose where is "computed" are added by name.
        ({"ip_literal": "8.8.8.8"}, []),
    ],
)
def test_classify_page_adds_only_the_computed_rules_it_is_given_and_the_table_has(computed, added):
    text = text_of("t", "", "x" * 50)
    assert all_names(classify_page("t", "", text, computed)) == added


def test_classify_page_uses_the_table_it_is_given():
    ip_literal = next(r for r in RULES if r.name == "ip_literal")
    only = (Rule("ip_literal", 1, "text", ip_literal.pattern, "x", ip_literal.check),)
    hits = classify_page("t", "", "t\n\n8.8.8.8", templated("ab" * 32), rules=only)
    assert all_names(hits) == ["ip_literal"]


def test_classify_page_tolerates_none_fields():
    # A stored page can have no description, and a row can have no text.
    assert classify_page(None, None, None) == []


def test_computed_hits_carry_their_evidence_and_one_match():
    text = text_of("t", "", "ok")
    hits = classify_page("t", "", text, computed_rules("ok"))
    hit = next(h for h in hits if h.rule.name == "empty_body")
    assert (hit.evidence, hit.matches) == ("2 characters", 1)


def test_computed_hits_are_sorted_into_table_order():
    # templated_body stands before the category rules in the table, so a
    # computed hit added after the pattern hits has to be moved up.
    order = [r.name for r in RULES]
    body = "see t.me/+AbCdEfGh 8.8.8.8:1080 " + "word " * 700
    text = text_of("t", "", body)
    found = all_names(classify_page("t", "", text, computed_rules(body, "ab" * 32)))
    assert {"templated_body", "template_spam", "telegram_invite", "single_ip_port"} <= set(found)
    assert found == sorted(found, key=order.index)


# --------------------------------------------------------------------------
# computed_rules: the facts no regex can see
# (plan/classification-plan-2026-11-15.md)
# --------------------------------------------------------------------------


def test_the_computed_rules_in_the_table_are_the_ones_computed_rules_returns():
    in_table = {r.name for r in RULES if r.where == "computed"}
    returned = set(computed_rules("", "ab" * 32)) | set(computed_rules("x" * 3001))
    assert returned == in_table == {
        "templated_body",
        "template_spam",
        "empty_body",
        "long_text_no_link",
    }


def test_an_ordinary_body_holds_no_computed_rule():
    assert computed_rules("an ordinary body of ordinary length") == {}


def test_a_templated_body_holds_both_template_rules_with_the_same_evidence():
    held = computed_rules("x" * 100, "abcdef0123456789" * 4)
    assert held == {
        "templated_body": "body abcdef012345",
        "template_spam": "body abcdef012345",
    }


@pytest.mark.parametrize(
    "body, evidence",
    [
        ("", "0 characters"),
        ("   \n", "0 characters"),
        ("x" * 19, "19 characters"),
        ("  " + "x" * 19 + "\n", "19 characters"),
    ],
)
def test_a_body_under_twenty_characters_holds_empty_body_and_says_how_many(body, evidence):
    assert computed_rules(body) == {"empty_body": evidence}


def test_a_body_of_twenty_characters_does_not_hold_empty_body():
    assert computed_rules("x" * 20) == {}


def test_a_body_over_three_thousand_characters_with_no_link_holds_long_text_no_link():
    assert computed_rules("x" * 3001) == {"long_text_no_link": "3,001 characters"}
    assert computed_rules("x" * 3000) == {}


@pytest.mark.parametrize("link", ["https://example.com", "t.me/somenews", "vless://x@y"])
def test_a_long_body_with_a_link_is_not_long_text_no_link(link):
    assert computed_rules("word " * 601 + link) == {}


def test_a_long_text_with_a_link_behind_its_words_is_not_prose():
    assert computed_rules("word " * 700, None, ["https://files.example.com/setup.exe"]) == {}


def test_a_templated_long_body_holds_all_three():
    held = computed_rules("word " * 601, "ab" * 32)
    assert set(held) == {"templated_body", "template_spam", "long_text_no_link"}


# --------------------------------------------------------------------------
# link_targets: the addresses behind a page's links (decided 22 November)
# --------------------------------------------------------------------------


def content_of(*nodes) -> str:
    return json.dumps(list(nodes))


def anchor(href: str, text: str = "Download here") -> dict:
    return {"tag": "a", "attrs": {"href": href}, "children": [text]}


def test_link_targets_gives_the_href_the_text_does_not_show():
    content = content_of({"tag": "p", "children": ["Free game. ", anchor("https://files.example.com/setup.exe")]})
    assert link_targets(content, "t\n\nFree game. Download here\n") == ["https://files.example.com/setup.exe"]


@pytest.mark.parametrize("url", ["https://example.com/page", "https://example.com/wiki/Mercury_(planet)"])
def test_a_url_that_is_its_own_link_text_is_not_given_twice(url):
    # Telegraph turns a URL typed into the body into a link to itself.
    content = content_of({"tag": "p", "children": [anchor(url, url)]})
    assert link_targets(content, f"t\n\n{url}\n") == []


def test_a_visible_url_followed_by_punctuation_is_not_given_a_second_time():
    url = "https://example.com/page"
    content = content_of({"tag": "p", "children": ["see ", anchor(url, url), ", then go on"]})
    assert link_targets(content, f"t\n\nsee {url}, then go on\n") == []


def test_a_hidden_target_that_is_the_start_of_a_longer_visible_url_is_still_given():
    # "Is the target somewhere in the text" hid https://site/a behind a
    # visible https://site/abc.
    content = content_of({"tag": "p", "children": ["see https://files.example.com/setup.exe.html ", anchor("https://files.example.com/setup.exe")]})
    text = "t\n\nsee https://files.example.com/setup.exe.html Download here\n"
    assert link_targets(content, text) == ["https://files.example.com/setup.exe"]


def test_a_picture_or_video_on_the_page_is_not_a_link_target():
    content = content_of({"tag": "img", "attrs": {"src": "/file/abc123.jpg"}}, {"tag": "p", "children": [anchor("#top", "up")]})
    assert link_targets(content, "t\n\nup\n") == []


def test_link_targets_keeps_embeds_and_telegram_links():
    content = content_of(
        {"tag": "iframe", "attrs": {"src": "https://video.example.com/embed/1"}},
        {"tag": "p", "children": [anchor("t.me/somechannel", "channel"), anchor("tg://proxy?server=8.8.8.8", "proxy")]},
    )
    assert link_targets(content, "t\n\nchannel proxy\n") == [
        "https://video.example.com/embed/1",
        "t.me/somechannel",
        "tg://proxy?server=8.8.8.8",
    ]


def test_link_targets_gives_each_target_once_in_page_order():
    content = content_of({"tag": "p", "children": [anchor("https://b.example.com/"), anchor("https://a.example.com/"), anchor("https://b.example.com/")]})
    assert link_targets(content, "") == ["https://b.example.com/", "https://a.example.com/"]


@pytest.mark.parametrize("content", [None, "not json", "[]", json.dumps([{"tag": "a", "attrs": {"href": 7}, "children": ["x"]}])])
def test_link_targets_of_nothing_readable_is_empty(content):
    assert link_targets(content, "text") == []


def test_a_lure_with_hyperlinked_text_gets_the_file_link_and_not_prose():
    # The page the review found: a paragraph, a link behind "Download here",
    # and filler. It was labelled prose and nothing else.
    body = "Free game, full version. Download here " + "filler " * 600
    text = text_of("Game", "", body)
    links = ["https://files.example.com/setup.exe"]
    hits = classify_page("Game", "", text, computed_rules(body, None, links), links=links)
    labels = labels_for(category_scores(hits))
    assert "malware_delivery" in labels
    assert "prose" not in labels
