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
    MIN_TEMPLATE_CHARS,
    MIN_TEMPLATE_TITLES,
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


def test_body_of_strips_the_title_and_description_lines():
    assert body_of("Hello", "desc", "Hello\ndesc\nthe body") == "the body"


def test_body_of_matches_what_page_text_built():
    page = fixture_page("Hello-10-17-5")
    title, description, text = page_fields(page)
    assert title + "\n" + description + "\n" + body_of(title, description, text) == text


def test_body_of_keeps_newlines_inside_the_body():
    assert body_of("t", "d", "t\nd\nline one\nline two") == "line one\nline two"


def test_body_of_is_empty_for_a_page_with_no_body():
    assert body_of("t", "d", "t\nd\n") == ""


def test_body_of_treats_none_as_empty():
    assert body_of(None, None, "\n\nbody") == "body"
    assert body_of(None, None, None) == ""


def test_body_of_returns_the_text_when_the_prefix_does_not_match():
    # Never guess: a row that was not built by page_text is hashed whole.
    assert body_of("Other", "d", "Hello\nd\nbody") == "Hello\nd\nbody"


# --------------------------------------------------------------------------
# body_hash
# --------------------------------------------------------------------------


def test_body_hash_is_the_sha256_of_the_body_text():
    body = "x" * MIN_TEMPLATE_CHARS
    assert body_hash(body) == hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_body_hash_is_none_below_the_length_guard():
    assert body_hash("x" * (MIN_TEMPLATE_CHARS - 1)) is None
    assert body_hash("") is None


def test_the_length_guard_is_forty_characters():
    assert MIN_TEMPLATE_CHARS == 40


def test_the_api_sample_body_is_too_short_to_be_a_template():
    # The actor's body. It also sits under other people's API tests, so
    # without the guard the actor would take the templated penalty.
    assert body_hash(API_SAMPLE) is None


def test_the_guard_measures_the_body_text_not_the_stored_json():
    # Wrapped in its content node the same body is over 40 characters.
    page = {"title": "Hello", "description": API_SAMPLE, "content": [API_SAMPLE]}
    stored_json = json.dumps([{"tag": "p", "children": [API_SAMPLE]}])
    assert len(stored_json) >= MIN_TEMPLATE_CHARS
    assert body_hash(body_of("Hello", API_SAMPLE, page_text(page))) is None


def test_body_hash_handles_non_ascii_bodies():
    body = "Привет, это шаблон объявления, длиннее сорока символов"
    assert body_hash(body) == hashlib.sha256(body.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# templated_hashes
# --------------------------------------------------------------------------


def test_a_body_under_three_titles_is_a_template():
    pairs = [("h1", "Alpha"), ("h1", "Beta"), ("h1", "Gamma")]
    assert templated_hashes(pairs) == {"h1"}


def test_a_body_under_two_titles_is_not():
    assert templated_hashes([("h1", "Alpha"), ("h1", "Beta")]) == set()


def test_the_same_title_many_times_counts_once():
    # Ten pages of one body under one title is a busy title, not a squatter.
    assert templated_hashes([("h1", "Alpha")] * 10) == set()


def test_pages_without_a_hash_are_ignored():
    pairs = [(None, "Alpha"), (None, "Beta"), (None, "Gamma")]
    assert templated_hashes(pairs) == set()


def test_min_titles_is_three_and_can_be_changed():
    assert MIN_TEMPLATE_TITLES == 3
    pairs = [("h1", "Alpha"), ("h1", "Beta")]
    assert templated_hashes(pairs, min_titles=2) == {"h1"}


def test_templated_hashes_takes_any_iterable():
    pairs = (pair for pair in [("h1", "a"), ("h1", "b"), ("h1", "c"), ("h2", "a")])
    assert templated_hashes(pairs) == {"h1"}


# --------------------------------------------------------------------------
# classify_page: known shapes flag
# --------------------------------------------------------------------------


def test_pointer_fixture_flags():
    hits = classify_page(*page_fields(fixture_page("Hello-10-17-154")))
    assert score(hits) >= THRESHOLD
    assert "templated_body" not in names(hits)


def test_spoof_url_shape_flags():
    hits = classify_page(
        SPOOF_TITLE, API_SAMPLE, text_of(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    )
    assert score(hits) >= THRESHOLD


def test_classify_page_without_a_template_is_apply_rules():
    fields = page_fields(fixture_page("Hello-10-17-154"))
    assert names(classify_page(*fields)) == names(classify_page(*fields, None))


# --------------------------------------------------------------------------
# classify_page: benign shapes do not
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["Hello-10-17-5", "Test-10-16"])
def test_benign_fixtures_do_not_flag(name):
    hits = classify_page(*page_fields(fixture_page(name)))
    assert score(hits) < THRESHOLD


def test_an_api_test_page_does_not_flag():
    hits = classify_page("Hello", API_SAMPLE, text_of("Hello", API_SAMPLE, API_SAMPLE))
    assert score(hits) == 1


def test_a_squatter_page_takes_the_template_penalty():
    text = text_of("Cobalt-Strike", "", SQUATTER_BODY)
    digest = body_hash(body_of("Cobalt-Strike", "", text))
    hits = classify_page("Cobalt-Strike", "", text, templated(digest))
    assert names(hits) == ["telegram_link", "templated_body"]
    assert score(hits) == -3


def test_the_template_hit_carries_the_short_body_hash_as_evidence():
    hits = classify_page("t", "", "t\n\n" + "x" * 50, templated("abcdef0123456789" * 4))
    by_name = {h.rule.name: h for h in hits}
    assert by_name["templated_body"].evidence == "body abcdef012345"


def test_the_template_hit_comes_last_in_table_order():
    order = [r.name for r in RULES]
    hits = classify_page("t", "", "t\n\nsee t.me/x " + "x" * 50, templated("ab" * 32))
    assert "templated_body" in all_names(hits)
    assert [order.index(n) for n in all_names(hits)] == sorted(
        order.index(n) for n in all_names(hits)
    )


def test_a_templated_spoof_page_still_flags():
    # 5 + 1 - 2: the penalty cannot hide the decisive shape.
    text = text_of(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    hits = classify_page(SPOOF_TITLE, API_SAMPLE, text, templated("ab" * 32))
    assert score(hits) >= THRESHOLD


def test_classify_page_tolerates_none_fields():
    assert classify_page(None, None, None) == []


def test_classify_page_skips_the_penalty_when_the_table_has_no_such_rule():
    ip_literal = next(r for r in RULES if r.name == "ip_literal")
    only = (Rule("ip_literal", 1, "text", ip_literal.pattern, "x", ip_literal.check),)
    hits = classify_page("t", "", "t\n\n8.8.8.8", templated("ab" * 32), rules=only)
    assert names(hits) == ["ip_literal"]


# --------------------------------------------------------------------------
# computed_rules: the facts no regex can see
# (plan/classification-plan-2026-11-15.md)
# --------------------------------------------------------------------------


def test_every_computed_rule_in_the_table_is_one_computed_rules_can_return():
    in_table = {r.name for r in RULES if r.where == "computed"}
    assert in_table == {
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


def test_template_spam_and_templated_body_fire_together():
    text = text_of("Cobalt-Strike", "", SQUATTER_BODY)
    digest = body_hash(body_of("Cobalt-Strike", "", text))
    hits = classify_page("Cobalt-Strike", "", text, templated(digest))
    assert {"templated_body", "template_spam"} <= set(all_names(hits))


def test_the_template_penalty_and_the_template_label_are_separate_scores():
    text = text_of("Cobalt-Strike", "", SQUATTER_BODY)
    digest = body_hash(body_of("Cobalt-Strike", "", text))
    scores = category_scores(classify_page("Cobalt-Strike", "", text, templated(digest)))
    assert scores["resolver"] == -3  # as before the categories existed
    assert scores["template_spam"] == 4
    assert labels_for(scores)[0] == "template_spam"


@pytest.mark.parametrize("body", ["", "   ", "\n\n", API_SAMPLE, "x" * 19, "  " + "x" * 19 + "\n"])
def test_a_body_under_twenty_characters_holds_empty_body(body):
    assert "empty_body" in computed_rules(body)


def test_empty_body_counts_the_stripped_body_and_says_so():
    assert computed_rules("  ok \n")["empty_body"] == "2 characters"
    assert computed_rules("")["empty_body"] == "0 characters"


def test_a_body_of_twenty_characters_does_not_hold_empty_body():
    assert "empty_body" not in computed_rules("x" * 20)


def test_a_long_body_with_no_link_holds_long_text_no_link():
    held = computed_rules("word " * 601)
    assert held == {"long_text_no_link": "3,005 characters"}


def test_exactly_three_thousand_characters_is_not_long():
    assert computed_rules("x" * 3000) == {}


@pytest.mark.parametrize("link", ["https://example.com", "http://example.com", "t.me/somenews", "vless://x@y"])
def test_a_long_body_with_a_link_is_not_long_text_no_link(link):
    assert "long_text_no_link" not in computed_rules("word " * 601 + link)


def test_a_templated_long_body_holds_all_three():
    held = computed_rules("word " * 601, "ab" * 32)
    assert set(held) == {"templated_body", "template_spam", "long_text_no_link"}


def test_classify_page_adds_only_the_computed_rules_it_is_given():
    text = text_of("t", "", "x" * 50)
    assert all_names(classify_page("t", "", text, {})) == []
    assert all_names(classify_page("t", "", text, {"empty_body": "0 characters"})) == ["empty_body"]


def test_classify_page_ignores_a_computed_name_that_is_not_in_the_table():
    text = text_of("t", "", "x" * 50)
    assert classify_page("t", "", text, {"no_such_rule": "x"}) == []


def test_a_pattern_rule_cannot_be_switched_on_through_the_computed_set():
    # Only rules whose where is "computed" are added by name.
    text = text_of("t", "", "x" * 50)
    assert classify_page("t", "", text, {"ip_literal": "8.8.8.8"}) == []


def test_computed_hits_carry_their_evidence_and_one_match():
    text = text_of("t", "", "ok")
    hits = classify_page("t", "", text, computed_rules("ok"))
    hit = next(h for h in hits if h.rule.name == "empty_body")
    assert (hit.evidence, hit.matches) == ("2 characters", 1)


def test_hits_stay_in_table_order_with_several_computed_rules():
    order = [r.name for r in RULES]
    body = "see t.me/x 8.8.8.8 " + "word " * 700
    text = text_of("t", "", body)
    hits = classify_page("t", "", text, computed_rules(body, "ab" * 32))
    positions = [order.index(n) for n in all_names(hits)]
    assert positions == sorted(positions)
    assert {"templated_body", "template_spam"} <= set(all_names(hits))


def test_the_actors_api_sample_body_is_a_placeholder_and_still_a_resolver():
    # 13 characters: empty_body holds, and the resolver score does not move.
    text = text_of(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    hits = classify_page(SPOOF_TITLE, API_SAMPLE, text, computed_rules(API_SAMPLE))
    assert score(hits) == 6
    assert labels_for(category_scores(hits))[0] == "resolver"
    assert "placeholder" in labels_for(category_scores(hits))


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


def test_a_url_that_is_its_own_link_text_is_not_given_twice():
    # Telegraph turns a URL typed into the body into a link to itself.
    url = "https://example.com/page"
    content = content_of({"tag": "p", "children": [anchor(url, url)]})
    assert link_targets(content, f"t\n\n{url}\n") == []


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


@pytest.mark.parametrize("content", [None, "", "not json", "[]", json.dumps([{"tag": "a", "attrs": {"href": 7}, "children": ["x"]}])])
def test_link_targets_of_nothing_readable_is_empty(content):
    assert link_targets(content, "text") == []


def test_a_long_text_with_a_link_behind_its_words_is_not_prose():
    body = "word " * 700
    assert "long_text_no_link" in computed_rules(body)
    assert "long_text_no_link" not in computed_rules(body, None, ["https://files.example.com/setup.exe"])


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


def test_classify_page_without_links_is_what_it_was():
    text = text_of("Game", "", "Free game. Download here")
    assert all_names(classify_page("Game", "", text, {})) == all_names(classify_page("Game", "", text, {}, links=[]))


def test_a_hidden_target_that_is_the_start_of_a_longer_visible_url_is_still_given():
    # "Is the target somewhere in the text" hid https://site/a behind a
    # visible https://site/abc.
    content = content_of({"tag": "p", "children": ["see https://files.example.com/setup.exe.html ", anchor("https://files.example.com/setup.exe")]})
    text = "t\n\nsee https://files.example.com/setup.exe.html Download here\n"
    assert link_targets(content, text) == ["https://files.example.com/setup.exe"]


def test_a_visible_url_followed_by_punctuation_is_not_given_a_second_time():
    url = "https://example.com/page"
    content = content_of({"tag": "p", "children": ["see ", anchor(url, url), ", then go on"]})
    assert link_targets(content, f"t\n\nsee {url}, then go on\n") == []
