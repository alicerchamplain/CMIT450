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
    templated_hashes,
)
from graphwatch.rules import RULES, THRESHOLD, Rule, score
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
    return [h.rule.name for h in hits]


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
    hits = classify_page("Cobalt-Strike", "", text, digest)
    assert names(hits) == ["telegram_link", "templated_body"]
    assert score(hits) == -3


def test_the_template_hit_carries_the_short_body_hash_as_evidence():
    hits = classify_page("t", "", "t\n\n" + "x" * 50, "abcdef0123456789" * 4)
    assert hits[-1].rule.name == "templated_body"
    assert hits[-1].evidence == "body abcdef012345"


def test_the_template_hit_comes_last_in_table_order():
    order = [r.name for r in RULES]
    hits = classify_page("t", "", "t\n\nsee t.me/x " + "x" * 50, "ab" * 32)
    assert [order.index(n) for n in names(hits)] == sorted(
        order.index(n) for n in names(hits)
    )


def test_a_templated_spoof_page_still_flags():
    # 5 + 1 - 2: the penalty cannot hide the decisive shape.
    text = text_of(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    hits = classify_page(SPOOF_TITLE, API_SAMPLE, text, "ab" * 32)
    assert score(hits) >= THRESHOLD


def test_classify_page_tolerates_none_fields():
    assert classify_page(None, None, None) == []


def test_classify_page_skips_the_penalty_when_the_table_has_no_such_rule():
    ip_literal = next(r for r in RULES if r.name == "ip_literal")
    only = (Rule("ip_literal", 1, "text", ip_literal.pattern, "x", ip_literal.check),)
    hits = classify_page("t", "", "t\n\n8.8.8.8", "ab" * 32, rules=only)
    assert names(hits) == ["ip_literal"]
