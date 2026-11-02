"""Tests for graphwatch.redact.

Nothing here touches the network or the disk except the fixtures under
plan/fixtures, which are the redacted form of real pages and so must come
back from redaction unchanged. The HMAC key is any fixed bytes: the tests
check the shape and stability of tokens, never a particular digest.
"""

import copy
import json
import re
from pathlib import Path

import pytest

from graphwatch.redact import MARKER, hash_secret, is_card, redact_page, redact_text
from graphwatch.telegraph import page_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plan" / "fixtures"

KEY = b"test-key"
OTHER_KEY = b"other-key"

TOKEN = re.compile(r"SECRET\{[0-9a-f]{64}\}")


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def tokens(s: str) -> list[str]:
    return TOKEN.findall(s)


# --- hash_secret -----------------------------------------------------------


def test_marker_is_the_token_prefix():
    assert hash_secret("x", KEY).startswith(MARKER)


def test_hash_secret_is_marker_plus_full_hex_digest_in_braces():
    assert TOKEN.fullmatch(hash_secret("hunter2", KEY))


def test_hash_secret_is_deterministic_for_the_same_key():
    assert hash_secret("hunter2", KEY) == hash_secret("hunter2", KEY)


def test_hash_secret_differs_between_inputs():
    assert hash_secret("hunter2", KEY) != hash_secret("hunter3", KEY)


def test_hash_secret_is_keyed():
    # Without the key the database alone cannot be matched against a wordlist.
    assert hash_secret("hunter2", KEY) != hash_secret("hunter2", OTHER_KEY)


def test_hash_secret_handles_non_ascii():
    assert TOKEN.fullmatch(hash_secret("пароль", KEY))


# --- is_card ---------------------------------------------------------------


@pytest.mark.parametrize(
    "digits",
    [
        "4111111111111111",  # Visa test number
        "5555555555554444",  # Mastercard test number
        "378282246310005",  # Amex test number, 15 digits
        "6011111111111117",  # Discover test number
    ],
)
def test_is_card_accepts_luhn_valid_numbers(digits):
    assert is_card(digits) is True


@pytest.mark.parametrize(
    "digits",
    [
        "4111111111111112",  # one digit off
        "1234567890123456",
        "0000000000000001",
    ],
)
def test_is_card_rejects_luhn_invalid_numbers(digits):
    assert is_card(digits) is False


def test_is_card_rejects_short_runs_even_when_luhn_valid():
    # 79927398713 is the Wikipedia Luhn example: valid checksum, 11 digits.
    assert is_card("79927398713") is False
    assert is_card("") is False


# --- storage keys in /! structures -----------------------------------------

RAW_HELLO_TITLE = (
    "198.13.32.106?rakuten.ne.jp@opportunizz.pro"
    "/!VzQ3NktFUDh0Tm5qdHZSdw==?T0lpc01IOHdHdGhzNjltOWJBR2Z3MTVNcU14NjdsdTJnNW1Oa3RiaA=="
    "?dGViaQ==?eWVsNA=="
)


def test_storage_keys_hashes_the_first_two_fields_only():
    out = redact_text(RAW_HELLO_TITLE, KEY)
    head, _, tail = out.partition("/!")
    fields = tail.split("?")
    assert head == "198.13.32.106?rakuten.ne.jp@opportunizz.pro"
    assert len(fields) == 4
    assert TOKEN.fullmatch(fields[0])
    assert TOKEN.fullmatch(fields[1])
    assert fields[2:] == ["dGViaQ==", "eWVsNA=="]


def test_storage_keys_pointer_parts_survive():
    out = redact_text(RAW_HELLO_TITLE, KEY)
    for part in ("198.13.32.106", "rakuten.ne.jp", "opportunizz.pro", "/!", "dGViaQ==", "eWVsNA=="):
        assert part in out


def test_storage_keys_raw_keys_are_gone():
    out = redact_text(RAW_HELLO_TITLE, KEY)
    assert "VzQ3NktFUDh0Tm5qdHZSdw==" not in out
    assert "T0lpc01IOHdHdGhzNjltOWJBR2Z3MTVNcU14NjdsdTJnNW1Oa3RiaA==" not in out


def test_storage_keys_same_key_gives_same_token_across_pages():
    a = redact_text("host/!AAAA?BBBB?c", KEY)
    b = redact_text("other/!AAAA?ZZZZ?d", KEY)
    assert tokens(a)[0] == tokens(b)[0]
    assert tokens(a)[1] != tokens(b)[1]


def test_storage_keys_with_one_field_hashes_it():
    out = redact_text("x/!onlyone", KEY)
    assert out == "x/!" + hash_secret("onlyone", KEY)


def test_storage_keys_with_two_fields_hashes_both():
    out = redact_text("x/!a?b", KEY)
    assert out == "x/!" + hash_secret("a", KEY) + "?" + hash_secret("b", KEY)


def test_storage_keys_stops_at_whitespace():
    out = redact_text("x/!a?b?c next", KEY)
    assert out.endswith("?c next")


def test_storage_keys_already_hashed_fields_are_left_alone():
    once = redact_text(RAW_HELLO_TITLE, KEY)
    assert redact_text(once, KEY) == once


# --- email:password ---------------------------------------------------------


def test_email_password_hashes_the_password():
    out = redact_text("login bob.smith@mail.ru:Qwerty123! next", KEY)
    assert out == "login bob.smith@mail.ru:" + hash_secret("Qwerty123!", KEY) + " next"


def test_email_password_requires_a_colon_right_after_the_domain():
    # The Vizit pointer has an @ but a slash follows the host: not a credential.
    s = "https://www.rapid7.com@dust1d9b.boj9h7vg.workers.dev/digitately"
    assert redact_text(s, KEY) == s


def test_email_without_password_is_untouched():
    s = "contact bob@example.com for details"
    assert redact_text(s, KEY) == s


def test_email_password_is_idempotent():
    once = redact_text("bob@example.com:secret", KEY)
    assert redact_text(once, KEY) == once


# --- labelled passwords ------------------------------------------------------


@pytest.mark.parametrize(
    "label, sep",
    [
        ("password", ": "),
        ("Password", "="),
        ("PASS", " = "),
        ("passwd", ":"),
        ("pwd", ": "),
        ("пароль", ": "),
        ("Пароль", ":"),
    ],
)
def test_labelled_password_hashes_the_value_and_keeps_the_label(label, sep):
    out = redact_text(f"{label}{sep}hunter2", KEY)
    assert out == f"{label}{sep}" + hash_secret("hunter2", KEY)


def test_labelled_password_only_hashes_to_the_next_whitespace():
    out = redact_text("password: hunter2 login: bob", KEY)
    assert out == "password: " + hash_secret("hunter2", KEY) + " login: bob"


def test_labelled_password_does_not_match_inside_other_words():
    s = "passport 123 and bypass: route"
    # "passport" has no separator after "pass"; "bypass" starts mid-word.
    assert redact_text(s, KEY) == s


def test_labelled_password_is_idempotent():
    once = redact_text("пароль: hunter2", KEY)
    assert redact_text(once, KEY) == once


# --- card numbers -------------------------------------------------------------


@pytest.mark.parametrize(
    "formatted",
    ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111"],
)
def test_card_hashes_luhn_valid_numbers_by_their_bare_digits(formatted):
    out = redact_text(f"card {formatted} end", KEY)
    assert out == "card " + hash_secret("4111111111111111", KEY) + " end"


def test_card_formatting_does_not_change_the_token():
    a = redact_text("4111 1111 1111 1111", KEY)
    b = redact_text("4111-1111-1111-1111", KEY)
    assert a == b


def test_card_leaves_luhn_invalid_runs_alone():
    s = "order 4111 1111 1111 1112 shipped"
    assert redact_text(s, KEY) == s


def test_card_leaves_phone_numbers_alone():
    s = "call +7 916 123 45 67 or 89161234567"
    assert redact_text(s, KEY) == s


def test_card_leaves_short_luhn_valid_runs_alone():
    s = "id 79927398713"
    assert redact_text(s, KEY) == s


# --- fixed-shape tokens --------------------------------------------------------


def test_telegram_bot_token_is_hashed_whole():
    tok = "123456789:AAHfiqksKZ8WmR2zSjiQ7_v4TMAKdiHm9T0"
    out = redact_text(f"bot {tok} ok", KEY)
    assert out == "bot " + hash_secret(tok, KEY) + " ok"


def test_aws_key_id_is_hashed_whole():
    out = redact_text("key AKIAIOSFODNN7EXAMPLE x", KEY)
    assert out == "key " + hash_secret("AKIAIOSFODNN7EXAMPLE", KEY) + " x"


@pytest.mark.parametrize("prefix", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
def test_github_tokens_are_hashed_whole(prefix):
    tok = prefix + "a" * 36
    assert redact_text(tok, KEY) == hash_secret(tok, KEY)


def test_short_hex_pointer_is_not_a_token():
    # ki06's armed placeholder: a pointer the classifier needs intact.
    assert redact_text("4313b32b3805", KEY) == "4313b32b3805"


def test_long_base64_is_not_a_token():
    # No generic base64 rule: encoded pointers must survive.
    s = "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRoL3RvL3Jlc291cmNl"
    assert redact_text(s, KEY) == s


# --- redact_text in general -------------------------------------------------------


def test_redact_text_empty_string():
    assert redact_text("", KEY) == ""


def test_redact_text_plain_text_is_unchanged():
    s = "Hello,+world!\nIS TIHSaaaaaaaaaaaaaaaaaaaaaaaa"
    assert redact_text(s, KEY) == s


def test_redact_text_applies_every_rule_in_one_pass():
    s = "pw password: hunter2 mail b@c.ru:Qwerty! card 4111111111111111 aws AKIAIOSFODNN7EXAMPLE"
    out = redact_text(s, KEY)
    assert len(tokens(out)) == 4
    for raw in ("hunter2", "Qwerty!", "4111111111111111", "AKIAIOSFODNN7EXAMPLE"):
        assert raw not in out


# --- redact_page -------------------------------------------------------------------


def test_redact_page_redacts_title_description_and_content():
    page = {
        "path": "x-01-01",
        "title": "password: a",
        "description": "password: b",
        "content": [{"tag": "p", "children": ["password: c"]}],
    }
    out = redact_page(page, KEY)
    assert out["title"] == "password: " + hash_secret("a", KEY)
    assert out["description"] == "password: " + hash_secret("b", KEY)
    assert out["content"][0]["children"][0] == "password: " + hash_secret("c", KEY)


def test_redact_page_does_not_mutate_its_input():
    page = {
        "path": "x-01-01",
        "title": "password: a",
        "description": None,
        "content": [{"tag": "p", "children": [{"tag": "b", "children": ["password: c"]}]}],
    }
    before = copy.deepcopy(page)
    redact_page(page, KEY)
    assert page == before


def test_redact_page_returns_new_containers():
    page = {"title": "t", "content": [{"tag": "p", "children": ["x"]}]}
    out = redact_page(page, KEY)
    assert out is not page
    assert out["content"] is not page["content"]
    assert out["content"][0] is not page["content"][0]


def test_redact_page_recurses_into_nested_children():
    page = {
        "content": [
            {
                "tag": "p",
                "children": [
                    "plain ",
                    {"tag": "a", "attrs": {"href": "u"}, "children": ["password: deep"]},
                ],
            }
        ]
    }
    out = redact_page(page, KEY)
    link = out["content"][0]["children"][1]
    assert link["tag"] == "a"
    assert link["attrs"] == {"href": "u"}
    assert link["children"] == ["password: " + hash_secret("deep", KEY)]
    assert out["content"][0]["children"][0] == "plain "


def test_redact_page_leaves_childless_nodes_as_they_are():
    page = {"content": [{"tag": "br"}, {"tag": "hr"}]}
    out = redact_page(page, KEY)
    assert out["content"] == [{"tag": "br"}, {"tag": "hr"}]


def test_redact_page_tolerates_missing_or_null_title_and_description():
    out = redact_page({"title": None, "content": []}, KEY)
    assert out["title"] is None
    assert out["content"] == []
    out = redact_page({"content": []}, KEY)
    assert out.get("title") is None
    assert out.get("description") is None


def test_redact_page_keeps_other_fields():
    page = {"path": "x-01-01", "url": "u", "views": 7, "author_name": "n", "content": []}
    out = redact_page(page, KEY)
    for k in ("path", "url", "views", "author_name"):
        assert out[k] == page[k]


def test_redact_page_text_has_no_raw_keys():
    page = {"title": RAW_HELLO_TITLE, "description": "Hello,+world!", "content": [{"tag": "p", "children": ["Hello,+world!"]}]}
    text = page_text(redact_page(page, KEY))
    assert "VzQ3NktFUDh0Tm5qdHZSdw==" not in text
    assert "T0lpc01IOHdHdGhzNjltOWJBR2Z3MTVNcU14NjdsdTJnNW1Oa3RiaA==" not in text
    assert "198.13.32.106" in text


# --- fixtures are the redacted form ------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["Hello-10-17-154", "Hello-10-17-5", "Vizit-12-28", "ki06-05-02", "Test-10-16"],
)
def test_fixture_is_already_redacted(name):
    # The fixtures in git are redact_page's output over the raw responses, so
    # redacting them again must change nothing. If this fails, a rule now
    # matches something it did not when the fixture was generated, or the
    # fixture was hand-edited.
    page = fixture_page(name)
    assert redact_page(page, KEY) == page


def test_hello_fixture_carries_tokens_in_the_title():
    title = fixture_page("Hello-10-17-154")["title"]
    assert len(tokens(title)) == 2
    assert title.endswith("?dGViaQ==?eWVsNA==")
