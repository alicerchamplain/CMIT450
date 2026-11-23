"""Tests for graphwatch.redact.

Nothing here touches the network or the disk except the fixtures under
plan/fixtures, which are the redacted form of real pages and so must come
back from redaction unchanged. The HMAC key is any fixed bytes: the tests
check the shape and stability of tokens, never a particular digest.
"""

import base64
import copy
import json
import re
from pathlib import Path

import pytest

from graphwatch.redact import (
    BARE_LOGIN_PASSWORD_PATTERN,
    EMAIL_AND_PASSWORD_PATTERN,
    MARKER,
    hash_secret,
    is_card,
    proxy_endpoint,
    redact_page,
    redact_text,
)
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
    for part in (
        "198.13.32.106",
        "rakuten.ne.jp",
        "opportunizz.pro",
        "/!",
        "dGViaQ==",
        "eWVsNA==",
    ):
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


# --- credential shapes seen in the 2026-11-05 shape pass ------------------------
#
# Three shapes from plan/reports/shape-notes-2026-11-05.md got past redact_text.
# Each test below pins the shape as it appeared on real pages. The guards at
# the end already pass and are there so the fix does not grow into URLs,
# times, or ordinary prose.


def test_labelled_password_hyphen_separator_hashes_the_value():
    # "пароль-Qwerty123" with a hyphen between label and value, no colon.
    out = redact_text("логин: ivan пароль-Qwerty123 ok", KEY)
    assert out == "логин: ivan пароль-" + hash_secret("Qwerty123", KEY) + " ok"


def test_labelled_password_on_the_next_line_hashes_the_value():
    # Label on one line, value on the next, no separator at all.
    out = redact_text("ПАРОЛЬ\nQwerty123\nготово", KEY)
    assert out == "ПАРОЛЬ\n" + hash_secret("Qwerty123", KEY) + "\nготово"


def test_bare_login_password_hashes_the_password():
    # "login:password" with no @ in the login.
    out = redact_text("acc admin_01:P@ssw0rd! next", KEY)
    assert out == "acc admin_01:" + hash_secret("P@ssw0rd!", KEY) + " next"


@pytest.mark.parametrize(
    "s",
    [
        "пароль-Qwerty123",
        "ПАРОЛЬ\nQwerty123",
        "admin_01:P@ssw0rd!",
    ],
)
def test_new_credential_shapes_are_idempotent(s):
    once = redact_text(s, KEY)
    assert redact_text(once, KEY) == once


@pytest.mark.parametrize(
    "s",
    [
        "https://t.me/some_bot?start=abc",
        "meet at 12:30 or 9:45",
        "password-protected archive inside",
        "Note: see below",
    ],
)
def test_credential_shape_guards_leave_ordinary_text_alone(s):
    assert redact_text(s, KEY) == s


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
        "content": [
            {"tag": "p", "children": [{"tag": "b", "children": ["password: c"]}]}
        ],
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
                    {
                        "tag": "a",
                        "attrs": {"href": "u"},
                        "children": ["password: deep"],
                    },
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
    page = {
        "path": "x-01-01",
        "url": "u",
        "views": 7,
        "author_name": "n",
        "content": [],
    }
    out = redact_page(page, KEY)
    for k in ("path", "url", "views", "author_name"):
        assert out[k] == page[k]


def test_redact_page_text_has_no_raw_keys():
    page = {
        "title": RAW_HELLO_TITLE,
        "description": "Hello,+world!",
        "content": [{"tag": "p", "children": ["Hello,+world!"]}],
    }
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


# --- secret shapes found by the 2026-11-15 survey ------------------------------------
#
# plan/classification-plan-2026-11-15.md, "Redaction gaps". Every string here
# is made up in the shape that was counted; none is a real key, token or
# account. Each shape gets the same three checks: the secret is hashed, the
# text around it survives, and a second pass changes nothing.

GOOGLE_KEY = "AIza" + "Sy" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
SK_KEY = "sk-" + "a1B2c3D4" * 5
DISCORD_TOKEN = "M" + "TIzNDU2Nzg5MDEyMzQ1Njc4" + ".Gh1jKl." + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXBhcnQ"
API_HASH = "0123456789abcdef0123456789abcdef"
UUID = "0f1e2d3c-4b5a-6978-8695-a4b3c2d1e0f9"
PROXY_SECRET = "dd" + "0123456789abcdef" * 2


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


VMESS_BLOB = b64('{"v":"2","add":"vpn.example.org","port":"443","id":"' + UUID + '"}')
SS_BLOB = b64("aes-256-gcm:made-up-password@203.0.113.7:8388")
SS_USERINFO = b64("chacha20-ietf-poly1305:made-up-password")
SESSION_KEY = "ab12" * 64  # 256 hex characters, the size of an auth key


def test_the_made_up_tokens_have_the_real_lengths():
    assert len(GOOGLE_KEY) == 39
    assert len(API_HASH) == 32


@pytest.mark.parametrize("secret", [GOOGLE_KEY, SK_KEY, DISCORD_TOKEN, JWT])
def test_fixed_shape_keys_are_hashed_whole(secret):
    out = redact_text(f"key {secret} end", KEY)
    assert out == "key " + hash_secret(secret, KEY) + " end"


def test_sk_inside_another_word_is_not_a_key():
    s = "task-" + "a" * 40
    assert redact_text(s, KEY) == s


def test_a_jwt_in_a_url_path_keeps_the_host():
    out = redact_text(f"https://dating.example.com/l/{JWT}/open", KEY)
    assert out == "https://dating.example.com/l/" + hash_secret(JWT, KEY) + "/open"


@pytest.mark.parametrize(
    "label",
    ["api_hash: ", "api_hash=", '"api_hash": "', "API_HASH = '"],
)
def test_api_hash_value_is_hashed_and_the_label_kept(label):
    out = redact_text(f"api_id: 1234567 {label}{API_HASH}", KEY)
    assert out == f"api_id: 1234567 {label}" + hash_secret(API_HASH, KEY)


def test_api_hash_needs_all_32_hex_characters():
    s = "api_hash: 0123456789abcdef"
    assert redact_text(s, KEY) == s


def test_vless_user_id_is_hashed_and_the_server_and_port_kept():
    out = redact_text(f"vless://{UUID}@vpn.example.org:443?security=tls#home", KEY)
    assert out == (
        "vless://" + hash_secret(UUID, KEY) + "@vpn.example.org:443?security=tls#home"
    )


@pytest.mark.parametrize("scheme", ["vless", "trojan", "ss", "socks5", "VLESS"])
def test_proxy_userinfo_is_hashed_for_each_scheme(scheme):
    out = redact_text(f"{scheme}://made-up-password@203.0.113.7:1080", KEY)
    assert out == (
        f"{scheme}://" + hash_secret("made-up-password", KEY) + "@203.0.113.7:1080"
    )


def test_a_proxy_link_without_userinfo_is_untouched():
    s = "socks5://203.0.113.7:1080"
    assert redact_text(s, KEY) == s


def test_vmess_config_is_hashed_and_its_endpoint_kept():
    out = redact_text(f"vmess://{VMESS_BLOB} next", KEY)
    assert out == "vmess://" + hash_secret(VMESS_BLOB, KEY) + "@vpn.example.org:443 next"
    assert UUID not in out


def test_encoded_ss_config_is_hashed_and_its_endpoint_kept():
    out = redact_text(f"ss://{SS_BLOB}#tag", KEY)
    assert out == "ss://" + hash_secret(SS_BLOB, KEY) + "@203.0.113.7:8388#tag"


def test_ss_with_encoded_userinfo_keeps_the_endpoint_already_in_the_link():
    out = redact_text(f"ss://{SS_USERINFO}@203.0.113.7:8388#tag", KEY)
    assert out == "ss://" + hash_secret(SS_USERINFO, KEY) + "@203.0.113.7:8388#tag"


def test_a_config_that_does_not_decode_is_hashed_with_no_endpoint():
    blob = "A" * 30 + "-_"
    assert redact_text(f"vmess://{blob}", KEY) == "vmess://" + hash_secret(blob, KEY)


def test_proxy_endpoint_reads_vmess_and_ss_configs():
    assert proxy_endpoint(VMESS_BLOB) == "vpn.example.org:443"
    assert proxy_endpoint(SS_BLOB) == "203.0.113.7:8388"


@pytest.mark.parametrize(
    "config",
    [
        '{"add":"vpn.example.org"}',  # no port
        '{"add":"a b\\nSECRET{","port":"443"}',  # not a plain host
        "[1, 2, 3]",
        "no endpoint in here at all",
        "{not json",
    ],
)
def test_proxy_endpoint_is_none_for_anything_but_a_plain_host_and_port(config):
    assert proxy_endpoint(b64(config)) is None


def test_proxy_endpoint_is_none_for_text_that_is_not_base64():
    assert proxy_endpoint("!!!not base64!!!") is None


def test_telegram_proxy_secret_is_hashed_and_the_server_kept():
    link = f"https://t.me/proxy?server=203.0.113.7&port=443&secret={PROXY_SECRET}"
    out = redact_text(link, KEY)
    assert out == (
        "https://t.me/proxy?server=203.0.113.7&port=443&secret="
        + hash_secret(PROXY_SECRET, KEY)
    )


def test_telegram_proxy_secret_in_base64_is_hashed():
    secret = "7gAAAAAAAAAAAAAAAAAAAABnb29nbGUuY29t"
    out = redact_text(f"tg://proxy?server=p.example.org&port=443&secret={secret}", KEY)
    assert out.endswith("&secret=" + hash_secret(secret, KEY))
    assert "p.example.org&port=443" in out


def test_a_short_secret_parameter_is_left_alone():
    s = "https://example.com/?secret=abc123"
    assert redact_text(s, KEY) == s


@pytest.mark.parametrize(
    "name", ["token", "auth", "access_token", "login_token", "session", "sid", "code"]
)
def test_login_token_in_a_url_is_hashed_and_the_link_kept(name):
    token = "a1b2c3d4e5f6a7b8c9d0"
    out = redact_text(f"go https://dating.example.com/in?u=7&{name}={token} now", KEY)
    assert out == (
        f"go https://dating.example.com/in?u=7&{name}=" + hash_secret(token, KEY) + " now"
    )


def test_a_short_token_parameter_is_left_alone():
    s = "https://example.com/watch?code=abc123"
    assert redact_text(s, KEY) == s


def test_a_token_parameter_outside_a_url_is_left_alone():
    s = "set token=a1b2c3d4e5f6a7b8c9d0 in the form"
    assert redact_text(s, KEY) == s


def test_an_autologin_link_has_every_long_value_hashed():
    # The dating autologin shape: the login token is in a parameter named key.
    key_value = "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
    message = "f0e1d2c3b4a5f6e7d8c9"
    link = (
        "https://m.dating.example.com/autologin/?"
        f"key={key_value}&uniqmessageId={message}&loc=en"
    )
    out = redact_text(link, KEY)
    assert out == (
        "https://m.dating.example.com/autologin/?key="
        + hash_secret(key_value, KEY)
        + "&uniqmessageId="
        + hash_secret(message, KEY)
        + "&loc=en"
    )


def test_a_key_parameter_on_an_ordinary_link_is_left_alone():
    s = "https://maps.example.com/embed?key=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
    assert redact_text(s, KEY) == s


def test_session_key_material_is_hashed_in_a_session_export():
    s = f'WARNING_BANNER\n"dc2_auth_key": "{SESSION_KEY}",\n"user_auth": 1'
    out = redact_text(s, KEY)
    assert out == (
        'WARNING_BANNER\n"dc2_auth_key": "'
        + hash_secret(SESSION_KEY, KEY)
        + '",\n"user_auth": 1'
    )


def test_a_long_run_outside_a_session_export_is_left_alone():
    # No generic rule for long runs: an encoded pointer has to survive.
    s = f'"dc2_auth_key": "{SESSION_KEY}"'
    assert redact_text(s, KEY) == s


def test_the_session_flag_hashes_a_run_in_text_that_has_no_banner():
    out = redact_text(SESSION_KEY, KEY, session=True)
    assert out == hash_secret(SESSION_KEY, KEY)


def test_a_run_under_64_characters_survives_in_a_session_export():
    s = "WARNING_BANNER " + "a" * 63
    assert redact_text(s, KEY) == s


def test_the_session_rule_does_not_hash_a_token_again():
    once = redact_text("WARNING_BANNER " + SESSION_KEY, KEY)
    assert len(tokens(once)) == 1
    assert redact_text(once, KEY) == once


@pytest.mark.parametrize(
    "s",
    [
        f"key {GOOGLE_KEY}",
        f"key {SK_KEY}",
        f"token {DISCORD_TOKEN}",
        f"https://dating.example.com/l/{JWT}",
        f'"api_hash": "{API_HASH}"',
        f"vless://{UUID}@vpn.example.org:443?security=tls",
        f"vmess://{VMESS_BLOB}",
        f"ss://{SS_BLOB}",
        f"ss://{SS_USERINFO}@203.0.113.7:8388",
        f"https://t.me/proxy?server=203.0.113.7&port=443&secret={PROXY_SECRET}",
        "https://dating.example.com/in?token=a1b2c3d4e5f6a7b8c9d0",
        "https://m.dating.example.com/autologin/?key=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
        f"WARNING_BANNER {SESSION_KEY}",
    ],
)
def test_survey_shapes_are_idempotent(s):
    once = redact_text(s, KEY)
    assert once != s
    assert redact_text(once, KEY) == once


def test_a_snapshot_stored_under_the_old_patterns_gets_its_user_id_hashed():
    # Before this change the email:password rule read uuid@host:port as an
    # email and hashed the port. Re-redacting such a snapshot hashes the user
    # id; the port it lost cannot come back.
    old_port = hash_secret("443?security=tls", KEY)
    stored = f"vless://{UUID}@vpn.example.org:{old_port}"
    out = redact_text(stored, KEY)
    assert out == f"vless://{hash_secret(UUID, KEY)}@vpn.example.org:{old_port}"


# --- a label in one text node, its secret in the next -------------------------------


def split_page(*children) -> dict:
    return {"content": [{"tag": "p", "children": list(children)}]}


def children_of(page: dict) -> list:
    return page["content"][0]["children"]


def test_a_password_after_a_label_node_is_hashed():
    page = split_page({"tag": "strong", "children": ["Password:"]}, " hunter2 ok")
    out = children_of(redact_page(page, KEY))
    assert out[0] == {"tag": "strong", "children": ["Password:"]}
    assert out[1] == " " + hash_secret("hunter2", KEY) + " ok"


def test_a_password_after_a_bare_label_node_is_hashed():
    # <strong>Password</strong>: hunter2, the separator opens the next node.
    page = split_page({"tag": "strong", "children": ["Password"]}, ": hunter2 ok")
    out = children_of(redact_page(page, KEY))
    assert out[1] == ": " + hash_secret("hunter2", KEY) + " ok"


def test_a_bare_label_node_needs_a_separator_in_the_next_node():
    page = split_page({"tag": "strong", "children": ["Password"]}, " reset is easy")
    assert redact_page(page, KEY) == page


def test_a_label_in_one_block_and_the_password_in_the_next_block():
    page = {
        "content": [
            {"tag": "p", "children": ["Пароль:"]},
            {"tag": "p", "children": ["Qwerty123"]},
        ]
    }
    out = redact_page(page, KEY)
    assert out["content"][1]["children"] == [hash_secret("Qwerty123", KEY)]


def test_whitespace_and_line_breaks_between_the_label_and_the_password():
    page = split_page("pwd =", " ", {"tag": "br"}, "hunter2")
    out = children_of(redact_page(page, KEY))
    assert out == ["pwd =", " ", {"tag": "br"}, hash_secret("hunter2", KEY)]


def test_an_api_hash_in_the_node_after_its_label_is_hashed():
    page = split_page("api_hash:", {"tag": "br"}, API_HASH)
    out = children_of(redact_page(page, KEY))
    assert out[2] == hash_secret(API_HASH, KEY)


def test_only_the_node_right_after_the_label_is_touched():
    page = split_page("Password:", "hunter2", "second node stays")
    out = children_of(redact_page(page, KEY))
    assert out[2] == "second node stays"


def test_the_rest_of_the_node_after_the_password_is_still_redacted():
    page = split_page("Password:", f"hunter2 and a key {GOOGLE_KEY}")
    out = children_of(redact_page(page, KEY))
    assert out[1] == (
        hash_secret("hunter2", KEY) + " and a key " + hash_secret(GOOGLE_KEY, KEY)
    )


def test_a_label_inside_a_sentence_does_not_reach_the_next_node():
    page = split_page("Password reset is easy.", "Click the link")
    assert redact_page(page, KEY) == page


def test_split_labels_are_idempotent():
    page = split_page({"tag": "strong", "children": ["Password"]}, ": hunter2 ok")
    once = redact_page(page, KEY)
    assert redact_page(once, KEY) == once


def test_a_label_in_the_title_does_not_reach_the_content():
    page = {"title": "Password:", "content": [{"tag": "p", "children": ["hello"]}]}
    assert redact_page(page, KEY) == page


# --- a session export split over several text nodes ---------------------------------


def test_the_banner_in_one_node_covers_the_key_in_another():
    page = {
        "content": [
            {"tag": "p", "children": ["WARNING_BANNER"]},
            {"tag": "p", "children": [SESSION_KEY]},
        ]
    }
    out = redact_page(page, KEY)
    assert out["content"][1]["children"] == [hash_secret(SESSION_KEY, KEY)]


def test_the_banner_covers_the_description_too():
    page = {
        "description": SESSION_KEY,
        "content": [{"tag": "p", "children": ["WARNING_BANNER"]}],
    }
    assert redact_page(page, KEY)["description"] == hash_secret(SESSION_KEY, KEY)


def test_a_page_without_the_banner_keeps_its_long_runs():
    page = {"content": [{"tag": "p", "children": [SESSION_KEY]}]}
    assert redact_page(page, KEY) == page


# --- the bare login pattern reads each run once (22 November) ------------------------
#
# The pattern as written on 5 November matched the right text but tried every
# way of splitting a run of login characters around a letter, so one long
# token took seconds. It was rewritten to read a run once. The old pattern is
# kept here as the reference: the rewrite has to hash exactly what it hashed.

# One thing was changed on purpose the same day: a URL's scheme is no longer
# taken for a password (link:https://site). The reference carries that one
# guard, (?![^\s:]+://), and is otherwise the pattern of 5 November.
OLD_BARE_LOGIN = re.compile(
    r"(?<![\w@./:-])([\w.+-]*[^\W\d_][\w.+-]*)(:)(?!/)(?![^\s:]+://)(?=[^\s:]*\D)([^\s:]+)"
)


def bare_login_old(s: str) -> str:
    def mark(m):
        if m.group(3).startswith(MARKER):
            return m.group(0)
        return m.group(1) + m.group(2) + "<" + m.group(3) + ">"

    return OLD_BARE_LOGIN.sub(mark, s)


def bare_login_new(s: str) -> str:
    def mark(m):
        if m.group(3).startswith(MARKER):
            return m.group(0)
        return m.group(0)[: m.start(3) - m.start()] + "<" + m.group(3) + ">"

    return BARE_LOGIN_PASSWORD_PATTERN.sub(mark, s)


def test_the_rewritten_bare_login_pattern_matches_every_short_string_the_old_one_did():
    # Every string up to five characters over the characters that matter:
    # a letter, a digit, each login character, and each character that stops
    # a login from starting. (All 21 million up to seven were compared once.)
    import itertools

    alphabet = ["a", "1", "_", "+", "-", ".", ":", "@", "/", " ", "!"]
    for length in range(6):
        for chars in itertools.product(alphabet, repeat=length):
            s = "".join(chars)
            assert bare_login_new(s) == bare_login_old(s), s


@pytest.mark.parametrize(
    "s",
    [
        "acc admin_01:P@ssw0rd! next",
        "user@a+b:secret1 x",  # the login is b: a run can start after a plus
        "x@abc:def!ghi:jkl",
        "a+b+c:pw and 1+2:pw and 1+a:pw",
        "логин:Пароль123 и ²:x и ½a:pw",
        "https://t.me/some_bot?start=abc",
        "meet at 12:30 or 9:45, host:8080, Note: see below",
        "a:b:c:d e:SECRET{" + "ab" * 32 + "}",
        "first.last-name+tag:pw1\nsecond:pw2\t3:third:x",
        ":a:b ::a:b /a:b .a:b -a:b +a:b @a:b",
        "link:https://d.example/x site:ftp://f.example a:b://c a:b:// a:b:/c a:b:c//",
        "a+b:vless://x and plain:word",
    ],
)
def test_the_rewritten_bare_login_pattern_matches_the_shapes_the_old_one_did(s):
    assert bare_login_new(s) == bare_login_old(s)
    assert [m.span(3) for m in BARE_LOGIN_PASSWORD_PATTERN.finditer(s)] == [
        m.span(3) for m in OLD_BARE_LOGIN.finditer(s)
    ]


def test_the_login_group_is_still_the_login():
    m = BARE_LOGIN_PASSWORD_PATTERN.search("acc admin_01:P@ssw0rd! next")
    assert m.groups() == ("admin_01", ":", "P@ssw0rd!")


def test_a_login_that_starts_after_a_plus_keeps_the_text_before_it():
    out = redact_text("mail user@a+b:hunter2 ok", KEY)
    assert out == "mail user@a+b:" + hash_secret("hunter2", KEY) + " ok"


@pytest.mark.parametrize(
    "text",
    [
        "A" * 60000,
        "0123456789abcdef" * 3750,
        "ab.cd-" * 10000,
        "a+" * 30000,
        "@" + "a+" * 30000 + "1:x",
        "https://example.com/?a=" + "x" * 60000,
        "1" * 60000 + ":x",
    ],
)
def test_the_bare_login_pattern_reads_a_long_run_once(text, laptop_seconds):
    # Each of these took 6 to 15 seconds with the old pattern.
    assert laptop_seconds(lambda: list(BARE_LOGIN_PASSWORD_PATTERN.finditer(text))) < 1.0


# --- the email:password pattern reads each run once (22 November) ---------------------
#
# The same fault as the bare login pattern, on another shape: \b let the old
# pattern start again at every dot, plus and dash inside a run. The old
# pattern is kept here as the reference for what has to be hashed.

OLD_EMAIL_AND_PASSWORD = re.compile(r"\b([\w.+-]+@[\w-]+(?:\.[\w-]+)+):(\S+)")


def email_password_old(s: str) -> str:
    def mark(m):
        if m.group(2).startswith(MARKER):
            return m.group(0)
        return m.group(1) + ":" + "<" + m.group(2) + ">"

    return OLD_EMAIL_AND_PASSWORD.sub(mark, s)


def email_password_new(s: str) -> str:
    def mark(m):
        if m.group(2).startswith(MARKER):
            return m.group(0)
        return m.group(0)[: m.start(2) - m.start()] + "<" + m.group(2) + ">"

    return EMAIL_AND_PASSWORD_PATTERN.sub(mark, s)


def test_the_rewritten_email_pattern_matches_every_short_string_the_old_one_did():
    # Every string up to eight characters over the characters that matter.
    # The shortest match, a@a.a:a, is seven. (All 43 million up to nine over
    # three such alphabets were compared once.)
    import itertools

    alphabet = ["a", "-", ".", ":", "@"]
    matched = 0
    for length in range(9):
        for chars in itertools.product(alphabet, repeat=length):
            s = "".join(chars)
            assert email_password_new(s) == email_password_old(s), s
            matched += OLD_EMAIL_AND_PASSWORD.search(s) is not None
    assert matched > 100  # the comparison is not of strings that never match


@pytest.mark.parametrize(
    "s",
    [
        "mail b@c.ru:Qwerty! next",
        "first.last+tag@mail.example.com:pw1 second_user@x.org:pw2",
        ".dotted@mail.example.com:pw",  # the email starts at the first word char
        "-+.a.b@mail.example.com:pw and +x@y.zz:q",
        "no-dot@localhost:pw and a@b.c",
        "a@b.c:SECRET{" + "ab" * 32 + "} a@b.c:d",
        "почта@пример.рф:Пароль123 é@ü.de:x",
        "https://user@host.example.com:8080/path",
        "a@b.c:d:e f@g.h:i\nj@k.l:m",
        "x@@y.com:pw x@y..com:pw x@.y.com:pw @y.com:pw",
    ],
)
def test_the_rewritten_email_pattern_matches_the_shapes_the_old_one_did(s):
    assert email_password_new(s) == email_password_old(s)
    assert [(m.span(1), m.span(2)) for m in EMAIL_AND_PASSWORD_PATTERN.finditer(s)] == [
        (m.span(1), m.span(2)) for m in OLD_EMAIL_AND_PASSWORD.finditer(s)
    ]


def test_the_email_group_is_still_the_email():
    m = EMAIL_AND_PASSWORD_PATTERN.search("mail b@c.ru:Qwerty! next")
    assert m.groups() == ("b@c.ru", "Qwerty!")


def test_punctuation_in_front_of_an_email_is_kept():
    out = redact_text("list: -.user@mail.example.com:hunter2 ok", KEY)
    assert out == "list: -.user@mail.example.com:" + hash_secret("hunter2", KEY) + " ok"


@pytest.mark.parametrize(
    "text",
    [
        "ab.cd-" * 10000,
        "a+" * 30000,
        ".+-" * 20000 + "@x.com:pw",
        "a@" + "ab.cd-" * 10000,
        "a@" * 30000,
    ],
)
def test_the_email_pattern_reads_a_long_run_once(text, laptop_seconds):
    # The first two took about 4 seconds each with the old pattern.
    assert laptop_seconds(lambda: list(EMAIL_AND_PASSWORD_PATTERN.finditer(text))) < 1.0


@pytest.mark.parametrize(
    "text",
    [
        "A" * 60000,
        "0123456789abcdef" * 3750,
        "ab.cd-" * 10000,
        "a+" * 30000,
        "a@" * 30000,
        "word:" * 12000,
        "1234567890" * 6000,
        "https://example.com/?a=" + "x" * 60000,
        "https://example.com/" + "a/" * 30000,
        "WARNING_BANNER " + "ab.cd-" * 10000,
    ],
)
def test_redact_text_is_quick_on_a_page_that_is_one_long_run(text, laptop_seconds):
    # A page is up to 64 KB and whoever posts it chooses the text.
    assert laptop_seconds(lambda: redact_text(text, KEY)) < 1.0


# --- what the review of 22 November found ---------------------------------------------
#
# An independent read of the day's redaction work confirmed nine defects. Each
# block below pins one. All strings are made up.

LOGIN_LINK = "https://d.example/autologin?token=abcdefghijklmnopqrstuvwx"


def link_page(href: str, text: str = "click here", tag: str = "a", attr: str = "href") -> dict:
    return {"content": [{"tag": "p", "children": [{"tag": tag, "attrs": {attr: href}, "children": [text]}]}]}


def attr_of(page: dict, attr: str = "href") -> str:
    return page["content"][0]["children"][0]["attrs"][attr]


# A link's target is stored with the content, so it is redacted too


def test_a_login_token_in_a_link_target_is_hashed():
    out = redact_page(link_page(LOGIN_LINK), KEY)
    assert attr_of(out) == "https://d.example/autologin?token=" + hash_secret(
        "abcdefghijklmnopqrstuvwx", KEY
    )
    assert out["content"][0]["children"][0]["children"] == ["click here"]


def test_a_link_target_and_the_same_link_as_text_get_the_same_token():
    out = redact_page(link_page(LOGIN_LINK, text=LOGIN_LINK), KEY)
    assert attr_of(out) == out["content"][0]["children"][0]["children"][0]


@pytest.mark.parametrize(
    "href",
    [
        f"https://t.me/proxy?server=203.0.113.7&port=443&secret={PROXY_SECRET}",
        f"vless://{UUID}@vpn.example.org:443",
        f"vmess://{VMESS_BLOB}",
        f"https://dating.example.com/l/{JWT}",
        "http://bobby:hunter2@203.0.113.7:8080",
    ],
)
def test_every_token_shape_is_hashed_in_a_link_target(href):
    out = attr_of(redact_page(link_page(href), KEY))
    assert out != href
    assert len(tokens(out)) == 1


def test_an_image_source_is_redacted_though_the_node_has_no_children():
    page = {"content": [{"tag": "img", "attrs": {"src": LOGIN_LINK}}]}
    out = redact_page(page, KEY)
    assert "abcdefghijklmnopqrstuvwx" not in out["content"][0]["attrs"]["src"]


@pytest.mark.parametrize(
    "href",
    [
        "mailto:bob@mail.example.com",
        "https://example.com/page:section",
        "tel:+15550100",
        "https://example.com/docs/admin:guide",
        "/relative/path",
    ],
)
def test_the_bare_login_pattern_does_not_run_on_a_link_target(href):
    # In text, word:word is the bare login shape. In a target it is the URL.
    assert attr_of(redact_page(link_page(href), KEY)) == href


@pytest.mark.parametrize(
    "url,secret",
    [
        ("https://x.example/login.php?user=bob&password=hunter2", "hunter2"),
        ("https://x.example/in?u=bob@mail.example.com:hunter2", "hunter2"),
        ("https://x.example/pay?cc=4111111111111111", "4111111111111111"),
        ("https://x.example/tg?api_hash=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"),
    ],
)
def test_a_secret_is_hashed_in_a_link_target_as_it_is_in_the_link_text(url, secret):
    # Telegraph turns a pasted URL into <a href=URL>URL</a>. The second
    # review found the text hashed and the href beside it in clear.
    out = redact_page(link_page(url, text=url), KEY)
    text = out["content"][0]["children"][0]["children"][0]
    assert secret not in attr_of(out)
    assert secret not in text
    assert tokens(attr_of(out)) == tokens(text)


def test_other_attributes_and_a_node_without_attrs_are_untouched():
    node = {"tag": "a", "attrs": {"href": "u", "target": LOGIN_LINK, "id": 7}, "children": ["x"]}
    out = redact_page({"content": [node, {"tag": "p", "children": ["y"]}]}, KEY)
    assert out["content"][0]["attrs"] == node["attrs"]
    assert out["content"][1] == {"tag": "p", "children": ["y"]}


def test_redacting_link_targets_does_not_mutate_the_page():
    page = link_page(LOGIN_LINK)
    before = copy.deepcopy(page)
    redact_page(page, KEY)
    assert page == before


def test_the_link_argument_leaves_out_the_bare_login_pattern_only():
    s = "https://example.com/docs/admin:guide"
    assert redact_text(s, KEY, link=True) == s
    assert redact_text("see admin:guide", KEY) != "see admin:guide"
    labelled = "https://example.com/?password=hunter2"
    assert redact_text(labelled, KEY, link=True) == redact_text(labelled, KEY)


# user:password in a URL of any scheme


@pytest.mark.parametrize(
    "scheme", ["http", "https", "socks5", "socks4", "ftp", "hysteria2", "tuic", "HTTP"]
)
def test_url_credentials_are_hashed_and_the_host_and_port_kept(scheme):
    out = redact_text(f"proxy {scheme}://bob:pw1@203.0.113.7:8080 ok", KEY)
    assert out == f"proxy {scheme}://" + hash_secret("bob:pw1", KEY) + "@203.0.113.7:8080 ok"


def test_a_spoof_url_has_no_credentials_to_hash():
    # The decoy of a spoof has no colon in it: it must survive for the rules.
    s = "https://www.tenable.com@agfc.harper18.workers.dev/"
    assert redact_text(s, KEY) == s


def test_an_at_sign_later_in_a_url_is_not_credentials():
    s = "https://example.com/users/a:b@c"
    assert "https://example.com/users/" in redact_text(s, KEY)
    assert redact_text("https://example.com/@handle", KEY) == "https://example.com/@handle"


@pytest.mark.parametrize("scheme", ["hysteria2", "hysteria", "tuic"])
def test_the_newer_proxy_schemes_have_their_user_id_hashed(scheme):
    out = redact_text(f"{scheme}://made-up-password@vpn.example.org:443", KEY)
    assert out == f"{scheme}://" + hash_secret("made-up-password", KEY) + "@vpn.example.org:443"


def test_redaction_knows_every_proxy_scheme_the_rules_call_a_proxy_link():
    from graphwatch.redact import PROXY_USERINFO_PATTERN
    from graphwatch.rules import PROXY_URI_PATTERN

    for scheme in ("vless", "trojan", "ss", "ssr", "socks", "socks5", "hysteria", "hysteria2", "tuic"):
        assert PROXY_URI_PATTERN.search(f"{scheme}://x")
        assert PROXY_USERINFO_PATTERN.search(f"{scheme}://made-up-password@h"), scheme


# A token value in plain base64, in a fragment, or percent-encoded


def test_a_base64_token_is_hashed_to_its_end_not_to_its_first_plus():
    token = "YWJjZGVmZ2hpamtsbW5vcA+/xyzABCDEFGHIJKLMNOP=="
    out = redact_text(f"https://d.example/login?token={token}", KEY)
    assert out == "https://d.example/login?token=" + hash_secret(token, KEY)


def test_a_token_in_a_url_fragment_is_hashed():
    out = redact_text("https://d.example/#access_token=abcdefghijklmnopqrstuvwx", KEY)
    assert out == "https://d.example/#access_token=" + hash_secret("abcdefghijklmnopqrstuvwx", KEY)


@pytest.mark.parametrize("secret", ["7gAAAAAA+AAAA/AAAAAAAAAAAAA=", "7gAAAAAA%2BAAAA%2FAAAAAAAAAA"])
def test_a_proxy_secret_with_plus_slash_or_percent_is_hashed_whole(secret):
    out = redact_text(f"tg://proxy?server=p.example.org&port=443&secret={secret}", KEY)
    assert out == "tg://proxy?server=p.example.org&port=443&secret=" + hash_secret(secret, KEY)


def test_a_value_stops_at_the_next_parameter():
    out = redact_text("https://d.example/in?token=abcdefghijklmnopqrstuvwx&lang=en", KEY)
    assert out.endswith("&lang=en")


# A second pass changes nothing, whatever the first one left


@pytest.mark.parametrize(
    "s",
    [
        "https://d.example/l?auth=longusername:pw",
        "https://d.example/l?code=alice.smith:pw1",
        "https://m.dating.example.com/autologin/?key=name:password1&x=1",
        "https://d.example/in?pass=hunter2hunter2hunter2&token=abcdefghijklmnopqrstuvwx",
        "bob@mail.example.com:https://d.example/in?token=abcdefghijklmnopqrstuvwx",
        "link:https://d.example/in?token=abcdefghijklmnopqrstuvwx",
        f"ss://{b64('aes-256-gcm:12345').rstrip('=')}@203.0.113.7:8388#tag",
        f"vmess://{VMESS_BLOB}",
        "http://bobby:hunter2@203.0.113.7:8080",
        "pass:word user:name key:value 12:30",
    ],
)
def test_redact_text_twice_is_redact_text_once(s):
    once = redact_text(s, KEY)
    assert redact_text(once, KEY) == once
    assert redact_text(once, KEY, link=True) == redact_text(redact_text(once, KEY, link=True), KEY, link=True)


def test_a_parameter_value_that_runs_into_a_hash_is_left_alone():
    # The bare login pattern hashed pw; name:SECRET is not a new 16 character token.
    once = redact_text("https://d.example/l?auth=longusername:pw", KEY)
    assert once == "https://d.example/l?auth=longusername:" + hash_secret("pw", KEY)
    assert redact_text(once, KEY) == once


# The endpoint written beside a hashed proxy config is never a secret


def test_an_ss_password_is_not_written_out_as_if_it_were_the_endpoint():
    # base64 of method:password, with the server after the @ in the link itself.
    blob = b64("aes-256-gcm:12345").rstrip("=")
    out = redact_text(f"ss://{blob}@203.0.113.7:8388#tag", KEY)
    assert out == "ss://" + hash_secret(blob, KEY) + "@203.0.113.7:8388#tag"
    assert "12345" not in out


def test_proxy_endpoint_is_none_when_the_config_names_no_server():
    assert proxy_endpoint(b64("aes-256-gcm:12345")) is None
    assert proxy_endpoint(b64("chacha20-ietf-poly1305:99999")) is None


@pytest.mark.parametrize(
    "host",
    ["AKIAIOSFODNN7EXAMPLE", "no-dot-here", "a b.example.org", "x.example.org/path", "SECRET{ab}.example.org"],
)
def test_proxy_endpoint_takes_only_an_address_for_a_host(host):
    assert proxy_endpoint(b64('{"add":"' + host + '","port":"443"}')) is None


def test_a_secret_shaped_host_in_a_vmess_config_is_not_written_out():
    # A JWT is dotted labels too. It would be hashed by the next pass, so it
    # is not put into the text by this one.
    blob = b64('{"add":"' + JWT + '","port":"443"}')
    out = redact_text(f"vmess://{blob}", KEY)
    assert out == "vmess://" + hash_secret(blob, KEY)
    assert redact_text(out, KEY) == out


def test_proxy_endpoint_reads_a_bracketed_ipv6_server():
    assert proxy_endpoint(b64('{"add":"[2001:db8::1]","port":"443"}')) == "[2001:db8::1]:443"


# A label in one node, its secret in the next: stored and fresh come out the same


def test_a_split_label_gives_the_same_result_from_a_stored_copy_and_a_fresh_fetch():
    fresh = split_page({"tag": "strong", "children": ["Password:"]}, "bob@mail.example.com:hunter2")
    stored = split_page(
        {"tag": "strong", "children": ["Password:"]},
        "bob@mail.example.com:" + hash_secret("hunter2", KEY),  # as the old code left it
    )
    assert redact_page(fresh, KEY) == redact_page(stored, KEY)
    # What is still in clear in front of the hash is hashed too: after a
    # label the whole first token is the secret.
    assert children_of(redact_page(fresh, KEY))[1] == hash_secret("bob@mail.example.com:", KEY) + hash_secret("hunter2", KEY)


def test_a_token_after_a_label_that_redaction_already_hashed_is_not_hashed_again():
    page = split_page("Password:", f"key {GOOGLE_KEY}")
    out = children_of(redact_page(page, KEY))
    assert out[1] == hash_secret("key", KEY) + " " + hash_secret(GOOGLE_KEY, KEY)
    page = split_page("Password:", GOOGLE_KEY)
    assert children_of(redact_page(page, KEY))[1] == hash_secret(GOOGLE_KEY, KEY)


# Long runs


@pytest.mark.parametrize(
    "text",
    [
        "pass" + " " * 64000 + "x",
        "pass" + " " * 64000 + "x",
        "pass " * 12000,
        "password:" + " " * 64000,
        "a.a." * 16000 + "://x:y@z",
        "?token=" * 9000,
        "#a=" * 20000,
    ],
)
def test_redact_page_is_quick_on_a_node_that_is_one_long_run(text, laptop_seconds):
    page = {"content": [{"tag": "p", "children": [text, "next node"]}]}
    assert laptop_seconds(lambda: redact_page(page, KEY)) < 1.0


def test_a_label_far_from_the_end_of_its_node_is_not_carried():
    page = split_page("Password:" + " " * 200 + "see the note below. Thanks", "hunter2")
    assert children_of(redact_page(page, KEY))[1] == "hunter2"


# --- a URL's scheme is not a password (decided 22 November) --------------------------


@pytest.mark.parametrize(
    "s",
    [
        "link:https://d.example/page",
        "Site:HTTP://d.example",
        "proxy:socks5://8.8.8.8:1080",
        "Ссылка:https://d.example/page",
        "DE1:vless://vpn.example.org:443",
    ],
)
def test_a_scheme_after_a_label_is_left_alone(s):
    # Hashed, the link became label:SECRET{...}://site and no URL rule and no
    # extractor could see it.
    assert redact_text(s, KEY) == s


def test_a_real_password_after_a_label_is_still_hashed():
    assert redact_text("admin:hunter2 next", KEY) == "admin:" + hash_secret("hunter2", KEY) + " next"
    assert redact_text("user:https next", KEY) == "user:" + hash_secret("https", KEY) + " next"


def test_the_token_of_a_labelled_link_is_hashed_and_its_scheme_kept():
    out = redact_text("link:https://d.example/in?token=abcdefghijklmnopqrstuvwx", KEY)
    assert out == "link:https://d.example/in?token=" + hash_secret("abcdefghijklmnopqrstuvwx", KEY)


# --- what the second review of 22 November found -------------------------------------


def test_a_proxy_config_with_a_number_too_long_to_read_does_not_raise():
    # json.loads raises ValueError on an integer of more than 4,300 digits,
    # and one such link on a swept page would have stopped the sweep at it
    # every night.
    blob = b64('{"add":"vpn.example.org","port":' + "1" * 4301 + "}")
    assert proxy_endpoint(blob) is None
    assert redact_text(f"vmess://{blob}", KEY) == "vmess://" + hash_secret(blob, KEY)
    out = redact_page(link_page(f"vmess://{blob}"), KEY)
    assert attr_of(out) == "vmess://" + hash_secret(blob, KEY)


def test_a_deeply_nested_page_is_redacted_not_crashed_on():
    node = "WARNING_BANNER " + SESSION_KEY
    for _ in range(400):
        node = {"tag": "b", "children": [node]}
    out = redact_page({"content": [node]}, KEY)
    for _ in range(400):
        out = out["content"][0] if "content" in out else out["children"][0]
    assert SESSION_KEY not in out


def test_a_password_beside_an_already_hashed_user_is_hashed():
    # s3n://ACCESS_KEY_ID:SECRET_KEY@bucket: the key id pattern hashes the
    # user first, and the guard then skipped the whole of it.
    key_id = "AKIAIOSFODNN7EXAMPLE"
    out = redact_text(f"s3n://{key_id}:made-up-secret-access-key@my-bucket/data", KEY)
    assert out == (
        "s3n://" + hash_secret(key_id, KEY) + ":" + hash_secret("made-up-secret-access-key", KEY) + "@my-bucket/data"
    )
    assert redact_text(out, KEY) == out


@pytest.mark.parametrize(
    "s",
    [
        "http://8.8.8.8:8080?contact=a@b.example.org",
        "http://proxy.example.org:3128#owner@example.org",
        "https://example.com:443?next=https://x.example/@name",
    ],
)
def test_a_server_and_port_in_front_of_a_later_at_sign_are_not_credentials(s):
    out = redact_text(s, KEY)
    assert out.startswith(s.split("?")[0].split("#")[0])


def test_session_key_material_after_an_equals_sign_is_hashed():
    s = f"WARNING_BANNER auth_key={SESSION_KEY}"
    assert redact_text(s, KEY) == "WARNING_BANNER auth_key=" + hash_secret(SESSION_KEY, KEY)


def test_two_padded_session_runs_side_by_side_are_both_hashed_in_one_pass():
    first = "Zm9v" * 16 + "Zg=="
    second = "YmFy" * 17
    once = redact_text(f"WARNING_BANNER {first}{second}", KEY)
    assert len(tokens(once)) == 2
    assert redact_text(once, KEY) == once


@pytest.mark.parametrize(
    "token,clear",
    [("pa:ss", "pa"), (f"hunter2,{GOOGLE_KEY}", "hunter2"), ("bob@mail.example.com:hunter2", "bob@mail")],
)
def test_no_part_of_the_first_token_after_a_label_stays_in_clear(token, clear):
    out = children_of(redact_page(split_page("Password:", token + " rest stays"), KEY))[1]
    assert clear not in out
    assert out.endswith(" rest stays")
    again = children_of(redact_page(split_page("Password:", out), KEY))[1]
    assert again == out


def test_a_card_number_with_spaces_inside_a_url_is_settled_in_one_call():
    # Hashing the card removes the spaces that ended the URL; the next pass
    # then saw a longer URL. redact_text now runs its passes a second time
    # when the first changed anything.
    s = "https://x.example/pay?token=4111 1111 1111 1111abcdefghijklmnop&z=1"
    once = redact_text(s, KEY)
    assert redact_text(once, KEY) == once


def test_an_ordinary_jwt_is_still_hashed_wherever_it_sits():
    for before in ("token=", "%3D", "x", '"', "/"):
        assert redact_text(before + JWT, KEY) == before + hash_secret(JWT, KEY)


# --- what the third review of 22 November found --------------------------------------


@pytest.mark.parametrize(
    "s",
    [
        "http://u:p-4111 1111 1111 1111&token=aaaaaaaaaaaaaaaa/aaa@host.example",
        "http://u:p,x:q'r:&token=aaaaaaaaaaaaaaaa/aaa@host.example",
        "WARNING_BANNER http://u:p-" + "A" * 57 + "/4111 1111 1111 1111@host.example",
    ],
)
def test_redaction_runs_until_nothing_changes(s):
    # Each of these needed three rounds: hashing one part made the next
    # pattern match. Two fixed rounds left the user and part of the password
    # in clear, and a later pass then hashed them.
    for link in (False, True):
        once = redact_text(s, KEY, link=link)
        assert redact_text(once, KEY, link=link) == once
    page = {"content": [{"tag": "p", "children": [s]}]}
    once = redact_page(page, KEY)
    assert redact_page(once, KEY) == once


def test_redact_text_stops_after_a_fixed_number_of_rounds():
    from graphwatch.redact import MAX_ROUNDS

    assert 3 <= MAX_ROUNDS <= 10


@pytest.mark.parametrize(
    "before,after",
    [
        ("https://api.telegram.org/bot", "/sendMessage?chat_id=1"),
        ("token ", " ok"),
        ("bot", ""),
        ("=", "&x=1"),
    ],
)
def test_a_bot_token_is_hashed_wherever_it_sits(before, after):
    # The pattern began with a word boundary, and there is none between the
    # word "bot" and the digits in the Bot API's own URL form.
    token = "123456789:AAHfiqksKZ8WmR2zSjiQ7_v4TMAKdiHm9T0"
    assert redact_text(before + token + after, KEY) == before + hash_secret(token, KEY) + after


@pytest.mark.parametrize(
    "s",
    [
        "12345678901234:AAHfiqksKZ8WmR2zSjiQ7_v4TMAKdiHm9T0",  # fourteen digits is not a bot id
        "123456789:AAHfiqksKZ8WmR2zSjiQ7_v4TMAKdiHm9T0x",  # a 36 character tail is not the secret
    ],
)
def test_a_longer_number_or_tail_is_not_a_bot_token(s):
    assert hash_secret("123456789:AAHfiqksKZ8WmR2zSjiQ7_v4TMAKdiHm9T0", KEY) not in redact_text(s, KEY)


def test_a_bot_token_in_a_link_target_is_hashed():
    token = "123456789:AAHfiqksKZ8WmR2zSjiQ7_v4TMAKdiHm9T0"
    out = redact_page(link_page(f"https://api.telegram.org/bot{token}/getMe"), KEY)
    assert attr_of(out) == "https://api.telegram.org/bot" + hash_secret(token, KEY) + "/getMe"


def test_a_jwt_with_a_very_long_header_is_still_hashed():
    long_jwt = "eyJ" + "a" * 3000 + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXBhcnQ"
    for before in (" ", "=", '"', "/"):
        assert redact_text("x" + before + long_jwt, KEY) == "x" + before + hash_secret(long_jwt, KEY)


@pytest.mark.parametrize("scheme", ["socks5", "vless", "ss", "trojan"])
def test_a_proxy_server_and_port_in_front_of_a_later_at_sign_are_left_alone(scheme):
    s = f"{scheme}://8.8.8.8:10800?owner=a@b.example.org"
    assert redact_text(s, KEY).startswith(f"{scheme}://8.8.8.8:10800")
    s = f"{scheme}://proxy.example.org:1080@elsewhere"
    assert redact_text(s, KEY) == s


def test_session_key_material_in_a_link_target_is_hashed_on_a_session_page():
    page = {"content": [{"tag": "p", "children": ["WARNING_BANNER"]}, {"tag": "a", "attrs": {"href": "tg://x?k=" + SESSION_KEY[:200]}, "children": ["open"]}]}
    out = redact_page(page, KEY)
    assert SESSION_KEY[:64] not in out["content"][1]["attrs"]["href"]


@pytest.mark.parametrize(
    "first,second",
    [
        ("login:password:", "admin:hunter2"),
        ("mail:pass=", "hunter2"),
        ("user:pass", ": hunter2"),
        ("https://x.example/a?token=abcdefghijklmnopqrstuvwxпароль:", "hunter2"),
        ("Password:", "pa:ss,more:stuff"),
    ],
)
def test_a_label_node_gives_the_same_page_from_a_stored_copy_and_a_fresh_fetch(first, second):
    # The decision to carry a label is taken from the node as it is stored,
    # and every clear stretch of the first token is hashed, so a second
    # redaction of the stored page changes nothing.
    page = split_page(first, second)
    once = redact_page(page, KEY)
    assert redact_page(once, KEY) == once


def test_every_clear_stretch_of_the_first_token_after_a_label_is_hashed():
    out = children_of(redact_page(split_page("Password:", f"pre,{GOOGLE_KEY},post next"), KEY))[1]
    assert len(tokens(out)) == 3
    assert "pre" not in out and "post" not in out
    assert out.endswith(" next")
