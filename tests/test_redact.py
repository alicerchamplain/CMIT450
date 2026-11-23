"""Tests for graphwatch.redact.

Nothing here touches the network or the disk except the fixtures under
plan/fixtures, which are the redacted form of real pages and so must come
back from redaction unchanged. The HMAC key is any fixed bytes: no digest is
written out here, a test works out the one it expects.

Every secret in this file is made up in the shape that was seen. The ones
with a provider's prefix are put together from pieces, so the file holds no
string a secret scanner would stop a push for.
"""

import base64
import copy
import hmac
import itertools
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
from graphwatch.rules import PROXY_URI_PATTERN

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plan" / "fixtures"

KEY = b"test-key"
OTHER_KEY = b"other-key"

TOKEN = re.compile(r"SECRET\{[0-9a-f]{64}\}")


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def tokens(s: str) -> list[str]:
    return TOKEN.findall(s)


def hashed(s: str, *secrets: str) -> str:
    """s as redaction should leave it: each of the secrets hashed, the rest as it was"""
    if not secrets:
        return s
    pattern = "|".join(re.escape(secret) for secret in secrets)
    return re.sub(pattern, lambda m: hash_secret(m.group(0), KEY), s)


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# --- hash_secret -----------------------------------------------------------


@pytest.mark.parametrize("secret", ["hunter2", "пароль"])
def test_hash_secret_is_the_marker_and_the_hmac_sha256_of_the_secret(secret):
    digest = hmac.new(KEY, secret.encode("utf-8"), "sha256").hexdigest()
    assert MARKER == "SECRET{"
    assert hash_secret(secret, KEY) == "SECRET{" + digest + "}"


def test_hash_secret_differs_between_secrets_and_between_keys():
    # Without the key the database alone cannot be matched against a wordlist.
    assert hash_secret("hunter2", KEY) != hash_secret("hunter3", KEY)
    assert hash_secret("hunter2", KEY) != hash_secret("hunter2", OTHER_KEY)


# --- is_card ---------------------------------------------------------------


@pytest.mark.parametrize(
    "digits",
    [
        "4111111111111111",  # Visa test number
        "5555555555554444",  # Mastercard test number: a doubled 5 is 10
        "378282246310005",  # Amex test number, 15 digits
        "4222222222222",  # 13 digits, the shortest card
    ],
)
def test_is_card_accepts_luhn_valid_numbers(digits):
    assert is_card(digits) is True


def test_is_card_rejects_a_number_one_digit_off():
    assert is_card("4111111111111112") is False


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
    # The pointer in front of /! and the fields after the second are what the
    # classifier reads, so they stay.
    assert redact_text(RAW_HELLO_TITLE, KEY) == (
        "198.13.32.106?rakuten.ne.jp@opportunizz.pro/!"
        + hash_secret("VzQ3NktFUDh0Tm5qdHZSdw==", KEY)
        + "?"
        + hash_secret("T0lpc01IOHdHdGhzNjltOWJBR2Z3MTVNcU14NjdsdTJnNW1Oa3RiaA==", KEY)
        + "?dGViaQ==?eWVsNA=="
    )


@pytest.mark.parametrize(
    "s, keys",
    [
        ("x/!onlyone", ["onlyone"]),
        ("x/!a?b", ["a", "b"]),
        ("x/!a?b?c next", ["a", "b"]),
        ("ends in /! and goes on", []),  # nothing after the /!
    ],
)
def test_storage_keys_with_one_two_or_three_fields_or_none(s, keys):
    assert redact_text(s, KEY) == hashed(s, *keys)


# --- a login and its password ------------------------------------------------
#
# email:password, and the bare login:password of the 2026-11-05 shape pass
# (plan/reports/shape-notes-2026-11-05.md). Only the password is hashed.


@pytest.mark.parametrize(
    "s, password",
    [
        ("login bob.smith@mail.ru:Qwerty123! next", "Qwerty123!"),
        ("list: -.user@mail.example.com:hunter2 ok", "hunter2"),  # punctuation in front of the email is kept
        ("acc admin_01:P@ssw0rd! next", "P@ssw0rd!"),  # no @ in the login
        ("mail user@a+b:hunter2 ok", "hunter2"),  # the login is b: a run can start after a plus
        ("user:https next", "https"),  # a word that is also a scheme is a password without ://
        ("admin:hunter2 https://d.example/login", "hunter2"),  # the link after it is not part of it
        ("admin:hunter2:https://d.example/login", "hunter2"),
        ("http://example.org and bob:pw1@x", "pw1@x"),  # the link before it is not its login
    ],
)
def test_the_password_of_a_login_and_password_pair_is_hashed(s, password):
    assert redact_text(s, KEY) == hashed(s, password)


# --- labelled passwords ------------------------------------------------------


@pytest.mark.parametrize(
    "label, sep",
    [
        ("password", ": "),
        ("Password", "="),
        ("PASS", " = "),
        ("passwd", " = "),
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


@pytest.mark.parametrize("label", ["пароль", "Пароль"])
def test_labelled_password_hyphen_separator_hashes_the_value(label):
    # "пароль-Qwerty123" with a hyphen between label and value, no colon.
    out = redact_text(f"логин: ivan {label}-Qwerty123 ok", KEY)
    assert out == f"логин: ivan {label}-" + hash_secret("Qwerty123", KEY) + " ok"


@pytest.mark.parametrize(
    "label, gap",
    [
        ("ПАРОЛЬ", "\n"),
        ("password", "\n"),
        ("Passwd", " \n"),
        ("pass", "\t\n\t"),
        ("pwd", "\n  "),
    ],
)
def test_labelled_password_on_the_next_line_hashes_the_value(label, gap):
    # Label on one line, value on the next, no separator at all.
    out = redact_text(f"{label}{gap}Qwerty123\nготово", KEY)
    assert out == f"{label}{gap}" + hash_secret("Qwerty123", KEY) + "\nготово"


@pytest.mark.parametrize("indent", ["  ", "\t"])
def test_an_indented_label_on_a_later_line_has_the_password_under_it_hashed(indent):
    # Only the end is compared. Today the indentation in front of the label
    # is lost from the stored text, which is reported as a defect; comparing
    # the whole text would hold that in place.
    out = redact_text(f"логин ivan\n{indent}пароль\n{indent}Qwerty123", KEY)
    assert out.endswith(f"пароль\n{indent}" + hash_secret("Qwerty123", KEY))


@pytest.mark.parametrize(
    "s",
    [
        "Hello,+world!\nIS TIHSaaaaaaaaaaaaaaaaaaaaaaaa",
        "contact bob@example.com for details",  # an email with no password
        # The Vizit pointer has an @ but a slash follows the host: not a credential.
        "https://www.rapid7.com@dust1d9b.boj9h7vg.workers.dev/digitately",
        "passport 123 and bypass: route",  # no separator after "pass"; "bypass" starts mid-word
        "https://t.me/some_bot?start=abc",
        "meet at 12:30 or 9:45",
        "password-protected archive inside",
        "автопароль-2000",
        "пароль- и логин",  # nothing right after the hyphen
        "Note: see below",
        "Пароль\n\nQwerty123",  # an empty line between: the label is a heading
        "4313b32b3805",  # ki06's armed placeholder: a pointer the classifier needs intact
        # No generic base64 rule: encoded pointers must survive.
        "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRoL3RvL3Jlc291cmNl",
    ],
)
def test_text_with_no_credential_in_it_is_left_alone(s):
    assert redact_text(s, KEY) == s


# --- card numbers -------------------------------------------------------------


@pytest.mark.parametrize(
    "formatted, digits",
    [
        ("4111111111111111", "4111111111111111"),
        ("4111 1111 1111 1111", "4111111111111111"),
        ("4111-1111-1111-1111", "4111111111111111"),
        ("4222222222222", "4222222222222"),  # 13 digits, the shortest
        ("4111111111111111110", "4111111111111111110"),  # 19 digits, the longest
    ],
)
def test_card_hashes_luhn_valid_numbers_by_their_bare_digits(formatted, digits):
    out = redact_text(f"card {formatted} end", KEY)
    assert out == "card " + hash_secret(digits, KEY) + " end"


@pytest.mark.parametrize(
    "s",
    [
        "order 4111 1111 1111 1112 shipped",  # fails the Luhn check
        "call +7 916 123 45 67 or 89161234567",
        "id 79927398713",  # passes the check, 11 digits
        "id 41111111111111111115",  # passes the check, 20 digits
        # A number inside a longer token, a hex pointer say, is not cut out of it
        "ab4111111111111111",
        "4111111111111111cd",
    ],
)
def test_card_leaves_other_runs_of_digits_alone(s):
    assert redact_text(s, KEY) == s


# --- fixed-shape tokens --------------------------------------------------------
#
# The bot token, AWS key id and GitHub token patterns are the first ones; the
# rest are shapes the 2026-11-15 survey found stored in clear
# (plan/classification-plan-2026-11-15.md, "Redaction gaps").

AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # the id AWS documents as an example
GITHUB_TOKEN = "ghp_" + "aB3" * 12
GOOGLE_KEY = "AIza" + "Sy" + "A1b2C3d4-5f6G7h8_9j0K1l2M3n4O5p6Q"
SK_KEY = "sk-" + "a1B2_c3D-" * 4 + "e5F6"
DISCORD_TOKEN = "M" + "TIzNDU2_zg5MDEy-zQ1Njc4" + ".Gh_j-l." + "a1B2c3D4_5F6g7H8-9J0k1L2m3N"
JWT = "eyJhbGci_iJIUzI1-iJ9" + ".eyJzdWIi_iIxMjM0-TY3ODkwIn0" + ".c2lnbmF0_XJlLXBh-nQ"
SHORTEST_JWT = "eyJ" + "a1B2c3D4" + ".eyJ" + "a1B2c3D4" + "." + "a1B2c3D4"  # eight characters to a part
BOT_SECRET = "AAHfiqks-Z8WmR2zSjiQ7_v4TMAKdiHm9T0"
BOT_TOKEN = "123456789:" + BOT_SECRET
API_HASH = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    "secret",
    [
        AWS_KEY_ID,
        GOOGLE_KEY,
        SK_KEY,
        "sk-" + "a1B2c3D4" * 4,  # 32 characters after the prefix, the shortest
        DISCORD_TOKEN,  # the shortest id part and the shortest signature
        "N" + "a1B2c" * 5 + ".Gh1jKl." + "a1B2c3D4" * 4,  # the longest id part
        "O" + DISCORD_TOKEN[1:],
    ],
)
def test_fixed_shape_keys_are_hashed_whole(secret):
    out = redact_text(f"key {secret} end", KEY)
    assert out == "key " + hash_secret(secret, KEY) + " end"


@pytest.mark.parametrize("prefix", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
def test_github_tokens_are_hashed_whole(prefix):
    tok = prefix + GITHUB_TOKEN[4:]
    assert redact_text(tok, KEY) == hash_secret(tok, KEY)


@pytest.mark.parametrize(
    "s",
    [
        "x" + AWS_KEY_ID,
        AWS_KEY_ID + "X",
        "x" + GITHUB_TOKEN,
        "x" + GOOGLE_KEY,
        GOOGLE_KEY + "x",
        "task-" + "a" * 40,
        "x" + DISCORD_TOKEN,
    ],
)
def test_a_key_shape_inside_a_longer_word_is_not_a_key(s):
    assert redact_text(s, KEY) == s


@pytest.mark.parametrize(
    "s",
    [
        "ghp_" + "aB3" * 11 + "aB",
        "sk-" + "a1B2c3D4" * 3 + "a1B2c3D",
        "M" + "a1B2c3D4e5F6g7H8i9J0k1" + ".Gh1jKl." + "a1B2c3D4" * 4,  # the id part
        "M" + "a1B2c" * 5 + "a" + ".Gh1jKl." + "a1B2c3D4" * 4,  # the id part, one too long
        DISCORD_TOKEN[:-1],  # the signature
        # A JWT with seven characters after eyJ, at the start of a run and inside one
        "eyJa1B2c3D.eyJa1B2c3D4.a1B2c3D4 xeyJa1B2c3D.eyJa1B2c3D4.a1B2c3D4",
        "eyJa1B2c3D4.eyJa1B2c3D.a1B2c3D4",  # its payload
        "eyJa1B2c3D4.eyJa1B2c3D4.a1B2c3D",  # its signature
        "1234567:" + BOT_SECRET,  # the bot id
        "api_hash: " + API_HASH[:-1],
        "api_hash: " + API_HASH + "0",  # a longer hex run is not cut in half
    ],
)
def test_a_key_shape_one_character_short_is_not_a_key(s):
    assert redact_text(s, KEY) == s


@pytest.mark.parametrize(
    "before, jwt, after",
    [
        ("key ", JWT, " end"),
        ("x", JWT, ""),  # in the middle of a run of token characters
        ("https://dating.example.com/l/", JWT, "/open"),  # the host of a login link is kept
        ("key ", SHORTEST_JWT, " end"),
        ("x", SHORTEST_JWT, " end"),
    ],
)
def test_a_jwt_is_hashed_wherever_it_sits(before, jwt, after):
    assert redact_text(before + jwt + after, KEY) == before + hash_secret(jwt, KEY) + after


def test_a_jwt_with_a_very_long_header_is_still_hashed():
    # Inside a run the header is read to 1024 characters only; at the start
    # of one it is read to its end.
    long_jwt = "eyJ" + "aB3_-" * 600 + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXBhcnQ"
    for before in (" ", "=", '"', "/"):
        assert redact_text("x" + before + long_jwt, KEY) == "x" + before + hash_secret(long_jwt, KEY)


@pytest.mark.parametrize(
    "before, token, after",
    [
        # The pattern began with a word boundary, and there is none between
        # the word "bot" and the digits in the Bot API's own URL form.
        ("https://api.telegram.org/bot", BOT_TOKEN, "/sendMessage?chat_id=1"),
        ("token ", BOT_TOKEN, " ok"),
        ("=", BOT_TOKEN, "&x=1"),  # the value of a parameter
        ("", "12345678:" + BOT_SECRET, ""),  # eight digits, the shortest bot id
        ("", "1234567890:" + BOT_SECRET, ""),  # ten, the longest
    ],
)
def test_a_bot_token_is_hashed_wherever_it_sits(before, token, after):
    assert redact_text(before + token + after, KEY) == before + hash_secret(token, KEY) + after


@pytest.mark.parametrize(
    "s",
    [
        "12345678901:" + BOT_SECRET,  # eleven digits is not a bot id
        "12345678901234:" + BOT_SECRET,  # nor is fourteen
        BOT_TOKEN + "x",  # a 36 character tail is not the secret
        BOT_TOKEN + "-",
    ],
)
def test_a_longer_number_or_tail_is_not_a_bot_token(s):
    assert redact_text(s, KEY) == s


@pytest.mark.parametrize("label", ['"api_hash": "', "API_HASH = '"])
def test_api_hash_value_is_hashed_and_the_label_kept(label):
    out = redact_text(f"api_id: 1234567 {label}{API_HASH}", KEY)
    assert out == f"api_id: 1234567 {label}" + hash_secret(API_HASH, KEY)


# --- proxy links ---------------------------------------------------------------
#
# The user id or password is hashed and the server and port, which Breadth
# counts, are kept.

UUID = "0f1e2d3c-4b5a-6978-8695-a4b3c2d1e0f9"
VMESS_BLOB = b64('{"v":"2","add":"vpn.example.org","port":"443","id":"' + UUID + '"}')
SS_BLOB = b64("aes-256-gcm:made-up-password@203.0.113.7:8388")
# method:password only, unpadded; the server comes after the @ in the link itself
SS_USERINFO = b64("aes-256-gcm:12345").rstrip("=")

PROXY_SCHEMES = ["vless", "trojan", "ss", "ssr", "socks", "socks5", "hysteria", "hysteria2", "tuic"]


@pytest.mark.parametrize("scheme", PROXY_SCHEMES + ["VLESS"])
def test_every_scheme_the_rules_call_a_proxy_link_has_its_user_id_hashed(scheme):
    assert PROXY_URI_PATTERN.search(f"{scheme}://x")
    out = redact_text(f"{scheme}://made-up-password@203.0.113.7:1080", KEY)
    assert out == f"{scheme}://" + hash_secret("made-up-password", KEY) + "@203.0.113.7:1080"


@pytest.mark.parametrize(
    "link, user_id",
    [
        (f"vless://{UUID}@vpn.example.org:443?security=tls#home", UUID),
        ("trojan://pass-wd1@vpn.example.org:443", "pass-wd1"),  # eight characters, the shortest
    ],
)
def test_a_proxy_user_id_is_hashed_and_the_server_and_port_kept(link, user_id):
    assert redact_text(link, KEY) == hashed(link, user_id)


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


@pytest.mark.parametrize(
    "scheme, blob",
    [
        ("vmess", "A" * 30 + "-_"),  # decodes, to bytes that are not text
        ("VMESS", "A" * 9 + "+/" + "A" * 9),  # 20 characters, the shortest
    ],
)
def test_a_config_that_does_not_decode_is_hashed_with_no_endpoint(scheme, blob):
    assert redact_text(f"{scheme}://{blob}", KEY) == f"{scheme}://" + hash_secret(blob, KEY)


def test_a_secret_shaped_host_in_a_vmess_config_is_not_written_out():
    # A JWT is dotted labels too. It would be hashed by the next pass, so it
    # is not put into the text by this one.
    blob = b64('{"add":"' + JWT.replace("_", "a") + '","port":"443"}')
    out = redact_text(f"vmess://{blob}", KEY)
    assert out == "vmess://" + hash_secret(blob, KEY)
    assert redact_text(out, KEY) == out


@pytest.mark.parametrize(
    "s",
    [
        "socks5://203.0.113.7:1080 owner a@b.example",
        # Under the lengths the patterns ask for today, eight characters in
        # front of the @ and twenty of config. These two rows hold the limits
        # where they are; they do not say a shorter secret ought to stay.
        "socks5://abcdefg@proxyhost",
        "ss://" + "A" * 19,
        # wss is not ss
        "wss://verylonghostnamewithnodots/path",
        "wss://long-user-name@host.example",
    ],
)
def test_a_proxy_link_with_no_user_id_in_it_is_left_alone(s):
    assert redact_text(s, KEY) == s


@pytest.mark.parametrize(
    "config, endpoint",
    [
        ('{"add":"[2001:db8::1]","port":"443"}', "[2001:db8::1]:443"),
        # Capitals, digits and dashes in a host, a one letter label, a port as a number
        ('{"add":"X.VPN-1.Example.xn--p1ai","port":10808}', "X.VPN-1.Example.xn--p1ai:10808"),
    ],
)
def test_proxy_endpoint_reads_an_ipv6_server_and_a_host_of_any_plain_spelling(config, endpoint):
    assert proxy_endpoint(b64(config)) == endpoint


@pytest.mark.parametrize(
    "config",
    [
        "plain.example:12345",  # no @: the server is not in the config
        '{"add":"vpn.example.org"}',  # no port
        '{"add":"vpn.example.org","port":"100000"}',
        '{"add":"no-dot-here","port":"443"}',
        '{"add":"a b.example.org","port":"443"}',  # a space in the host
        '{"add":"x.example.org/path","port":"443"}',  # a path after it
        '{"add":"SECRET{ab}.example.org","port":"443"}',
        '{"add":"vpn..example.org","port":"443"}',
        '{"add":"vpn.example.","port":"443"}',
        '{"add":"[]","port":"443"}',
    ],
)
def test_proxy_endpoint_is_none_for_anything_but_a_plain_host_and_port(config):
    assert proxy_endpoint(b64(config)) is None


def test_proxy_endpoint_is_none_for_text_that_is_not_base64():
    assert proxy_endpoint("!!!not base64!!!") is None


def test_a_proxy_config_that_json_cannot_read_does_not_raise():
    # json.loads raises ValueError on an integer of more than 4,300 digits,
    # and one such link on a swept page would have stopped the sweep at it
    # every night.
    blob = b64('{"add":"vpn.example.org","port":' + "1" * 4301 + "}")
    assert proxy_endpoint(blob) is None
    assert redact_text(f"vmess://{blob}", KEY) == "vmess://" + hash_secret(blob, KEY)
    # And RecursionError on lists nested deeper than it will follow. On
    # Python 3.14 that is deeper than a 64 KB page can hold, so this is the
    # except clause being checked, not a page that could be met.
    assert proxy_endpoint(b64('{"add":' + "[" * 200000)) is None


# user:password in a URL of any scheme


@pytest.mark.parametrize(
    "scheme",
    [
        "http",
        "HTTP",
        "socks5",
        "hysteria2",  # nine characters; a scheme may be as long as 16
        "ss",  # two characters, the shortest scheme
    ],
)
def test_url_credentials_are_hashed_and_the_host_and_port_kept(scheme):
    out = redact_text(f"proxy {scheme}://bob:pw1@203.0.113.7:8080 ok", KEY)
    assert out == f"proxy {scheme}://" + hash_secret("bob:pw1", KEY) + "@203.0.113.7:8080 ok"


def test_a_password_beside_an_already_hashed_user_is_hashed():
    # s3n://ACCESS_KEY_ID:SECRET_KEY@bucket: the key id pattern hashes the
    # user first, and the guard then skipped the whole of it.
    out = redact_text(f"s3n://{AWS_KEY_ID}:made-up-secret-access-key@my-bucket/data", KEY)
    assert out == (
        "s3n://" + hash_secret(AWS_KEY_ID, KEY) + ":" + hash_secret("made-up-secret-access-key", KEY) + "@my-bucket/data"
    )
    assert redact_text(out, KEY) == out


@pytest.mark.parametrize(
    "s",
    [
        # The decoy of a spoof has no colon in it: it must survive for the rules.
        "https://www.tenable.com@agfc.harper18.workers.dev/",
        # A server and its port, with an @ somewhere after them
        "socks5://proxy.example.org:1080@elsewhere",
        "socks5://8.8.8.8:10800?owner=a@b.example.org",
        "socks5://8.8.8.8:10800#owner@b.example.org",
        "trojan://vpn.example.org/a@b",
        "https://example.com:8080/users/@name",
        # A colon and an @ in the path, the query or the fragment
        "https://example.com/users/a:b@c",
        "http://example.org?t=1:2@c",
        "http://example.org#t=1:2@c",
        "http://localhost:3000/admin",  # no @ at all
    ],
)
def test_a_url_with_no_login_in_front_of_its_host_is_left_alone(s):
    assert redact_text(s, KEY) == s


# --- secrets in the parameters of a link ----------------------------------------

PROXY_SECRET = "dd" + "0123456789abcdef" * 2
LOGIN_TOKEN = "abcdefghijklmnopqrstuvwx"
LOGIN_LINK = "https://d.example/autologin?token=" + LOGIN_TOKEN


@pytest.mark.parametrize(
    "link, secret",
    [
        (f"https://t.me/proxy?server=203.0.113.7&port=443&secret={PROXY_SECRET}", PROXY_SECRET),
        # Base64 beside the hex ones: padded, percent-encoded, in the URL-safe alphabet
        ("tg://proxy?server=p.example.org&port=443&secret=7gAAAAAA+AAAA/AAAAAAAAAAAA==", "7gAAAAAA+AAAA/AAAAAAAAAAAA=="),
        ("tg://proxy?server=p.example.org&port=443&secret=7gAAAAAA%2BAAAA%2FAAAAAAAAAA", "7gAAAAAA%2BAAAA%2FAAAAAAAAAA"),
        ("tg://proxy?server=p.example.org&port=443&secret=7gAAAAAA-AAAA_AAAAAAAAAAAAA", "7gAAAAAA-AAAA_AAAAAAAAAAAAA"),
        # The first parameter, and 16 characters, the shortest
        ("https://t.me/proxy?secret=0123456789abcdef&server=203.0.113.7&port=443", "0123456789abcdef"),
        ("https://t.me/proxy#SECRET=0123456789abcdef0123", "0123456789abcdef0123"),
    ],
)
def test_telegram_proxy_secret_is_hashed_and_the_server_kept(link, secret):
    assert redact_text(link, KEY) == hashed(link, secret)


@pytest.mark.parametrize(
    "name", ["token", "auth", "access_token", "login_token", "session", "sid", "code"]
)
def test_login_token_in_a_url_is_hashed_and_the_link_kept(name):
    token = "a1b2c3d4e5f6a7b8c9d0"
    out = redact_text(f"go https://dating.example.com/in?u=7&{name}={token} now", KEY)
    assert out == (
        f"go https://dating.example.com/in?u=7&{name}=" + hash_secret(token, KEY) + " now"
    )


@pytest.mark.parametrize(
    "link, token",
    [
        # Plain base64 is hashed to its end, not to its first plus
        ("https://d.example/login?token=YWJjZGVmZ2hpamtsbW5vcA+/xyzABCDEFGHIJKLMNOP==", "YWJjZGVmZ2hpamtsbW5vcA+/xyzABCDEFGHIJKLMNOP=="),
        ("https://d.example/in?token=ab%2Fcd.ef_gh:ij~kl-mnopqrst next", "ab%2Fcd.ef_gh:ij~kl-mnopqrst"),
        (f"https://d.example/#access_token={LOGIN_TOKEN}", LOGIN_TOKEN),  # in the fragment
        (f"https://d.example/in?token={LOGIN_TOKEN}&lang=en", LOGIN_TOKEN),  # the next parameter stays
        (f"HTTPS://D.EXAMPLE/in?TOKEN={LOGIN_TOKEN}", LOGIN_TOKEN),
        ("http://d.example/in?sid=abcdefghijklmnop", "abcdefghijklmnop"),  # 16 characters, the shortest
        # Hashed, the scheme of a labelled link left label:SECRET{...}://site
        (f"link:https://d.example/in?token={LOGIN_TOKEN}", LOGIN_TOKEN),
        # The word SECRET at the end of a value is not a hash that follows it
        ("https://d.example/in?token=abcdefghijklmnopSECRET next", "abcdefghijklmnopSECRET"),
    ],
)
def test_a_login_token_is_hashed_to_its_end_whatever_is_in_it(link, token):
    assert redact_text(link, KEY) == hashed(link, token)


@pytest.mark.parametrize(
    "link, values",
    [
        # The dating autologin shape: the login token is in a parameter named key.
        (
            "https://m.dating.example.com/autologin/?key=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d&uniqmessageId=f0e1d2c3b4a5f6e7d8c9&loc=en",
            ["0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d", "f0e1d2c3b4a5f6e7d8c9"],
        ),
        ("https://d.example/autologin#key=0a1b2c3d4e5f6a7b", ["0a1b2c3d4e5f6a7b"]),  # 16 characters
        (
            "https://d.example/AutoLogin?login-key=Ab%2Fcd.ef_gh:ij+kl/mn=op~qr-st&user.id=0A1B2C3D4E5F6A7B8C9D&n=0a1b2c3d4e5f6a7",
            ["Ab%2Fcd.ef_gh:ij+kl/mn=op~qr-st", "0A1B2C3D4E5F6A7B8C9D"],  # the 15 characters of n stay
        ),
        ("https://d.example/token-login?k=0a1b2c3d4e5f6a7b8c9d", ["0a1b2c3d4e5f6a7b8c9d"]),
    ],
)
def test_an_autologin_link_has_every_long_value_hashed(link, values):
    assert redact_text(link, KEY) == hashed(link, *values)


@pytest.mark.parametrize(
    "s",
    [
        "https://t.me/proxy?secret=0123456789abcde",  # 15 characters
        "https://example.com/watch?code=abcdefghijklmno",
        "set token=a1b2c3d4e5f6a7b8c9d0 in the form",  # not in a URL
        "https://maps.example.com/embed?key=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",  # not a login link
    ],
)
def test_a_parameter_that_is_not_a_long_login_token_is_left_alone(s):
    assert redact_text(s, KEY) == s


@pytest.mark.parametrize("between", [" ", '"', "'", "<", ">"])
def test_a_link_ends_where_the_next_one_begins(between):
    # The key of the ordinary link is not the autologin link's to lose.
    s = "https://maps.example.com/embed?key=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d" + between + "https://d.example/autologin/"
    assert redact_text(s, KEY) == s


def test_a_parameter_value_that_runs_into_a_hash_is_left_alone():
    # The bare login pattern hashed pw; name:SECRET is not a new 16 character token.
    once = redact_text("https://d.example/l?auth=longusername:pw", KEY)
    assert once == "https://d.example/l?auth=longusername:" + hash_secret("pw", KEY)
    assert redact_text(once, KEY) == once


# --- Telegram session exports ----------------------------------------------------

SESSION_KEY = "ab12" * 64  # 256 hex characters, the size of an auth key


@pytest.mark.parametrize(
    "s, runs",
    [
        (f'WARNING_BANNER\n"dc2_auth_key": "{SESSION_KEY}",\n"user_auth": 1', [SESSION_KEY]),
        (f"WARNING_BANNER auth_key={SESSION_KEY}", [SESSION_KEY]),
        ("WARNING_BANNER " + "Zm9v+/8x" * 8, ["Zm9v+/8x" * 8]),  # base64, and 64 characters, the shortest
        # Two padded runs side by side are both hashed in one pass
        ("WARNING_BANNER " + "Zm9v" * 16 + "Zg==" + "YmFy" * 17, ["Zm9v" * 16 + "Zg==", "YmFy" * 17]),
    ],
)
def test_session_key_material_is_hashed_in_a_session_export(s, runs):
    assert redact_text(s, KEY) == hashed(s, *runs)


def test_the_session_flag_hashes_a_run_in_text_that_has_no_banner():
    out = redact_text(SESSION_KEY, KEY, session=True)
    assert out == hash_secret(SESSION_KEY, KEY)


@pytest.mark.parametrize(
    "s",
    [
        # No generic rule for long runs: an encoded pointer has to survive.
        f'"dc2_auth_key": "{SESSION_KEY}"',
        "WARNING_BANNER " + "a" * 63,
    ],
)
def test_a_long_run_outside_a_session_export_or_a_shorter_one_in_it_is_left_alone(s):
    assert redact_text(s, KEY) == s


# --- redact_text in general -------------------------------------------------------


def test_redact_text_hashes_each_secret_of_a_text_that_holds_several():
    s = "pw password: hunter2 mail b@c.ru:Qwerty! card 4111111111111111 aws AKIAIOSFODNN7EXAMPLE"
    assert redact_text(s, KEY) == hashed(s, "hunter2", "Qwerty!", "4111111111111111", AWS_KEY_ID)


def test_every_line_of_a_long_list_of_logins_is_hashed():
    # Twelve lines, more than redact_text has rounds. A pattern that hashed
    # one match and stopped would pass every shorter text here, because the
    # next round hashes the next one; the ninth line would stay in clear.
    lines = [
        f"user{i}@mail.example.com:Qwerty{i}! login{i}:hunter{i} password: letmein{i}"
        for i in range(12)
    ]
    expected = [
        f"user{i}@mail.example.com:"
        + hash_secret(f"Qwerty{i}!", KEY)
        + f" login{i}:"
        + hash_secret(f"hunter{i}", KEY)
        + " password: "
        + hash_secret(f"letmein{i}", KEY)
        for i in range(12)
    ]
    assert redact_text("\n".join(lines), KEY) == "\n".join(expected)


@pytest.mark.parametrize(
    "s",
    [
        RAW_HELLO_TITLE,
        "bob@example.com:secret",
        "пароль: hunter2",
        "пароль-Qwerty123",
        "ПАРОЛЬ\nQwerty123",
        "admin_01:P@ssw0rd!",
        f"https://dating.example.com/l/{JWT}",
        f'"api_hash": "{API_HASH}"',
        f"vless://{UUID}@vpn.example.org:443?security=tls",
        f"vmess://{VMESS_BLOB}",
        f"ss://{SS_USERINFO}@203.0.113.7:8388#tag",
        "http://bobby:hunter2@203.0.113.7:8080",
        "https://dating.example.com/in?token=a1b2c3d4e5f6a7b8c9d0",
        f"WARNING_BANNER {SESSION_KEY}",
        # What one pattern leaves is what the next one reads
        "https://d.example/l?auth=longusername:pw",
        "https://m.dating.example.com/autologin/?key=name:password1&x=1",
        "https://d.example/in?pass=hunter2hunter2hunter2&token=abcdefghijklmnopqrstuvwx",
        "bob@mail.example.com:https://d.example/in?token=abcdefghijklmnopqrstuvwx",
        "link:https://d.example/in?token=abcdefghijklmnopqrstuvwx",
        "pass:word user:name key:value 12:30",
    ],
)
def test_redact_text_twice_is_redact_text_once(s):
    once = redact_text(s, KEY)
    assert once != s
    assert redact_text(once, KEY) == once
    assert redact_text(once, KEY, link=True) == redact_text(redact_text(once, KEY, link=True), KEY, link=True)


THREE_ROUNDS = "http://u:p-4111 1111 1111 1111&token=aaaaaaaaaaaaaaaa/aaa@host.example"


@pytest.mark.parametrize(
    "s",
    [
        THREE_ROUNDS,
        "http://u:p,x:q'r:&token=aaaaaaaaaaaaaaaa/aaa@host.example",
        "WARNING_BANNER http://u:p-" + "A" * 57 + "/4111 1111 1111 1111@host.example",
        # Hashing the card removes the spaces that ended the URL
        "https://x.example/pay?token=4111 1111 1111 1111abcdefghijklmnop&z=1",
    ],
)
def test_redaction_runs_until_nothing_changes(s):
    # The first three needed three rounds: hashing one part made the next
    # pattern match. Two fixed rounds left the user and part of the password
    # in clear, and a later pass then hashed them.
    for link in (False, True):
        once = redact_text(s, KEY, link=link)
        assert redact_text(once, KEY, link=link) == once
    page = {"content": [{"tag": "p", "children": [s]}]}
    once = redact_page(page, KEY)
    assert redact_page(once, KEY) == once


def test_redact_text_gives_up_after_max_rounds(monkeypatch):
    # Held to one round, the text above is not settled: it is the rounds
    # that settle it, and the limit on them is kept.
    settled = redact_text(THREE_ROUNDS, KEY)
    monkeypatch.setattr("graphwatch.redact.MAX_ROUNDS", 1)
    assert redact_text(THREE_ROUNDS, KEY) != settled


def test_a_snapshot_stored_under_the_old_patterns_gets_its_user_id_hashed():
    # Before 22 November the email:password rule read uuid@host:port as an
    # email and hashed the port. Re-redacting such a snapshot hashes the user
    # id; the port it lost cannot come back.
    old_port = hash_secret("443?security=tls", KEY)
    stored = f"vless://{UUID}@vpn.example.org:{old_port}"
    out = redact_text(stored, KEY)
    assert out == f"vless://{hash_secret(UUID, KEY)}@vpn.example.org:{old_port}"


# --- redact_page -------------------------------------------------------------------


def test_redact_page_redacts_title_description_and_content_and_keeps_the_rest():
    page = {
        "path": "x-01-01",
        "url": "u",
        "views": 7,
        "author_name": "n",
        "title": "password: a",
        "description": "password: b",
        "content": [{"tag": "p", "children": ["password: c"]}],
    }
    assert redact_page(page, KEY) == {
        "path": "x-01-01",
        "url": "u",
        "views": 7,
        "author_name": "n",
        "title": "password: " + hash_secret("a", KEY),
        "description": "password: " + hash_secret("b", KEY),
        "content": [{"tag": "p", "children": ["password: " + hash_secret("c", KEY)]}],
    }


def test_redact_page_does_not_mutate_its_input():
    page = {
        "path": "x-01-01",
        "title": "password: a",
        "description": None,
        "content": [
            {"tag": "p", "children": [{"tag": "b", "children": ["password: c"]}]},
            {"tag": "a", "attrs": {"href": LOGIN_LINK}, "children": ["click here"]},
        ],
    }
    before = copy.deepcopy(page)
    assert redact_page(page, KEY) != before
    assert page == before


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


def test_redact_page_leaves_what_is_not_text_as_it_is():
    page = {"content": [{"tag": "br"}, {"tag": "p", "children": [{"tag": "hr"}, 7]}]}
    assert redact_page(page, KEY) == page


def test_redact_page_tolerates_missing_or_null_title_and_description():
    out = redact_page({"title": None, "content": []}, KEY)
    assert out["title"] is None
    assert out["content"] == []
    out = redact_page({"content": []}, KEY)
    assert out.get("title") is None
    assert out.get("description") is None


def test_a_deeply_nested_page_is_redacted_not_crashed_on():
    # 400 levels, with the banner at the bottom of them. The node walk calls
    # itself for every level, so this is not the deepest page there can be:
    # past about 1,000 levels redaction raises and the sweep skips the page.
    node = "WARNING_BANNER " + SESSION_KEY
    for _ in range(400):
        node = {"tag": "b", "children": [node]}
    out = redact_page({"content": [node]}, KEY)["content"][0]
    for _ in range(400):
        out = out["children"][0]
    assert out == "WARNING_BANNER " + hash_secret(SESSION_KEY, KEY)


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


# --- a label in one text node, its secret in the next -------------------------------


def split_page(*children) -> dict:
    return {"content": [{"tag": "p", "children": list(children)}]}


def children_of(page: dict) -> list:
    return page["content"][0]["children"]


@pytest.mark.parametrize(
    "label, text",
    [
        ("Password:", " hunter2 ok"),
        # <strong>Password</strong>: hunter2, the separator opens the next node.
        ("Password", ": hunter2 ok"),
        ("Password", ":hunter2"),
        # What comes after the first line of the node is kept
        ("Password", " = hunter2\nsecond line"),
        ("Password:", "hunter2\nsecond line"),
    ],
)
def test_a_password_in_the_node_after_its_label_is_hashed(label, text):
    page = split_page({"tag": "strong", "children": [label]}, text)
    out = children_of(redact_page(page, KEY))
    assert out == [{"tag": "strong", "children": [label]}, hashed(text, "hunter2")]


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


@pytest.mark.parametrize(
    "first, second",
    [
        ({"tag": "strong", "children": ["Password"]}, " reset is easy"),  # no separator opens the next node
        ("Password reset is easy.", ": click the link"),  # the label does not end its node
        ("see the bypass:", "route 66"),  # the end of another word
    ],
)
def test_the_next_node_is_left_alone_unless_a_label_and_its_separator_come_right_before_it(first, second):
    assert children_of(redact_page(split_page(first, second), KEY))[1] == second


def test_a_label_in_the_title_does_not_reach_the_content():
    page = {"title": "Password:", "content": [{"tag": "p", "children": ["hello"]}]}
    assert redact_page(page, KEY) == page


# After a label the whole first token is the secret, whatever redaction has
# already done to it. The 22 November reviews found a stored copy and a fresh
# fetch of the same page coming out differently.


def test_a_split_label_gives_the_same_result_from_a_stored_copy_and_a_fresh_fetch():
    fresh = split_page({"tag": "strong", "children": ["Password:"]}, "bob@mail.example.com:hunter2")
    stored = split_page(
        {"tag": "strong", "children": ["Password:"]},
        "bob@mail.example.com:" + hash_secret("hunter2", KEY),  # as the old code left it
    )
    assert redact_page(fresh, KEY) == redact_page(stored, KEY)
    # What is still in clear in front of the hash is hashed too
    assert children_of(redact_page(fresh, KEY))[1] == hash_secret("bob@mail.example.com:", KEY) + hash_secret("hunter2", KEY)


def test_a_token_after_a_label_that_redaction_already_hashed_is_not_hashed_again():
    page = split_page("Password:", GOOGLE_KEY)
    assert children_of(redact_page(page, KEY))[1] == hash_secret(GOOGLE_KEY, KEY)


def test_every_clear_stretch_of_the_first_token_after_a_label_is_hashed():
    out = children_of(redact_page(split_page("Password:", f"pre,{GOOGLE_KEY},post next"), KEY))[1]
    assert out == hash_secret("pre,", KEY) + hash_secret(GOOGLE_KEY, KEY) + hash_secret(",post", KEY) + " next"


@pytest.mark.parametrize(
    "token,clear",
    [("pa:ss", "pa"), ("bob@mail.example.com:hunter2", "bob@mail")],
)
def test_no_part_of_the_first_token_after_a_label_stays_in_clear(token, clear):
    out = children_of(redact_page(split_page("Password:", token + " rest stays"), KEY))[1]
    assert clear not in out
    assert out.endswith(" rest stays")
    again = children_of(redact_page(split_page("Password:", out), KEY))[1]
    assert again == out


@pytest.mark.parametrize(
    "first,second",
    [
        ({"tag": "strong", "children": ["Password"]}, ": hunter2 ok"),
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
    assert once != page
    assert redact_page(once, KEY) == once


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


def test_the_banner_covers_the_title_and_the_description_too():
    page = {
        "title": SESSION_KEY,
        "description": SESSION_KEY,
        "content": [{"tag": "p", "children": ["WARNING_BANNER"]}],
    }
    out = redact_page(page, KEY)
    assert out["title"] == out["description"] == hash_secret(SESSION_KEY, KEY)


def test_a_page_without_the_banner_keeps_its_long_runs():
    page = {"content": [{"tag": "p", "children": [SESSION_KEY]}]}
    assert redact_page(page, KEY) == page


# --- link targets -------------------------------------------------------------------
#
# A link's target is stored with the content, so it is redacted too. The
# first review of 22 November found targets copied as they came.


def link_page(href: str, text: str = "click here") -> dict:
    return {"content": [{"tag": "p", "children": [{"tag": "a", "attrs": {"href": href}, "children": [text]}]}]}


def attr_of(page: dict) -> str:
    return page["content"][0]["children"][0]["attrs"]["href"]


def test_a_login_token_in_a_link_target_is_hashed():
    out = redact_page(link_page(LOGIN_LINK), KEY)
    assert attr_of(out) == "https://d.example/autologin?token=" + hash_secret(LOGIN_TOKEN, KEY)
    assert out["content"][0]["children"][0]["children"] == ["click here"]


@pytest.mark.parametrize(
    "url",
    [
        LOGIN_LINK,
        f"https://t.me/proxy?server=203.0.113.7&port=443&secret={PROXY_SECRET}",
        f"vless://{UUID}@vpn.example.org:443",
        f"vmess://{VMESS_BLOB}",
        f"https://dating.example.com/l/{JWT}",
        "http://bobby:hunter2@203.0.113.7:8080",
        f"https://api.telegram.org/bot{BOT_TOKEN}/getMe",
        "https://x.example/login.php?user=bob&password=hunter2",
        "https://x.example/in?u=bob@mail.example.com:hunter2",
        "https://x.example/pay?cc=4111111111111111",
        f"https://x.example/tg?api_hash={API_HASH}",
    ],
)
def test_a_secret_is_hashed_in_a_link_target_as_it_is_in_the_link_text(url):
    # Telegraph turns a pasted URL into <a href=URL>URL</a>. The second
    # review found the text hashed and the href beside it in clear.
    out = redact_page(link_page(url, text=url), KEY)
    text = out["content"][0]["children"][0]["children"][0]
    assert attr_of(out) == text == redact_text(url, KEY)
    assert len(tokens(text)) == 1


def test_an_image_source_is_redacted_though_the_node_has_no_children():
    page = {"content": [{"tag": "img", "attrs": {"src": LOGIN_LINK}}]}
    out = redact_page(page, KEY)
    assert out["content"] == [{"tag": "img", "attrs": {"src": hashed(LOGIN_LINK, LOGIN_TOKEN)}}]


def test_session_key_material_in_a_link_target_is_hashed_on_a_session_page():
    page = {"content": [{"tag": "p", "children": ["WARNING_BANNER"]}, {"tag": "a", "attrs": {"href": "tg://x?k=" + SESSION_KEY}, "children": ["open"]}]}
    out = redact_page(page, KEY)
    assert out["content"][1]["attrs"]["href"] == "tg://x?k=" + hash_secret(SESSION_KEY, KEY)


@pytest.mark.parametrize("href", ["mailto:bob@mail.example.com", "tel:+15550100"])
def test_the_bare_login_pattern_does_not_run_on_a_link_target(href):
    # In text, word:word is the bare login shape. In a target it is the URL.
    # The first line is not a wish that mailto: and tel: be hashed in text:
    # it shows the pattern takes them there today, so that the second line
    # is the link flag's doing. If the pattern stops taking them, find
    # another target that it does take.
    assert redact_text(href, KEY) != href
    assert attr_of(redact_page(link_page(href), KEY)) == href


def test_other_attributes_a_node_without_attrs_and_a_target_that_is_not_text_are_untouched():
    node = {"tag": "a", "attrs": {"href": "u", "target": LOGIN_LINK, "id": 7}, "children": ["x"]}
    rest = [{"tag": "p", "children": ["y"]}, {"tag": "a", "attrs": {"href": None}, "children": ["z"]}]
    out = redact_page({"content": [node] + rest}, KEY)
    assert out["content"][0]["attrs"] == node["attrs"]
    assert out["content"][1:] == rest


# --- a URL's scheme is not a password (decided 22 November) --------------------------


@pytest.mark.parametrize(
    "s",
    [
        "link:https://d.example/page",
        "Site:HTTP://d.example",  # a scheme in capitals is a scheme too
        "proxy:socks5://8.8.8.8:1080",
    ],
)
def test_a_scheme_after_a_label_is_left_alone(s):
    # Hashed, the link became label:SECRET{...}://site and no URL rule and no
    # extractor could see it.
    assert redact_text(s, KEY) == s


# --- the bare login pattern reads each run once (22 November) ------------------------
#
# The pattern as written on 5 November matched the right text but tried every
# way of splitting a run of login characters around a letter, so one long
# token took seconds. It was rewritten to read a run once. The old pattern is
# kept here as the reference: the rewrite has to hash exactly what it hashed.

# One thing was changed on purpose the same day: a URL's scheme is no longer
# taken for a password (link:https://site). The reference carries that one
# guard, (?![^\s:]+://), and is otherwise the pattern of 5 November.
#
# These tests compare the pattern with the reference and with nothing else,
# so they hold what the reference gets wrong as well: a port followed by more
# text is hashed (host:8080 is up), and in a:b:c:d only b is. A fix to either
# has to be made in the reference too, as the scheme guard was. The same goes
# for the email reference further down, which hashes the port of user@host:21.
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
        "user@a.b+c:secret1 x@a-b+c:secret2",  # and the plus need not be the run's second character
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


# --- long runs ------------------------------------------------------------------------

# A page is up to 64 KB and whoever posts it chooses every character. Each of
# these is one text node that some pattern, or the search for a label at the
# end of a node, once took seconds to read: 6 to 15 for the old bare login
# pattern and about 4 for the old email one.
LONG_RUNS = {
    "letters": "A" * 60000,
    "digits": "1234567890" * 6000,
    "dotted labels": "ab.cd-" * 10000,
    "pluses": "a+" * 30000,
    "an @ and pluses": "@" + "a+" * 30000 + "1:x",
    "digits and a colon": "1" * 60000 + ":x",
    "punctuation and an email": ".+-" * 20000 + "@x.com:pw",
    "an @ and dotted labels": "a@" + "ab.cd-" * 10000,
    "at signs": "a@" * 30000,
    "colons": "word:" * 12000,
    "a long query": "https://example.com/?a=" + "x" * 60000,
    "a long path": "https://example.com/" + "a/" * 30000,
    "a session export": "WARNING_BANNER " + "ab.cd-" * 10000,
    "a label, spaces and a word": "pass" + " " * 64000 + "x",
    # Not the row above again: no-break spaces, which are whitespace to a
    # pattern and are not the character a fix that only looks for " " sees
    "a label, no-break spaces and a word": "pass" + "\u00a0" * 64000 + "x",
    "labels": "pass " * 12000,
    "a label and spaces": "password:" + " " * 64000,
    "dots in front of a scheme": "a.a." * 16000 + "://x:y@z",
    "token parameters": "?token=" * 9000,
    "short parameters": "#a=" * 20000,
}


@pytest.mark.parametrize("text", LONG_RUNS.values(), ids=LONG_RUNS.keys())
def test_redact_page_is_quick_on_a_node_that_is_one_long_run(text, laptop_seconds):
    page = {"content": [{"tag": "p", "children": [text, "next node"]}]}
    assert laptop_seconds(lambda: redact_page(page, KEY)) < 1.0
