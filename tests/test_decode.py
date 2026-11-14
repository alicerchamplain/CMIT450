"""Tests for graphwatch.decode, the decoders (issue #28).

decode.py imports nothing from graphwatch, so these tests pass their own
`accept` function. The hosts are made up or come from the actor's Hello
pages; nothing here reads a held-out page.
"""

import base64
import re

import pytest

from graphwatch.decode import (
    MAX_POINTER_BYTES,
    MIN_XOR_BYTES,
    Decoded,
    as_text,
    decode_pointer,
    from_base32,
    from_base64,
    from_hex,
    rot,
)

HOST = "s3.redarodas.com"
IP = "45.77.93.187"


def dotted(s: str) -> bool:
    """A stand-in for rules.is_pointer: lowercase labels and digits joined by dots."""
    return re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", s) is not None


def only(target: str):
    return lambda s: s == target


def xored(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


# --------------------------------------------------------------------------
# the single decoders
# --------------------------------------------------------------------------


def test_from_base64_decodes_a_padded_token():
    assert from_base64("czMucmVkYXJvZGFzLmNvbQ==") == HOST.encode()


def test_from_base64_decodes_without_padding():
    assert from_base64("czMucmVkYXJvZGFzLmNvbQ") == HOST.encode()


def test_from_base64_decodes_the_url_safe_alphabet():
    data = b"http://a.com/?>~"
    token = base64.urlsafe_b64encode(data).decode()
    assert "-" in token or "_" in token  # the example really needs the alphabet
    assert from_base64(token) == data


@pytest.mark.parametrize("token", ["not base64!", "a", "abcde", "====", "приве"])
def test_from_base64_returns_none_for_what_is_not_base64(token):
    assert from_base64(token) is None


def test_from_hex_decodes_either_case():
    assert from_hex("6578616d706c652e636f6d") == b"example.com"
    assert from_hex("6578616D706C652E636F6D") == b"example.com"


@pytest.mark.parametrize("token", ["abc", "zz", "0x41", "привет"])
def test_from_hex_returns_none_for_what_is_not_hex(token):
    assert from_hex(token) is None


def test_from_base32_decodes_padded_unpadded_and_lowercase():
    token = base64.b32encode(b"example.com").decode()
    assert token.endswith("=")
    assert from_base32(token) == b"example.com"
    assert from_base32(token.rstrip("=")) == b"example.com"
    assert from_base32(token.lower()) == b"example.com"


@pytest.mark.parametrize("token", ["1", "abc01", "!!!!!!!!", "привет"])
def test_from_base32_returns_none_for_what_is_not_base32(token):
    assert from_base32(token) is None


def test_rot_thirteen_is_the_familiar_one():
    assert rot("rknzcyr.pbz", 13) == "example.com"


def test_rot_keeps_case_digits_and_punctuation():
    assert rot("Abc-9.Xyz", 1) == "Bcd-9.Yza"


@pytest.mark.parametrize("n", range(1, 26))
def test_rot_is_undone_by_the_complement(n):
    assert rot(rot("s3.RedArodas.com", n), 26 - n) == "s3.RedArodas.com"


def test_rot_leaves_non_ascii_letters_alone():
    assert rot("привет", 13) == "привет"


def test_as_text_accepts_printable_ascii_only():
    assert as_text(b"example.com") == "example.com"
    assert as_text(b"") is None
    assert as_text(b"exa\x00mple") is None
    assert as_text(b"line\nbreak") is None
    assert as_text("é".encode()) is None


# --------------------------------------------------------------------------
# decode_pointer: every encoding finds a host and an IP
# --------------------------------------------------------------------------


@pytest.mark.parametrize("pointer", [HOST, IP])
def test_decode_pointer_finds_base64(pointer):
    token = base64.b64encode(pointer.encode()).decode()
    assert decode_pointer(token, dotted) == [Decoded("base64", pointer)]


@pytest.mark.parametrize("pointer", [HOST, IP])
def test_decode_pointer_finds_hex(pointer):
    assert Decoded("hex", pointer) in decode_pointer(pointer.encode().hex(), dotted)


@pytest.mark.parametrize("pointer", [HOST, IP])
def test_decode_pointer_finds_base32(pointer):
    token = base64.b32encode(pointer.encode()).decode()
    assert Decoded("base32", pointer) in decode_pointer(token, dotted)


@pytest.mark.parametrize("n", [1, 5, 13, 25])
def test_decode_pointer_finds_a_rotation(n):
    token = rot(HOST, 26 - n)
    assert decode_pointer(token, only(HOST)) == [Decoded(f"rot{n}", HOST)]


@pytest.mark.parametrize("key", [0x01, 0x5A, 0xFF])
def test_decode_pointer_finds_single_byte_xor_under_base64(key):
    token = base64.b64encode(xored(HOST.encode(), key)).decode()
    assert Decoded(f"base64+xor{key:02x}", HOST) in decode_pointer(token, only(HOST))


def test_decode_pointer_finds_single_byte_xor_under_hex():
    token = xored(IP.encode(), 0x42).hex()
    assert Decoded("hex+xor42", IP) in decode_pointer(token, only(IP))


def test_the_actor_title_token_decodes_to_its_host():
    assert decode_pointer("czMucmVkYXJvZGFzLmNvbQ==", dotted) == [Decoded("base64", HOST)]


# --------------------------------------------------------------------------
# decode_pointer: whole pointers only
# --------------------------------------------------------------------------


@pytest.mark.parametrize("token", ["dGViaQ==", "eWVsNA=="])
def test_the_actor_short_fields_decode_to_words_and_are_rejected(token):
    # "tebi" and "yel4": printable, but not pointers.
    assert as_text(from_base64(token)) in ("tebi", "yel4")
    assert decode_pointer(token, dotted) == []


def test_a_pointer_with_text_around_it_is_not_whole():
    token = base64.b64encode(b"go to s3.redarodas.com now").decode()
    assert decode_pointer(token, dotted) == []


@pytest.mark.parametrize("token", ["", "hello", "!!!", "2+2=", "привет", "SECRET{ab}"])
def test_garbage_decodes_to_nothing(token):
    assert decode_pointer(token, dotted) == []


def test_accept_never_sees_bytes_that_are_not_printable():
    seen = []

    def spy(s):
        seen.append(s)
        return False

    decode_pointer(base64.b64encode(bytes(range(200, 216))).decode(), spy)
    assert all(s.isascii() and s.isprintable() for s in seen)


def test_accept_decides_and_nothing_is_kept_when_it_says_no():
    token = base64.b64encode(HOST.encode()).decode()
    assert decode_pointer(token, lambda s: False) == []


def test_xor_is_not_tried_on_short_byte_strings():
    short = b"a.co"
    assert len(short) < MIN_XOR_BYTES
    token = base64.b64encode(xored(short, 0x5A)).decode()
    assert decode_pointer(token, only("a.co")) == []


def test_xor_is_tried_from_the_minimum_length_up():
    exact = b"ab.cd.ef"
    assert len(exact) == MIN_XOR_BYTES
    token = base64.b64encode(xored(exact, 0x5A)).decode()
    assert decode_pointer(token, only("ab.cd.ef")) == [Decoded("base64+xor5a", "ab.cd.ef")]


def test_xor_key_zero_is_not_reported_twice():
    # Key 0 would repeat the plain decoding.
    token = base64.b64encode(HOST.encode()).decode()
    assert decode_pointer(token, only(HOST)) == [Decoded("base64", HOST)]


def test_a_rotation_that_changes_nothing_is_not_a_decoding():
    # An IP has no letters: all 25 rotations are the IP itself.
    assert decode_pointer(IP, only(IP)) == []


def test_oversized_tokens_are_skipped():
    big = b"a" * (MAX_POINTER_BYTES + 1)
    calls = []
    decode_pointer(big.hex(), lambda s: calls.append(len(s)) or False)
    assert MAX_POINTER_BYTES + 1 not in calls


def test_decode_pointer_returns_decoded_records():
    result = decode_pointer(base64.b64encode(HOST.encode()).decode(), dotted)[0]
    assert (result.encoding, result.value) == ("base64", HOST)
    with pytest.raises(AttributeError):
        result.value = "other"
