"""Tests for graphwatch.decode, the decoders (issue #28).

decode.py imports nothing from graphwatch, so these tests pass their own
`accept` function. The hosts are made up or come from the actor's Hello
pages; nothing here reads a held-out page.
"""

import base64
import re

import pytest

from graphwatch.decode import (
    Decoded,
    as_text,
    decode_base64_pointer,
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


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# --------------------------------------------------------------------------
# the single decoders
# --------------------------------------------------------------------------


def test_from_base64_decodes_padded_unpadded_and_url_safe():
    assert from_base64("czMucmVkYXJvZGFzLmNvbQ==") == HOST.encode()
    assert from_base64("czMucmVkYXJvZGFzLmNvbQ") == HOST.encode()  # two = missing
    assert from_base64("NDUuNzcuOTMuMTg") == b"45.77.93.18"  # one = missing
    data = b"http://a.com/???>~"
    token = base64.urlsafe_b64encode(data).decode()
    assert "-" in token and "_" in token  # the example needs both URL-safe characters
    assert from_base64(token) == data


def test_from_hex_decodes_either_case():
    assert from_hex("6578616d706c652e636f6d") == b"example.com"
    assert from_hex("6578616D706C652E636F6D") == b"example.com"


def test_from_base32_decodes_padded_unpadded_and_lowercase():
    token = base64.b32encode(b"example.com").decode()
    assert token.endswith("=")
    assert from_base32(token) == b"example.com"
    assert from_base32(token.rstrip("=")) == b"example.com"
    assert from_base32(token.lower()) == b"example.com"


# One token per way of not being the encoding. The Cyrillic ones are refused
# by the standard library with a different exception from the others.
@pytest.mark.parametrize(
    "decoder, token",
    [
        (from_base64, "not base64!"),
        (from_base64, "abcde"),  # no padding makes five characters whole
        (from_base64, "===="),
        (from_base64, "приве"),
        (from_hex, "abc"),  # half a pair
        (from_hex, "zz"),
        (from_hex, "привет"),
        (from_base32, "abc01"),  # 0 and 1 are not in the alphabet
        (from_base32, "привет"),
    ],
)
def test_a_decoder_returns_none_for_what_is_not_its_encoding(decoder, token):
    assert decoder(token) is None


@pytest.mark.parametrize(
    "token, n, rotated",
    [
        ("rknzcyr.pbz", 13, "example.com"),
        ("Abc-9.Xyz", 1, "Bcd-9.Yza"),  # case, digits and punctuation kept; z wraps to a
        ("привет", 13, "привет"),
    ],
)
def test_rot_moves_the_ascii_letters_and_nothing_else(token, n, rotated):
    assert rot(token, n) == rotated


def test_as_text_accepts_printable_ascii_only():
    assert as_text(b" example.com~") == " example.com~"  # bytes 32 and 126, the two ends
    for raw in (b"", b"\x1fa", b"a\x7f", b"line\nbreak", "é".encode()):
        assert as_text(raw) is None, raw


# --------------------------------------------------------------------------
# decode_pointer: every encoding finds the pointer
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "encoding, token",
    [
        ("base64", "czMucmVkYXJvZGFzLmNvbQ=="),  # the token in the actor's title
        ("hex", HOST.encode().hex()),
        ("base32", base64.b32encode(HOST.encode()).decode()),
    ],
)
def test_decode_pointer_finds_each_plain_encoding_and_reports_it_once(encoding, token):
    # Exactly one: XOR with key 0 would repeat the plain decoding
    assert decode_pointer(token, dotted) == [Decoded(encoding, HOST)]


# Both ends, the familiar one, and one of the other 22: an even one, because
# trying every second rotation would still find 1, 13 and 25
@pytest.mark.parametrize("n", [1, 8, 13, 25])
def test_decode_pointer_finds_a_rotation(n):
    token = rot(HOST, 26 - n)
    assert decode_pointer(token, only(HOST)) == [Decoded(f"rot{n}", HOST)]


@pytest.mark.parametrize("key", [0x01, 0x5A, 0xFF])
def test_decode_pointer_finds_single_byte_xor_under_base64(key):
    token = b64(xored(HOST.encode(), key))
    assert decode_pointer(token, only(HOST)) == [Decoded(f"base64+xor{key:02x}", HOST)]


def test_decode_pointer_finds_single_byte_xor_under_hex():
    token = xored(IP.encode(), 0x42).hex()
    assert decode_pointer(token, only(IP)) == [Decoded("hex+xor42", IP)]


# --------------------------------------------------------------------------
# decode_pointer: whole pointers only
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "",
        "привет",
        "2+2=",  # base64, but of bytes that are not text
        "dGViaQ==",  # the actor's short field: "tebi", printable but no pointer
        b64(b"go to s3.redarodas.com now"),  # a pointer with text around it
    ],
)
def test_what_is_not_a_whole_pointer_decodes_to_nothing(token):
    assert decode_pointer(token, dotted) == []


def test_accept_never_sees_bytes_that_are_not_printable():
    seen = []

    def spy(s):
        seen.append(s)
        return False

    decode_pointer(b64(bytes(range(200, 216))), spy)
    assert seen  # some keys do make these bytes printable
    assert all(s.isascii() and s.isprintable() for s in seen)


def test_xor_is_tried_from_eight_bytes_up():
    # MIN_XOR_BYTES: seven bytes are left alone, eight are tried
    seven, eight = "a.bc.de", "ab.cd.ef"
    assert decode_pointer(b64(xored(seven.encode(), 0x5A)), only(seven)) == []
    assert decode_pointer(b64(xored(eight.encode(), 0x5A)), only(eight)) == [
        Decoded("base64+xor5a", eight)
    ]


def test_a_rotation_that_changes_nothing_is_not_a_decoding():
    # An IP has no letters: all 25 rotations are the IP itself.
    assert decode_pointer(IP, only(IP)) == []


@pytest.mark.parametrize("decode", [decode_pointer, decode_base64_pointer])
def test_a_pointer_may_be_255_bytes_and_no_longer(decode):
    # MAX_POINTER_BYTES, in both decoders
    fits, too_long = "a" * 255, "a" * 256
    assert decode(b64(fits.encode()), only(fits)) == [Decoded("base64", fits)]
    assert decode(b64(too_long.encode()), only(too_long)) == []


def test_a_decoded_record_cannot_be_changed():
    result = decode_pointer(b64(HOST.encode()), dotted)[0]
    with pytest.raises(AttributeError):
        result.value = "other"


# --------------------------------------------------------------------------
# decode_base64_pointer: plain base64 only, for unpadded tokens
# --------------------------------------------------------------------------

UNPADDED_IP = "NDUuNzcuOTMuMTg3"  # 45.77.93.187: 12 bytes, so no padding


def test_decode_base64_pointer_finds_an_unpadded_pointer():
    assert b64(IP.encode()) == UNPADDED_IP
    assert decode_base64_pointer(UNPADDED_IP, dotted) == [Decoded("base64", IP)]


@pytest.mark.parametrize(
    "token",
    [
        "internationalization",  # base64, but of bytes that are not text
        "dGViaQ",  # "tebi": text, but no pointer
        "",
        "!!!!",
    ],
)
def test_decode_base64_pointer_rejects_ordinary_words(token):
    assert decode_base64_pointer(token, dotted) == []


def test_decode_base64_pointer_does_not_try_xor():
    hidden = b"cdn.example.com"  # 15 bytes: unpadded
    token = b64(xored(hidden, 0x5A))
    assert not token.endswith("=")
    assert decode_base64_pointer(token, only("cdn.example.com")) == []
    # the full decoder would have found it
    assert decode_pointer(token, only("cdn.example.com")) != []


def test_decode_base64_pointer_does_not_try_hex_or_rotations():
    assert decode_base64_pointer(HOST.encode().hex(), dotted) == []
    assert decode_base64_pointer(rot(HOST, 13), only(HOST)) == []
