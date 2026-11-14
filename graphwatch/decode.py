"""Decoders: undo an encoding and keep the result only if it is a whole pointer"""

import base64
import binascii
import string
from collections.abc import Callable
from dataclasses import dataclass

MIN_XOR_BYTES = 8
MAX_POINTER_BYTES = 255

URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


@dataclass(frozen=True)
class Decoded:
    """One accepted decoding: how the token was encoded and what it said"""

    encoding: str
    value: str


def from_base64(token: str) -> bytes | None:
    """Decode base64 in the standard or URL-safe alphabet, padded or not

    Args:
        token (str): the candidate token

    Returns:
        bytes | None: the decoded bytes, or None if the token is not base64
    """
    token = token.translate(URLSAFE_TO_STANDARD)
    token += "=" * (-len(token) % 4)
    try:
        return base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None


def from_hex(token: str) -> bytes | None:
    """Decode a run of hex digit pairs

    Args:
        token (str): the candidate token

    Returns:
        bytes | None: the decoded bytes, or None if the token is not hex
    """
    try:
        return bytes.fromhex(token)
    except ValueError:
        return None


def from_base32(token: str) -> bytes | None:
    """Decode base32, either case, padded or not

    Args:
        token (str): the candidate token

    Returns:
        bytes | None: the decoded bytes, or None if the token is not base32
    """
    token = token.upper()
    token += "=" * (-len(token) % 8)
    try:
        return base64.b32decode(token)
    except (binascii.Error, ValueError):
        return None


def rot(token: str, n: int) -> str:
    """Rotate the ASCII letters n places; digits and punctuation stay put

    Args:
        token (str): the text to rotate
        n (int): how far, 1 to 25. rot(rot(s, n), 26 - n) is s again.

    Returns:
        str: the rotated text
    """
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    table = str.maketrans(lower + upper, lower[n:] + lower[:n] + upper[n:] + upper[:n])
    return token.translate(table)


def as_text(raw: bytes) -> str | None:
    """Bytes as text, if every byte is printable ASCII

    Args:
        raw (bytes): decoded bytes

    Returns:
        str | None: the text, or None for empty or non-printable input
    """
    if not raw or not all(32 <= byte < 127 for byte in raw):
        return None
    return raw.decode("ascii")


BYTE_DECODERS: tuple[tuple[str, Callable[[str], bytes | None]], ...] = (
    ("base64", from_base64),
    ("hex", from_hex),
    ("base32", from_base32),
)


def decode_pointer(token: str, accept: Callable[[str], bool]) -> list[Decoded]:
    """Try every decoder on a token and keep the results that are pointers

    Tried in order: base64, hex and base32, each plain and then XORed with
    every single-byte key; then the 25 letter rotations of the token itself.

    Args:
        token (str): the candidate token, e.g. czMucmVkYXJvZGFzLmNvbQ==
        accept (Callable[[str], bool]): True if the whole decoded string is a
            pointer; a decoding it rejects is dropped

    Returns:
        list[Decoded]: the accepted decodings, empty if there are none
    """
    results = []
    for name, decoder in BYTE_DECODERS:
        raw = decoder(token)
        if raw is None or len(raw) > MAX_POINTER_BYTES:
            continue
        text = as_text(raw)
        if text is not None and accept(text):
            results.append(Decoded(name, text))
        if len(raw) < MIN_XOR_BYTES:
            continue
        for key in range(1, 256):
            text = as_text(bytes(byte ^ key for byte in raw))
            if text is not None and accept(text):
                results.append(Decoded(f"{name}+xor{key:02x}", text))
    for n in range(1, 26):
        text = rot(token, n)
        if text != token and accept(text):
            results.append(Decoded(f"rot{n}", text))
    return results


def decode_base64_pointer(token: str, accept: Callable[[str], bool]) -> list[Decoded]:
    """Try plain base64 only, for tokens that carry no padding

    Without the = on the end a base64 token looks like any long word, and
    there are far too many of those to try XOR, hex, base32 and the rotations
    on each. Plain base64 is cheap and does not turn words into hostnames.

    Args:
        token (str): the candidate token, e.g. NDUuNzcuOTMuMTg3
        accept (Callable[[str], bool]): True if the whole decoded string is a
            pointer

    Returns:
        list[Decoded]: one base64 decoding if it is a pointer, else empty
    """
    raw = from_base64(token)
    if raw is None or len(raw) > MAX_POINTER_BYTES:
        return []
    text = as_text(raw)
    if text is not None and accept(text):
        return [Decoded("base64", text)]
    return []
