"""Extractor: typed indicators from a stored page (issue #27)

Reads text only. Nothing here resolves a name or contacts a host.
"""

import re
from dataclasses import dataclass

from graphwatch.decode import decode_pointer
from graphwatch.rules import (
    BASE64_PATTERN,
    HOST,
    IP_PATTERN,
    PORT_PATTERN,
    USERINFO_SPOOF_PATTERN,
    is_pointer,
    is_public_ip,
)

KINDS = frozenset(["ip", "host", "url", "decoy", "token"])

# Regex for a secret that redaction already hashed; never an indicator
# SECRET\{      : the marker redact.py writes
# [0-9a-f]+\}   : the HMAC hex and the closing brace
SECRET_PATTERN = re.compile(r"SECRET\{[0-9a-f]+\}")

# Regex for an http(s) URL
# https?://     : the scheme
# [^\s<>"']+    : everything up to whitespace, a quote or an angle bracket
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Punctuation that ends a sentence, not a URL
URL_TRAILING = ".,;:!?)]}"

# Regex for a hostname standing on its own
# (?<![\w.@-]) : not the tail of a longer name and not an email's domain
# HOST         : labels ending in a known TLD
# (?![\w@-])   : the name ends here and is not an email's local part
HOST_TOKEN_PATTERN = re.compile(rf"(?<![\w.@-])(?:{HOST})(?![\w@-])", re.IGNORECASE)

# Regex for a run of hex that could hide a pointer
# (?<![0-9A-Za-z])     : start of a token
# (?:[0-9a-fA-F]{2}){8,} : eight or more hex pairs
# (?![0-9A-Za-z])      : end of the token
HEX_PATTERN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){8,}(?![0-9A-Za-z])")


@dataclass(frozen=True)
class Indicator:
    """One thing pulled out of a page

    kind is one of KINDS: an ip, host or url is a pointer; a decoy is the
    left side of a host@host spoof, which is bait and never looked up; a
    token is an opaque run the decoders were offered. source is the field it
    was found in, plus the encoding when it was decoded: "title:base64".
    """

    kind: str
    value: str
    source: str


def pointer_kind(pointer: str) -> str:
    """Which kind of indicator a whole pointer is

    Args:
        pointer (str): a string that is_pointer accepted

    Returns:
        str: "url", "ip" or "host"
    """
    if pointer.lower().startswith(("http://", "https://")):
        return "url"
    if is_public_ip(PORT_PATTERN.sub("", pointer)):
        return "ip"
    return "host"


def extract(title: str | None, text: str | None) -> list[Indicator]:
    """Function to pull the indicators out of one page

    The title is scanned first, then the text, so an indicator in both is
    reported once with source "title".

    Args:
        title (str | None): snapshots.title
        text (str | None): snapshots.text

    Returns:
        list[Indicator]: indicators in order of appearance, no repeats
    """
    fields = (("title", title or ""), ("text", text or ""))
    decoys = set()
    for _source, field in fields:
        for match in USERINFO_SPOOF_PATTERN.finditer(field):
            decoys.add(match.group(1).lower())

    found = []
    seen = set()

    def add(kind: str, value: str, source: str) -> None:
        # A decoy host is bait wherever it appears on the page.
        if kind == "host" and value in decoys:
            return
        if (kind, value) not in seen:
            seen.add((kind, value))
            found.append(Indicator(kind, value, source))

    for source, field in fields:
        field = SECRET_PATTERN.sub(" ", field)
        for match in USERINFO_SPOOF_PATTERN.finditer(field):
            add("decoy", match.group(1).lower(), source)
            add("host", match.group(2).lower(), source)
        for match in URL_PATTERN.finditer(field):
            url = match.group(0).rstrip(URL_TRAILING)
            if is_pointer(url):
                add("url", url, source)
        # Blank out what is already claimed so its parts are not reported again.
        field = URL_PATTERN.sub(" ", field)
        field = USERINFO_SPOOF_PATTERN.sub(" ", field)
        for match in IP_PATTERN.finditer(field):
            if is_public_ip(match.group(0)):
                add("ip", match.group(0), source)
        for match in HOST_TOKEN_PATTERN.finditer(field):
            add("host", match.group(0).lower(), source)
        for pattern in (BASE64_PATTERN, HEX_PATTERN):
            for match in pattern.finditer(field):
                token = match.group(0)
                add("token", token, source)
                for decoded in decode_pointer(token, is_pointer):
                    kind = pointer_kind(decoded.value)
                    add(kind, decoded.value, f"{source}:{decoded.encoding}")
    return found
