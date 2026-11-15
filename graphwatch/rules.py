"""Clases and functions for threat scoring rules"""

import base64
import binascii
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from graphwatch.decode import decode_base64_pointer, decode_pointer

WHERE = frozenset(["title", "description", "text", "computed"])

# Score Threshold
THRESHOLD = 4

# Common TLDs, useful for checking if a string contains a domain
TLD = (
    "(?:com|net|org|edu|gov|mil|info|biz|pro|dev|app|io|me|su|online|site|xyz|top"
    "|club|shop|store|cloud|tech|ua|ru|by|kz|jp|de|uk|fr|it|es|pl|cz|nl|us|ca|cn"
    "|in|br|tr|ir|kr|tv|cc|ws|to|ly|ai|co|eu|asia|life|live|world|space|website"
    "|fun|icu|link|pw|st|tk|ml|ga|cf|gq)"
)

# Regex for detecting domains/hosts
# (?:[a-z0-9-]+\.)+ : one or more labels, each followed by a dot
# TLD               : a known top-level domain
HOST = rf"(?:[a-z0-9-]+\.)+{TLD}"

# HOST compiled for whole-string checks: HOST_PATTERN.fullmatch(s)
HOST_PATTERN = re.compile(HOST, re.IGNORECASE)

# Regex for a port number on the end of a host or IP
# :       : the separator
# \d{1,5} : one to five digits
# $       : at the very end
PORT_PATTERN = re.compile(r":\d{1,5}$")

# Regex for detecting Gamaredon fake userinfo strings like onmedservice[.]com[.]ua@opportunizz[.]pro
# (?<![\w.@-]) : not preceded by a word char, dot, @ or hyphen
# (HOST)@(HOST): a hostname on BOTH sides of the @
# (?![\w@-])   : the right host ends here
USERINFO_SPOOF_PATTERN = re.compile(
    rf"(?<![\w.@-])({HOST})@({HOST})(?![\w@-])", re.IGNORECASE
)

# Regex for detecting the same spoof in a title whatever the decoy's ending,
# like primewire[.]ag@agfc[.]harper18[.]workers[.]dev
# The left side is bait and can be any site, so only the right side, the real
# destination, has to end in a known TLD. Titles only: in body text this
# shape is mostly email addresses like first.last@provider.
# (?<![\w.@-])                  : not preceded by a word char, dot, @ or hyphen
# ((?:[a-z0-9-]+\.)+[a-z]{2,})  : the decoy, any dotted name
# @(HOST)                       : the destination, a hostname with a known TLD
# (?![\w@-])                    : the right host ends here
TITLE_SPOOF_PATTERN = re.compile(
    rf"(?<![\w.@-])((?:[a-z0-9-]+\.)+[a-z]{{2,}})@({HOST})(?![\w@-])", re.IGNORECASE
)

# Regex for detecting s3 storage keys used by Gamaredon
# /!   : the storage-key marker
# \S+  : the hashed key and whatever follows up to whitespace
STORAGE_KEY_PATTERN = re.compile(r"/!\S+")

# Regex for detecting email addresses
# [\w.+-]+@HOST : any email-shaped token
EMAIL_PATTERN = re.compile(rf"(?<![\w.@-])[\w.+-]+@{HOST}(?![\w@-])", re.IGNORECASE)

# Regex for detecting IPs
# (?<![\w.])          : not inside a longer dotted number or a word, so the
#                       version string v2.22.23.12 is not an IP
# \d{1,3}(?:\.\d{1,3}){3} : four groups of 1 to 3 digits
# (?![\d.])           : not followed by more digits or dots
IP_PATTERN = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


# Regex for detecting base64 strings
# (?<![A-Za-z0-9+/=]) : start of a token
# [A-Za-z0-9+/]{2,}={1,2} : base64 body then one or two padding characters
# (?![A-Za-z0-9+/=])  : end of the token
BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{2,}={1,2}(?![A-Za-z0-9+/=])"
)

# Regex for detecting base64 strings that need no padding
# Base64 only pads when the original length is not a multiple of 3, so
# 45.77.93.187 (12 characters) encodes to NDUuNzcuOTMuMTg3 with no = at all.
# (?<![A-Za-z0-9+/=])      : start of a token
# (?:[A-Za-z0-9+/]{4}){3,} : twelve or more base64 characters in groups of four
# (?![A-Za-z0-9+/=])       : end of the token
UNPADDED_BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){3,}(?![A-Za-z0-9+/=])"
)

# Either kind of base64 token: padded first, then unpadded
ENCODED_TOKEN_PATTERN = re.compile(
    f"{BASE64_PATTERN.pattern}|{UNPADDED_BASE64_PATTERN.pattern}"
)

# Regex for detecting the default API title
# ^Hello,\+world!$ : The createPage API example
API_SAMPLE_PATTERN = re.compile(r"^Hello,\+world!$")

# Regex for detecting Telegram invite links / telegram channel links
# t\.me/ or telegram\.me/ : a Telegram link
# (?<![\w@])@[A-Za-z]\w{4,31}\b : a Telegram @handle
TELEGRAM_PATTERN = re.compile(
    r"(?:t\.me/|telegram\.me/|(?<![\w@])@[A-Za-z]\w{4,31}\b)", re.IGNORECASE
)


@dataclass(frozen=True)
class Rule:
    """A scoring rule in the rule table"""

    name: str
    weight: int
    where: str
    pattern: re.Pattern | None
    exists_for: str
    check: Callable[[str], bool] | None = None


@dataclass(frozen=True)
class Hit:
    """A rule that fired on a page

    evidence is the first string the rule matched. matches is how many
    strings on the page it matched in all. The score counts a rule once
    however often it matched; matches is recorded, not scored.
    """

    rule: Rule
    evidence: str
    matches: int = 1


def is_public_ip(s: str) -> bool:
    """Function to check if a string that look like an IP is a publicly routable IP"""
    try:
        address = ipaddress.ip_address(s)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def is_pointer(s: str) -> bool:
    """Function to check if a whole string is a pointer to a server

    A pointer is a public IP, a hostname with a known TLD, or an http(s) URL
    to one of those. A port may follow the host. Nothing may be left over:
    "s3.redarodas.com" is a pointer, "go to s3.redarodas.com" is not.
    """
    if re.search(r"\s", s):
        return False
    if s.lower().startswith(("http://", "https://")):
        try:
            host = urlsplit(s).hostname or ""
        except ValueError:
            return False
    else:
        host = PORT_PATTERN.sub("", s)
    return is_public_ip(host) or HOST_PATTERN.fullmatch(host) is not None


def decodes_to_printable(s: str) -> bool:
    """Function to check if a base64 string decodes to valid ascii"""
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) > 0 and all(32 <= byte < 127 for byte in raw)


def decodes_to_pointer(s: str) -> bool:
    """Function to check if a token decodes to a whole pointer

    A padded token is tried with every decoder. An unpadded one looks like
    any long word, so it only gets plain base64.
    """
    if s.endswith("="):
        return len(decode_pointer(s, accept=is_pointer)) > 0
    return len(decode_base64_pointer(s, accept=is_pointer)) > 0


def _not_a_host_local_part(s: str) -> bool:
    local = s.split("@", 1)[0]
    return re.fullmatch(HOST, local, re.IGNORECASE) is None


RULES: tuple[Rule, ...] = (
    Rule(
        "userinfo_spoof",
        5,
        "text",
        USERINFO_SPOOF_PATTERN,
        "Matching the Gamaredon userinfo spoof pattern like onmedservice[.]com[.]ua@opportunizz[.]pro",
    ),
    Rule(
        "spoof_in_title",
        5,
        "title",
        TITLE_SPOOF_PATTERN,
        "Matching userinfo spoof titles whose decoy site ends in a TLD outside the list, like primewire[.]ag@agfc[.]harper18[.]workers[.]dev, which userinfo_spoof misses",
        check=_not_a_host_local_part,
    ),
    Rule(
        "ip_in_title",
        4,
        "title",
        IP_PATTERN,
        "Matching Gamaredon-like pages that have IPs in the title",
        check=is_public_ip,
    ),
    Rule(
        "storage_key_marker",
        4,
        "text",
        STORAGE_KEY_PATTERN,
        "Matching Gamaredon-like pages that have the s3 storage key marker /!",
    ),
    Rule(
        "base64_in_title",
        2,
        "title",
        BASE64_PATTERN,
        "Matching Gamaredon-like pages which have base64 encodded patterns in the title.",
        check=decodes_to_printable,
    ),
    Rule(
        "encoded_pointer",
        3,
        "text",
        ENCODED_TOKEN_PATTERN,
        "Matching pages that hide a server address in a base64 token, padded or not, like czMucmVkYXJvZGFzLmNvbQ== for s3[.]redarodas[.]com",
        check=decodes_to_pointer,
    ),
    Rule(
        "api_sample_body",
        1,
        "description",
        API_SAMPLE_PATTERN,
        "Matches posts that use the default API example body",
    ),
    Rule(
        "ip_literal",
        1,
        "text",
        IP_PATTERN,
        "Matches pages that have IPs in the text",
        check=is_public_ip,
    ),
    Rule(
        "email_address",
        1,
        "text",
        EMAIL_PATTERN,
        "Matches pages with email addresses",
        check=_not_a_host_local_part,
    ),
    Rule(
        "telegram_link",
        -1,
        "text",
        TELEGRAM_PATTERN,
        "Matches pages that has telegram links in them, reduces their score.",
    ),
    Rule(
        "templated_body",
        -2,
        "computed",
        None,
        "Matches pages with spammed duplicate page bodies",
    ),
)


def apply_rules(
    title: str | None, description: str | None, text: str | None, rules=RULES
) -> list[Hit]:
    """Run every pattern rule once over a page and return the hits

    Args:
        title (str | None): snapshots.title
        description (str | None): snapshots.description
        text (str | None): snapshots.text, the title, description and body joined
        rules (optional): the rules to apply. Defaults to RULES.

    Returns:
        list[Hit]: at most one Hit per rule, in table order, each carrying
            its first match as evidence and the number of matches
    """
    fields = {
        "title": title or "",
        "description": description or "",
        "text": text or "",
    }
    hits = []
    for rule in rules:
        if rule.pattern is None:
            continue
        evidence = None
        matches = 0
        for match in rule.pattern.finditer(fields[rule.where]):
            candidate = match.group(0)
            if rule.check is None or rule.check(candidate):
                if evidence is None:
                    evidence = candidate
                matches += 1
        if evidence is not None:
            hits.append(Hit(rule, evidence, matches))
    return hits


def score(hits: list[Hit]) -> int:
    """The sum of the weights of the rules that fired"""
    return sum(hit.rule.weight for hit in hits)


def _pattern_cell(rule: Rule) -> str:
    """The Pattern column: the regex, or a name when it is too long to read"""
    if rule.pattern is None:
        return "computed"
    source = rule.pattern.pattern
    if len(source) > 60:
        source = source.replace(TLD, "TLD")
    return "`" + source.replace("|", "\\|") + "`"


def render_table(rules=RULES) -> str:
    """The rule table as Markdown, one line per rule"""
    lines = [
        "| Rule | Weight | Where | Pattern | Exists for: |",
        "|---|---|---|---|---|",
    ]
    for rule in rules:
        pattern = _pattern_cell(rule)
        check = f" + `{rule.check.__name__}`" if rule.check is not None else ""
        lines.append(
            f"| `{rule.name}` | {rule.weight:+d} | {rule.where} | {pattern}{check} | {rule.exists_for} |"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(render_table(), end="")
