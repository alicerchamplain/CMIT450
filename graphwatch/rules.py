"""Clases and functions for threat scoring rules"""

import base64
import binascii
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass

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

# Regex for detecting Gamaredon fake userinfo strings like onmedservice[.]com[.]ua@opportunizz[.]pro
# (?<![\w.@-]) : not preceded by a word char, dot, @ or hyphen
# (HOST)@(HOST): a hostname on BOTH sides of the @
# (?![\w@-])   : the right host ends here
USERINFO_SPOOF_PATTERN = re.compile(
    rf"(?<![\w.@-])({HOST})@({HOST})(?![\w@-])", re.IGNORECASE
)

# Regex for detecting s3 storage keys used by Gamaredon
# /!   : the storage-key marker
# \S+  : the hashed key and whatever follows up to whitespace
STORAGE_KEY_PATTERN = re.compile(r"/!\S+")

# Regex for detecting email addresses
# [\w.+-]+@HOST : any email-shaped token
EMAIL_PATTERN = re.compile(rf"(?<![\w.@-])[\w.+-]+@{HOST}(?![\w@-])", re.IGNORECASE)

# Regex for detecting IPs
# (?<![\d.])          : not inside a longer dotted number
# \d{1,3}(?:\.\d{1,3}){3} : four groups of 1 to 3 digits
# (?![\d.])           : not followed by more digits or dots
IP_PATTERN = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


# Regex for detecting base64 strings
# (?<![A-Za-z0-9+/=]) : start of a token
# [A-Za-z0-9+/]{2,}={1,2} : base64 body then one or two padding characters
# (?![A-Za-z0-9+/=])  : end of the token
BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{2,}={1,2}(?![A-Za-z0-9+/=])"
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
    """A rule match with the string it matched on"""

    rule: Rule
    evidence: str


def is_public_ip(s: str) -> bool:
    """Function to check if a string that look like an IP is a publicly routable IP"""
    try:
        address = ipaddress.ip_address(s)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def decodes_to_printable(s: str) -> bool:
    """Function to check if a base64 string decodes to valid ascii"""
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) > 0 and all(32 <= byte < 127 for byte in raw)


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
        list[Hit]: at most one Hit per rule, in table order
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
        for match in rule.pattern.finditer(fields[rule.where]):
            evidence = match.group(0)
            if rule.check is None or rule.check(evidence):
                hits.append(Hit(rule, evidence))
                break
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
