"""Functionality to redact page snapshots from Telegraph"""

import hmac
import re

MARKER = "SECRET{"

# /!    : match strings starting with /!
# (\S+) : group 1, the key value (\S+) means one or more non-whitespace chars
STORAGE_KEYS_PATTERN = re.compile(r"/!(\S+)")

# \b             : word boundary, so it does not start mid-password
# [\w.+-]+       : characters, dot, plus, dash
# @[\w-]+        : the first @ domain label
# (?:\.[\w-]+)+  : group 1, one or more further labels, each starting with a dot.
# :(\S+)         : group 2, the password after the :
EMAIL_AND_PASSWORD_PATTERN = re.compile(r"\b([\w.+-]+@[\w-]+(?:\.[\w-]+)+):(\S+)")

# \b                                : word boundary, so it doesn't start mid-password
# (password|passwd|pass|pwd|пароль) : group 1, the password label
# (\s*[:=]\s*)            B_PASSW          : group 2, the : or = between the label and password
# (\S+)                             : group 3, the password after the splitter in group 2
# re.IGNORECASE                     : tells the python regex to ignore upper vs lowercase
LABELED_PASSWORD_PATTERN = re.compile(
    r"\b(password|passwd|pass|pwd|пароль)(\s*[:=]\s*)(\S+)", re.IGNORECASE
)

# \b            : word boundary, so it does not start mid-word
# (пароль)      : group 1, the Cyrillic label only; English "password-protected"
#                 is a common compound so it stays with the : and = rule
# (-)           : group 2, the hyphen between the label and password
# (\S+)         : group 3, the password up to the next whitespace
# re.IGNORECASE : tells the python regex to ignore upper vs lowercase
HYPHEN_PASSWORD_PATTERN = re.compile(r"\b(пароль)(-)(\S+)", re.IGNORECASE)

# ^                                 : start of a line (re.MULTILINE), so the label must open its line
# [ \t]*                            : leading spaces or tabs, never \s because that would swallow newlines
# (password|passwd|pass|pwd|пароль) : group 1, the password label
# ([ \t]*\n[ \t]*)                  : group 2, exactly one line break with optional spaces either side,
#                                     kept in the output so the line structure survives
# (\S+)                             : group 3, the password, the first token on the next line
# re.IGNORECASE                     : tells the python regex to ignore upper vs lowercase
# re.MULTILINE                      : makes ^ match at every line start, not just the string start
NEWLINE_PASSWORD_PATTERN = re.compile(
    r"^[ \t]*(password|passwd|pass|pwd|пароль)([ \t]*\n[ \t]*)(\S+)",
    re.IGNORECASE | re.MULTILINE,
)

# (?<![\w@./:-])          : negative lookbehind, the login cannot start right after a word char,
#                           @, dot, slash, colon or hyphen; this keeps it out of emails and URLs
# ([\w.+-]*               : group 1 starts, any login chars before the letter
#  [^\W\d_]               : at least one Unicode letter, so 12:30 and 9:45 do not match
#  [\w.+-]*)              : group 1 ends, any login chars after the letter
# (:)                     : group 2, the colon between login and password
# (?!/)                   : negative lookahead, the password cannot start with /, which rejects https://
# (?=[^\s:]*\D)           : positive lookahead, the password must contain a non-digit, which rejects host:8080
# ([^\s:]+)               : group 3, the password up to the next whitespace or colon
BARE_LOGIN_PASSWORD_PATTERN = re.compile(
    r"(?<![\w@./:-])([\w.+-]*[^\W\d_][\w.+-]*)(:)(?!/)(?=[^\s:]*\D)([^\s:]+)"
)

# \b                                : word boundary, so it doesn't start mid-credit card
# \d                                : digit
# (?:[ -]?\d)                       : group 1, - or space followed by another digit
# {12,18}                           : repeat group 1 12-18 times
# \b                                : word boundary to not grab longer digit strings
CREDIT_CARD_PATTERN = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# \b             : word boundary, so it does not start mid-token
TELEGRAM_BOT_TOKEN_PATTERN = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")

# \b             : word boundary, so it does not start mid-key
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# \b             : word boundary, so it does not start mid-token
GITHUB_TOKEN_PATTERN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")


def hash_secret(s: str, key: bytes) -> str:
    """Hash a secret value and return it's keyed sha256 hash

    Args:
        s (str): secret string
        key (bytes): the hashing key

    Returns:
        str: keyed sha256 hash in SECRET{} format
    """
    digest = hmac.new(key, s.encode("utf-8"), "sha256").hexdigest()
    return MARKER + digest + "}"


def is_card(digits: str) -> bool:
    """Checks if digits represent a credit card using the Luhn algorithm

    Args:
        digits (str): Digits to check

    Returns:
        bool: If the digits are a card or not
    """

    # Length gate to bail early
    if len(digits) < 13:
        return False

    total = 0
    # Reverse the digits
    for i, digit in enumerate(reversed(digits)):
        # Convert to int
        digit = int(digit)
        # Double every second digit
        if i % 2 == 1:
            double = digit * 2
            # Add any products less than or equal to 9, otherwise subtract 9
            total += double if double <= 9 else double - 9
        else:
            total += digit

    ## Number is a credit card if mod 10 = 0
    return total % 10 == 0


def redact_text(s: str, key: bytes) -> str:
    """Redacts text strings using known secret patterns

    Args:
        s (str): text string to redact
        key (bytes): The hmac key for redactions

    Returns:
        str: Redacted string
    """

    def _hash_whole(m: re.Match) -> str:
        return hash_secret(m.group(0), key)

    def _hash_labelled(m: re.Match) -> str:
        if m.group(3).startswith(MARKER):
            return m.group(0)
        return m.group(1) + m.group(2) + hash_secret(m.group(3), key)

    def _hash_email_password(m: re.Match) -> str:
        if m.group(2).startswith(MARKER):
            return m.group(0)
        return m.group(1) + ":" + hash_secret(m.group(2), key)

    def _hash_card(m: re.Match) -> str:
        digits = m.group(0).replace(" ", "").replace("-", "")
        return hash_secret(digits, key) if is_card(digits) else m.group(0)

    def _hash_storage_keys(m: re.Match) -> str:
        fields = m.group(1).split("?")
        for i in range(min(2, len(fields))):
            if not fields[i].startswith(MARKER):
                fields[i] = hash_secret(fields[i], key)
        return "/!" + "?".join(fields)

    s = STORAGE_KEYS_PATTERN.sub(_hash_storage_keys, s)
    s = TELEGRAM_BOT_TOKEN_PATTERN.sub(_hash_whole, s)
    s = AWS_KEY_PATTERN.sub(_hash_whole, s)
    s = GITHUB_TOKEN_PATTERN.sub(_hash_whole, s)
    s = LABELED_PASSWORD_PATTERN.sub(_hash_labelled, s)
    s = HYPHEN_PASSWORD_PATTERN.sub(_hash_labelled, s)
    s = NEWLINE_PASSWORD_PATTERN.sub(_hash_labelled, s)
    s = EMAIL_AND_PASSWORD_PATTERN.sub(_hash_email_password, s)
    s = CREDIT_CARD_PATTERN.sub(_hash_card, s)
    s = BARE_LOGIN_PASSWORD_PATTERN.sub(_hash_labelled, s)

    return s


def redact_page(page: dict, key: bytes) -> dict:
    """Function to redact entire page contents using redact_text

    Args:
        page (dict): A telegraph page in dictionary form
        key (bytes): The hmac key for redactions

    Returns:
        dict: The redacted page in dictionary form
    """

    def _redact_node(node):
        if isinstance(node, str):
            return redact_text(node, key)
        if isinstance(node, dict):
            if "children" not in node:
                return node
            return {
                **node,
                "children": [_redact_node(child) for child in node["children"]],
            }
        return node

    content = [_redact_node(block) for block in page.get("content", [])]

    out = {**page, "content": content}

    if isinstance(page.get("title"), str):
        out["title"] = redact_text(page["title"], key)

    if isinstance(page.get("description"), str):
        out["description"] = redact_text(page["description"], key)

    return out
