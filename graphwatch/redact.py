"""Functionality to redact page snapshots from Telegraph"""

import hmac
import json
import re

from graphwatch.decode import from_base64

MARKER = "SECRET{"

# Regex for a secret that is already hashed: the marker, the 64 hex characters
# of the HMAC, and the closing brace
MARKER_PATTERN = re.compile(r"SECRET\{[0-9a-f]{64}\}")

# How many times redact_text runs its patterns over a text before it gives
# up waiting for the text to stop changing. One round is enough for almost
# every text and three for the worst shape found; see redact_text.
MAX_ROUNDS = 8

# /!    : match strings starting with /!
# (\S+) : group 1, the key value (\S+) means one or more non-whitespace chars
STORAGE_KEYS_PATTERN = re.compile(r"/!(\S+)")

# The email starts at the first word char of a run of email chars (word chars, dot, plus,
# dash), which is where a word boundary would let it start. The pattern reads each run once
# from its first char. Written the short way, \b([\w.+-]+@...), it matched the same text but
# started again at every dot, plus and dash inside a run: 4 seconds on a page that is one
# 60,000 char run of dotted labels.
#
# (?<![\w.+-])   : negative lookbehind, this is the first char of a run of email chars
# [.+-]*         : any dots, pluses and dashes the run opens with; they are not part of the email
# (\w[\w.+-]*    : group 1 starts, a word char and then the rest of the local part
#  @[\w-]+       : the @ and the first domain label
#  (?:\.[\w-]+)+): group 1 ends, one or more further labels, each starting with a dot
# :(\S+)         : group 2, the password after the :
EMAIL_AND_PASSWORD_PATTERN = re.compile(
    r"(?<![\w.+-])[.+-]*(\w[\w.+-]*@[\w-]+(?:\.[\w-]+)+):(\S+)"
)

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

# A login is a run of login chars (word chars, dot, plus, dash) with at least one letter in it,
# right before a colon. It cannot start right after a word char, @, dot, slash, colon or hyphen;
# this keeps it out of emails and URLs. The pattern reads each run once from its first char.
# Written the short way, ([\w.+-]*[^\W\d_][\w.+-]*) after (?<![\w@./:-]), it matched the same
# text but tried every way of splitting a run around a letter: 15 seconds on a page that is
# one 60,000 char token.
#
# (?<![\w.+-])            : negative lookbehind, this is the first char of a run of login chars
# (?:(?<![@/:])           : either the run can start a login here, it is not right after @, slash or colon,
#   |[\w.-]*\+)           : or skip to just after the first plus in the run, the only other place
#                           a login can start (user@a+b:pw gives the login b)
# (?=[\d_.+-]*[^\W\d_])   : positive lookahead, a Unicode letter comes before the run ends,
#                           so 12:30 and 9:45 do not match
# ([\w.+-]+)              : group 1, the login, the rest of the run
# (:)                     : group 2, the colon between login and password
# (?!/)                   : negative lookahead, the password cannot start with /, which rejects https://
# (?![^\s:]+://)          : negative lookahead, the password cannot be a URL's scheme, which
#                           rejects link:https://site, where https is not anybody's password
# (?=[^\s:]*\D)           : positive lookahead, the password must contain a non-digit, which rejects host:8080
# ([^\s:]+)               : group 3, the password up to the next whitespace or colon
BARE_LOGIN_PASSWORD_PATTERN = re.compile(
    r"(?<![\w.+-])(?:(?<![@/:])|[\w.-]*\+)(?=[\d_.+-]*[^\W\d_])"
    r"([\w.+-]+)(:)(?!/)(?![^\s:]+://)(?=[^\s:]*\D)([^\s:]+)"
)

# \b                                : word boundary, so it doesn't start mid-credit card
# \d                                : digit
# (?:[ -]?\d)                       : group 1, - or space followed by another digit
# {12,18}                           : repeat group 1 12-18 times
# \b                                : word boundary to not grab longer digit strings
CREDIT_CARD_PATTERN = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# (?<!\d)               : the bot id starts here, it is not the tail of a longer number.
#                         Not a word boundary: in api.telegram.org/bot123456789:AA...
#                         the id comes right after the word "bot"
# \d{8,10}              : the bot id
# :[A-Za-z0-9_-]{35}     : the colon and the 35 character secret
# (?![A-Za-z0-9_-])      : the secret ends here
TELEGRAM_BOT_TOKEN_PATTERN = re.compile(
    r"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"
)

# \b             : word boundary, so it does not start mid-key
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# \b             : word boundary, so it does not start mid-token
GITHUB_TOKEN_PATTERN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")

# Secret shapes the 2026-11-15 survey found stored in clear
# (plan/classification-plan-2026-11-15.md, "Redaction gaps")

# \b                   : word boundary, so it does not start mid-key
# AIza                 : the prefix every Google API key starts with
# [0-9A-Za-z_-]{35}    : the 35 key characters
# \b                   : word boundary, so it does not grab a longer run
GOOGLE_API_KEY_PATTERN = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")

# \b                   : word boundary, so the sk- in "task-" does not match
# sk-                  : the prefix of an API secret key
# [A-Za-z0-9_-]{32,}   : 32 or more key characters
# \b                   : word boundary at the end of the key
SK_API_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")

# \b                   : word boundary, so it does not start mid-token
# [MNO]                : the first character of a base64 encoded user id
# [A-Za-z\d_-]{23,25}  : the rest of the user id part
# \.[A-Za-z\d_-]{6}    : a dot and the 6 character timestamp part
# \.[A-Za-z\d_-]{27,}  : a dot and the signature part
# \b                   : word boundary at the end of the token
DISCORD_TOKEN_PATTERN = re.compile(
    r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b"
)

# (?:(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,} : the header, base64 of a JSON object always starts
#                            eyJ. Any length where it starts a run of token characters,
#   |eyJ[A-Za-z0-9_-]{8,1024}) : and at most 1024 characters where it starts inside one, so a
#                            long run of eyJeyJeyJ with no dot in it is not read to its end
#                            from every eyJ
# \.eyJ[A-Za-z0-9_-]{8,}   : a dot and the payload, another JSON object
# \.[A-Za-z0-9_-]{8,}      : a dot and the signature
JWT_PATTERN = re.compile(
    r"(?:(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{8,1024})"
    r"\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)

# (api_hash\W{0,40}?)  : group 1, the label and the punctuation after it, like api_hash": "
# ([0-9a-f]{32})       : group 2, the 32 hex character hash
# \b                   : word boundary, so a longer hex run is not cut in half
# re.IGNORECASE        : tells the python regex to ignore upper vs lowercase
API_HASH_PATTERN = re.compile(r"(api_hash\W{0,40}?)([0-9a-f]{32})\b", re.IGNORECASE)

# \b                        : word boundary, so it does not start mid-word
# (vmess|ssr?)              : group 1, the scheme
# ://                       : the scheme separator
# ([A-Za-z0-9+/=_-]{20,})   : group 2, the base64 config, which holds the server and the user id
# re.IGNORECASE             : tells the python regex to ignore upper vs lowercase
ENCODED_PROXY_PATTERN = re.compile(
    r"\b(vmess|ssr?)://([A-Za-z0-9+/=_-]{20,})", re.IGNORECASE
)

# (?:\d{1,3}(?:\.\d{1,3}){3}         : an IPv4 address,
#   |\[[0-9a-f:]+\]                  : or an IPv6 address in brackets,
#   |(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}) : or a hostname of two or more labels
# :\d{1,5}                           : the port
# re.IGNORECASE                      : tells the python regex to ignore upper vs lowercase
PROXY_ENDPOINT_PATTERN = re.compile(
    r"(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\]|(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63})"
    r":\d{1,5}",
    re.IGNORECASE,
)

# A proxy written on one line as address:port:user:password, the way sellers list them.
# No other pattern sees its password: the user comes right after a colon, where a bare
# login cannot start, and an IP address has no letter in it to be a login itself.
#
# (?<![\w.-])                               : negative lookbehind, this is the first char of the address.
#                                             A colon may stand in front, as in socks5:8.8.8.8:1080:user:password
# ((?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}    : group 1 starts, the address: two or more labels with dots
#                                             between them, so 8.8.8.8 and proxy.site.com both fit
#  :\d{1,5}                                 : the port
#  :[^\s:]+:)                               : the user, between two colons; group 1 ends
# ([^\s:]+)                                 : group 2, the password up to the next whitespace or colon
# re.IGNORECASE                             : tells the python regex to ignore upper vs lowercase
PROXY_LOGIN_PATTERN = re.compile(
    r"(?<![\w.-])((?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}:\d{1,5}:[^\s:]+:)([^\s:]+)",
    re.IGNORECASE,
)

# \b                        : word boundary, so it does not start mid-word
# ([a-z][a-z0-9+.-]{1,15})  : group 1, any scheme: http, https, socks5 and the rest.
#                             At most 16 characters, so a long dotted run is not read
#                             again from every dot
# (://)                     : group 2, the scheme separator
# ([^\s/@:?#]*)             : group 3, the user: no slash, ? or #, so this is still the
#                             part of the URL before its path and query. It can be
#                             empty, redis://:password@host has no user
# (:)                       : group 4, the colon that makes it credentials and not the
#                             decoy of a spoof, www.site.com@other.site
# ([^\s/?#]+)               : group 5, the password. It may hold an @ of its own: the
#                             host starts after the last @, as a browser reads it
# (?=@)                     : positive lookahead, the @ must follow but stays in the text
# re.IGNORECASE             : tells the python regex to ignore upper vs lowercase
URL_CREDENTIALS_PATTERN = re.compile(
    r"\b([a-z][a-z0-9+.-]{1,15})(://)([^\s/@:?#]*)(:)([^\s/?#]+)(?=@)",
    re.IGNORECASE,
)

# \b                        : word boundary, so it does not start mid-word
# (vless|trojan|ssr?|socks5?|hysteria2?|tuic) : group 1, the scheme
# (://)                     : group 2, the scheme separator
# (?!SECRET\{)              : negative lookahead, skip a user id that is already hashed
# ([^@\s/?#]{8,})           : group 3, the user id or password, everything up to the @.
#                             No ? or #, so this is still the part before the query
# (?=@)                     : positive lookahead, the @ must follow but stays in the text
# re.IGNORECASE             : tells the python regex to ignore upper vs lowercase
PROXY_USERINFO_PATTERN = re.compile(
    r"\b(vless|trojan|ssr?|socks5?|hysteria2?|tuic)(://)(?!SECRET\{)([^@\s/?#]{8,})(?=@)",
    re.IGNORECASE,
)

# ([?&#]secret)                  : group 1, the secret parameter of a Telegram proxy link
# (=)                            : group 2, the = between the name and the value
# ([A-Za-z0-9_%+/-]{16,}={0,2})  : group 3, the secret, hex or base64, percent-encoded or not
# re.IGNORECASE                  : tells the python regex to ignore upper vs lowercase
PROXY_SECRET_PATTERN = re.compile(
    r"([?&#]secret)(=)([A-Za-z0-9_%+/-]{16,}={0,2})", re.IGNORECASE
)

# https?://     : the scheme
# [^\s<>"']+    : everything up to whitespace, a quote or an angle bracket
# re.IGNORECASE : tells the python regex to ignore upper vs lowercase
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# ([?&#](?:token|auth|access_token|login_token|session|sid|code)) : group 1, a parameter named
#                              like a login token, in the query or in the fragment after a #
# (=)                        : group 2, the = between the name and the value
# ([A-Za-z0-9%._:+/=~-]{16,}) : group 3, the token, 16 or more characters. The + / and = are
#                              there because a token is often plain base64
# re.IGNORECASE              : tells the python regex to ignore upper vs lowercase
LOGIN_PARAM_PATTERN = re.compile(
    r"([?&#](?:token|auth|access_token|login_token|session|sid|code))(=)"
    r"([A-Za-z0-9%._:+/=~-]{16,})",
    re.IGNORECASE,
)

# ([?&#][\w.-]+)             : group 1, any parameter name
# (=)                        : group 2, the = between the name and the value
# ([A-Za-z0-9%._:+/=~-]{16,}) : group 3, the value, 16 or more characters
ANY_PARAM_PATTERN = re.compile(r"([?&#][\w.-]+)(=)([A-Za-z0-9%._:+/=~-]{16,})")

# A URL with one of these words in it logs the reader in as someone else, so
# every long value in its query is treated as the login token
AUTOLOGIN_WORDS = ("autologin", "token-login")

# The line a Telegram session export starts with
SESSION_BANNER = "WARNING_BANNER"

# (?<![A-Za-z0-9+/{])       : negative lookbehind, the run starts here and is not the hex inside
#                             SECRET{}. A run may follow an =, as in key=AAAA... or after the
#                             padding of the run before it
# [A-Za-z0-9+/]{64,}        : 64 or more hex or base64 characters, the session's key material
# ={0,2}                    : optional base64 padding
SESSION_KEY_PATTERN = re.compile(r"(?<![A-Za-z0-9+/{])[A-Za-z0-9+/]{64,}={0,2}")

# \b                                         : word boundary, so it doesn't start mid-word
# (password|passwd|pass|pwd|пароль|api_hash) : group 1, the label
# \s*([:=]?)\s*                              : group 2, the : or = after the label, empty if there is none
# $                                          : the text node ends here, so the secret is in the next node
# re.IGNORECASE                              : tells the python regex to ignore upper vs lowercase
LABEL_AT_END_PATTERN = re.compile(
    r"\b(password|passwd|pass|pwd|пароль|api_hash)\s*([:=]?)\s*$", re.IGNORECASE
)

# How much of the end of a text node is searched for a label. The label and
# its separator are a few characters; searching a whole node that ends in
# thousands of spaces would walk them again for every label word in it.
LABEL_TAIL_CHARS = 80

# (\s*)   : group 1, leading whitespace
# (\S+)   : group 2, the first token, the secret
# (.*)    : group 3, the rest of the text node (re.DOTALL lets . cross newlines)
FIRST_TOKEN_PATTERN = re.compile(r"(\s*)(\S+)(.*)", re.DOTALL)

# (\s*[:=]\s*) : group 1, the : or = that the label's own node did not have
# (\S+)        : group 2, the first token after it, the secret
# (.*)         : group 3, the rest of the text node (re.DOTALL lets . cross newlines)
SEPARATOR_FIRST_PATTERN = re.compile(r"(\s*[:=]\s*)(\S+)(.*)", re.DOTALL)


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


def proxy_endpoint(blob: str) -> str | None:
    """Reads the server and port out of a base64 proxy config

    A vmess config is a JSON object with "add" and "port". An ss config is
    method:password@host:port. The endpoint is what Breadth counts, so it is
    kept beside the hashed config.

    Args:
        blob (str): the base64 text after vmess:// or ss://

    Returns:
        str | None: host:port, or None if the config can't be read
    """
    raw = from_base64(blob)
    if raw is None:
        return None
    try:
        config = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None

    if config.startswith("{"):
        try:
            fields = json.loads(config)
        except (ValueError, RecursionError):
            # ValueError covers JSON that does not parse and a number too
            # long for Python to read; whoever posted the page wrote this
            return None
        if not isinstance(fields, dict):
            return None
        endpoint = f"{fields.get('add', '')}:{fields.get('port', '')}"
    elif "@" in config:
        endpoint = config.rpartition("@")[2]
    else:
        # method:password with no server in it: the server is outside the
        # base64, after an @ in the link itself
        return None

    # The config is written by whoever posted the page, so only a plain
    # host:port is let through
    if PROXY_ENDPOINT_PATTERN.fullmatch(endpoint):
        return endpoint
    return None


def redact_text(
    s: str, key: bytes, session: bool = False, link: bool = False
) -> str:
    """Redacts text strings using known secret patterns

    Args:
        s (str): text string to redact
        key (bytes): The hmac key for redactions
        session (bool, optional): True if the page this text is from is a
            Telegram session export. Defaults to False.
        link (bool, optional): True if s is the target of a link, an href or
            a src. Every pattern runs but the bare login:password one, which
            would read mailto:bob@host or any word:word in a link as a
            login. Defaults to False.

    Returns:
        str: Redacted string
    """

    def _hash_whole(m: re.Match) -> str:
        return hash_secret(m.group(0), key)

    def _hash_api_hash(m: re.Match) -> str:
        return m.group(1) + hash_secret(m.group(2), key)

    def _hash_encoded_proxy(m: re.Match) -> str:
        out = m.group(1) + "://" + hash_secret(m.group(2), key)
        endpoint = proxy_endpoint(m.group(2))
        # The endpoint goes back into the stored text, so it must be text
        # that redaction leaves alone: a second pass must change nothing
        if endpoint is not None and redact_text(endpoint, key) == endpoint:
            out = out + "@" + endpoint
        return out

    def _hash_param(m: re.Match) -> str:
        value = m.group(3)
        # A value that runs into a marker, name:SECRET{...}, has its secret
        # hashed already; hashing the two together would not be repeatable
        runs_into_marker = value.endswith(MARKER[:-1]) and m.string.startswith(
            "{", m.end(3)
        )
        if value.startswith(MARKER) or runs_into_marker:
            return m.group(0)
        return m.group(1) + m.group(2) + hash_secret(value, key)

    def _hash_login_url(m: re.Match) -> str:
        url = m.group(0)
        if any(word in url.lower() for word in AUTOLOGIN_WORDS):
            return ANY_PARAM_PATTERN.sub(_hash_param, url)
        return LOGIN_PARAM_PATTERN.sub(_hash_param, url)

    def _hash_labelled(m: re.Match) -> str:
        if m.group(3).startswith(MARKER):
            return m.group(0)
        return m.group(1) + m.group(2) + hash_secret(m.group(3), key)

    def _hash_bare_login(m: re.Match) -> str:
        if m.group(3).startswith(MARKER):
            return m.group(0)
        # Everything before the password is kept as it is, the part of the
        # run that was skipped to reach the login included
        kept = m.group(0)[: m.start(3) - m.start()]
        return kept + hash_secret(m.group(3), key)

    def _hash_email_password(m: re.Match) -> str:
        if m.group(2).startswith(MARKER):
            return m.group(0)
        # Everything before the password is kept as it is, any dots, pluses
        # and dashes in front of the email included
        kept = m.group(0)[: m.start(2) - m.start()]
        return kept + hash_secret(m.group(2), key)

    def _hash_card(m: re.Match) -> str:
        digits = m.group(0).replace(" ", "").replace("-", "")
        return hash_secret(digits, key) if is_card(digits) else m.group(0)

    def _hash_storage_keys(m: re.Match) -> str:
        fields = m.group(1).split("?")
        for i in range(min(2, len(fields))):
            if not fields[i].startswith(MARKER):
                fields[i] = hash_secret(fields[i], key)
        return "/!" + "?".join(fields)

    def _hash_url_credentials(m: re.Match) -> str:
        user, password = m.group(3), m.group(5)
        if password.startswith(MARKER):
            return m.group(0)
        # 8.8.8.8:8080 in front of an @ further on is a server, not a login.
        # Up to the first @, which is where the password ended before it
        # could hold one: what was a server then is a server now
        if PROXY_ENDPOINT_PATTERN.fullmatch(user + ":" + password.partition("@")[0]):
            return m.group(0)
        head = m.group(1) + m.group(2)
        if user.startswith(MARKER) or not user:
            # An earlier pattern hashed the user, an access key id say, or
            # there is no user at all; the password still has to go
            return head + user + ":" + hash_secret(password, key)
        return head + hash_secret(user + ":" + password, key)

    def _hash_proxy_login(m: re.Match) -> str:
        if m.group(2).startswith(MARKER):
            return m.group(0)
        return m.group(1) + hash_secret(m.group(2), key)

    def _hash_proxy_userinfo(m: re.Match) -> str:
        # socks5://8.8.8.8:1080 in front of an @ further on is the server
        # itself, which _hash_url_credentials has just left alone as well
        if PROXY_ENDPOINT_PATTERN.fullmatch(m.group(3)):
            return m.group(0)
        return _hash_labelled(m)

    def _passes(s: str) -> str:
        s = STORAGE_KEYS_PATTERN.sub(_hash_storage_keys, s)
        s = TELEGRAM_BOT_TOKEN_PATTERN.sub(_hash_whole, s)
        s = AWS_KEY_PATTERN.sub(_hash_whole, s)
        s = GITHUB_TOKEN_PATTERN.sub(_hash_whole, s)
        s = GOOGLE_API_KEY_PATTERN.sub(_hash_whole, s)
        s = SK_API_KEY_PATTERN.sub(_hash_whole, s)
        s = DISCORD_TOKEN_PATTERN.sub(_hash_whole, s)
        s = JWT_PATTERN.sub(_hash_whole, s)
        # The proxy patterns run before the email:password one, which would
        # otherwise read uuid@host:port as an email and hash the port
        s = ENCODED_PROXY_PATTERN.sub(_hash_encoded_proxy, s)
        s = URL_CREDENTIALS_PATTERN.sub(_hash_url_credentials, s)
        s = PROXY_USERINFO_PATTERN.sub(_hash_proxy_userinfo, s)
        s = PROXY_SECRET_PATTERN.sub(_hash_param, s)
        s = URL_PATTERN.sub(_hash_login_url, s)
        s = API_HASH_PATTERN.sub(_hash_api_hash, s)
        if session or SESSION_BANNER in s:
            s = SESSION_KEY_PATTERN.sub(_hash_whole, s)
        s = LABELED_PASSWORD_PATTERN.sub(_hash_labelled, s)
        s = HYPHEN_PASSWORD_PATTERN.sub(_hash_labelled, s)
        s = NEWLINE_PASSWORD_PATTERN.sub(_hash_labelled, s)
        s = EMAIL_AND_PASSWORD_PATTERN.sub(_hash_email_password, s)
        s = CREDIT_CARD_PATTERN.sub(_hash_card, s)
        # Before the bare login pattern, which reads proxy.site.com:8080 as a
        # login and a password and hashes the port: this one needs the port
        # still there to know the line for a proxy
        s = PROXY_LOGIN_PATTERN.sub(_hash_proxy_login, s)
        # In a link target word:word is the URL itself, mailto:bob@host or
        # https://site/page:section, so the bare login pattern stays out of it
        if not link:
            s = BARE_LOGIN_PASSWORD_PATTERN.sub(_hash_bare_login, s)
        return s

    # Hashing one thing can uncover another: a card number written with
    # spaces ends a URL until its spaces are gone, and the longer URL can
    # then be credentials. So the patterns are run until a round changes
    # nothing, which makes redacting twice the same as redacting once.
    for _round in range(MAX_ROUNDS):
        out = _passes(s)
        if out == s:
            break
        s = out
    return out


def redact_page(page: dict, key: bytes) -> dict:
    """Function to redact entire page contents using redact_text

    Args:
        page (dict): A telegraph page in dictionary form
        key (bytes): The hmac key for redactions

    Returns:
        dict: The redacted page in dictionary form
    """

    def _has_banner(nodes: list) -> bool:
        # A list used as a stack, not a function that calls itself: a page
        # can nest its nodes deeper than Python lets a function recurse
        stack = list(nodes)
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                if SESSION_BANNER in node:
                    return True
            elif isinstance(node, dict):
                stack.extend(node.get("children", []))
        return False

    # A session export can be split over several text nodes, so the banner
    # is looked for once and every node of the page is told about it
    session = _has_banner(page.get("content", []))

    # What the last text node left for the next one, because redact_text
    # only sees one node at a time:
    #   None        : nothing
    #   "secret"    : it ended with a label and its separator, like
    #                 <strong>Password:</strong>, so the next node opens with the secret
    #   "separator" : it ended with a bare label, like <strong>Password</strong>,
    #                 so the next node has to open with : or = and then the secret
    waiting = None

    def _redact_string(s: str) -> str:
        nonlocal waiting
        # A node of only whitespace sits between the label and the secret
        if not s.strip():
            return s
        out = redact_text(s, key, session)
        m = None
        if waiting == "secret":
            m = FIRST_TOKEN_PATTERN.match(out)
        elif waiting == "separator":
            m = SEPARATOR_FIRST_PATTERN.match(out)
        # The node is redacted first, and then whatever of its first token
        # is still in clear is hashed: all of it, or the parts around the
        # hashes redaction put in it. So pa:ss after a label does not
        # keep its "pa", bob@host:pw comes out the same from a fresh fetch
        # and from a stored copy that already holds bob@host:SECRET{...},
        # and a second pass finds a hash first and changes nothing.
        if m is not None:
            token = m.group(2)
            # Every stretch of the token that is not a hash yet: in front
            # of, between and behind the hashes redaction put in it
            pieces = []
            position = 0
            for marker in MARKER_PATTERN.finditer(token):
                clear = token[position : marker.start()]
                pieces.append(hash_secret(clear, key) if clear else "")
                pieces.append(marker.group(0))
                position = marker.end()
            if token[position:]:
                pieces.append(hash_secret(token[position:], key))
            out = m.group(1) + "".join(pieces) + m.group(3)

        # The label is looked for in the node as it will be stored, not as
        # it came: a stored copy only has the redacted text to go by, and it
        # has to come to the same decision as a fresh fetch
        label = LABEL_AT_END_PATTERN.search(out.rstrip()[-LABEL_TAIL_CHARS:])
        if label is None:
            waiting = None
        elif label.group(2):
            waiting = "secret"
        else:
            waiting = "separator"
        return out

    def _redact_attrs(node: dict) -> dict:
        # A link's target is not in the page text, but it is stored with the
        # content: <a href="https://site/autologin?key=..."> has to lose its
        # key as well
        attrs = node.get("attrs")
        if not isinstance(attrs, dict):
            return node
        redacted = {
            name: redact_text(attrs[name], key, session, link=True)
            for name in ("href", "src")
            if isinstance(attrs.get(name), str)
        }
        return {**node, "attrs": {**attrs, **redacted}}

    def _redact_node(node):
        if isinstance(node, str):
            return _redact_string(node)
        if isinstance(node, dict):
            node = _redact_attrs(node)
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
        out["title"] = redact_text(page["title"], key, session)

    if isinstance(page.get("description"), str):
        out["description"] = redact_text(page["description"], key, session)

    return out
