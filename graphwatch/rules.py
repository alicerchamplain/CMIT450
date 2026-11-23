"""Clases and functions for threat scoring rules"""

import base64
import binascii
import functools
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from graphwatch.decode import (
    BYTE_DECODERS,
    as_text,
    decode_base64_pointer,
    decode_pointer,
)

WHERE = frozenset(["title", "description", "text", "body", "page", "computed"])

# Score Threshold
THRESHOLD = 4

# Every category a rule can count towards, in the order that picks a page's
# primary label: the first category in this tuple that a page is labelled
# with is the one it is counted under when each page is counted once.
CATEGORIES = (
    "resolver",
    "template_spam",
    "pointer",
    "leaked_credentials",
    "proxy_list",
    "malware_delivery",
    "fraud_market",
    "crypto_lure",
    "phishing",
    "doxx",
    "telegram_funnel",
    "seo_spam",
    "placeholder",
    "prose",
)

# The categories that are intelligence. The rest are noise, which is named
# so that it can be subtracted.
INTELLIGENCE = frozenset(
    [
        "resolver",
        "pointer",
        "leaked_credentials",
        "proxy_list",
        "malware_delivery",
        "fraud_market",
        "crypto_lure",
        "phishing",
        "doxx",
    ]
)

# Computed rules: body length limits
EMPTY_BODY_CHARS = 20
LONG_TEXT_CHARS = 3000

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

# The spoof, and after it the unlisted-decoy form of it, without groups, for
# the two patterns below
SPOOF = rf"(?<![\w.@-])(?:{HOST})@(?:{HOST})(?![\w@-])"
ANY_DECOY_SPOOF = rf"(?<![\w.@-])(?:(?:[a-z0-9-]+\.)+[a-z]{{2,}})@(?:{HOST})(?![\w@-])"

# Regex for detecting the spoof where it is a spoof and not an email address
# host@host is also what name.com@gmail.com looks like. A spoof only works in
# a URL, so it is counted in the three places the actor's pages put it:
# (?:(?<=://)|(?<=\?))SPOOF : right after a scheme, or after the ? of the
#                             pointer title, 207.246.108.214?decoy@destination/!...
# SPOOF(?=/)                : or with a path after it, decoy@destination/
# \ASPOOF$                  : or as the whole first line of the text, which is the title
#                             (re.MULTILINE lets $ match at the end of that line)
SPOOF_URL_PATTERN = re.compile(
    rf"(?:(?<=://)|(?<=\?)){SPOOF}|{SPOOF}(?=/)|\A{SPOOF}$",
    re.IGNORECASE | re.MULTILINE,
)

# The same three places for a title whose decoy ends in a TLD outside the list
# \AANY_DECOY_SPOOF\s*\Z   : here the whole title, since this pattern only reads titles
TITLE_SPOOF_URL_PATTERN = re.compile(
    rf"(?:(?<=://)|(?<=\?)){ANY_DECOY_SPOOF}|{ANY_DECOY_SPOOF}(?=/)"
    rf"|\A{ANY_DECOY_SPOOF}\s*\Z",
    re.IGNORECASE,
)

# Hosts that hand out mailboxes. The right side of a spoof is the actor's own
# server, so host@host with one of these on the right is an email address.
MAILBOX_PROVIDERS = (
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "gmx.com",
    "gmx.de",
    "gmx.net",
    "web.de",
    "proton.me",
    "protonmail.com",
    "tutanota.com",
    "mail.com",
    "mail.ru",
    "bk.ru",
    "list.ru",
    "inbox.ru",
    "internet.ru",
    "yandex.ru",
    "yandex.com",
    "yandex.ua",
    "ya.ru",
    "rambler.ru",
    "ukr.net",
    "i.ua",
    "meta.ua",
    "qq.com",
    "163.com",
)

# Regex for detecting an IP that opens a title
# The pointer title leads with its address: 207.246.108.214?decoy@destination/!...
# A title with an address further in is a sentence, like Patch 1.12.1.5.
# (?:\A                  : the IP is the first thing in the title,
#   |(?<=\Ahttp://)      : or the first thing after a scheme
#   |(?<=\Ahttps://))
# \d{1,3}(?:\.\d{1,3}){3} : four groups of 1 to 3 digits
# (?![\d.])             : not followed by more digits or dots
TITLE_IP_PATTERN = re.compile(
    r"(?:\A|(?<=\Ahttp://)|(?<=\Ahttps://))\d{1,3}(?:\.\d{1,3}){3}(?![\d.])",
    re.IGNORECASE,
)

# Regex for detecting s3 storage keys used by Gamaredon
# /!   : the storage-key marker
# \S+  : the hashed key and whatever follows up to whitespace
STORAGE_KEY_PATTERN = re.compile(r"/!\S+")

# Regex for detecting email addresses
# [\w.+-]+@HOST : any email-shaped token
EMAIL_PATTERN = re.compile(rf"(?<![\w.+@-])[\w.+-]+@{HOST}(?![\w@-])", re.IGNORECASE)

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

# --------------------------------------------------------------------------
# Patterns for the category rules (plan/classification-plan-2026-11-15.md)
# They read the text as it is stored, so a secret is already SECRET{hex}
# --------------------------------------------------------------------------

# Regex for a secret that redaction hashed, with the login in front of it if it has one
# (?:[\w.+@-]{1,64}:)? : optional, a login and its colon right before the secret,
#                     like Size:SECRET{...}; counted_secret decides if it counts.
#                     At most 64 characters, so a long run with no colon in it
#                     is not walked again from every one of its characters
# (?<!://)          : not a proxy link's user id, which is hashed too but is
#                     a proxy and not a leaked account
# (?<!secret=)      : not a Telegram proxy link's secret, for the same reason
# SECRET\{          : the marker redact.py writes
# [0-9a-f]{64}\}    : the HMAC hex and the closing brace
HASHED_SECRET_PATTERN = re.compile(
    r"(?:[\w.+@-]{1,64}:)?(?<!://)(?<!secret=)SECRET\{[0-9a-f]{64}\}"
)

# The labels redact.py hashes a value after. A secret behind one of these is
# a password; a secret behind any other word and a colon is the bare
# login:password shape, which is also what Size:400MB looks like.
SECRET_LABELS = ("password", "passwd", "pass", "pwd", "пароль", "api_hash")

# Regex for one line of a combo list, email:password with the password hashed
# [\w.+-]{1,64}@        : the local part and the @. At most 64 characters, which
#                         is the longest a local part can be, so a long run with
#                         no @ in it is not walked again from every character
# [\w-]+(?:\.[\w-]+)+   : the domain, two or more labels
# :SECRET\{             : the colon and the start of the hashed password
COMBO_LINE_PATTERN = re.compile(r"[\w.+-]{1,64}@[\w-]+(?:\.[\w-]+)+:SECRET\{")

# Regex for a Telegram API credential pair, in either order
# api_id[\s\S]{0,200}?api_hash : api_id, then api_hash within 200 characters
# api_hash[\s\S]{0,200}?api_id : or the other way round
TELEGRAM_API_PAIR_PATTERN = re.compile(
    r"api_id[\s\S]{0,200}?api_hash|api_hash[\s\S]{0,200}?api_id",
    re.IGNORECASE | re.ASCII,
)

# Regex for one http(s) URL, whole
# https?://     : the scheme
# [^\s<>"']+    : everything up to whitespace, a quote or an angle bracket
# The rules about links read one whole URL and let a check function decide.
# A pattern that looks for something inside the URL, https?://\S*autologin\S*,
# starts again at every http:// of a page that repeats it and takes seconds.
URL_TOKEN_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Punctuation that ends a sentence or closes a quotation, not a URL
URL_TRAILING = ".,;:!?)]}*»“”’„…"

# A URL with one of these words in it logs the reader in as someone else
AUTOLOGIN_WORDS = ("autologin", "token-login")

# Regex for a login parameter whose value redaction hashed
# [?&#]                     : the parameter starts the query, follows another, or is in the fragment
# (?:token|auth|access_token|login_token|session|sid|code) : a name like a login token's
# =SECRET\{                 : and a hashed value
HASHED_LOGIN_PARAM_PATTERN = re.compile(
    r"[?&#](?:token|auth|access_token|login_token|session|sid|code)=SECRET\{",
    re.IGNORECASE,
)

# What a link straight to something that runs ends in, and what an archive ends in
EXECUTABLE_EXTENSIONS = (".exe", ".apk", ".msi", ".scr", ".ps1", ".lnk", ".hta", ".iso")
ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z")

# Regex for a body that is one URL with a token in its query
# \A(?=\S+\Z)          : the whole body is one token: no whitespace anywhere in it.
#                         Checked first and once, so a body that has whitespace
#                         further on is turned away before the query is read
# https?://[^\s?#]+     : a URL, up to its query
# \?\S*?               : the query, as little of it as is needed
# (?:SECRET\{           : to reach a token that redaction hashed
#   |[A-Za-z0-9%_-]{16,}) : or a run of 16 or more token characters
TRACKING_URL_BODY_PATTERN = re.compile(
    r"\A(?=\S+\Z)https?://[^\s?#]+\?\S*?(?:SECRET\{|[A-Za-z0-9%_-]{16,})",
    re.IGNORECASE,
)

# Regex for a body that is a single short token: no whitespace, under 80 characters
BARE_BODY_PATTERN = re.compile(r"\A\S{4,79}\Z")

# Regex for a body under 200 characters (re.DOTALL lets . cross newlines)
SHORT_BODY_PATTERN = re.compile(r"\A.{1,199}\Z", re.DOTALL)

# Regex for a body that is one run of base64, hex or base32 characters
ENCODED_BODY_PATTERN = re.compile(r"\A[A-Za-z0-9+/=_-]{12,}\Z")

# Regex for a host on a tunnel or dynamic-DNS service
# (?<![\w.-])         : start of the whole hostname, not of a label inside it,
#                       so a long dotted run is read once and not once per label
# (?:[a-z0-9-]+\.)+   : one or more labels, the part the poster chose
# (?:workers\.dev|...) : the service's own domain
# (?![\w-])           : the name ends here
TUNNEL_HOST_PATTERN = re.compile(
    r"(?<![\w.-])(?:[a-z0-9-]+\.)+"
    r"(?:workers\.dev|trycloudflare\.com|ngrok\.io|ngrok\.app|ngrok-free\.app"
    r"|ngrok-free\.dev|duckdns\.org|ddns\.net|hopto\.org|zapto\.org|sytes\.net"
    r"|serveo\.net|loca\.lt|portmap\.io|playit\.gg)(?![\w-])",
    re.IGNORECASE,
)

# Regex for a link to raw paste or raw repository content
RAW_PASTE_PATTERN = re.compile(
    r"(?:pastebin\.com/raw|raw\.githubusercontent\.com|gist\.githubusercontent\.com)"
    r"[^\s<>\"']*",
    re.IGNORECASE,
)

# Regex for a proxy or VPN link
# (?<![a-z0-9])   : start of the scheme, so the ss:// inside wss:// is not one
# (?:vless|vmess|ssr?|trojan|socks5?|hysteria2?|tuic) : the scheme
# ://             : the scheme separator
PROXY_URI_PATTERN = re.compile(
    r"(?<![a-z0-9])(?:vless|vmess|ssr?|trojan|socks5?|hysteria2?|tuic)://",
    re.IGNORECASE,
)

# Regex for an ip:port pair
# (?<![\w.])               : not inside a longer dotted number or a word
# \d{1,3}(?:\.\d{1,3}){3}  : four groups of 1 to 3 digits
# :\d{2,5}\b               : the colon and a port of 2 to 5 digits
IP_PORT_PATTERN = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b")

# Regex for a Telegram proxy link, MTProto or SOCKS, with its whole query
# (?:t\.me/|tg://)   : the link, web or app form
# (?:proxy|socks)\?  : the proxy or socks command and the ? that opens its query
# [^\s<>"']*         : the query; names_a_server checks that it has a server= in it
TELEGRAM_PROXY_PATTERN = re.compile(
    r"(?:t\.me/|tg://)(?:proxy|socks)\?[^\s<>\"']*", re.IGNORECASE | re.ASCII
)

# Regex for the JSON keys of a proxy client config
# "(?:server|port|address)" : one of the three key names, quoted
# \s*:                      : the colon that makes it a key
PROXY_CONFIG_KEY_PATTERN = re.compile(r'"(?:server|port|address)"\s*:', re.IGNORECASE)

# Regex for a download-and-run command
RUN_COMMAND_PATTERN = re.compile(
    r"(?<![\w-])(?:powershell|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin"
    r"|invoke-webrequest|frombase64string|curl -|wget http|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)

# Regex for a link to a file host
FILE_HOST_PATTERN = re.compile(
    r"(?:mega\.nz|mediafire\.com|gofile\.io|anonfiles|dropmefiles|disk\.yandex"
    r"|yadi\.sk|drive\.google\.com|dropbox\.com|cdn\.discordapp\.com/attachments"
    r"|/releases/download/|transfer\.sh|catbox\.moe|pixeldrain)",
    re.IGNORECASE,
)

# Regex for a Tor hidden service name
# \b(?:[a-z2-7]{56}|[a-z2-7]{16}) : a v3 name (56 base32 characters) or a v2 name (16)
# \.onion\b                       : the .onion ending
ONION_PATTERN = re.compile(
    r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.IGNORECASE | re.ASCII
)

# Regex for carding vocabulary
CARD_TERMS_PATTERN = re.compile(r"\b(?:cvv2?|fullz|carding)\b|кардинг", re.IGNORECASE)

# Regex for stealer vocabulary and stealer family names
STEALER_TERMS_PATTERN = re.compile(
    r"stealer|stealler|стиллер|стилер|redline|lumma|vidar|raccoon", re.IGNORECASE
)

# Regex for wallet-drainer and fake-airdrop vocabulary
DRAINER_TERMS_PATTERN = re.compile(
    r"seed phrase|сид[ -]фраз|airdrop|аирдроп|wallet ?connect|metamask"
    r"|trust wallet|drainer|дрейнер",
    re.IGNORECASE,
)

# Regex for a cryptocurrency wallet address
# \b0x[a-fA-F0-9]{40}\b                 : Ethereum, 0x and 40 hex characters
# \bT[1-9A-HJ-NP-Za-km-z]{33}\b         : Tron, T and 33 base58 characters
# \bbc1[a-z0-9]{25,60}\b                : Bitcoin, the bech32 form
# \b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b   : Bitcoin, the older base58 form
WALLET_ADDRESS_PATTERN = re.compile(
    r"\b0x[a-fA-F0-9]{40}\b"
    r"|\bT[1-9A-HJ-NP-Za-km-z]{33}\b"
    r"|\bbc1[a-z0-9]{25,60}\b"
    r"|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
)

# Regex for one <input ...> tag of an HTML form, whole
# <input      : the tag opens
# [^>]*       : everything up to its closing >
INPUT_TAG_PATTERN = re.compile(r"<input[^>]*", re.IGNORECASE | re.ASCII)

# Regex for the attribute that makes an input a password field
PASSWORD_TYPE_PATTERN = re.compile(r"type\s*=\s*[\"']?password", re.IGNORECASE | re.ASCII)

# Regex for a host on a free hosting service, same shape as TUNNEL_HOST_PATTERN
FREE_HOST_PATTERN = re.compile(
    r"(?<![\w.-])(?:[a-z0-9-]+\.)+"
    r"(?:pages\.dev|web\.app|firebaseapp\.com|vercel\.app|netlify\.app|github\.io"
    r"|glitch\.me|repl\.co|onrender\.com|herokuapp\.com|000webhostapp\.com"
    r"|weebly\.com|blogspot\.com|wixsite\.com)(?![\w-])",
    re.IGNORECASE,
)

# Regex for a link through a URL shortener
# (?<![\w.-])        : start of the hostname, so habit.ly/ is not bit.ly/
# (?:bit\.ly|...)    : the shortener
# /\w                : and a path, which is what makes it a link
SHORTENER_PATTERN = re.compile(
    r"(?<![\w.-])(?:bit\.ly|clck\.ru|tinyurl\.com|cutt\.ly|is\.gd|goo\.su|vk\.cc"
    r"|rb\.gy|shorturl\.at|tiny\.cc|ow\.ly)/\w",
    re.IGNORECASE,
)

# Regexes for the field names of an identity document, one per field
PASSPORT_FIELD_PATTERN = re.compile(r"паспорт", re.IGNORECASE)
REGISTRATION_FIELD_PATTERN = re.compile(r"прописк", re.IGNORECASE)
BIRTH_DATE_FIELD_PATTERN = re.compile(r"дата рождения", re.IGNORECASE)
ADDRESS_FIELD_PATTERN = re.compile(r"адрес проживания", re.IGNORECASE)

# Regex for a Telegram invite link
TELEGRAM_INVITE_PATTERN = re.compile(r"t\.me/(?:\+|joinchat/)[\w-]+", re.IGNORECASE)

# Regex for a link to a Telegram bot: bot usernames have to end in "bot"
TELEGRAM_BOT_PATTERN = re.compile(r"t\.me/\w+bot\b", re.IGNORECASE)

# Regex for a Telegram @handle
# (?<![\w@])   : not inside an email address or a spoof
# @[A-Za-z]\w{4,31}\b : @, a letter, then 4 to 31 more word characters
TELEGRAM_HANDLE_PATTERN = re.compile(r"(?<![\w@])@[A-Za-z]\w{4,31}\b")

# Regex for the vocabulary of the "sliv" and VIP-bot adverts
ADULT_AD_TERMS_PATTERN = re.compile(r"порно|porn|секс|слив|intim|эскорт", re.IGNORECASE)

# Regex for the file hosts that movie-link spam points at
MOVIE_LINK_TERMS_PATTERN = re.compile(r"mdisk|terabox", re.IGNORECASE)

# Regex for casino and betting brand names
CASINO_TERMS_PATTERN = re.compile(
    r"casino|казино|1xbet|1win|vavada|букмекер|pin-?up", re.IGNORECASE
)


@dataclass(frozen=True)
class Rule:
    """A scoring rule in the rule table

    category is the category the weight counts towards. min_matches holds the
    rule back until it has matched that many times: a proxy list is three
    ip:port lines, not one. gate is a lower-case substring that has to be in
    the field before the regex is run at all; it saves time and never changes
    a result, so it has to be text every match of the pattern contains.
    """

    name: str
    weight: int
    where: str
    pattern: re.Pattern | None
    exists_for: str
    check: Callable[[str], bool] | None = None
    category: str = "resolver"
    min_matches: int = 1
    gate: str | None = None


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


@functools.lru_cache(maxsize=4096)
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


def is_spoof(s: str) -> bool:
    """Function to check if a host@host match is a spoof and not an email address

    The right side of a spoof is where the link really goes, so it is never
    a mailbox provider. name.com@gmail.com is somebody's email address.
    """
    destination = s.rpartition("@")[2].lower()
    for provider in MAILBOX_PROVIDERS:
        if destination == provider or destination.endswith("." + provider):
            return False
    return True


def is_unlisted_decoy_spoof(s: str) -> bool:
    """Function to check if a spoof's decoy ends in a TLD outside the list

    Those are the ones userinfo_spoof cannot see. A decoy it can see is left
    to it, so one spoof is not scored by both rules.
    """
    return is_spoof(s) and _not_a_host_local_part(s)


def is_bare_pointer(s: str) -> bool:
    """Function to check if a whole string is a server address and nothing more

    A bare IP or hostname, with or without a port, or a URL that stops at
    its host. A URL with a path, a query or a fragment points at a page, an
    image or a file, not at a server: https://pin.it/abc is a link to share.
    """
    if not is_pointer(s):
        return False
    if s.lower().startswith(("http://", "https://")):
        # is_pointer already turned away a URL that urlsplit cannot read
        parts = urlsplit(s)
        return parts.path in ("", "/") and not parts.query and not parts.fragment
    return True


def is_autologin_link(url: str) -> bool:
    """Function to check if a URL logs the reader in as someone else

    It does when it has an autologin word in it, or a login parameter whose
    value redaction hashed.
    """
    lowered = url.lower()
    if any(word in lowered for word in AUTOLOGIN_WORDS):
        return True
    return HASHED_LOGIN_PARAM_PATTERN.search(url) is not None


def has_token_in_path(url: str) -> bool:
    """Function to check if a URL has a hashed token as a segment of its path

    The path is what comes after the host and before any ? or #. The host
    part is left out so the hashed credentials of scheme://SECRET{...}@host
    are not taken for a path segment.
    """
    rest = url.partition("://")[2]
    # The query and the fragment are cut off first: in https://site?next=/x
    # the slash is in the query, and the URL has no path at all
    rest = rest.partition("?")[0].partition("#")[0]
    path = rest.partition("/")[2]
    return ("/" + path).find("/SECRET{") != -1


def _path_ends_with(url: str, extensions: tuple[str, ...]) -> bool:
    try:
        path = urlsplit(url.rstrip(URL_TRAILING)).path
    except ValueError:
        return False
    return path.lower().endswith(extensions)


def is_executable_link(url: str) -> bool:
    """Function to check if a URL's path ends in an executable's extension

    The path, not the URL: https://www.msi.com/laptop and a hostname with a
    label like iso or lnk are links to ordinary pages.
    """
    return _path_ends_with(url, EXECUTABLE_EXTENSIONS)


def is_archive_link(url: str) -> bool:
    """Function to check if a URL's path ends in an archive's extension"""
    return _path_ends_with(url, ARCHIVE_EXTENSIONS)


def names_a_server(s: str) -> bool:
    """Function to check if a Telegram proxy link carries the server it connects to"""
    return "server=" in s.lower()


def is_password_input(s: str) -> bool:
    """Function to check if an <input> tag is a password field"""
    return PASSWORD_TYPE_PATTERN.search(s) is not None


def counted_secret(s: str) -> bool:
    """Function to check if a hashed secret counts towards a page of leaked accounts

    The bare login:password pattern in redact.py also hashes ordinary
    word:word text, like the Size:400MB of a movie-link page. So a secret
    right behind a word and a colon is only counted when the word is a
    password label. An email:password line is left to combo_lines.
    """
    login, colon, _secret = s.partition(":SECRET{")
    if not colon:
        return True
    return login.lower().endswith(SECRET_LABELS)


def has_public_ip(s: str) -> bool:
    """Function to check if a string holds a publicly routable IP anywhere in it"""
    return any(is_public_ip(match.group(0)) for match in IP_PATTERN.finditer(s))


def is_public_ip_port(s: str) -> bool:
    """Function to check if the address of an ip:port pair is publicly routable"""
    return is_public_ip(s.rpartition(":")[0])


def decodes_to_text(s: str) -> bool:
    """Function to check if a token decodes to printable text

    Tried with base64, hex and base32. An ordinary word almost never passes:
    every decoded byte has to be printable ASCII.
    """
    for _name, decoder in BYTE_DECODERS:
        raw = decoder(s)
        if raw is not None and as_text(raw) is not None:
            return True
    return False


RULES: tuple[Rule, ...] = (
    # ----------------------------------------------------------------------
    # resolver: the known actor's shapes. These eleven rules and their
    # weights are the verdict reported since 14 November and do not change.
    # ----------------------------------------------------------------------
    Rule(
        "userinfo_spoof",
        5,
        "text",
        SPOOF_URL_PATTERN,
        "Matching the Gamaredon userinfo spoof pattern like onmedservice[.]com[.]ua@opportunizz[.]pro, where it is part of a URL: after a scheme or a ?, before a /, or as the whole title. An email address whose name ends like a domain, name[.]com@gmail[.]com, has the same shape and is none of those",
        check=is_spoof,
    ),
    Rule(
        "spoof_in_title",
        5,
        "title",
        TITLE_SPOOF_URL_PATTERN,
        "Matching userinfo spoof titles whose decoy site ends in a TLD outside the list, like primewire[.]ag@agfc[.]harper18[.]workers[.]dev, which userinfo_spoof misses",
        check=is_unlisted_decoy_spoof,
    ),
    Rule(
        "ip_in_title",
        4,
        "title",
        TITLE_IP_PATTERN,
        "Matching Gamaredon-like pages whose title opens with an IP, as the pointer title does. An address further into a title is a sentence about something else, like Patch 1[.]12[.]1[.]5",
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
    # ----------------------------------------------------------------------
    # template_spam
    # ----------------------------------------------------------------------
    Rule(
        "template_spam",
        4,
        "computed",
        None,
        "Matches pages whose body is posted under three or more titles, the same fact as templated_body, so a title squatter's advert is counted once, as spam, whatever words it uses",
        category="template_spam",
    ),
    # ----------------------------------------------------------------------
    # pointer
    # ----------------------------------------------------------------------
    Rule(
        "bare_pointer_body",
        4,
        "body",
        BARE_BODY_PATTERN,
        "Matches pages whose whole body is one server address under 80 characters: a bare IP or host, with or without a port, or a URL with no path. The dead-drop shape, whoever posted it. A URL with a path is a link to a page or a file: of 311 single-URL bodies on the first night, 67 were a Telegram link and most others pointed at image and file hosts",
        check=is_bare_pointer,
        category="pointer",
    ),
    Rule(
        "ip_in_short_body",
        3,
        "body",
        SHORT_BODY_PATTERN,
        "Matches pages with a public IP in a body under 200 characters",
        check=has_public_ip,
        category="pointer",
    ),
    Rule(
        "tunnel_host",
        3,
        "page",
        TUNNEL_HOST_PATTERN,
        "Matches pages naming a host on a tunnel or dynamic-DNS service like trycloudflare[.]com, workers[.]dev, ngrok or duckdns[.]org",
        category="pointer",
    ),
    Rule(
        "encoded_body",
        3,
        "body",
        ENCODED_BODY_PATTERN,
        "Matches pages whose whole body is one token that base64, hex or base32 turns into printable text",
        check=decodes_to_text,
        category="pointer",
    ),
    Rule(
        "raw_paste_link",
        2,
        "page",
        RAW_PASTE_PATTERN,
        "Matches pages linking to raw paste or raw repository content, which a script reads and a person does not",
        category="pointer",
    ),
    Rule(
        "api_sample_page",
        1,
        "description",
        API_SAMPLE_PATTERN,
        "Matches posts that use the default API example body, so the page was made by a script",
        category="pointer",
    ),
    Rule(
        "tracking_url_body",
        -3,
        "body",
        TRACKING_URL_BODY_PATTERN,
        "Matches pages whose body is one URL with a token in its query. Most single-address bodies are dating-site login links, which are leaked sessions and not dead drops",
        category="pointer",
        gate="://",
    ),
    # ----------------------------------------------------------------------
    # leaked_credentials
    # ----------------------------------------------------------------------
    Rule(
        "combo_lines",
        4,
        "body",
        COMBO_LINE_PATTERN,
        "Matches combo lists: three or more email:password lines, the passwords hashed at ingest",
        category="leaked_credentials",
        min_matches=3,
        gate=":secret{",
    ),
    Rule(
        "many_secrets",
        4,
        "body",
        HASHED_SECRET_PATTERN,
        "Matches pages where redaction hashed ten or more secrets. Proxy user ids are not counted, and neither is a secret behind a bare word and a colon, which is how a movie-link page's Size:400MB is hashed",
        check=counted_secret,
        category="leaked_credentials",
        min_matches=10,
        gate="secret{",
    ),
    Rule(
        "some_secrets",
        2,
        "body",
        HASHED_SECRET_PATTERN,
        "Matches pages where redaction hashed three or more secrets, counted the same way as many_secrets",
        check=counted_secret,
        category="leaked_credentials",
        min_matches=3,
        gate="secret{",
    ),
    Rule(
        "telegram_session",
        4,
        "page",
        re.compile("WARNING_BANNER"),
        "Matches Telegram session exports, which start with WARNING_BANNER",
        category="leaked_credentials",
        gate="warning_banner",
    ),
    Rule(
        "telegram_api_pair",
        4,
        "page",
        TELEGRAM_API_PAIR_PATTERN,
        "Matches pages carrying a Telegram api_id with its api_hash",
        category="leaked_credentials",
        gate="api_hash",
    ),
    Rule(
        "autologin_link",
        4,
        "page",
        URL_TOKEN_PATTERN,
        "Matches links that log the reader in as someone else: an autologin path, or a login parameter whose value redaction hashed",
        check=is_autologin_link,
        category="leaked_credentials",
        gate="://",
    ),
    Rule(
        "token_in_path",
        2,
        "page",
        URL_TOKEN_PATTERN,
        "Matches links with a hashed token as a path segment, which is where some dating login links carry it. Weak, because a numeric id that passes the Luhn check is hashed as a card number and looks the same: 11 of 28 on the first night",
        check=has_token_in_path,
        category="leaked_credentials",
        gate="://",
    ),
    # ----------------------------------------------------------------------
    # proxy_list
    # ----------------------------------------------------------------------
    Rule(
        "proxy_uri",
        4,
        "page",
        PROXY_URI_PATTERN,
        "Matches proxy and VPN links: vless://, vmess://, ss://, trojan://, socks5:// and the like",
        category="proxy_list",
        gate="://",
    ),
    Rule(
        "ip_port_list",
        4,
        "body",
        IP_PORT_PATTERN,
        "Matches proxy tables: three or more public ip:port pairs",
        check=is_public_ip_port,
        category="proxy_list",
        min_matches=3,
        gate=":",
    ),
    Rule(
        "telegram_proxy_link",
        4,
        "page",
        TELEGRAM_PROXY_PATTERN,
        "Matches Telegram proxy links, t[.]me/proxy? and tg://proxy",
        check=names_a_server,
        category="proxy_list",
        gate="server=",
    ),
    Rule(
        "proxy_config_keys",
        2,
        "body",
        PROXY_CONFIG_KEY_PATTERN,
        'Matches proxy client configs: two or more of "server", "port" and "address" as JSON keys',
        category="proxy_list",
        min_matches=2,
        gate='"',
    ),
    Rule(
        "single_ip_port",
        1,
        "page",
        IP_PORT_PATTERN,
        "Matches pages with at least one public ip:port pair",
        check=is_public_ip_port,
        category="proxy_list",
        gate=":",
    ),
    # ----------------------------------------------------------------------
    # malware_delivery
    # ----------------------------------------------------------------------
    Rule(
        "executable_link",
        4,
        "page",
        URL_TOKEN_PATTERN,
        "Matches links straight to something that runs: a URL whose path ends in .exe, .apk, .msi, .scr, .ps1, .lnk, .hta or .iso",
        check=is_executable_link,
        category="malware_delivery",
        gate="://",
    ),
    Rule(
        "run_command",
        3,
        "page",
        RUN_COMMAND_PATTERN,
        "Matches download-and-run commands: powershell, mshta, certutil, curl, wget and the like",
        category="malware_delivery",
    ),
    Rule(
        "archive_link",
        2,
        "page",
        URL_TOKEN_PATTERN,
        "Matches links to an archive: a URL whose path ends in .zip, .rar or .7z",
        check=is_archive_link,
        category="malware_delivery",
        gate="://",
    ),
    Rule(
        "file_host_link",
        1,
        "page",
        FILE_HOST_PATTERN,
        "Matches links to a file host like mega[.]nz, mediafire or a GitHub release download",
        category="malware_delivery",
    ),
    # ----------------------------------------------------------------------
    # fraud_market
    # ----------------------------------------------------------------------
    Rule(
        "onion_address",
        3,
        "page",
        ONION_PATTERN,
        "Matches pages naming a Tor hidden service, a darknet market mirror mostly",
        category="fraud_market",
        gate=".onion",
    ),
    Rule(
        "card_terms",
        3,
        "page",
        CARD_TERMS_PATTERN,
        "Matches carding adverts: cvv, fullz, carding",
        category="fraud_market",
    ),
    Rule(
        "stealer_terms",
        2,
        "page",
        STEALER_TERMS_PATTERN,
        "Matches stealer-log adverts: stealer, redline, lumma, vidar. Most pages with these words are templated adverts, which template_spam counts first",
        category="fraud_market",
    ),
    # ----------------------------------------------------------------------
    # crypto_lure
    # ----------------------------------------------------------------------
    Rule(
        "drainer_terms",
        3,
        "page",
        DRAINER_TERMS_PATTERN,
        "Matches airdrop, claim and drainer lures: airdrop, seed phrase, wallet connect, drainer",
        category="crypto_lure",
    ),
    Rule(
        "wallet_address",
        2,
        "page",
        WALLET_ADDRESS_PATTERN,
        "Matches pages listing an Ethereum, Tron or Bitcoin address to pay",
        category="crypto_lure",
    ),
    # ----------------------------------------------------------------------
    # phishing
    # ----------------------------------------------------------------------
    Rule(
        "login_form_source",
        4,
        "page",
        INPUT_TAG_PATTERN,
        "Matches pages whose body is the HTML source of a login form, an input of type password",
        check=is_password_input,
        category="phishing",
        gate="<input",
    ),
    Rule(
        "free_host_link",
        2,
        "page",
        FREE_HOST_PATTERN,
        "Matches links to a free hosting service like pages[.]dev, web[.]app, netlify[.]app or github[.]io, where credential-collection pages are put up",
        category="phishing",
    ),
    Rule(
        "shortener_link",
        1,
        "page",
        SHORTENER_PATTERN,
        "Matches links through a URL shortener, which hide where they lead",
        category="phishing",
    ),
    # ----------------------------------------------------------------------
    # doxx: one rule per identity field, so two different fields make a label
    # ----------------------------------------------------------------------
    Rule(
        "identity_passport",
        2,
        "page",
        PASSPORT_FIELD_PATTERN,
        "Matches pages with a passport field. Counted, never excerpted",
        category="doxx",
    ),
    Rule(
        "identity_registration",
        2,
        "page",
        REGISTRATION_FIELD_PATTERN,
        "Matches pages with a registered-address field. Counted, never excerpted",
        category="doxx",
    ),
    Rule(
        "identity_birth_date",
        2,
        "page",
        BIRTH_DATE_FIELD_PATTERN,
        "Matches pages with a date-of-birth field. Counted, never excerpted",
        category="doxx",
    ),
    Rule(
        "identity_address",
        2,
        "page",
        ADDRESS_FIELD_PATTERN,
        "Matches pages with a home-address field. Counted, never excerpted",
        category="doxx",
    ),
    # ----------------------------------------------------------------------
    # telegram_funnel
    # ----------------------------------------------------------------------
    Rule(
        "telegram_invite",
        2,
        "page",
        TELEGRAM_INVITE_PATTERN,
        "Matches adverts that lead to a private Telegram channel through an invite link",
        category="telegram_funnel",
        gate="t.me/",
    ),
    Rule(
        "telegram_bot_link",
        2,
        "page",
        TELEGRAM_BOT_PATTERN,
        "Matches adverts that lead to a Telegram bot",
        category="telegram_funnel",
        gate="t.me/",
    ),
    Rule(
        "telegram_handle",
        1,
        "page",
        TELEGRAM_HANDLE_PATTERN,
        "Matches pages that name a Telegram @handle",
        category="telegram_funnel",
        gate="@",
    ),
    Rule(
        "adult_ad_terms",
        1,
        "page",
        ADULT_AD_TERMS_PATTERN,
        "Matches the vocabulary of the sliv and VIP-bot adverts",
        category="telegram_funnel",
    ),
    # ----------------------------------------------------------------------
    # seo_spam
    # ----------------------------------------------------------------------
    Rule(
        "movie_link_terms",
        4,
        "page",
        MOVIE_LINK_TERMS_PATTERN,
        "Matches movie-link spam, which points at mdisk and terabox",
        category="seo_spam",
    ),
    Rule(
        "casino_terms",
        3,
        "page",
        CASINO_TERMS_PATTERN,
        "Matches casino and betting spam by brand name",
        category="seo_spam",
    ),
    # ----------------------------------------------------------------------
    # placeholder
    # ----------------------------------------------------------------------
    Rule(
        "empty_body",
        4,
        "computed",
        None,
        "Matches pages whose body is empty or under 20 characters",
        category="placeholder",
    ),
    # ----------------------------------------------------------------------
    # prose
    # ----------------------------------------------------------------------
    Rule(
        "long_text_no_link",
        4,
        "computed",
        None,
        "Matches pages with over 3,000 characters of text and no link: stories, essays, news reposts",
        category="prose",
    ),
)


def body_of(title: str | None, description: str | None, text: str | None) -> str:
    """The page body: snapshots.text without its title and description lines

    page_text builds text as title, description and body joined by newlines,
    so the body is whatever follows that prefix.

    Args:
        title (str | None): snapshots.title
        description (str | None): snapshots.description
        text (str | None): snapshots.text

    Returns:
        str: the body text, or all of text if it does not start with the prefix
    """
    text = text or ""
    prefix = f"{title or ''}\n{description or ''}\n"
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


def apply_rules(
    title: str | None,
    description: str | None,
    text: str | None,
    rules=RULES,
    links=(),
) -> list[Hit]:
    """Run every pattern rule once over a page and return the hits

    A rule reads one field. body is the text without its title and
    description lines and without the whitespace around it, so a rule
    anchored with \\A and \\Z is a rule about the whole body. The description
    repeats the start of the body, so a rule that counts its matches reads
    body and does not count the same line twice. page is the text with the
    page's link targets after it, one to a line: the address behind
    "Download here" is not in the text. The category rules about links read
    page. The resolver rules read text, as they always have.

    Args:
        title (str | None): snapshots.title
        description (str | None): snapshots.description
        text (str | None): snapshots.text, the title, description and body joined
        rules (optional): the rules to apply. Defaults to RULES.
        links (optional): the page's link targets that its text does not
            already show, from classify.link_targets. Defaults to none.

    Returns:
        list[Hit]: at most one Hit per rule, in table order, each carrying
            its first match as evidence and the number of matches
    """
    fields = {
        "title": title or "",
        "description": description or "",
        "text": text or "",
        "body": body_of(title, description, text).strip(),
    }
    fields["page"] = "\n".join([fields["text"], *links])
    # Lower-cased copies for the gates, made only for the fields a gate reads
    lowered = {}
    hits = []
    for rule in rules:
        if rule.pattern is None:
            continue
        field = fields[rule.where]
        if rule.gate is not None:
            if rule.where not in lowered:
                lowered[rule.where] = field.lower()
            if rule.gate not in lowered[rule.where]:
                continue
        evidence = None
        matches = 0
        for match in rule.pattern.finditer(field):
            candidate = match.group(0)
            if rule.check is None or rule.check(candidate):
                if evidence is None:
                    evidence = candidate
                matches += 1
        if evidence is not None and matches >= rule.min_matches:
            hits.append(Hit(rule, evidence, matches))
    return hits


def category_scores(hits: list[Hit]) -> dict[str, int]:
    """The sum of the weights of the rules that fired, per category

    Args:
        hits (list[Hit]): the hits for one page

    Returns:
        dict[str, int]: one entry per category that has a hit, in CATEGORIES
            order. A category whose weights cancel out is there with a 0.
    """
    totals = {}
    for hit in hits:
        category = hit.rule.category
        totals[category] = totals.get(category, 0) + hit.rule.weight
    return {
        category: totals[category] for category in CATEGORIES if category in totals
    }


def labels_for(scores: dict[str, int], threshold: int = THRESHOLD) -> list[str]:
    """The categories a page is labelled with

    Args:
        scores (dict[str, int]): the page's score per category, from category_scores
        threshold (int, optional): a category is a label at this score or
            above. Defaults to THRESHOLD.

    Returns:
        list[str]: the labels in CATEGORIES order, empty for an unlabelled page
    """
    return [
        category
        for category in CATEGORIES
        if scores.get(category, 0) >= threshold
    ]


def primary_label(labels: list[str]) -> str | None:
    """The one label a page is counted under when each page is counted once

    Args:
        labels (list[str]): the page's labels, in any order

    Returns:
        str | None: the label that comes first in CATEGORIES, or None for an
            unlabelled page
    """
    for category in CATEGORIES:
        if category in labels:
            return category
    return None


def score(hits: list[Hit]) -> int:
    """The resolver score: the sum of the weights of the resolver rules that fired

    Rules in the other categories do not count here, so this number means
    what it meant before the categories existed.
    """
    return category_scores(hits).get("resolver", 0)


def _pattern_cell(rule: Rule) -> str:
    """The Pattern column: the regex, or a name when it is too long to read"""
    if rule.pattern is None:
        return "computed"
    source = rule.pattern.pattern
    if len(source) > 60:
        source = source.replace(TLD, "TLD")
    cell = "`" + source.replace("|", "\\|") + "`"
    if rule.min_matches > 1:
        cell += f" at least {rule.min_matches} times"
    return cell


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


def render_categories(rules=RULES) -> str:
    """The whole rule table as Markdown: a heading and a table per category"""
    sections = []
    for category in CATEGORIES:
        members = tuple(rule for rule in rules if rule.category == category)
        if not members:
            continue
        kind = "intelligence" if category in INTELLIGENCE else "noise"
        sections.append(f"## `{category}` ({kind})\n\n" + render_table(members))
    return "\n".join(sections)


if __name__ == "__main__":
    print(render_categories(), end="")
