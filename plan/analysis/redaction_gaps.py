"""Read-only count of secret shapes that are stored in clear. Counts only."""
import re
import sqlite3
import sys
from collections import Counter

I = re.IGNORECASE
SHAPES = {
    # name: (gate substring in lowercased text, regex)
    "api_hash value": ("api_hash", re.compile(r"api_hash\W{0,40}[0-9a-f]{32}\b", I)),
    "vless/trojan user id": ("://", re.compile(r"\b(?:vless|trojan)://(?!SECRET\{)[^@\s/]{8,}@", I)),
    "vmess/ss encoded config": ("://", re.compile(r"\b(?:vmess|ssr?)://[A-Za-z0-9+/=_-]{20,}", I)),
    "telegram proxy secret": ("secret=", re.compile(r"[?&]secret=[0-9a-f]{16,}", I)),
    "JWT": ("eyj", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    "login token in a URL": ("://", re.compile(r"https?://\S*(?:autologin|token-login|[?&](?:token|auth|access_token|login_token|session|sid|code)=)[A-Za-z0-9%._:-]{16,}", I)),
    "labelled password": ("", re.compile(r"(?:passw(?:or)?d|pwd|пароль)\s*[:=]\s*(?!SECRET\{)\S{6,}", I)),
    "bot token": (":", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    "private key block": ("private key", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")),
    "Google API key": ("aiza", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    "Slack token": ("xox", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{20,}")),
    "sk- API key": ("sk-", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
    "Discord token": (".", re.compile(r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b")),
}
conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
rows = conn.execute(
    """SELECT s.text FROM pages p JOIN snapshots s ON s.id = (
           SELECT id FROM snapshots WHERE page_id = p.id ORDER BY fetched_at DESC, id DESC LIMIT 1)
       WHERE p.held_out = 0"""
)
pages = Counter(); matches = Counter(); session = Counter(); total = 0
for (text,) in rows:
    total += 1
    text = text or ""
    low = text.lower()
    for name, (gate, pattern) in SHAPES.items():
        if gate and gate not in low:
            continue
        found = sum(1 for _ in pattern.finditer(text))
        if found:
            pages[name] += 1
            matches[name] += found
    if "WARNING_BANNER" in text:
        session["pages"] += 1
        session["with a SECRET marker"] += "SECRET{" in text
        session["with a 64+ char hex or base64 run in clear"] += bool(
            re.search(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{64,}={0,2}", re.sub(r"SECRET\{[0-9a-f]{64}\}", " ", text)))
print("pages read", total)
for name in SHAPES:
    print(f"{name:<28} pages {pages[name]:>6,}  matches {matches[name]:>7,}")
print("telegram session exports:", dict(session))
