"""Read-only survey of the prod database for the classification plan.

Counts candidate category features over the newest snapshot of every page
that is not held out. Prints counts, a first-match category sizing, and a few
short excerpts for the features that are safe to show. Writes nothing.
"""

import hashlib
import re
import sqlite3
import sys
from array import array
from collections import Counter, defaultdict

from graphwatch.rules import IP_PATTERN, is_pointer, is_public_ip

I = re.IGNORECASE
SECRET = re.compile(r"SECRET\{[0-9a-f]{64}\}")
REGEX = {
    "leak_combo": (re.compile(r"@[\w-]+(?:\.[\w-]+)+:SECRET\{"), 3),
    "ip_port": (re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b"), 1),
    "ip_port_list": (re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b"), 3),
    "tme_bot": (re.compile(r"t\.me/\w+bot\b", I), 1),
    "handle": (re.compile(r"(?<![\w@])@[A-Za-z]\w{4,31}\b"), 1),
    "wallet_btc": (re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), 1),
    "wallet_eth": (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), 1),
    "wallet_tron": (re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"), 1),
    # \S{1,500}, not \S+: a page that repeats http:// with no whitespace made
    # the unbounded form start again at each one and run to the end of the page.
    "file_link": (re.compile(r"https?://\S{1,500}\.(?:exe|apk|msi|scr|bat|cmd|ps1|vbs|jar|lnk|hta|dll|iso)(?![\w])", I), 1),
    "archive_link": (re.compile(r"https?://\S{1,500}\.(?:zip|rar|7z)(?![\w])", I), 1),
    "onion": (re.compile(r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b", I), 1),
    "b64_blob": (re.compile(r"(?<![A-Za-z0-9+/=])(?=[A-Za-z0-9+/]*[0-9+/])(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[A-Z])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"), 1),
    "hex_blob": (re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])"), 1),
    "config_keys": (re.compile(r'"(?:host|server|port|c2|address|token|password)"\s*:', I), 2),
}
WORDS = {
    "stealer_words": ("stealer", "stealler", "стиллер", "стилер", "redline", "lumma", "vidar", "raccoon"),
    "card_words": ("cvv", "fullz", "carding", "кардинг"),
    "doxx_words": ("паспорт", "прописк", "дата рождения", "адрес проживания", "деанон", "doxx", "doxed"),
    "proxy_uri": ("ss://", "ssr://", "vless://", "vmess://", "trojan://", "hysteria://", "hysteria2://", "tuic://", "socks5://", "socks://"),
    "tg_proxy": ("t.me/proxy?", "t.me/socks?", "tg://proxy", "tg://socks"),
    "url": ("http://", "https://"),
    "tme_link": ("t.me/", "telegram.me/"),
    "tme_invite": ("t.me/+", "t.me/joinchat/"),
    "movie_spam": ("mdisk", "terabox"),
    "casino": ("casino", "казино", "1xbet", "1win", "vavada", "букмекер", "pin-up", "pinup"),
    "adult_sliv": ("порно", "porn", "секс", "слив", "intim", "эскорт"),
    "crypto_words": ("seed phrase", "сид фраз", "сид-фраз", "airdrop", "аирдроп", "walletconnect", "wallet connect", "metamask", "trust wallet", "drainer", "дрейнер"),
    "tunnel_dyn": (".workers.dev", ".trycloudflare.com", ".ngrok.io", ".ngrok.app", ".ngrok-free.app", ".ngrok-free.dev", ".duckdns.org", ".ddns.net", ".hopto.org", ".zapto.org", ".sytes.net", ".serveo.net", ".loca.lt", ".portmap.io", ".playit.gg"),
    "free_host": (".pages.dev", ".web.app", ".firebaseapp.com", ".vercel.app", ".netlify.app", ".github.io", ".glitch.me", ".repl.co", ".onrender.com", ".herokuapp.com", ".000webhostapp.com", ".weebly.com", ".blogspot.com", ".wixsite.com"),
    "shortener": ("bit.ly/", "clck.ru/", "tinyurl.com/", "cutt.ly/", "is.gd/", "goo.su/", "vk.cc/", "rb.gy/", "shorturl.at/", "tiny.cc/", "ow.ly/"),
    "file_host": ("mega.nz", "mediafire.com", "gofile.io", "anonfiles", "dropmefiles", "disk.yandex", "yadi.sk", "drive.google.com", "dropbox.com", "cdn.discordapp.com/attachments", "/releases/download/", "transfer.sh", "catbox.moe", "pixeldrain"),
    "paste_raw": ("pastebin.com/raw", "raw.githubusercontent.com", "gist.githubusercontent.com"),
    "script_code": ("<script", "powershell", "cmd.exe", "/bin/sh", "/bin/bash", "curl -", "wget http", "invoke-webrequest", "frombase64string", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin"),
}
# A regex only runs when this cheap substring is present in the lowercased text.
GATE = {
    "leak_combo": ":secret{", "ip_port": ":", "ip_port_list": ":", "tme_bot": "t.me/",
    "handle": "@", "wallet_eth": "0x", "file_link": "://", "archive_link": "://",
    "onion": ".onion", "config_keys": '":',
}
LITERAL = {
    "tg_session": "WARNING_BANNER",
    "tg_api_hash": "api_hash",
    "squatter_a": "SLlV_INTIM_BOT",
    "squatter_b": "YztOEovieQIzZjY8",
}
COMPUTED = [
    "secret_any", "secret_10plus", "ip_public", "ip_short_body", "body_single_pointer",
    "body_one_token", "api_sample", "empty_body", "long_prose", "flagged",
]
NAMES = list(REGEX) + list(WORDS) + list(LITERAL) + COMPUTED
BIT = {name: 1 << i for i, name in enumerate(NAMES)}
SHOW = {
    "proxy_uri", "tg_proxy", "ip_port_list", "tunnel_dyn", "file_link", "paste_raw",
    "onion", "b64_blob", "hex_blob", "config_keys", "script_code", "body_single_pointer",
    "body_one_token", "ip_short_body", "api_sample", "wallet_eth", "free_host",
}


def features(title, description, text, flagged):
    text = text or ""
    prefix = f"{title or ''}\n{description or ''}\n"
    body = text[len(prefix):] if text.startswith(prefix) else text
    stripped = body.strip()
    bits = 0
    secrets = text.count("SECRET{")
    plain = SECRET.sub(" ", text) if secrets else text
    low = text.lower()
    for name, words in WORDS.items():
        if any(word in low for word in words):
            bits |= BIT[name]
    for name, (pattern, need) in REGEX.items():
        if name in GATE and GATE[name] not in low:
            continue
        source = text if name == "leak_combo" else plain
        found = 0
        for _ in pattern.finditer(source):
            found += 1
            if found >= need:
                bits |= BIT[name]
                break
    for name, needle in LITERAL.items():
        if needle in text:
            bits |= BIT[name]
    if secrets:
        bits |= BIT["secret_any"]
    if secrets >= 10:
        bits |= BIT["secret_10plus"]
    if any(is_public_ip(m.group(0)) for m in IP_PATTERN.finditer(plain)):
        bits |= BIT["ip_public"]
        if len(stripped) < 200:
            bits |= BIT["ip_short_body"]
    if 4 <= len(stripped) <= 300 and is_pointer(stripped):
        bits |= BIT["body_single_pointer"]
    if 12 <= len(stripped) <= 4000 and not re.search(r"\s", stripped) and "SECRET{" not in stripped:
        bits |= BIT["body_one_token"]
    if description == "Hello,+world!":
        bits |= BIT["api_sample"]
    if len(stripped) < 20:
        bits |= BIT["empty_body"]
    if len(body) > 3000 and "://" not in body and "t.me/" not in body:
        bits |= BIT["long_prose"]
    if flagged:
        bits |= BIT["flagged"]
    digest = hashlib.blake2b(body.encode("utf-8"), digest_size=8).digest()
    return bits, int.from_bytes(digest, "big"), len(stripped), stripped


def has(bits, *names):
    return any(bits & BIT[n] for n in names)


def provisional(bits):
    """First match wins. Only for sizing; the real rules are next week's work."""
    if has(bits, "flagged"):
        return "ddr_flagged"
    if has(bits, "squatter_a", "squatter_b"):
        return "title_squatter"
    if has(bits, "leak_combo", "tg_session", "tg_api_hash", "secret_10plus"):
        return "leaked_credentials"
    if has(bits, "proxy_uri", "tg_proxy", "ip_port_list"):
        return "proxy_list"
    if has(bits, "body_single_pointer", "body_one_token", "ip_short_body", "tunnel_dyn", "paste_raw", "onion"):
        return "pointer_like"
    if has(bits, "file_link", "script_code"):
        return "malware_delivery"
    if has(bits, "card_words", "stealer_words"):
        return "fraud_market"
    if has(bits, "wallet_btc", "wallet_eth", "wallet_tron", "crypto_words"):
        return "crypto_lure"
    if has(bits, "doxx_words"):
        return "doxx"
    if has(bits, "casino", "movie_spam"):
        return "seo_spam"
    if has(bits, "squatter_a", "squatter_b", "tme_link", "handle"):
        return "telegram_funnel"
    if has(bits, "free_host", "shortener", "file_host", "archive_link"):
        return "link_out"
    if has(bits, "empty_body"):
        return "placeholder"
    if has(bits, "long_prose"):
        return "prose"
    if has(bits, "url"):
        return "other_with_url"
    return "other"


def main(path):
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    scored = conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'scores'").fetchone()
    flag = "(SELECT sc.flagged FROM scores sc WHERE sc.snapshot_id = s.id)" if scored else "NULL"
    rows = conn.execute(
        f"""
        SELECT p.path, COALESCE(t.source, '?'), p.title_id, s.title, s.description, s.text,
               {flag}
        FROM pages p
        LEFT JOIN titles t ON t.id = p.title_id
        JOIN snapshots s ON s.id = (
            SELECT id FROM snapshots WHERE page_id = p.id
            ORDER BY fetched_at DESC, id DESC LIMIT 1
        )
        WHERE p.held_out = 0
        """
    )
    masks, hashes, sources = array("Q"), array("Q"), []
    titles_of = {}
    examples = defaultdict(list)
    source_ids = {}
    lengths = Counter()
    for path_, source, title_id, title, description, text, flagged in rows:
        bits, digest, size, stripped = features(title, description, text, flagged)
        masks.append(bits)
        hashes.append(digest)
        sources.append(source_ids.setdefault(source, len(source_ids)))
        seen = titles_of.get(digest, ())
        # Same guard as the classifier: a body under 40 characters is not a template.
        if size < 40:
            titles_of.setdefault(digest, ())
        elif len(seen) < 3 and title_id not in seen:
            titles_of[digest] = seen + (title_id,)
        lengths[min(size // 100, 50)] += 1
        for name in SHOW:
            if bits & BIT[name] and len(examples[name]) < 40:
                examples[name].append((digest, path_, stripped[:110].replace("\n", " / ")))
    total = len(masks)
    templated = {d for d, seen in titles_of.items() if len(seen) >= 3}
    print(f"pages {total:,}  distinct bodies {len(titles_of):,}  "
          f"pages with a templated body {sum(1 for d in hashes if d in templated):,}")
    print("\nFEATURE                 pages   not-templated  distinct-bodies  also-flagged")
    for name in NAMES:
        bit = BIT[name]
        pages = plain = flagged = 0
        bodies = set()
        for bits, digest in zip(masks, hashes):
            if bits & bit:
                pages += 1
                bodies.add(digest)
                plain += digest not in templated
                flagged += bool(bits & BIT["flagged"])
        print(f"{name:<22}{pages:>8,}{plain:>14,}{len(bodies):>16,}{flagged:>14,}")
    print("\nPROVISIONAL CATEGORY    pages   not-templated  distinct-bodies")
    by_cat = defaultdict(lambda: [0, 0, set()])
    by_source = defaultdict(Counter)
    names_of_source = {v: k for k, v in source_ids.items()}
    for bits, digest, source in zip(masks, hashes, sources):
        cat = provisional(bits)
        entry = by_cat[cat]
        entry[0] += 1
        entry[1] += digest not in templated
        entry[2].add(digest)
        by_source[names_of_source[source]][cat] += 1
    for cat, (pages, plain, bodies) in sorted(by_cat.items(), key=lambda kv: -kv[1][0]):
        print(f"{cat:<22}{pages:>8,}{plain:>14,}{len(bodies):>16,}")
    cats = [c for c, _ in sorted(by_cat.items(), key=lambda kv: -kv[1][0])]
    print("\nSOURCE LIST x PROVISIONAL CATEGORY (pages)")
    print("source".ljust(20) + "".join(c[:10].rjust(11) for c in cats))
    for source, counts in sorted(by_source.items()):
        print(source.ljust(20) + "".join(f"{counts[c]:>11,}" for c in cats))
    print("\nEXAMPLES (not templated, one per body, at most 4)")
    for name in sorted(SHOW):
        shown = set()
        print(f"[{name}]")
        for digest, path_, excerpt in examples[name]:
            if digest in templated or digest in shown or len(shown) >= 4:
                continue
            shown.add(digest)
            print(f"   {path_}: {excerpt}")
    print("\nBODY LENGTH (stripped chars, buckets of 100, last is 5000+)")
    print(" ".join(f"{k * 100}:{v}" for k, v in sorted(lengths.items())))


if __name__ == "__main__":
    main(sys.argv[1])
