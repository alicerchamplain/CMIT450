"""Feed key check (plan step 6): known-bad and made-up values through each feed

Uses the FeedClient the enrich command uses, so what passes here is what
enrich will do. No database is opened and nothing is stored. Only the four
feed hosts are contacted, and every request is a lookup.

The known-bad values are fetched fresh: ThreatFox's and URLhaus's own lists
of recent entries, so each of the two must know its own value. What the
other feeds say about them is printed but not required.

OTX answers a lookup with any key or none (at the anonymous rate limit, a
429 after about 90 requests on 23 November 2026), so its key is tested on
/user/me, which answers 403 without a valid one.

Run: .venv/bin/python plan/analysis/feed_check.py [--config PATH] [--feeds threatfox,otx]
Exits 1 if a feed's key is refused or a required answer is wrong.
"""

import argparse
import secrets
import sys
from pathlib import Path

import requests

from graphwatch.config import CONFIG, load_config
from graphwatch.enrich import defang
from graphwatch.feeds import FEEDS, KEY_NAMES, FeedClient, Verdict, bare_host

# The names the config file uses today, beside the names feeds.py reads
ALIASES = {
    "ABUSE_CH_KEY": ("ABUSE_CH_KEY", "ABUSECH_AUTH_KEY"),
    "OTX_KEY": ("OTX_KEY", "OTX_API_KEY"),
    "VT_KEY": ("VT_KEY", "VT_API_KEY"),
}


class Recorder:
    """A session that keeps the last answer, so a failed lookup can be shown"""

    def __init__(self, session):
        self.session = session
        self.last = None

    def request(self, *args, **kwargs):
        self.last = None  # a request that raises leaves no answer to show
        self.last = self.session.request(*args, **kwargs)
        return self.last


def load_keys(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """feed name to key, and feed name to the config name the key was under"""
    config = load_config(path)
    keys, names = {}, {}
    for feed in FEEDS:
        for name in ALIASES[KEY_NAMES[feed]]:
            if config.get(name):
                keys[feed], names[feed] = config[name], name
                break
    return keys, names


def get_json(client: FeedClient, method: str, url: str, key: str, body=None):
    """One direct request to an abuse.ch list endpoint, behind the client's allowlist"""
    client._check_host(url)
    resp = client.session.request(
        method,
        url,
        headers={"User-Agent": client.user_agent, "Auth-Key": key},
        json=body,
        timeout=30,
        allow_redirects=False,
    )
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, None


def recent_threatfox(client: FeedClient, key: str) -> list[tuple[str, str]]:
    """One ip, one host and one url ThreatFox listed in the last three days"""
    status, data = get_json(
        client, "POST", "https://threatfox-api.abuse.ch/api/v1/", key, {"query": "get_iocs", "days": 3}
    )
    rows = data.get("data") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        shape = data.get("query_status") if isinstance(data, dict) else None
        print(f"threatfox recent list: HTTP {status}, query_status {shape!r}, no list")
        return []
    kinds = {"ip:port": "ip", "domain": "host", "url": "url"}
    picked = {}
    # The oldest entries last: the other feeds have had the longest to see them
    for row in reversed(rows):
        kind = kinds.get(row.get("ioc_type"))
        if kind and kind not in picked and isinstance(row.get("ioc"), str):
            value = row["ioc"]
            picked[kind] = bare_host(value) if kind != "url" else value
    return list(picked.items())


def recent_urlhaus(client: FeedClient, key: str) -> list[tuple[str, str]]:
    """One url URLhaus listed recently, and its host"""
    status, data = get_json(
        client, "GET", "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/", key
    )
    rows = data.get("urls") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows:
        shape = data.get("query_status") if isinstance(data, dict) else None
        print(f"urlhaus recent list: HTTP {status}, query_status {shape!r}, no list")
        return []
    row = rows[-1]
    out = [("url", row["url"])]
    host = row.get("host")
    if isinstance(host, str) and host:
        is_ip = host.replace(".", "").isdigit()
        out.append(("ip" if is_ip else "host", host))
    return out


def otx_key_status(client: FeedClient, key: str) -> int | None:
    """The HTTP status of OTX's own-account endpoint: 200 with a valid key, 403 without"""
    url = "https://otx.alienvault.com/api/v1/user/me"
    client._check_host(url)
    try:
        resp = client.session.request(
            "GET",
            url,
            headers={"User-Agent": client.user_agent, "X-OTX-API-KEY": key},
            timeout=30,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None
    return resp.status_code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--feeds", default=",".join(FEEDS))
    args = parser.parse_args()

    keys, names = load_keys(args.config)
    wanted = [feed for feed in args.feeds.split(",") if feed]
    for feed in wanted:
        if feed in keys:
            ok = names[feed] == KEY_NAMES[feed]
            note = "" if ok else f"  <- feeds.py reads {KEY_NAMES[feed]}"
            print(f"{feed:<11} key under {names[feed]}{note}")
        else:
            print(f"{feed:<11} NO KEY ({' or '.join(ALIASES[KEY_NAMES[feed]])})")
    keys = {feed: key for feed, key in keys.items() if feed in wanted}
    if not keys:
        return 1

    client = FeedClient(keys)
    recorder = Recorder(client.session)
    client.session = recorder

    made_up = f"gw-check-{secrets.token_hex(6)}.com"
    # (who vouches for it, kind, value): a feed must know its own value
    values = []
    if "threatfox" in keys:
        values += [("threatfox", kind, value) for kind, value in recent_threatfox(client, keys["threatfox"])]
    if "urlhaus" in keys:
        values += [("urlhaus", kind, value) for kind, value in recent_urlhaus(client, keys["urlhaus"])]
    values += [
        ("made-up", "host", made_up),
        ("made-up", "url", f"http://{made_up}/check"),
        # A documentation address (TEST-NET-3): nobody's server. Shown, not required
        ("reserved", "ip", "203.0.113.77"),
    ]

    problems = []
    answered = {feed: 0 for feed in keys}
    refused = set()
    if "otx" in keys:
        status = otx_key_status(client, keys["otx"])
        if status != 200:
            refused.add("otx")
            problems.append(f"otx: the key is not accepted on /user/me (HTTP {status})")
    print()
    print(f"{'feed':<11} {'from':<9} {'kind':<4} {'verdict':<8} {'http':<5} {'ms':>6}  value / detail")
    for origin, kind, value in values:
        for feed in client.feeds():
            lookup = client.lookup(feed, kind, value)
            shown = defang(kind, value)
            if len(shown) > 60:
                shown = shown[:57] + "..."
            print(
                f"{feed:<11} {origin:<9} {kind:<4} {lookup.verdict.name:<8} "
                f"{str(lookup.status):<5} {lookup.elapsed_ms:>6}  {shown}  [{lookup.detail or '-'}]"
            )
            if lookup.verdict is Verdict.FAILED:
                body = recorder.last.text[:160].replace("\n", " ") if recorder.last is not None else ""
                print(f"{'':<11} answer began: {body!r}")
            else:
                answered[feed] += 1
            if origin == feed and lookup.verdict is not Verdict.KNOWN:
                problems.append(f"{feed} does not know its own {kind}: {lookup.verdict.name}")
            if origin == "made-up" and lookup.verdict is not Verdict.UNKNOWN:
                problems.append(f"{feed} made-up {kind}: {lookup.verdict.name} ({lookup.detail})")

    print()
    for feed in client.feeds():
        state = "key accepted" if answered[feed] else "NO ANSWER ACCEPTED"
        if feed in refused:
            state = "KEY REFUSED, lookups answered without it"
        print(f"{feed:<11} {state}, {answered[feed]} of {len(values)} lookups answered")
        if not answered[feed]:
            problems.append(f"{feed}: no lookup was answered")
    print(f"{client.requests_made} requests")
    for problem in problems:
        print("PROBLEM:", problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
