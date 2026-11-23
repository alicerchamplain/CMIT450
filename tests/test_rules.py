"""Tests for graphwatch.rules, the draft rule table (issue #23).

Positive examples are the known actor's Hello pages: the Hello-10-17-154
fixture and title shapes copied from the night-1 database. Negative examples
are the benign fixtures and synthetic strings. Nothing here reads a held-out
page from known.txt; those are for the recall check (#31), never for rules.
"""

import base64
import json
import re
from pathlib import Path

import pytest

from graphwatch.rules import (
    CATEGORIES,
    ENCODED_TOKEN_PATTERN,
    IP_PATTERN,
    MAILBOX_PROVIDERS,
    RULES,
    THRESHOLD,
    TITLE_SPOOF_PATTERN,
    UNPADDED_BASE64_PATTERN,
    WHERE,
    Hit,
    Rule,
    SECRET_LABELS,
    apply_rules,
    category_scores,
    counted_secret,
    decodes_to_pointer,
    decodes_to_printable,
    is_bare_pointer,
    is_pointer,
    is_spoof,
    is_public_ip,
    labels_for,
    primary_label,
    render_categories,
    render_table,
    score,
)
from graphwatch.telegraph import page_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plan" / "fixtures"
KNOWN = {
    line.strip()
    for line in (ROOT / "known.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
}

# Actor title shapes, as stored after redaction (night-1 copy, held_out = 0).
POINTER_TITLE = (
    "207.246.108.214?onmedservice.com.ua@opportunizz.pro/!SECRET{"
    + "0" * 64
    + "}?SECRET{"
    + "1" * 64
    + "}?dGViaQ==?eWVsNA=="
)
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"
API_SAMPLE = "Hello,+world!"


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def hits_for(page: dict) -> list[Hit]:
    return apply_rules(page.get("title"), page.get("description"), page_text(page))


def resolver(hits) -> list[Hit]:
    """Only the resolver rules' hits, which is what this file is about.

    apply_rules runs the category rules too (tests/test_categories.py); they
    sit after the resolver rules in the table and never change its score.
    """
    return [h for h in hits if h.rule.category == "resolver"]


def names(hits) -> list[str]:
    return [h.rule.name for h in resolver(hits)]


def rule(name: str) -> Rule:
    return next(r for r in RULES if r.name == name)


# --------------------------------------------------------------------------
# the table itself
# --------------------------------------------------------------------------


def test_fixtures_used_here_are_not_held_out():
    for name in ("Hello-10-17-154", "Hello-10-17-5", "Test-10-16"):
        assert name not in KNOWN
        assert name.casefold() not in {k.casefold() for k in KNOWN}


def test_rules_is_an_immutable_tuple_of_rules():
    assert isinstance(RULES, tuple)
    assert all(isinstance(r, Rule) for r in RULES)
    assert len(RULES) >= 8


def test_rule_names_are_unique_identifiers():
    seen = [r.name for r in RULES]
    assert len(set(seen)) == len(seen)
    for name in seen:
        assert re.fullmatch(r"[a-z][a-z0-9_]*", name), name


def test_every_rule_has_a_nonzero_weight():
    assert all(r.weight != 0 for r in RULES)
    assert any(r.weight > 0 for r in RULES)
    assert any(r.weight < 0 for r in RULES)


def test_where_is_one_of_the_known_fields():
    assert {"title", "description", "text", "body", "page", "computed"} == WHERE
    for r in RULES:
        assert r.where in WHERE, r.name


def test_computed_rules_have_no_pattern_and_pattern_rules_do():
    for r in RULES:
        if r.where == "computed":
            assert r.pattern is None, r.name
        else:
            assert isinstance(r.pattern, re.Pattern), r.name


def test_rules_are_frozen_dataclasses():
    with pytest.raises(Exception):
        RULES[0].weight = 99  # type: ignore[misc]


def test_the_expected_rules_are_present():
    assert {
        "userinfo_spoof",
        "spoof_in_title",
        "ip_in_title",
        "storage_key_marker",
        "base64_in_title",
        "encoded_pointer",
        "api_sample_body",
        "ip_literal",
        "email_address",
        "telegram_link",
        "templated_body",
    } <= {r.name for r in RULES}


def test_the_draft_threshold_is_four():
    assert THRESHOLD == 4


def test_each_decisive_rule_clears_the_threshold_alone():
    for name in ("userinfo_spoof", "spoof_in_title", "ip_in_title", "storage_key_marker"):
        assert rule(name).weight >= THRESHOLD, name


def test_no_single_weak_rule_clears_the_threshold():
    for name in ("base64_in_title", "encoded_pointer", "api_sample_body", "ip_literal"):
        assert 0 < rule(name).weight < THRESHOLD, name


def test_the_spoof_shape_survives_both_regex_penalties():
    # The thinnest actor margin: a Spoof-URL page that also carried an email
    # and a t.me link would still sit exactly on the threshold.
    thinnest = (
        rule("userinfo_spoof").weight
        + rule("api_sample_body").weight
        + rule("email_address").weight
        + rule("telegram_link").weight
    )
    assert thinnest >= THRESHOLD


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    ["207.246.108.214", "45.77.93.187", "198.13.32.106", "149.154.167.40", "8.8.8.8"],
)
def test_is_public_ip_accepts_routable_addresses(ip):
    assert is_public_ip(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "192.168.1.64",
        "10.0.0.1",
        "172.16.5.5",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.1.1",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
    ],
)
def test_is_public_ip_rejects_private_reserved_and_multicast(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("s", ["999.1.1.1", "1.2.3", "1.2.3.4.5", "", "host", "1.0.2"])
def test_is_public_ip_rejects_things_that_are_not_addresses(s):
    assert not is_public_ip(s)


@pytest.mark.parametrize(
    "token, plain",
    [
        ("dGViaQ==", "tebi"),
        ("eWVsNA==", "yel4"),
        ("ZnI=", "fr"),
        ("YWxsZW4=", "allen"),
        ("czMucmVkYXJvZGFzLmNvbQ==", "s3.redarodas.com"),
        ("aGVsbG8=", "hello"),
    ],
)
def test_decodes_to_printable_accepts_the_actor_fields(token, plain):
    assert decodes_to_printable(token)


@pytest.mark.parametrize("token", ["2+2=", "////", "AAAA", "abc", "abcde=", "", "===="])
def test_decodes_to_printable_rejects_binary_and_malformed(token):
    assert not decodes_to_printable(token)


@pytest.mark.parametrize(
    "s",
    [
        "s3.redarodas.com",
        "S3.REDARODAS.COM",
        "opportunizz.pro",
        "agfc.harper18.workers.dev",
        "45.77.93.187",
        "45.77.93.187:8443",
        "s3.redarodas.com:443",
        "http://s3.redarodas.com/",
        "https://45.77.93.187:8443/a/b?c=d",
        "HTTP://S3.REDARODAS.COM/x",
        "http://www.tenable.com@agfc.harper18.workers.dev/",
    ],
)
def test_is_pointer_accepts_a_whole_ip_host_or_url(s):
    assert is_pointer(s)


@pytest.mark.parametrize(
    "s",
    [
        "",
        "tebi",
        "yel4",
        "go to s3.redarodas.com",
        "s3.redarodas.com now",
        "s3.redarodas.com\n",
        "s3.redarodas.com/path",
        "192.168.1.1",
        "http://192.168.1.1/",
        "http://localhost/",
        "http://",
        "ftp://s3.redarodas.com/",
        "solano.elsa",
        "grove.7",
        "bob@gmail.com",
        "2.22.23",
        "s3.redarodas.com:port",
    ],
)
def test_is_pointer_rejects_partial_private_and_non_pointers(s):
    assert not is_pointer(s)


# --------------------------------------------------------------------------
# the actor's two shapes flag
# --------------------------------------------------------------------------


def test_pointer_fixture_fires_the_pointer_rules():
    hits = hits_for(fixture_page("Hello-10-17-154"))
    assert {
        "userinfo_spoof",
        "ip_in_title",
        "storage_key_marker",
        "base64_in_title",
        "api_sample_body",
    } <= set(names(hits))


def test_pointer_fixture_fires_no_exclusion():
    hits = hits_for(fixture_page("Hello-10-17-154"))
    assert all(h.rule.weight > 0 for h in hits)


def test_pointer_title_evidence_is_the_matched_text():
    hits = apply_rules(
        POINTER_TITLE, API_SAMPLE, POINTER_TITLE + "\n" + API_SAMPLE + "\n" + API_SAMPLE
    )
    by_name = {h.rule.name: h.evidence for h in hits}
    assert by_name["ip_in_title"] == "207.246.108.214"
    assert by_name["userinfo_spoof"] == "onmedservice.com.ua@opportunizz.pro"
    assert by_name["storage_key_marker"].startswith("/!SECRET{")
    assert by_name["base64_in_title"] == "dGViaQ=="
    assert by_name["api_sample_body"] == "Hello,+world!"


def test_storage_key_rule_matches_the_marker_not_the_raw_key():
    # After redaction only the marker and the SECRET token survive; the rule
    # must not depend on anything about the key itself.
    text = "x/!SECRET{" + "a" * 64 + "}?SECRET{" + "b" * 64 + "}"
    hits = apply_rules(None, None, text)
    assert names(hits) == ["storage_key_marker"]
    assert (
        "a" * 64 in hits[0].evidence
    )  # the evidence is the hashed token, never a raw key


def test_spoof_title_fires_userinfo_spoof_and_the_api_sample():
    text = SPOOF_TITLE + "\n" + API_SAMPLE + "\n" + API_SAMPLE
    hits = apply_rules(SPOOF_TITLE, API_SAMPLE, text)
    assert names(hits) == ["userinfo_spoof", "api_sample_body"]
    assert hits[0].evidence == "www.tenable.com@agfc.harper18.workers.dev"


# --------------------------------------------------------------------------
# spoof_in_title: the decoy ends in a TLD outside the list
# --------------------------------------------------------------------------

# Seen on 20 Hello pages from 3 to 18 October in the full sweep (held_out = 0):
# userinfo_spoof missed them all because .ag is not in TLD.
AG_TITLE = "primewire.ag@agfc.harper18.workers.dev/"


def test_userinfo_spoof_misses_a_decoy_with_an_unlisted_tld():
    hits = apply_rules(AG_TITLE, API_SAMPLE, AG_TITLE + "\n" + API_SAMPLE + "\n" + API_SAMPLE)
    assert "userinfo_spoof" not in names(hits)


def test_spoof_in_title_catches_the_unlisted_decoy_and_the_page_flags():
    hits = apply_rules(AG_TITLE, API_SAMPLE, AG_TITLE + "\n" + API_SAMPLE + "\n" + API_SAMPLE)
    assert names(hits) == ["spoof_in_title", "api_sample_body", "email_address"]
    assert hits[0].evidence == "primewire.ag@agfc.harper18.workers.dev"
    assert score(hits) >= THRESHOLD


def test_title_spoof_pattern_captures_the_decoy_and_the_destination():
    match = TITLE_SPOOF_PATTERN.search(AG_TITLE)
    assert match.group(1) == "primewire.ag"
    assert match.group(2) == "agfc.harper18.workers.dev"


@pytest.mark.parametrize(
    "title",
    [
        "primewire.ag@agfc.harper18.workers.dev/",
        "PRIMEWIRE.AG@AGFC.HARPER18.WORKERS.DEV/",
        "some-site.museum@venture-cpu-sur-everyone.trycloudflare.com",
        "news.example.today@opportunizz.pro/x",
    ],
)
def test_spoof_in_title_fires_whatever_the_decoy_ends_in(title):
    assert "spoof_in_title" in names(apply_rules(title, None, title))


def test_spoof_in_title_leaves_listed_decoys_to_userinfo_spoof():
    # One rule per page for one spoof, so scores stay comparable.
    for title in (SPOOF_TITLE, POINTER_TITLE):
        fired = names(apply_rules(title, None, title))
        assert "userinfo_spoof" in fired
        assert "spoof_in_title" not in fired


def test_spoof_in_title_needs_a_known_tld_on_the_destination():
    title = "primewire.ag@agfc.harper18.workers.zz"
    assert "spoof_in_title" not in names(apply_rules(title, None, title))


def test_spoof_in_title_does_not_look_at_the_body():
    # In body text this shape is first.last@provider email: 80 pages on night 1.
    text = "Netflix\n\nlogin solano.elsa@icloud.com:SECRET{" + "c" * 64 + "}"
    assert "spoof_in_title" not in names(apply_rules("Netflix", None, text))


def test_a_plain_email_in_a_title_is_not_a_spoof():
    title = "write to bob@gmail.com"
    assert "spoof_in_title" not in names(apply_rules(title, None, title))


def test_a_dotted_email_in_a_title_is_no_longer_a_spoof():
    # first.last@provider in a title looks exactly like a spoof with an
    # unlisted decoy. It was the documented false positive until 22 November:
    # it is not part of a URL, and a mailbox provider is not a destination.
    for title in ("contact solano.elsa@icloud.com", "solano.elsa@icloud.com"):
        assert "spoof_in_title" not in names(apply_rules(title, None, title))


@pytest.mark.parametrize(
    "title",
    [
        "www.kpi.kharkiv.edu.ua@venture-cpu-sur-everyone.trycloudflare.com",
        "bbc.com@agfc.harper18.workers.dev/",
        "www.alibabacloud.com@mike-arrives-evaluate-decent.trycloudflare.com",
        "WWW.TENABLE.COM@AGFC.HARPER18.WORKERS.DEV/",
    ],
)
def test_every_observed_spoof_front_fires(title):
    assert "userinfo_spoof" in names(apply_rules(title, None, title))


def test_actor_shapes_score_above_four():
    pointer = hits_for(fixture_page("Hello-10-17-154"))
    spoof = apply_rules(SPOOF_TITLE, API_SAMPLE, SPOOF_TITLE + "\n" + API_SAMPLE)
    assert score(pointer) >= 4
    assert score(spoof) >= 4


# --------------------------------------------------------------------------
# encoded_pointer: a token that decodes to a whole pointer (#28)
# --------------------------------------------------------------------------

HIDDEN_HOST = "czMucmVkYXJvZGFzLmNvbQ=="  # s3.redarodas.com, from the actor's titles


def test_decodes_to_pointer_accepts_a_token_hiding_a_host_or_ip():
    assert decodes_to_pointer(HIDDEN_HOST)
    assert decodes_to_pointer("NDUuNzcuOTMuMTg=")  # 45.77.93.18


@pytest.mark.parametrize("token", ["dGViaQ==", "eWVsNA==", "2+2=", "aGVsbG8gd29ybGQ="])
def test_decodes_to_pointer_rejects_tokens_that_decode_to_words(token):
    # tebi, yel4, arithmetic, "hello world": printable, not pointers
    assert not decodes_to_pointer(token)


def test_encoded_pointer_fires_on_the_long_pointer_title():
    title = POINTER_TITLE + "?" + HIDDEN_HOST
    hits = apply_rules(title, API_SAMPLE, title + "\n" + API_SAMPLE + "\n" + API_SAMPLE)
    by_name = {h.rule.name: h.evidence for h in hits}
    assert by_name["encoded_pointer"] == HIDDEN_HOST
    # base64_in_title still reports the first padded token, as before
    assert by_name["base64_in_title"] == "dGViaQ=="


def test_encoded_pointer_does_not_fire_on_the_short_pointer_title():
    hits = apply_rules(POINTER_TITLE, API_SAMPLE, POINTER_TITLE + "\n" + API_SAMPLE)
    assert "encoded_pointer" not in names(hits)
    assert "base64_in_title" in names(hits)


def test_encoded_pointer_fires_in_the_body_too():
    hits = apply_rules("Hello", "", "Hello\n\nconfig " + HIDDEN_HOST)
    assert names(hits) == ["encoded_pointer"]


def test_an_encoded_pointer_alone_does_not_flag_but_with_the_api_sample_it_does():
    alone = apply_rules("Hello", "", "Hello\n\n" + HIDDEN_HOST)
    assert score(alone) == 3 < THRESHOLD
    with_sample = apply_rules(
        "Hello", API_SAMPLE, "Hello\n" + API_SAMPLE + "\n" + HIDDEN_HOST
    )
    assert names(with_sample) == ["encoded_pointer", "api_sample_body"]
    assert score(with_sample) >= THRESHOLD


UNPADDED_IP = "NDUuNzcuOTMuMTg3"  # 45.77.93.187: 12 bytes, so base64 adds no padding


@pytest.mark.parametrize("run", ["a" * 12, "a" * 16, "NDUuNzcuOTMuMTg3", "ab+/" * 5])
def test_unpadded_pattern_matches_whole_runs_in_groups_of_four(run):
    assert UNPADDED_BASE64_PATTERN.fullmatch(run)
    assert [m.group(0) for m in UNPADDED_BASE64_PATTERN.finditer(f"x {run} y")] == [run]


@pytest.mark.parametrize("run", ["a" * 8, "a" * 11, "a" * 13, "a" * 14, "a" * 15])
def test_unpadded_pattern_ignores_short_runs_and_odd_lengths(run):
    assert UNPADDED_BASE64_PATTERN.findall(f"x {run} y") == []


def test_unpadded_pattern_leaves_padded_tokens_to_the_padded_pattern():
    assert UNPADDED_BASE64_PATTERN.findall(HIDDEN_HOST) == []
    assert ENCODED_TOKEN_PATTERN.findall(HIDDEN_HOST) == [HIDDEN_HOST]
    assert ENCODED_TOKEN_PATTERN.findall(f"{HIDDEN_HOST} {UNPADDED_IP}") == [
        HIDDEN_HOST,
        UNPADDED_IP,
    ]


def test_decodes_to_pointer_accepts_an_unpadded_token():
    assert decodes_to_pointer(UNPADDED_IP)


@pytest.mark.parametrize(
    "word", ["internationalization", "abcdefghijkl", "YztOEovieQIzZjY8", "0123456789abcdef"]
)
def test_decodes_to_pointer_rejects_ordinary_unpadded_words(word):
    assert not decodes_to_pointer(word)


def test_an_unpadded_token_only_gets_plain_base64():
    # 15 bytes XORed with 0x5a: the full decoder would find it, but unpadded
    # tokens look like ordinary words, so XOR is not tried on them.
    hidden = bytes(b ^ 0x5A for b in b"cdn.example.com")
    token = base64.b64encode(hidden).decode()
    assert not token.endswith("=")
    assert not decodes_to_pointer(token)


def test_encoded_pointer_fires_on_an_unpadded_token():
    hits = apply_rules("Hello", "", "Hello\n\nconfig " + UNPADDED_IP)
    assert [(h.rule.name, h.evidence) for h in hits] == [("encoded_pointer", UNPADDED_IP)]


def test_encoded_pointer_ignores_long_ordinary_words():
    text = "Hello\n\ninternationalization of t.me/+YztOEovieQIzZjY8 abcdefghijkl"
    assert "encoded_pointer" not in names(apply_rules("Hello", "", text))


def test_base64_in_title_still_needs_padding():
    # The unpadded pattern belongs to encoded_pointer only.
    hits = apply_rules(UNPADDED_IP, "", UNPADDED_IP)
    assert names(hits) == ["encoded_pointer"]


def test_encoded_pointer_ignores_base64_that_hides_ordinary_text():
    hits = apply_rules("Hello", "", "Hello\n\nsecret: aGVsbG8gd29ybGQ=")
    assert "encoded_pointer" not in names(hits)


# --------------------------------------------------------------------------
# benign shapes do not
# --------------------------------------------------------------------------


def test_benign_hello_fixture_fires_nothing_positive():
    hits = hits_for(fixture_page("Hello-10-17-5"))
    assert [h for h in hits if h.rule.weight > 0] == []


def test_benign_test_fixture_fires_nothing_positive():
    hits = hits_for(fixture_page("Test-10-16"))
    assert [h for h in hits if h.rule.weight > 0] == []


def test_an_api_sample_page_without_a_pointer_scores_at_most_one():
    hits = apply_rules("Hello", API_SAMPLE, "Hello\n" + API_SAMPLE + "\n" + API_SAMPLE)
    assert names(hits) == ["api_sample_body"]
    assert score(hits) == 1


@pytest.mark.parametrize(
    "email",
    [
        "matt.grove.7@gmail.com",
        "Daniilsergiienko@gmail.com",
        "jean-michel.laurin@wanadoo.fr",
        "solano.elsa@icloud.com",
    ],
)
def test_an_email_is_not_a_userinfo_spoof(email):
    text = f"login {email}:SECRET{{{'c' * 64}}}"
    hits = apply_rules(None, None, text)
    assert "userinfo_spoof" not in names(hits)
    assert "email_address" in names(hits)


def test_a_host_shaped_local_part_is_no_longer_a_spoof_hit():
    # cfihelp.ua@gmail.com was the 1 false flag in 92,977 on night 1, and the
    # shape of the eight on the full table: an email whose name ends like a domain.
    hits = apply_rules(None, None, "contact cfihelp.ua@gmail.com")
    assert names(hits) == []


def test_private_ip_in_a_config_dump_fires_no_ip_rule():
    text = "ListenAddress 0.0.0.0\nserverIp = 192.168.1.64, port = 31337"
    assert names(apply_rules("Ss", None, text)) == []


def test_public_ip_in_the_body_only_fires_the_weak_rule():
    text = "api\nMTProto servers\nTest configuration: 149.154.167.40:443 DC 2"
    hits = apply_rules("api", "MTProto servers", text)
    assert names(hits) == ["ip_literal"]
    assert hits[0].evidence == "149.154.167.40"


def test_version_string_is_the_documented_false_positive_of_ip_literal():
    hits = apply_rules("News", None, "VL700 Firmware [vli_vl700_(1.0.2.10).bin]")
    assert names(hits) == ["ip_literal"]
    assert score(hits) == 1


@pytest.mark.parametrize(
    "text",
    [
        "WhatsApp v2.22.23.12 released",
        "build V8.8.8.8",
        "version2.22.23.12",
        "app_8.8.8.8",
        "сборка8.8.8.8",
    ],
)
def test_a_dotted_number_glued_to_a_word_is_not_an_ip(text):
    # Version strings: 282 of the 1,688 benign IP matches on night 1.
    assert names(apply_rules("News", None, text)) == []


@pytest.mark.parametrize(
    "text",
    [
        "8.8.8.8",
        "ip 8.8.8.8",
        "ip:8.8.8.8",
        "ip=8.8.8.8",
        "(8.8.8.8)",
        "http://8.8.8.8/x",
        "user@8.8.8.8",
        "first\n8.8.8.8",
        "8.8.8.8:53",
    ],
)
def test_an_ip_after_punctuation_or_space_is_still_an_ip(text):
    assert [m.group(0) for m in IP_PATTERN.finditer(text)] == ["8.8.8.8"]


def test_the_pointer_title_still_leads_with_its_ip():
    assert IP_PATTERN.match(POINTER_TITLE).group(0) == "207.246.108.214"


def test_a_longer_dotted_number_is_not_an_ip():
    assert names(apply_rules("1.2.3.4.5", None, "1.2.3.4.5")) == []


def test_arithmetic_in_a_title_is_not_base64():
    assert "base64_in_title" not in names(apply_rules("2+2=4 and 2+2=", None, None))


def test_base64_without_padding_is_not_claimed_by_the_draft_rule():
    # Unpadded tokens are left to the #28 decoders.
    assert names(apply_rules("Zm9v", None, None)) == []


def test_telegram_link_and_handle_are_negative():
    hits = apply_rules(
        "Proxy", None, "join https://t.me/+YztOEovieQIzZjY8 or @SLlV_INTIM_BOT"
    )
    assert names(hits) == ["telegram_link"]
    assert score(hits) < 0


def test_handle_inside_an_email_or_spoof_is_not_a_telegram_handle():
    assert "telegram_link" not in names(
        apply_rules(None, None, "Daniilsergiienko@gmail.com")
    )
    assert "telegram_link" not in names(apply_rules(SPOOF_TITLE, None, SPOOF_TITLE))


def test_squatter_a_body_scores_negative():
    body = "Proxy\n\nhttps://t.me/SLlV_INTIM_BOT\nслив интим бот proxy socks vpn free"
    assert score(apply_rules("Proxy", None, body)) < 0


# --------------------------------------------------------------------------
# apply_rules mechanics
# --------------------------------------------------------------------------


def test_apply_rules_tolerates_none_fields():
    assert apply_rules(None, None, None) == []


def test_apply_rules_fires_each_rule_at_most_once():
    text = "1.1.1.1 and 8.8.8.8 and 9.9.9.9"
    hits = apply_rules("8.8.8.8 9.9.9.9", None, text)
    assert names(hits).count("ip_in_title") == 1
    assert names(hits).count("ip_literal") == 1


def test_a_hit_counts_every_match_and_keeps_the_first_as_evidence():
    text = "1.1.1.1 and 8.8.8.8 and 9.9.9.9"
    hits = apply_rules("8.8.8.8 9.9.9.9", None, text)
    by_name = {h.rule.name: h for h in hits}
    # Only the address that opens the title counts for ip_in_title.
    assert (by_name["ip_in_title"].evidence, by_name["ip_in_title"].matches) == (
        "8.8.8.8",
        1,
    )
    assert (by_name["ip_literal"].evidence, by_name["ip_literal"].matches) == (
        "1.1.1.1",
        3,
    )


def test_matches_counts_only_what_the_check_accepted():
    # Two private addresses and one public one: one match, and it is the evidence.
    hits = resolver(apply_rules(None, None, "192.168.1.1 10.0.0.1 8.8.8.8"))
    assert [(h.rule.name, h.evidence, h.matches) for h in hits] == [
        ("ip_literal", "8.8.8.8", 1)
    ]


def test_matches_counts_repeats_of_the_same_string():
    link = "https://t.me/+YztOEovieQIzZjY8"
    hits = resolver(apply_rules(None, None, f"{link} ads {link} {link}"))
    assert [(h.rule.name, h.matches) for h in hits] == [("telegram_link", 3)]


def test_a_single_match_counts_one():
    hits = resolver(apply_rules(SPOOF_TITLE, API_SAMPLE, SPOOF_TITLE + "\n" + API_SAMPLE))
    assert [h.matches for h in hits] == [1, 1]


def test_matches_does_not_change_the_score():
    # A rule adds its weight once, however often it matched.
    once = apply_rules(None, None, "8.8.8.8")
    often = apply_rules(None, None, "8.8.8.8 9.9.9.9 1.1.1.1 4.4.4.4")
    assert often[0].matches == 4
    assert score(often) == score(once) == 1


def test_a_hit_built_without_a_count_has_one_match():
    assert Hit(rule("ip_literal"), "8.8.8.8").matches == 1


def test_apply_rules_returns_hits_in_table_order():
    hits = hits_for(fixture_page("Hello-10-17-154"))
    order = [r.name for r in RULES]
    assert names(hits) == sorted(names(hits), key=order.index)


def test_apply_rules_skips_computed_rules():
    assert "templated_body" not in names(hits_for(fixture_page("Hello-10-17-154")))


def test_apply_rules_accepts_a_custom_rule_list():
    only = (rule("ip_literal"),)
    hits = apply_rules(POINTER_TITLE, API_SAMPLE, POINTER_TITLE, rules=only)
    assert names(hits) == ["ip_literal"]


def test_score_is_the_sum_of_weights():
    hits = [Hit(rule("ip_in_title"), "x"), Hit(rule("telegram_link"), "y")]
    assert score(hits) == rule("ip_in_title").weight + rule("telegram_link").weight
    assert score([]) == 0


# --------------------------------------------------------------------------
# render_table
# --------------------------------------------------------------------------


def test_render_table_has_a_header_and_one_row_per_rule():
    lines = render_table().splitlines()
    assert lines[0].startswith("| Rule | Weight | Where | Pattern |")
    assert set(lines[1]) <= set("|-")
    assert len(lines) == 2 + len(RULES)


def test_render_table_rows_name_each_rule_with_a_signed_weight():
    lines = render_table().splitlines()[2:]
    for r, line in zip(RULES, lines):
        assert line.startswith(f"| `{r.name}` | {r.weight:+d} | {r.where} |")


def test_render_table_escapes_pipes_inside_patterns():
    rules = (Rule("alt", 1, "text", re.compile(r"a|b"), "Miss: x" + "." * 40),)
    row = render_table(rules).splitlines()[2]
    assert "`a\\|b`" in row
    assert (
        len(row.strip("|").split(" | ")) == 5
    )  # the escaped pipe did not split the row


def test_render_table_marks_computed_rules():
    row = next(l for l in render_table().splitlines() if "templated_body" in l)
    assert "| computed | computed |" in row


def test_render_table_abbreviates_the_tld_list():
    row = next(l for l in render_table().splitlines() if "`userinfo_spoof`" in l)
    assert "TLD" in row
    assert "com\\|net" not in row


def test_render_table_names_the_check_next_to_the_pattern():
    row = next(l for l in render_table().splitlines() if "`ip_in_title`" in l)
    assert "+ `is_public_ip`" in row
    row = next(l for l in render_table().splitlines() if "`storage_key_marker`" in l)
    assert "+ `" not in row


def test_render_table_ends_with_a_newline():
    assert render_table().endswith("\n")


def test_module_prints_the_table_when_run(tmp_path):
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-m", "graphwatch.rules"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out == render_categories()


# --------------------------------------------------------------------------
# the category engine: category, min_matches, gate, the body field
# (plan/classification-plan-2026-11-15.md)
# --------------------------------------------------------------------------

RESOLVER_RULES = (
    ("userinfo_spoof", 5),
    ("spoof_in_title", 5),
    ("ip_in_title", 4),
    ("storage_key_marker", 4),
    ("base64_in_title", 2),
    ("encoded_pointer", 3),
    ("api_sample_body", 1),
    ("ip_literal", 1),
    ("email_address", 1),
    ("telegram_link", -1),
    ("templated_body", -2),
)


def custom(name="r", weight=1, where="text", pattern=r"x", **kwargs) -> Rule:
    return Rule(name, weight, where, re.compile(pattern), "test rule", **kwargs)


def test_a_rule_defaults_to_the_resolver_category_one_match_and_no_gate():
    r = custom()
    assert (r.category, r.min_matches, r.gate) == ("resolver", 1, None)


def test_the_eleven_resolver_rules_keep_their_names_weights_and_order():
    kept = tuple((r.name, r.weight) for r in RULES if r.category == "resolver")
    assert kept == RESOLVER_RULES
    assert tuple((r.name, r.weight) for r in RULES[:11]) == RESOLVER_RULES


def test_the_resolver_rules_have_no_gate_and_no_match_count():
    for r in RULES:
        if r.category == "resolver":
            assert (r.min_matches, r.gate) == (1, None), r.name


def test_every_rule_belongs_to_a_known_category():
    for r in RULES:
        assert r.category in CATEGORIES, r.name


def test_every_category_has_at_least_one_rule():
    assert {r.category for r in RULES} == set(CATEGORIES)


def test_categories_are_unique_and_resolver_comes_first():
    assert len(set(CATEGORIES)) == len(CATEGORIES)
    assert CATEGORIES[0] == "resolver"


def test_the_actor_shapes_keep_their_resolver_scores():
    # The verdict reported since 14 November: +17 for the pointer page whose
    # tokens hide no host, +6 for the spoof page.
    pointer = apply_rules(POINTER_TITLE, API_SAMPLE, POINTER_TITLE + "\n" + API_SAMPLE + "\n" + API_SAMPLE)
    spoof = apply_rules(SPOOF_TITLE, API_SAMPLE, SPOOF_TITLE + "\n" + API_SAMPLE + "\n" + API_SAMPLE)
    assert score(pointer) == 17
    assert score(spoof) == 6


def test_score_counts_the_resolver_rules_only():
    other = custom("other", 4, category="pointer")
    hits = [Hit(rule("ip_in_title"), "x"), Hit(other, "y")]
    assert score(hits) == rule("ip_in_title").weight
    assert score([Hit(other, "y")]) == 0


# --- min_matches ---


def test_min_matches_holds_a_rule_back_until_the_count_is_reached():
    r = custom(pattern=r"\d+", min_matches=3)
    assert apply_rules(None, None, "1 2", rules=(r,)) == []
    hits = apply_rules(None, None, "1 2 3", rules=(r,))
    assert [(h.evidence, h.matches) for h in hits] == [("1", 3)]


def test_min_matches_counts_only_what_the_check_accepted():
    r = custom(pattern=r"\d+", check=lambda s: int(s) > 5, min_matches=2)
    assert apply_rules(None, None, "1 2 3 9", rules=(r,)) == []
    assert len(apply_rules(None, None, "1 8 3 9", rules=(r,))) == 1


def test_a_rule_still_adds_its_weight_once_above_min_matches():
    r = custom(weight=4, pattern=r"\d+", category="pointer", min_matches=2)
    hits = apply_rules(None, None, "1 2 3 4 5 6", rules=(r,))
    assert category_scores(hits) == {"pointer": 4}


# --- gate ---


class CountingPattern:
    """Stands in for a compiled regex and counts how often it is run."""

    def __init__(self, pattern: str):
        self.compiled = re.compile(pattern)
        self.pattern = pattern
        self.runs = 0

    def finditer(self, s: str):
        self.runs += 1
        return self.compiled.finditer(s)


def test_gate_skips_the_regex_when_the_substring_is_missing():
    pattern = CountingPattern(r"https?://\S+")
    r = Rule("r", 1, "text", pattern, "test rule", gate="://")
    assert apply_rules(None, None, "no link here", rules=(r,)) == []
    assert pattern.runs == 0


def test_gate_runs_the_regex_when_the_substring_is_there():
    pattern = CountingPattern(r"https?://\S+")
    r = Rule("r", 1, "text", pattern, "test rule", gate="://")
    hits = apply_rules(None, None, "see https://example.com", rules=(r,))
    assert pattern.runs == 1
    assert hits[0].evidence == "https://example.com"


def test_gate_is_compared_with_the_lower_cased_field():
    r = custom(pattern=r"WARNING_BANNER", gate="warning_banner")
    assert len(apply_rules(None, None, "WARNING_BANNER here", rules=(r,))) == 1


def test_gate_looks_at_the_rules_own_field():
    r = custom(where="title", pattern=r"https?://\S+", gate="://")
    assert apply_rules("plain title", None, "body https://example.com", rules=(r,)) == []


def test_every_gate_is_lower_case():
    for r in RULES:
        if r.gate is not None:
            assert r.gate == r.gate.lower(), r.name


GATE_CORPUS = [
    "plain text with nothing in it",
    "8.8.8.8:1080\n1.1.1.1:3128\n9.9.9.9:8080",
    "vless://SECRET{" + "ab" * 32 + "}@vpn.example.org:443",
    "VLESS://SECRET{" + "ab" * 32 + "}@VPN.EXAMPLE.ORG:443",
    "https://t.me/proxy?server=8.8.8.8&port=443&secret=SECRET{" + "ab" * 32 + "}",
    "TG://PROXY?SERVER=8.8.8.8&PORT=443",
    ("user@mail.example.com:SECRET{" + "ab" * 32 + "}\n") * 4,
    ("panel password: SECRET{" + "ab" * 32 + "}\n") * 10,
    "WARNING_BANNER\napi_id: 1\nAPI_HASH: SECRET{" + "ab" * 32 + "}",
    "HTTPS://FILES.EXAMPLE.COM/SETUP.EXE and https://files.example.com/a.zip",
    "mirror http://a2b3c4d5e6f7g2h3.ONION/ cvv",
    '<INPUT NAME="p" TYPE="password"> {"server": "a", "port": 1}',
    "join https://T.ME/+AbCdEfGh or https://t.me/shop_bot or @some_handle",
    "https://m.dating.example.com/autologin/?key=SECRET{" + "ab" * 32 + "}",
    "HTTPS://dating.example.com/l/SECRET{" + "ab" * 32 + "}/open",
]


@pytest.mark.parametrize("text", GATE_CORPUS)
def test_a_gate_never_changes_a_result(text):
    # Every gate has to be text that every match of its pattern contains, so
    # the table with its gates removed must give exactly the same hits.
    from dataclasses import replace

    ungated = tuple(replace(r, gate=None) for r in RULES)
    with_gates = [(h.rule.name, h.evidence, h.matches) for h in apply_rules("t", "", f"t\n\n{text}")]
    without = [(h.rule.name, h.evidence, h.matches) for h in apply_rules("t", "", f"t\n\n{text}", rules=ungated)]
    assert with_gates == without


def test_the_gate_corpus_exercises_every_gated_rule():
    fired = set()
    for text in GATE_CORPUS:
        fired |= {h.rule.name for h in apply_rules("t", "", f"t\n\n{text}")}
    gated = {r.name for r in RULES if r.gate is not None}
    assert gated <= fired, gated - fired


# --- the body field ---


def test_body_of_lives_in_rules_and_classify_still_exports_it():
    from graphwatch import classify, rules

    assert classify.body_of is rules.body_of


def test_a_body_rule_reads_the_text_without_its_title_and_description():
    r = custom(where="body", pattern=r"needle")
    assert apply_rules("needle", "needle", "needle\nneedle\nhay", rules=(r,)) == []
    assert len(apply_rules("t", "d", "t\nd\nneedle", rules=(r,))) == 1


def test_the_body_field_is_stripped_so_a_whole_body_rule_can_anchor():
    r = custom(where="body", pattern=r"\A\S+\Z")
    hits = apply_rules("t", "d", "t\nd\n  one-token\n\n", rules=(r,))
    assert [h.evidence for h in hits] == ["one-token"]
    assert apply_rules("t", "d", "t\nd\ntwo tokens\n", rules=(r,)) == []


def test_a_body_rule_counts_a_line_once_though_the_description_repeats_it():
    r = custom(where="body", pattern=r"\d+\.\d+")
    hits = apply_rules("t", "1.5 2.5", "t\n1.5 2.5\n1.5 2.5", rules=(r,))
    assert hits[0].matches == 2
    text_rule = custom(where="text", pattern=r"\d+\.\d+")
    assert apply_rules("t", "1.5 2.5", "t\n1.5 2.5\n1.5 2.5", rules=(text_rule,))[0].matches == 4


def test_the_body_is_the_whole_text_when_the_prefix_does_not_match():
    r = custom(where="body", pattern=r"\Aneedle\Z")
    assert len(apply_rules("other", None, "needle", rules=(r,))) == 1


# --- category_scores, labels_for, primary_label ---


def test_category_scores_sums_weights_per_category_in_category_order():
    hits = [
        Hit(custom("a", 3, category="seo_spam"), "x"),
        Hit(custom("b", 4, category="pointer"), "x"),
        Hit(custom("c", -3, category="pointer"), "x"),
        Hit(custom("d", 5), "x"),
    ]
    scores = category_scores(hits)
    assert scores == {"resolver": 5, "pointer": 1, "seo_spam": 3}
    assert list(scores) == ["resolver", "pointer", "seo_spam"]


def test_category_scores_keeps_a_category_whose_weights_cancel():
    hits = [Hit(custom("a", 3, category="pointer"), "x"), Hit(custom("b", -3, category="pointer"), "x")]
    assert category_scores(hits) == {"pointer": 0}


def test_category_scores_of_no_hits_is_empty():
    assert category_scores([]) == {}


def test_labels_for_is_every_category_at_or_above_the_threshold():
    scores = {"resolver": 3, "pointer": 4, "seo_spam": 7, "prose": -1}
    assert labels_for(scores) == ["pointer", "seo_spam"]


def test_labels_for_takes_the_threshold_as_an_argument():
    assert labels_for({"resolver": 3}, threshold=3) == ["resolver"]
    assert labels_for({"resolver": 3}, threshold=4) == []


def test_labels_for_returns_category_order_whatever_order_it_is_given():
    assert labels_for({"prose": 4, "resolver": 4}) == ["resolver", "prose"]


def test_primary_label_is_the_first_label_in_category_order():
    assert primary_label(["prose", "seo_spam", "pointer"]) == "pointer"
    assert primary_label(["placeholder", "resolver"]) == "resolver"


def test_primary_label_of_no_labels_is_none():
    assert primary_label([]) is None


# --- render ---


def test_render_table_shows_the_match_count_a_rule_needs():
    row = next(l for l in render_table().splitlines() if "`ip_port_list`" in l)
    assert "at least 3 times" in row
    row = next(l for l in render_table().splitlines() if "`single_ip_port`" in l)
    assert "times" not in row


def test_render_categories_has_a_section_per_category_in_order():
    out = render_categories()
    headings = [l for l in out.splitlines() if l.startswith("## ")]
    assert [h.split("`")[1] for h in headings] == list(CATEGORIES)
    assert headings[0] == "## `resolver` (intelligence)"
    assert "## `prose` (noise)" in headings


def test_render_categories_lists_every_rule_once():
    out = render_categories()
    for r in RULES:
        assert out.count(f"| `{r.name}` |") == 1, r.name


def test_render_categories_skips_a_category_with_no_rules():
    out = render_categories((rule("ip_literal"),))
    assert out.count("## ") == 1


# --- checks added with the decisions of 22 November ---


@pytest.mark.parametrize(
    "s",
    ["8.8.8.8", "8.8.8.8:8443", "c2.example.org", "c2.example.org:443",
     "http://8.8.8.8", "https://c2.example.org/", "HTTPS://c2.example.org:8443/"],
)
def test_is_bare_pointer_accepts_an_address_with_nothing_after_it(s):
    assert is_bare_pointer(s) is True


@pytest.mark.parametrize(
    "s",
    ["https://t.me/somenews", "https://c2.example.org/gate", "https://c2.example.org/?a=1",
     "https://c2.example.org?a=1", "https://c2.example.org/#top", "192.168.1.1",
     "not a pointer", "http://[broken", ""],
)
def test_is_bare_pointer_rejects_links_private_addresses_and_non_pointers(s):
    assert is_bare_pointer(s) is False


SECRET_TOKEN = "SECRET{" + "ab" * 32 + "}"


@pytest.mark.parametrize(
    "s",
    [SECRET_TOKEN, "password:" + SECRET_TOKEN, "PASSWORD:" + SECRET_TOKEN,
     "db_passwd:" + SECRET_TOKEN, "пароль:" + SECRET_TOKEN, "api_hash:" + SECRET_TOKEN],
)
def test_counted_secret_counts_a_secret_alone_or_behind_a_password_label(s):
    assert counted_secret(s) is True


@pytest.mark.parametrize(
    "s",
    ["Size:" + SECRET_TOKEN, "admin_01:" + SECRET_TOKEN, "user@mail.example.com:" + SECRET_TOKEN],
)
def test_counted_secret_does_not_count_the_bare_login_shape(s):
    assert counted_secret(s) is False


def test_the_secret_labels_are_the_ones_redaction_hashes_after():
    from graphwatch.redact import LABEL_AT_END_PATTERN

    for label in SECRET_LABELS:
        assert LABEL_AT_END_PATTERN.search(label + ":"), label


# --- no rule may take seconds on one page ---

LONG_RUNS = {
    "letters": "A" * 60000,
    "base64": "aB3+/" * 12000,
    "hex": "0123456789abcdef" * 3750,
    "dotted labels": "ab.cd-" * 10000,
    "digits": "1234567890" * 6000,
    "url path": "https://example.com/" + "a/" * 30000,
    "url query": "https://example.com/?a=" + "x" * 60000,
    "at signs": "a@" * 30000,
    "colons": "word:" * 12000,
    "secrets": ("SECRET{" + "ab" * 32 + "}") * 800,
    "handles": "@handle_name " * 4600,
}


@pytest.mark.parametrize("name", sorted(LONG_RUNS))
def test_no_category_rule_is_slow_on_a_long_unbroken_run(name, laptop_seconds):
    # A page is up to 64 KB and whoever posts it chooses the text. A pattern
    # that restarts from every character of a long run takes seconds on one
    # page; these finish in milliseconds. The resolver rules are left out:
    # they are unchanged, and timed in the nightly run since 14 November.
    text = LONG_RUNS[name]
    for r in RULES:
        if r.pattern is None or r.category == "resolver":
            continue
        assert laptop_seconds(lambda: list(r.pattern.finditer(text))) < 1.0, (r.name, name)


# --------------------------------------------------------------------------
# resolver rules tightened on 22 November: flag the real resolver pages only
#
# Eleven flagged pages on the full table were not resolvers: eight emails
# whose name ends like a domain (name.com@gmail.com), read as host@host, and
# a version number in a title (Patch 1.12.1.5) read as a public IP. The
# shapes below are the ones counted on the sweep's own pages (night-1 copy,
# held_out = 0): all 55 actor pages have the spoof after a ?, before a /, or
# as the whole title, and all 27 pointer titles open with the IP. Held-out
# recall was 7/15 before and after, measured as a count and nothing else.
# --------------------------------------------------------------------------

SPOOF = "www.tenable.com@agfc.harper18.workers.dev"


def resolver_score(title, body="", description=""):
    return score(apply_rules(title, description, f"{title}\n{description}\n{body}"))


@pytest.mark.parametrize(
    "title",
    [
        SPOOF + "/",  # 42 of the 55 actor titles on night 1
        SPOOF,  # 13 of the 55: the spoof is the whole title
        "http://" + SPOOF,
        "https://" + SPOOF + "/login",
        POINTER_TITLE,  # 27 of the 55: after the ? of the pointer shape
    ],
)
def test_the_spoof_still_fires_in_every_shape_the_actor_uses_in_a_title(title):
    hits = apply_rules(title, API_SAMPLE, title + "\n" + API_SAMPLE + "\n" + API_SAMPLE)
    assert "userinfo_spoof" in names(hits)
    assert score(hits) >= THRESHOLD


@pytest.mark.parametrize(
    "body",
    [
        "open " + SPOOF + "/ in the browser",
        "open https://" + SPOOF + " in the browser",
        "8.8.8.8?" + SPOOF + "/!x",
    ],
)
def test_the_spoof_still_fires_in_a_body_when_it_is_part_of_a_url(body):
    assert "userinfo_spoof" in names(apply_rules("note", "", "note\n\n" + body))


@pytest.mark.parametrize(
    "body",
    [
        "cfihelp.ua@gmail.com write to us",  # opens the body, a space after it
        "contact first.ai@company.example.com for a quote",
        "mailto:name.com@mail.example.org",
        "emails: a.com@b.example.org, c.net@d.example.org.",
        "name.com@gmail.com",  # alone on a line of the body
    ],
)
def test_an_email_whose_name_ends_like_a_domain_is_not_a_spoof(body):
    hits = apply_rules("Contacts", "", "Contacts\n\n" + body)
    assert "userinfo_spoof" not in names(hits)
    assert score(hits) < THRESHOLD


def test_a_spoof_alone_on_a_line_counts_only_when_that_line_is_the_title():
    assert "userinfo_spoof" in names(apply_rules(SPOOF, "", SPOOF + "\n\nbody"))
    assert "userinfo_spoof" not in names(apply_rules("t", "", "t\n\n" + SPOOF))
    assert "userinfo_spoof" not in names(apply_rules("t", "", "t\n\nline one\n" + SPOOF + "\nline three"))


@pytest.mark.parametrize(
    "s", ["name.com@gmail.com", "name.com@GMAIL.com", "a.ua@mail.ru", "x.org@sub.yandex.ru"]
)
def test_is_spoof_rejects_a_mailbox_provider_on_the_right(s):
    assert is_spoof(s) is False


@pytest.mark.parametrize(
    "s", [SPOOF, "onmedservice.com.ua@opportunizz.pro", "a.com@notgmail.com", "a.com@gmail.com.evil.pro"]
)
def test_is_spoof_accepts_any_other_destination(s):
    assert is_spoof(s) is True


def test_a_mailbox_provider_title_is_not_a_spoof_even_as_the_whole_title():
    assert resolver_score("name.com@gmail.com", "hi") < THRESHOLD
    assert resolver_score("first.last@icloud.com", "hi") < THRESHOLD


def test_the_mailbox_providers_are_lower_case_hostnames():
    for provider in MAILBOX_PROVIDERS:
        assert provider == provider.lower()
        assert "." in provider and "@" not in provider


@pytest.mark.parametrize(
    "title",
    ["primewire.ag@agfc.harper18.workers.dev", "primewire.ag@agfc.harper18.workers.dev/", "x?primewire.ag@agfc.harper18.workers.dev/!y"],
)
def test_spoof_in_title_still_fires_in_the_same_three_places(title):
    assert "spoof_in_title" in names(apply_rules(title, None, title))


def test_spoof_in_title_does_not_fire_on_an_unlisted_decoy_inside_a_sentence():
    title = "see primewire.ag@agfc.harper18.workers.dev for more"
    assert "spoof_in_title" not in names(apply_rules(title, None, title))


@pytest.mark.parametrize("title", ["8.8.8.8", "8.8.8.8?x", "http://8.8.8.8", "HTTPS://8.8.8.8/gate", POINTER_TITLE])
def test_ip_in_title_fires_when_the_address_opens_the_title(title):
    assert "ip_in_title" in names(apply_rules(title, None, title))


@pytest.mark.parametrize(
    "title",
    ["Patch 1.12.1.5", "server 8.8.8.8", "v 8.8.8.8", "ftp://8.8.8.8", "x http://8.8.8.8", " 8.8.8.8"],
)
def test_ip_in_title_does_not_fire_on_an_address_further_into_the_title(title):
    hits = apply_rules(title, None, title)
    assert "ip_in_title" not in names(hits)
    assert score(hits) < THRESHOLD


def test_the_version_number_title_that_was_flagged_is_a_near_miss_now():
    # Patch-10-18-2 on the full table: +4 and flagged until 22 November.
    assert resolver_score("Patch 1.12.1.5", "release notes") == 1


def test_a_private_address_opening_a_title_is_still_not_an_ip_in_title():
    assert "ip_in_title" not in names(apply_rules("192.168.1.1", None, "192.168.1.1"))


def test_the_extractor_still_reads_the_spoof_patterns_it_always_read():
    # The rules use the URL-shaped patterns; extract.py keeps the plain ones,
    # so what it reports for a flagged page does not change.
    from graphwatch import extract, rules

    assert extract.USERINFO_SPOOF_PATTERN is rules.USERINFO_SPOOF_PATTERN
    assert extract.TITLE_SPOOF_PATTERN is rules.TITLE_SPOOF_PATTERN
    assert rule("userinfo_spoof").pattern is rules.SPOOF_URL_PATTERN


# --- a gate is a true pre-test, for any spelling ---


@pytest.mark.parametrize(
    "text",
    [
        "API_ID and APİ_HASH",  # dotted capital I
        "t.me/proxy?ſerver=8.8.8.8",  # long s
        "abcdefghijklmnop.onıon",  # dotless i
        "<İnput type=password>",
    ],
)
def test_a_gate_never_changes_a_result_for_letters_that_fold_oddly(text):
    # re.IGNORECASE matches these letters against ASCII ones, and str.lower()
    # does not turn them into ASCII, so a gate would have skipped a rule that
    # its pattern matched. The gated patterns fold ASCII only now.
    from dataclasses import replace

    ungated = tuple(replace(r, gate=None) for r in RULES)
    with_gates = [(h.rule.name, h.matches) for h in apply_rules("t", "", f"t\n\n{text}")]
    without = [(h.rule.name, h.matches) for h in apply_rules("t", "", f"t\n\n{text}", rules=ungated)]
    assert with_gates == without


# --- the page field: the text and the link targets behind it (22 November) ---


def test_a_page_rule_reads_the_text_and_the_link_targets():
    r = custom(where="page", pattern=r"https?://\S+")
    hits = apply_rules("t", "", "t\n\nsee https://a.example.com", rules=(r,), links=["https://b.example.com/x"])
    assert [(h.evidence, h.matches) for h in hits] == [("https://a.example.com", 2)]


def test_without_links_the_page_field_is_the_text():
    r = custom(where="page", pattern=r"needle")
    assert len(apply_rules("t", "", "t\n\nneedle", rules=(r,))) == 1
    assert apply_rules("t", "", "t\n\nhay", rules=(r,)) == []


def test_a_text_rule_and_a_body_rule_never_see_a_link_target():
    for where in ("text", "body", "title", "description"):
        r = custom(where=where, pattern=r"hidden\.example\.com")
        assert apply_rules("t", "d", "t\nd\nclick here", rules=(r,), links=["https://hidden.example.com/"]) == []


def test_link_targets_are_one_to_a_line_so_two_never_join_into_one_url():
    r = custom(where="page", pattern=r"https?://\S+")
    hits = apply_rules("t", "", "t\n\nx", rules=(r,), links=["https://a.example.com/1", "https://b.example.com/2"])
    assert hits[0].matches == 2


def test_the_resolver_rules_read_text_and_the_other_pattern_rules_do_not():
    for r in RULES:
        if r.where == "computed":
            continue
        if r.category == "resolver":
            assert r.where in ("text", "title", "description"), r.name
        else:
            assert r.where in ("page", "body", "description"), r.name


def test_a_spoof_url_behind_a_link_does_not_move_the_resolver_score():
    # The resolver verdict is about what the page shows, as it always was.
    hits = apply_rules("t", "", "t\n\nclick here", links=["https://www.tenable.com@agfc.harper18.workers.dev/"])
    assert score(hits) == 0
    assert "tunnel_host" in [h.rule.name for h in hits]  # a category rule does see it


# --- what the second review of 22 November found ---


def test_the_email_pattern_reads_a_run_of_plus_signs_once(laptop_seconds):
    # The one resolver pattern that restarted inside a run: + is a local-part
    # character and was not in the lookbehind.
    from graphwatch.rules import EMAIL_PATTERN

    for text in ("+" * 64000, "a+" * 32000, "a+" * 32000 + "@x.com"):
        assert laptop_seconds(lambda: list(EMAIL_PATTERN.finditer(text))) < 1.0


@pytest.mark.parametrize(
    "text,found",
    [
        ("mail bob@gmail.com now", ["bob@gmail.com"]),
        ("first.last+tag@mail.example.com", ["first.last+tag@mail.example.com"]),
        ("a+b@x.io and c@y.io", ["a+b@x.io", "c@y.io"]),
        ("+bob@x.io", ["+bob@x.io"]),
        ("x@bob@x.io", []),
    ],
)
def test_the_email_pattern_still_finds_ordinary_addresses(text, found):
    from graphwatch.rules import EMAIL_PATTERN

    assert [m.group(0) for m in EMAIL_PATTERN.finditer(text)] == found


def test_the_one_shape_the_email_pattern_no_longer_takes():
    # A run with a plus in it that itself follows an @: " b1@+b@x.io" used to
    # give b@x.io. Not an address anyone writes; recorded so it is no surprise.
    from graphwatch.rules import EMAIL_PATTERN

    assert EMAIL_PATTERN.search(" b1@+b@x.io") is None


def test_a_token_is_decoded_once_however_often_a_page_repeats_it():
    decodes_to_pointer.cache_clear()
    for _ in range(500):
        assert decodes_to_pointer(HIDDEN_HOST) is True
    info = decodes_to_pointer.cache_info()
    assert (info.misses, info.hits) == (1, 499)


def test_a_page_packed_with_one_padded_token_is_quick(laptop_seconds):
    decodes_to_pointer.cache_clear()
    text = "t\n\n" + (HIDDEN_HOST + " ") * 2500
    assert laptop_seconds(lambda: apply_rules("t", "", text)) < 1.0
    assert "encoded_pointer" in names(apply_rules("t", "", text))


@pytest.mark.parametrize("closer", ["»", "”", "’", "…", "*", "“"])
def test_a_file_link_closed_by_a_typographic_mark_is_still_a_file_link(closer):
    from graphwatch.rules import is_executable_link

    assert is_executable_link("https://files.example.com/setup.exe" + closer) is True


@pytest.mark.parametrize(
    "url,found",
    [
        ("https://d.example.com/l/SECRET{ab}/open", True),
        ("https://d.example.com/SECRET{ab}", True),
        ("https://d.example.com?next=/SECRET{ab}", False),
        ("https://d.example.com#/SECRET{ab}", False),
        ("https://d.example.com/page?next=/SECRET{ab}", False),
        ("http://SECRET{ab}@8.8.8.8:8080/list", False),
    ],
)
def test_has_token_in_path_looks_at_the_path_only(url, found):
    from graphwatch.rules import has_token_in_path

    assert has_token_in_path(url) is found
