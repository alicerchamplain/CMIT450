"""Tests for graphwatch.rules, the draft rule table (issue #23).

Positive examples are the known actor's Hello pages: the Hello-10-17-154
fixture and title shapes copied from the night-1 database. Negative examples
are the benign fixtures and synthetic strings. Nothing here reads a held-out
page from known.txt; those are for the recall check (#31), never for rules.
"""

import json
import re
from pathlib import Path

import pytest

from graphwatch.rules import (
    RULES,
    THRESHOLD,
    WHERE,
    Hit,
    Rule,
    apply_rules,
    decodes_to_printable,
    is_public_ip,
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


def names(hits) -> list[str]:
    return [h.rule.name for h in hits]


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
    assert WHERE == {"title", "description", "text", "computed"}
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
        "ip_in_title",
        "storage_key_marker",
        "base64_in_title",
        "api_sample_body",
        "ip_literal",
        "email_address",
        "telegram_link",
        "templated_body",
    } <= {r.name for r in RULES}


def test_the_draft_threshold_is_four():
    assert THRESHOLD == 4


def test_each_decisive_rule_clears_the_threshold_alone():
    for name in ("userinfo_spoof", "ip_in_title", "storage_key_marker"):
        assert rule(name).weight >= THRESHOLD, name


def test_no_single_weak_rule_clears_the_threshold():
    for name in ("base64_in_title", "api_sample_body", "ip_literal"):
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


def test_a_host_shaped_local_part_is_the_one_known_benign_spoof_hit():
    # cfihelp.ua@gmail.com: documented in the rule's reason as the 1 in 92,977.
    hits = apply_rules(None, None, "contact cfihelp.ua@gmail.com")
    assert names(hits) == ["userinfo_spoof"]


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
    assert out == render_table()
