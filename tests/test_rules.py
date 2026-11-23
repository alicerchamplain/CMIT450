"""Tests for graphwatch.rules: the rule engine and the resolver rules (issue #23).

Positive examples are the known actor's Hello pages: the Hello-10-17-154
fixture and title shapes copied from the night-1 database. Negative examples
are the benign fixtures and synthetic strings. Nothing here reads a held-out
page from known.txt; those are for the recall check (#31), never for rules.
The rules of the other categories are in tests/test_categories.py.
"""

import base64
import dataclasses
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from graphwatch.rules import (
    CATEGORIES,
    EMAIL_PATTERN,
    ENCODED_TOKEN_PATTERN,
    IP_PATTERN,
    MAILBOX_PROVIDERS,
    RULES,
    SECRET_LABELS,
    THRESHOLD,
    TITLE_SPOOF_PATTERN,
    UNPADDED_BASE64_PATTERN,
    USERINFO_SPOOF_PATTERN,
    Hit,
    Rule,
    apply_rules,
    category_scores,
    counted_secret,
    decodes_to_pointer,
    decodes_to_printable,
    has_public_ip,
    has_token_in_path,
    is_archive_link,
    is_bare_pointer,
    is_executable_link,
    is_pointer,
    is_public_ip,
    is_spoof,
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
SPOOF = "www.tenable.com@agfc.harper18.workers.dev"
SPOOF_TITLE = SPOOF + "/"
POINTER_TITLE = (
    "207.246.108.214?onmedservice.com.ua@opportunizz.pro/!SECRET{"
    + "0" * 64
    + "}?SECRET{"
    + "1" * 64
    + "}?dGViaQ==?eWVsNA=="
)
API_SAMPLE = "Hello,+world!"

# Seen on 20 Hello pages from 3 to 18 October in the full sweep (held_out = 0):
# userinfo_spoof missed them all because .ag is not in TLD.
AG_SPOOF = "primewire.ag@agfc.harper18.workers.dev"
AG_TITLE = AG_SPOOF + "/"

HIDDEN_HOST = "czMucmVkYXJvZGFzLmNvbQ=="  # s3.redarodas.com, from the actor's titles
UNPADDED_IP = "NDUuNzcuOTMuMTg3"  # 45.77.93.187: 12 bytes, so base64 adds no padding
SECRET_TOKEN = "SECRET{" + "ab" * 32 + "}"


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def hits_for(page: dict) -> list[Hit]:
    return apply_rules(page.get("title"), page.get("description"), page_text(page))


def page_hits(title, description="", body="", **kwargs) -> list[Hit]:
    """The hits on a page whose text is joined the way page_text joins it"""
    return apply_rules(title, description, f"{title}\n{description}\n{body}", **kwargs)


def resolver(hits) -> list[Hit]:
    """Only the resolver rules' hits, which is what this file is about.

    apply_rules runs the category rules too (tests/test_categories.py); they
    sit after the resolver rules in the table and never change its score.
    """
    return [h for h in hits if h.rule.category == "resolver"]


def names(hits) -> list[str]:
    return [h.rule.name for h in resolver(hits)]


def found(hits) -> list[tuple]:
    return [(h.rule.name, h.evidence, h.matches) for h in resolver(hits)]


def rule(name: str) -> Rule:
    return next(r for r in RULES if r.name == name)


def custom(name="r", weight=1, where="text", pattern=r"x", **kwargs) -> Rule:
    return Rule(name, weight, where, re.compile(pattern), "test rule", **kwargs)


# --------------------------------------------------------------------------
# the table itself
# --------------------------------------------------------------------------

# The verdict reported since 14 November: these names, weights and fields.
RESOLVER_RULES = (
    ("userinfo_spoof", 5, "text"),
    ("spoof_in_title", 5, "title"),
    ("ip_in_title", 4, "title"),
    ("storage_key_marker", 4, "text"),
    ("base64_in_title", 2, "title"),
    ("encoded_pointer", 3, "text"),
    ("api_sample_body", 1, "description"),
    ("ip_literal", 1, "text"),
    ("email_address", 1, "text"),
    ("telegram_link", -1, "text"),
    ("templated_body", -2, "computed"),
)

LISTED_TLDS = (
    "com net org edu gov mil info biz pro dev app io me su online site xyz top "
    "club shop store cloud tech ua ru by kz jp de uk fr it es pl cz nl us ca cn "
    "in br tr ir kr tv cc ws to ly ai co eu asia life live world space website "
    "fun icu link pw st tk ml ga cf gq"
).split()


def test_fixtures_used_here_are_not_held_out():
    for name in ("Hello-10-17-154", "Hello-10-17-5", "Test-10-16"):
        assert name not in KNOWN
        assert name.casefold() not in {k.casefold() for k in KNOWN}


def test_the_eleven_resolver_rules_keep_their_names_weights_fields_and_order():
    kept = tuple((r.name, r.weight, r.where) for r in RULES if r.category == "resolver")
    assert kept == RESOLVER_RULES
    assert tuple((r.name, r.weight, r.where) for r in RULES[:11]) == RESOLVER_RULES
    assert all((r.min_matches, r.gate) == (1, None) for r in RULES[:11])
    assert THRESHOLD == 4


def test_every_rule_is_a_row_the_engine_can_use():
    # a tuple: nothing can add a rule to the table while it runs
    assert isinstance(RULES, tuple)
    seen = [r.name for r in RULES]
    assert len(set(seen)) == len(seen)
    for r in RULES:
        # apply_rules skips a rule with no pattern, whatever field it names
        assert (r.pattern is None) == (r.where == "computed"), r.name
        # The link targets are in page and nowhere else. A category rule that
        # read text would miss the address behind "Download here".
        if r.category != "resolver" and r.pattern is not None:
            assert r.where in ("page", "body", "description"), r.name
    # category_scores drops a category it does not know
    assert {r.category for r in RULES} == set(CATEGORIES)


def test_a_rule_and_a_hit_have_the_defaults_the_resolver_rules_rely_on():
    r = custom()
    assert (r.category, r.min_matches, r.gate, r.check) == ("resolver", 1, None, None)
    assert Hit(r, "x").matches == 1


def test_a_rule_cannot_be_changed_once_it_is_in_the_table():
    with pytest.raises(dataclasses.FrozenInstanceError):
        RULES[0].weight = 99  # type: ignore[misc]


def test_every_listed_tld_ends_a_hostname_and_an_ending_outside_the_list_does_not():
    # The list decides where a spoof or an encoded pointer can lead. An ending
    # lost from it by a slip is an actor page the sweep stops flagging.
    for tld in LISTED_TLDS:
        assert is_pointer(f"c2.example.{tld}") is True, tld
    # .ag and .museum are real endings the list does not have: spoof_in_title
    # exists because of .ag. The other three are not endings at all.
    for tld in ("ag", "museum", "zz", "comet", "c"):
        assert is_pointer(f"c2.example.{tld}") is False, tld


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "s, public",
    [
        ("207.246.108.214", True),
        ("8.8.8.8", True),
        ("192.168.1.64", False),
        ("0.0.0.0", False),
        ("100.64.0.1", False),  # carrier NAT: not private, not routable either
        ("224.0.0.1", False),  # multicast
        ("999.1.1.1", False),  # the IP patterns let this through, the check does not
        ("host", False),
    ],
)
def test_is_public_ip_takes_a_routable_address_only(s, public):
    assert is_public_ip(s) is public


@pytest.mark.parametrize(
    "token, printable",
    [
        ("dGViaQ==", True),  # tebi, a field of the actor's title
        ("ZnI=", True),  # fr
        ("YQ==", True),  # a: one byte is enough
        ("aGVsbG8gd29ybGQ=", True),  # hello world: a space is printable
        ("////", False),  # bytes above ASCII
        ("AAAA", False),  # NUL bytes
        ("YX8=", False),  # a, then DEL
        ("abc", False),  # not base64: the length is wrong
        ("dGVi aQ==", False),  # not base64: a space inside
        ("", False),
    ],
)
def test_decodes_to_printable_takes_base64_of_printable_ascii_only(token, printable):
    assert decodes_to_printable(token) is printable


@pytest.mark.parametrize(
    "s",
    [
        "s3.redarodas.com",
        "S3.REDARODAS.COM",
        "45.77.93.187",
        "45.77.93.187:8443",
        "45.77.93.187:65535",
        "s3.redarodas.com:1",
        "http://s3.redarodas.com/",
        "https://45.77.93.187:8443/a/b?c=d",
        "HTTP://S3.REDARODAS.COM/x",
        "http://www.tenable.com@agfc.harper18.workers.dev/",
    ],
)
def test_is_pointer_accepts_a_whole_ip_host_or_url(s):
    assert is_pointer(s) is True


@pytest.mark.parametrize(
    "s",
    [
        "",
        "tebi",
        "go to s3.redarodas.com",
        "s3.redarodas.com\n",
        "http://s3.redarodas.com/ and more",
        "s3.redarodas.com/path",
        ".com",
        "192.168.1.1",
        "http://192.168.1.1/",
        "http://localhost/",
        "http://",
        "http://[broken",
        "ftp://s3.redarodas.com/",
        "first.last",
        "bob@gmail.com",
        "2.22.23",
        "s3.redarodas.com:port",
        "s3.redarodas.com:",
        "s3.redarodas.com:123456",
        "45.77.93.187:80:80",
    ],
)
def test_is_pointer_rejects_partial_private_and_non_pointers(s):
    assert is_pointer(s) is False


@pytest.mark.parametrize(
    "s, bare",
    [
        ("8.8.8.8:8443", True),
        ("c2.example.org", True),
        ("http://8.8.8.8", True),
        ("HTTPS://c2.example.org:8443/", True),
        ("https://c2.example.org/gate", False),
        ("https://c2.example.org?a=1", False),
        ("https://c2.example.org/#top", False),
        ("192.168.1.1", False),
        ("http://[broken", False),
    ],
)
def test_is_bare_pointer_takes_an_address_with_nothing_after_it(s, bare):
    assert is_bare_pointer(s) is bare


@pytest.mark.parametrize(
    "s, spoof",
    [
        (SPOOF, True),
        ("a.com@notgmail.com", True),
        ("a.com@gmail.com.evil.pro", True),
        ("name.com@gmail.com", False),
        ("name.com@GMAIL.com", False),
        ("x.org@sub.yandex.ru", False),
        ("a.ua@mail.ru", False),
    ],
)
def test_is_spoof_rejects_a_mailbox_provider_on_the_right_and_nothing_else(s, spoof):
    assert is_spoof(s) is spoof


def test_the_mailbox_providers_are_lower_case_hostnames():
    # is_spoof lower-cases the destination before it looks here
    for provider in MAILBOX_PROVIDERS:
        assert provider == provider.lower()
        assert "." in provider and "@" not in provider


@pytest.mark.parametrize(
    "token, pointer",
    [
        (HIDDEN_HOST, True),
        ("NDUuNzcuOTMuMTg=", True),  # 45.77.93.18
        (UNPADDED_IP, True),
        ("dGViaQ==", False),  # tebi
        ("2+2=", False),
        ("aGVsbG8gd29ybGQ=", False),  # hello world: printable, not a pointer
        ("internationalization", False),
        ("YztOEovieQIzZjY8", False),  # the code of a t.me invite link
    ],
)
def test_decodes_to_pointer_takes_a_token_that_hides_a_whole_pointer(token, pointer):
    assert decodes_to_pointer(token) is pointer


def test_only_a_padded_token_gets_the_xor_decoders():
    # An unpadded token looks like any long word, and there are far too many
    # of those to try every key on each: it gets plain base64 and no more.
    padded = base64.b64encode(bytes(b ^ 0x10 for b in b"s3.redarodas.com")).decode()
    unpadded = base64.b64encode(bytes(b ^ 0x10 for b in b"cdn.example.com")).decode()
    # YyM+YnV0cWJ/dHFjPnN/fQ==: the rule has to read it whole, + and / included
    assert padded.endswith("=") and "+" in padded and "/" in padded
    assert not unpadded.endswith("=")
    assert found(page_hits("Hello", body="config " + padded)) == [("encoded_pointer", padded, 1)]
    assert names(page_hits("Hello", body="config " + unpadded)) == []


def test_a_token_is_decoded_once_however_often_a_page_repeats_it():
    decodes_to_pointer.cache_clear()
    for _ in range(500):
        assert decodes_to_pointer(HIDDEN_HOST) is True
    info = decodes_to_pointer.cache_info()
    assert (info.misses, info.hits) == (1, 499)


@pytest.mark.parametrize(
    "s, public",
    [
        ("server 8.8.8.8 is up", True),
        ("192.168.1.1 then 8.8.8.8", True),
        ("192.168.1.1 then 10.0.0.1", False),
        ("no address here", False),
    ],
)
def test_has_public_ip_looks_for_one_routable_address_anywhere(s, public):
    assert has_public_ip(s) is public


@pytest.mark.parametrize(
    "s, counted",
    [
        (SECRET_TOKEN, True),
        ("PASSWORD:" + SECRET_TOKEN, True),
        ("db_passwd:" + SECRET_TOKEN, True),
        ("пароль:" + SECRET_TOKEN, True),
        ("api_hash:" + SECRET_TOKEN, True),
        ("Size:" + SECRET_TOKEN, False),
        ("user@mail.example.com:" + SECRET_TOKEN, False),
    ],
)
def test_counted_secret_counts_a_secret_alone_or_behind_a_password_label(s, counted):
    assert counted_secret(s) is counted


def test_the_secret_labels_are_the_ones_redaction_hashes_after():
    from graphwatch.redact import LABEL_AT_END_PATTERN

    for label in SECRET_LABELS:
        assert LABEL_AT_END_PATTERN.search(label + ":"), label


def test_a_file_link_closed_by_a_typographic_mark_is_still_a_file_link():
    for closer in "»”’…*“":
        assert is_executable_link("https://files.example.com/setup.exe" + closer) is True, closer


def test_a_url_that_cannot_be_read_is_not_a_file_link():
    assert is_executable_link("http://[broken/setup.exe") is False
    assert is_archive_link("http://[broken/setup.zip") is False


@pytest.mark.parametrize(
    "url,in_path",
    [
        ("https://d.example.com/l/SECRET{ab}/open", True),
        ("https://d.example.com/SECRET{ab}", True),
        ("https://d.example.com?next=/SECRET{ab}", False),
        ("https://d.example.com#/SECRET{ab}", False),
        ("https://d.example.com/page?next=/SECRET{ab}", False),
        ("http://SECRET{ab}@8.8.8.8:8080/list", False),
    ],
)
def test_has_token_in_path_looks_at_the_path_only(url, in_path):
    assert has_token_in_path(url) is in_path


# --------------------------------------------------------------------------
# the actor's two shapes flag
# --------------------------------------------------------------------------


def test_the_pointer_fixture_fires_the_pointer_rules_and_no_other():
    hits = hits_for(fixture_page("Hello-10-17-154"))
    assert names(hits) == [
        "userinfo_spoof",
        "ip_in_title",
        "storage_key_marker",
        "base64_in_title",
        "api_sample_body",
        "ip_literal",
    ]
    assert score(hits) == 17


def test_the_pointer_title_page_keeps_its_evidence_and_its_score():
    hits = page_hits(POINTER_TITLE, API_SAMPLE, API_SAMPLE)
    assert found(hits) == [
        ("userinfo_spoof", "onmedservice.com.ua@opportunizz.pro", 1),
        ("ip_in_title", "207.246.108.214", 1),
        # the marker and the hashed tokens behind it, never a raw key
        ("storage_key_marker", POINTER_TITLE[POINTER_TITLE.index("/!") :], 1),
        ("base64_in_title", "dGViaQ==", 2),
        ("api_sample_body", API_SAMPLE, 1),
        ("ip_literal", "207.246.108.214", 1),
    ]
    # The verdict reported since 14 November
    assert score(hits) == 17


def test_the_spoof_title_page_keeps_its_evidence_and_its_score():
    hits = page_hits(SPOOF_TITLE, API_SAMPLE, API_SAMPLE)
    assert found(hits) == [("userinfo_spoof", SPOOF, 1), ("api_sample_body", API_SAMPLE, 1)]
    assert score(hits) == 6


def test_the_storage_key_rule_needs_the_marker_and_something_behind_it():
    assert found(apply_rules(None, None, "x/!" + SECRET_TOKEN)) == [
        ("storage_key_marker", "/!" + SECRET_TOKEN, 1)
    ]
    assert names(apply_rules(None, None, "yes/no/! and so on")) == []
    assert names(apply_rules(None, None, "Wow!great news")) == []


# --------------------------------------------------------------------------
# userinfo_spoof: host@host where it is part of a URL
#
# Tightened on 22 November. Eight flagged pages on the full table were emails
# whose name ends like a domain (name.com@gmail.com), read as host@host. The
# shapes below are the ones counted on the sweep's own pages (night-1 copy,
# held_out = 0): all 55 actor pages have the spoof after a ?, before a /, or
# as the whole title. Held-out recall was 7/15 before and after, measured as
# a count and nothing else.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        SPOOF + "/",  # 42 of the 55 actor titles on night 1
        SPOOF,  # 13 of the 55: the spoof is the whole title
        "http://" + SPOOF,
        "207.246.108.214?" + SPOOF,  # after a ?, as in the pointer shape (27 of the 55)
        "WWW.TENABLE.COM@AGFC.HARPER18.WORKERS.DEV/",
        "www.kpi.kharkiv.edu.ua@venture-cpu-sur-everyone.trycloudflare.com",
    ],
)
def test_the_spoof_fires_in_every_shape_the_actor_uses_in_a_title(title):
    hits = page_hits(title, API_SAMPLE, API_SAMPLE)
    assert "userinfo_spoof" in names(hits)
    assert score(hits) >= THRESHOLD


@pytest.mark.parametrize(
    "body", ["open " + SPOOF + "/ in the browser", "open https://" + SPOOF + " in the browser"]
)
def test_the_spoof_fires_in_a_body_when_it_is_part_of_a_url(body):
    assert "userinfo_spoof" in names(page_hits("note", body=body))


@pytest.mark.parametrize(
    "title, body",
    [
        # the shape of the 1 false flag in 92,977 on night 1 (the address here
        # is made up; the page's own is not kept), and the shape of the eight
        ("Contacts", "example.ua@gmail.com write to us"),
        ("Contacts", "contact first.ai@company.example.com for a quote"),
        ("Contacts", "mailto:name.com@mail.example.org"),
        # the whole title, but a mailbox provider is not a destination
        ("name.com@gmail.com", "hi"),
        # opens the title and does not end it
        (SPOOF + " is down", "hi"),
        # The destination's ending is not in the list, so today the page does
        # not flag at all. What must hold is that the rule does not cut the
        # name short and report evil.net, a host this page does not name.
        ("https://www.tenable.com@evil.network/", "hi"),
    ],
)
def test_a_host_at_host_that_is_not_a_spoof_url_fires_nothing(title, body):
    assert names(page_hits(title, body=body)) == []


def test_a_spoof_alone_on_a_line_counts_only_when_that_line_is_the_title():
    assert "userinfo_spoof" in names(apply_rules(SPOOF, "", SPOOF + "\n\nbody"))
    assert "userinfo_spoof" not in names(apply_rules("t", "", "t\n\n" + SPOOF))
    assert "userinfo_spoof" not in names(apply_rules("t", "", "t\n\nline one\n" + SPOOF + "\nline three"))


def test_a_spoof_url_behind_a_link_does_not_move_the_resolver_score():
    # The resolver verdict is about what the page shows, as it always was.
    hits = apply_rules("t", "", "t\n\nclick here", links=["https://" + SPOOF_TITLE])
    assert score(hits) == 0
    assert "tunnel_host" in [h.rule.name for h in hits]  # a category rule does see it


@pytest.mark.parametrize("email", ["first-middle.last@wanadoo.fr", "first.last@icloud.com"])
def test_an_email_in_a_body_is_an_email_address_and_not_a_spoof(email):
    assert found(apply_rules(None, None, f"login {email}:{SECRET_TOKEN}")) == [
        ("email_address", email, 1)
    ]


# --------------------------------------------------------------------------
# spoof_in_title: the decoy ends in a TLD outside the list
# --------------------------------------------------------------------------


def test_spoof_in_title_catches_the_unlisted_decoy_and_the_page_flags():
    hits = page_hits(AG_TITLE, API_SAMPLE, API_SAMPLE)
    assert names(hits) == ["spoof_in_title", "api_sample_body", "email_address"]
    assert resolver(hits)[0].evidence == AG_SPOOF
    assert score(hits) == 7


@pytest.mark.parametrize(
    "title",
    [
        AG_SPOOF,  # the whole title
        AG_SPOOF + "/x",  # before a slash
        "https://" + AG_SPOOF,  # after a scheme
        "207.246.108.214?" + AG_SPOOF,  # after the ? of the pointer shape
        AG_SPOOF.upper() + "/",
        "some-site4.museum@venture-cpu-sur-everyone.trycloudflare.com",
    ],
)
def test_spoof_in_title_fires_in_the_same_three_places_whatever_the_decoy_ends_in(title):
    assert "spoof_in_title" in names(apply_rules(title, None, title))


@pytest.mark.parametrize(
    "title",
    [
        "primewire.ag@agfc.harper18.workers.zz",  # the destination needs a listed ending
        "https://primewire.ag@evil.network/",  # and is not cut short to evil.net to reach one
        # first.last@provider as a whole title: the documented false positive
        # until 22 November. A mailbox provider is not a destination
        "first.last@icloud.com",
        "see " + AG_SPOOF + " for more",
        "see " + AG_SPOOF,  # ends the title, does not open it
        AG_SPOOF + " for more",  # opens the title, does not end it
    ],
)
def test_spoof_in_title_does_not_fire_anywhere_else(title):
    hits = apply_rules(title, None, title)
    assert "spoof_in_title" not in names(hits)
    assert score(hits) < THRESHOLD


def test_spoof_in_title_leaves_listed_decoys_to_userinfo_spoof():
    # One rule per page for one spoof, so scores stay comparable.
    for title in (SPOOF_TITLE, POINTER_TITLE):
        fired = names(apply_rules(title, None, title))
        assert "userinfo_spoof" in fired
        assert "spoof_in_title" not in fired


def test_spoof_in_title_does_not_look_at_the_body():
    # In body text this shape is first.last@provider email: 80 pages on night 1.
    assert "spoof_in_title" not in names(page_hits("Netflix", body=AG_TITLE))


@pytest.mark.parametrize(
    "pattern, text, sides",
    [
        (
            TITLE_SPOOF_PATTERN,
            "some-site4.museum@agfc.harper18.workers.dev/",
            [("some-site4.museum", "agfc.harper18.workers.dev")],
        ),
        (
            USERINFO_SPOOF_PATTERN,
            "open WWW.TENABLE.COM@agfc.harper18.workers.dev now",
            [("WWW.TENABLE.COM", "agfc.harper18.workers.dev")],
        ),
        # evil.net would be an indicator for a host the page does not name
        (TITLE_SPOOF_PATTERN, "primewire.ag@evil.network", []),
        (USERINFO_SPOOF_PATTERN, "www.tenable.com@evil.network", []),
    ],
)
def test_the_patterns_the_extractor_reads_capture_the_decoy_and_the_destination(pattern, text, sides):
    assert [m.groups() for m in pattern.finditer(text)] == sides


# --------------------------------------------------------------------------
# ip_in_title and ip_literal
# --------------------------------------------------------------------------


@pytest.mark.parametrize("title", ["8.8.8.8", "http://8.8.8.8", "HTTPS://8.8.8.8/gate"])
def test_ip_in_title_fires_when_the_address_opens_the_title(title):
    assert "ip_in_title" in names(apply_rules(title, None, title))


@pytest.mark.parametrize(
    "title",
    [
        "Patch 1.12.1.5",  # Patch-10-18-2 on the full table: flagged until 22 November
        "ftp://8.8.8.8",
        "x http://8.8.8.8",
        "x https://8.8.8.8",
        "1.2.3.4.5",
        "8.8.8.1234",
        "192.168.1.1",
        " 8.8.8.8",
    ],
)
def test_ip_in_title_does_not_fire_on_anything_else(title):
    hits = apply_rules(title, None, title)
    assert "ip_in_title" not in names(hits)
    assert score(hits) < THRESHOLD


@pytest.mark.parametrize(
    "text, addresses",
    [
        ("8.8.8.8", ["8.8.8.8"]),
        ("ip=8.8.8.8", ["8.8.8.8"]),
        ("ip:8.8.8.8", ["8.8.8.8"]),
        ("user@8.8.8.8", ["8.8.8.8"]),
        ("http://8.8.8.8:53/x", ["8.8.8.8"]),
        # the documented false positive: a version number that stands alone
        ("VL700 Firmware [vli_vl700_(1.0.2.10).bin]", ["1.0.2.10"]),
        # Glued to a word or part of a longer number: version strings, 282
        # of the 1,688 benign IP matches on night 1
        ("WhatsApp v2.22.23.12 released", []),
        ("build V8.8.8.8", []),
        ("app_8.8.8.8", []),
        ("сборка8.8.8.8", []),
        ("1.2.3.4.5", []),
        ("8.8.8.1234", []),
    ],
)
def test_the_ip_pattern_takes_an_address_that_stands_alone(text, addresses):
    assert [m.group(0) for m in IP_PATTERN.finditer(text)] == addresses
    # and it is the pattern ip_literal runs: every address above is a public one
    assert ("ip_literal" in names(apply_rules(None, None, text))) is bool(addresses)


# --------------------------------------------------------------------------
# base64_in_title and encoded_pointer (#28)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title, evidence",
    [
        ("x?YQ==", "YQ=="),  # one byte: the shortest token there is
        ("2+2=4 and 2+2=", None),  # arithmetic does not decode to text
        ("dGViaQ==abc", None),  # a token ends at its padding
        (UNPADDED_IP, None),  # the unpadded pattern belongs to encoded_pointer only
    ],
)
def test_base64_in_title_needs_a_padded_token_that_decodes_to_text(title, evidence):
    by_name = {h.rule.name: h.evidence for h in apply_rules(title, None, title)}
    assert by_name.get("base64_in_title") == evidence


def test_encoded_pointer_fires_on_the_long_pointer_title():
    title = POINTER_TITLE + "?" + HIDDEN_HOST
    hits = found(page_hits(title, API_SAMPLE, API_SAMPLE))
    assert [name for name, _evidence, _matches in hits] == [
        "userinfo_spoof",
        "ip_in_title",
        "storage_key_marker",
        "base64_in_title",
        "encoded_pointer",
        "api_sample_body",
        "ip_literal",
    ]
    # Table order, not weight order: base64_in_title still comes first, and
    # still reports the first padded token
    assert hits[3:5] == [("base64_in_title", "dGViaQ==", 3), ("encoded_pointer", HIDDEN_HOST, 1)]


def test_an_encoded_pointer_alone_does_not_flag_but_with_the_api_sample_it_does():
    alone = page_hits("Hello", body="config " + HIDDEN_HOST)
    assert found(alone) == [("encoded_pointer", HIDDEN_HOST, 1)]
    assert score(alone) == 3 < THRESHOLD
    with_sample = page_hits("Hello", API_SAMPLE, HIDDEN_HOST)
    assert names(with_sample) == ["encoded_pointer", "api_sample_body"]
    assert score(with_sample) >= THRESHOLD


def test_encoded_pointer_fires_on_an_unpadded_token():
    # Also the title: base64_in_title does not take a token without padding
    hits = apply_rules(UNPADDED_IP, "", UNPADDED_IP + "\n\nconfig " + UNPADDED_IP)
    assert found(hits) == [("encoded_pointer", UNPADDED_IP, 2)]


def test_encoded_pointer_ignores_long_words_and_base64_that_hides_ordinary_text():
    body = "internationalization of t.me/+YztOEovieQIzZjY8 abcdefghijkl secret: aGVsbG8gd29ybGQ="
    assert "encoded_pointer" not in names(page_hits("Hello", body=body))


@pytest.mark.parametrize("run", ["a" * 12, "ab+/" * 5])
def test_unpadded_pattern_matches_whole_runs_in_groups_of_four(run):
    assert UNPADDED_BASE64_PATTERN.fullmatch(run)
    assert [m.group(0) for m in UNPADDED_BASE64_PATTERN.finditer(f"x {run} y")] == [run]


@pytest.mark.parametrize("run", ["a" * 8, "a" * 13, "A" * 13, "7" * 13, "+" * 13, "/" * 13])
def test_unpadded_pattern_ignores_short_runs_and_never_reads_part_of_a_run(run):
    # A run of 13 holds a run of 12 from either end. Reading it would offer
    # the decoders every window of a long blob instead of the blob once.
    assert UNPADDED_BASE64_PATTERN.findall(f"x {run} y") == []


def test_unpadded_pattern_leaves_padded_tokens_to_the_padded_pattern():
    assert UNPADDED_BASE64_PATTERN.findall(HIDDEN_HOST) == []
    assert ENCODED_TOKEN_PATTERN.findall(HIDDEN_HOST) == [HIDDEN_HOST]
    assert ENCODED_TOKEN_PATTERN.findall(f"{HIDDEN_HOST} {UNPADDED_IP}") == [
        HIDDEN_HOST,
        UNPADDED_IP,
    ]


def test_a_page_packed_with_one_padded_token_is_quick(laptop_seconds):
    decodes_to_pointer.cache_clear()
    text = "t\n\n" + (HIDDEN_HOST + " ") * 2500
    assert laptop_seconds(lambda: apply_rules("t", "", text)) < 1.0
    assert "encoded_pointer" in names(apply_rules("t", "", text))


# --------------------------------------------------------------------------
# api_sample_body, email_address, telegram_link, and pages that fire nothing
# --------------------------------------------------------------------------


def test_an_api_sample_page_without_a_pointer_scores_one():
    hits = page_hits("Hello", API_SAMPLE, API_SAMPLE)
    assert names(hits) == ["api_sample_body"]
    assert score(hits) == 1


@pytest.mark.parametrize("description", [API_SAMPLE + " and more", "say " + API_SAMPLE])
def test_the_api_sample_has_to_be_the_whole_description(description):
    assert names(page_hits("Hello", description, description)) == []


@pytest.mark.parametrize(
    "text,addresses",
    [
        ("mail bob@gmail.com now", ["bob@gmail.com"]),
        ("BOB@EXAMPLE.COM", ["BOB@EXAMPLE.COM"]),
        ("a+b@x.io and c@y.io", ["a+b@x.io", "c@y.io"]),
        ("+bob@x.io", ["+bob@x.io"]),
        ("x@bob@x.io", []),
        ("write to @example.com", []),
        ("bob@example.comet", []),
        # A run with a plus in it that itself follows an @ used to give
        # b@x.io. Not an address anyone writes; recorded so it is no surprise.
        (" b1@+b@x.io", []),
    ],
)
def test_the_email_pattern_finds_ordinary_addresses(text, addresses):
    assert [m.group(0) for m in EMAIL_PATTERN.finditer(text)] == addresses


def test_a_telegram_link_and_a_handle_take_a_point_off():
    hits = apply_rules("Proxy", None, "join https://t.me/+YztOEovieQIzZjY8 or @SLlV_INTIM_BOT")
    assert [(h.rule.name, h.matches) for h in resolver(hits)] == [("telegram_link", 2)]
    assert score(hits) == -1


@pytest.mark.parametrize(
    "text, fires",
    [
        ("T.ME/SOMENEWS", True),
        ("telegram.me/somenews", True),
        ("@abcde", True),  # five characters, the shortest username
        ("@abcd", False),
        ("@" + "a" * 32, True),  # and 32, the longest
        ("@" + "a" * 33, False),
        ("Firstnamelastname@gmail.com", False),  # the domain of an email
        (SPOOF_TITLE, False),  # the destination of a spoof
    ],
)
def test_telegram_link_takes_a_link_or_a_handle_of_five_to_32_characters(text, fires):
    assert ("telegram_link" in names(apply_rules(None, None, text))) is fires


@pytest.mark.parametrize("name", ["Hello-10-17-5", "Test-10-16"])
def test_a_benign_fixture_fires_nothing(name):
    assert hits_for(fixture_page(name)) == []


# --------------------------------------------------------------------------
# apply_rules mechanics
# --------------------------------------------------------------------------


def test_apply_rules_tolerates_none_fields():
    assert apply_rules(None, None, None) == []


def test_a_rule_fires_once_counts_every_match_and_keeps_the_first_as_evidence():
    hits = apply_rules("8.8.8.8 9.9.9.9", None, "1.1.1.1 and 8.8.8.8 and 9.9.9.9")
    # Only the address that opens the title counts for ip_in_title.
    assert found(hits) == [("ip_in_title", "8.8.8.8", 1), ("ip_literal", "1.1.1.1", 3)]


def test_matches_counts_only_what_the_check_accepted():
    # Two private addresses and one public one: one match, and it is the evidence.
    hits = apply_rules(None, None, "192.168.1.1 10.0.0.1 8.8.8.8")
    assert found(hits) == [("ip_literal", "8.8.8.8", 1)]


def test_matches_counts_repeats_of_the_same_string():
    link = "https://t.me/+YztOEovieQIzZjY8"
    hits = apply_rules(None, None, f"{link} ads {link} {link}")
    assert found(hits) == [("telegram_link", "t.me/", 3)]


def test_score_is_the_sum_of_the_resolver_weights_however_often_a_rule_matched():
    other = custom("other", 4, category="pointer")
    hits = [Hit(rule("ip_in_title"), "x", 7), Hit(rule("telegram_link"), "y"), Hit(other, "z")]
    assert score(hits) == 4 - 1
    assert score([Hit(other, "z")]) == 0
    assert score([]) == 0


def test_min_matches_holds_a_rule_back_until_enough_matches_pass_the_check():
    r = custom(pattern=r"\d+", check=lambda s: int(s) > 5, min_matches=2)
    assert apply_rules(None, None, "1 2 3 9", rules=(r,)) == []
    hits = apply_rules(None, None, "1 8 3 9", rules=(r,))
    assert [(h.evidence, h.matches) for h in hits] == [("8", 2)]


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


def test_a_gate_skips_the_regex_unless_the_lower_cased_field_holds_it():
    pattern = CountingPattern(r"WARNING_BANNER")
    r = Rule("r", 1, "text", pattern, "test rule", gate="warning_banner")
    assert apply_rules(None, None, "no banner here", rules=(r,)) == []
    assert pattern.runs == 0
    hits = apply_rules(None, None, "a WARNING_BANNER here", rules=(r,))
    assert pattern.runs == 1
    assert [h.evidence for h in hits] == ["WARNING_BANNER"]


def test_gate_looks_at_the_rules_own_field():
    r = custom(where="title", pattern=r"https?://\S+", gate="://")
    assert apply_rules("plain title", None, "body https://example.com", rules=(r,)) == []
    # and a second field is not judged by the first one's lower-cased copy
    in_body = custom(where="body", pattern=r"needle", gate="needle")
    assert len(apply_rules("https://x", "", "https://x\n\nneedle", rules=(r, in_body))) == 2


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
    # Letters that fold oddly. re.IGNORECASE matches them against ASCII ones
    # and str.lower() does not turn them into ASCII, so a gate would skip a
    # rule that its pattern matched. The gated patterns fold ASCII only.
    "API_ID and APİ_HASH",  # dotted capital I
    "t.me/proxy?ſerver=8.8.8.8",  # long s
    "abcdefghijklmnop.onıon",  # dotless i
    "<İnput type=password>",
]


@pytest.mark.parametrize("text", GATE_CORPUS)
def test_a_gate_never_changes_a_result(text):
    # Every gate has to be text that every match of its pattern contains, so
    # the table with its gates removed must give exactly the same hits.
    ungated = tuple(dataclasses.replace(r, gate=None) for r in RULES)
    with_gates = [(h.rule.name, h.evidence, h.matches) for h in page_hits("t", body=text)]
    without = [
        (h.rule.name, h.evidence, h.matches) for h in page_hits("t", body=text, rules=ungated)
    ]
    assert with_gates == without


def test_the_gate_corpus_exercises_every_gated_rule():
    fired = set()
    for text in GATE_CORPUS:
        fired |= {h.rule.name for h in page_hits("t", body=text)}
    gated = {r.name for r in RULES if r.gate is not None}
    assert gated <= fired, gated - fired


# --- the body field, and the page field: the text and the link targets behind it ---


def test_a_body_rule_reads_the_text_without_its_title_and_description():
    r = custom(where="body", pattern=r"needle")
    assert apply_rules("needle", "needle", "needle\nneedle\nhay", rules=(r,)) == []
    assert len(apply_rules("t", "d", "t\nd\nneedle", rules=(r,))) == 1
    # and all of the text when it does not start with them
    assert len(apply_rules("other", None, "needle", rules=(r,))) == 1


def test_the_body_field_is_stripped_so_a_whole_body_rule_can_anchor():
    r = custom(where="body", pattern=r"\A\S+\Z")
    hits = apply_rules("t", "d", "t\nd\n  one-token\n\n", rules=(r,))
    assert [h.evidence for h in hits] == ["one-token"]
    assert apply_rules("t", "d", "t\nd\ntwo tokens\n", rules=(r,)) == []


def test_a_page_rule_reads_the_text_and_the_link_targets_one_to_a_line():
    r = custom(where="page", pattern=r"https?://\S+")
    links = ["https://b.example.com/1", "https://c.example.com/2"]
    hits = page_hits("https://t.example.com", body="see https://a.example.com", rules=(r,), links=links)
    # the title, the body and both targets: no two were joined into one URL
    assert [(h.evidence, h.matches) for h in hits] == [("https://t.example.com", 4)]
    # and each target is a line of its own
    whole_line = custom(where="page", pattern=r"(?m)^https://[bc]\.example\.com/\d$")
    assert [h.matches for h in page_hits("t", body="x", rules=(whole_line,), links=links)] == [2]


def test_no_other_field_sees_a_link_target():
    for where in ("text", "body", "title", "description"):
        r = custom(where=where, pattern=r"hidden\.example\.com")
        assert apply_rules("t", "d", "t\nd\nclick here", rules=(r,), links=["https://hidden.example.com/"]) == []


# --- category_scores, labels_for, primary_label ---


def test_category_scores_sums_weights_per_category_in_category_order():
    hits = [
        Hit(custom("a", 3, category="seo_spam"), "x"),
        Hit(custom("b", 4, category="pointer"), "x"),
        Hit(custom("c", -4, category="pointer"), "x"),
        Hit(custom("d", 5), "x"),
    ]
    scores = category_scores(hits)
    # A category whose weights cancel is there with a 0
    assert scores == {"resolver": 5, "pointer": 0, "seo_spam": 3}
    assert list(scores) == ["resolver", "pointer", "seo_spam"]
    assert category_scores([]) == {}


def test_labels_for_is_every_category_at_or_above_the_threshold_in_category_order():
    scores = {"prose": 4, "seo_spam": 7, "resolver": 3, "pointer": 4, "doxx": -1}
    assert labels_for(scores) == ["pointer", "seo_spam", "prose"]
    assert labels_for({"resolver": 3}, threshold=3) == ["resolver"]
    # a category with no score is not a label, however low the threshold
    assert labels_for({"resolver": 3}, threshold=1) == ["resolver"]


def test_primary_label_is_the_first_label_in_category_order():
    assert primary_label(["prose", "seo_spam", "pointer"]) == "pointer"
    assert primary_label(["placeholder", "resolver"]) == "resolver"
    assert primary_label([]) is None


# --------------------------------------------------------------------------
# render_table and render_categories
# --------------------------------------------------------------------------

RENDERED = (
    Rule("many", 3, "body", re.compile(r"\d"), "Why three", check=is_public_ip, min_matches=2, category="prose"),
    Rule("alt", 2, "text", re.compile(r"a|b"), "Why one"),
    Rule("gone", -1, "computed", None, "Why two"),
)


def test_render_table_is_a_markdown_row_per_rule():
    assert render_table(RENDERED) == (
        "| Rule | Weight | Where | Pattern | Exists for: |\n"
        "|---|---|---|---|---|\n"
        "| `many` | +3 | body | `\\d` at least 2 times + `is_public_ip` | Why three |\n"
        # the pipe is escaped so it does not split the row
        "| `alt` | +2 | text | `a\\|b` | Why one |\n"
        "| `gone` | -1 | computed | computed | Why two |\n"
    )


def test_render_table_abbreviates_the_tld_list():
    row = next(l for l in render_table().splitlines() if "`userinfo_spoof`" in l)
    assert "TLD" in row
    assert "com\\|net" not in row


def test_render_categories_is_a_section_per_category_that_has_rules_in_category_order():
    assert render_categories(RENDERED) == (
        "## `resolver` (intelligence)\n\n"
        + render_table(RENDERED[1:])
        + "\n## `prose` (noise)\n\n"
        + render_table(RENDERED[:1])
    )


def test_module_prints_the_table_when_run():
    out = subprocess.run(
        [sys.executable, "-m", "graphwatch.rules"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out == render_categories()
    for r in RULES:
        assert out.count(f"| `{r.name}` |") == 1, r.name
    # and one line: a description with a line break in it would split its row
    assert len(render_table().splitlines()) == 2 + len(RULES)


# --------------------------------------------------------------------------
# no rule may take seconds on one page
# --------------------------------------------------------------------------

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
    # + is a local-part character and was not in the email pattern's
    # lookbehind, so the pattern started again inside the run (second review
    # of 22 November)
    "plus signs": "a+" * 30000,
}


@pytest.mark.parametrize("name", sorted(LONG_RUNS))
def test_no_rule_is_slow_on_a_long_unbroken_run(name, laptop_seconds):
    # A page is up to 64 KB and whoever posts it chooses the text. A pattern
    # that restarts from every character of a long run takes seconds on one
    # page; these finish in milliseconds.
    text = LONG_RUNS[name]
    for r in RULES:
        if r.pattern is None:
            continue
        assert laptop_seconds(lambda: list(r.pattern.finditer(text))) < 1.0, (r.name, name)
