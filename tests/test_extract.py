"""Tests for graphwatch.extract, the extractor (issue #27).

Inputs are the actor's non-held-out Hello shapes and synthetic strings.
Nothing here reads a held-out page from known.txt.
"""

import base64
import json
from pathlib import Path

import pytest

from graphwatch.extract import KINDS, Indicator, extract, pointer_kind
from graphwatch.telegraph import page_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plan" / "fixtures"

POINTER_TITLE = (
    "207.246.108.214?onmedservice.com.ua@opportunizz.pro/!SECRET{"
    + "0" * 64
    + "}?SECRET{"
    + "1" * 64
    + "}?dGViaQ==?eWVsNA==?czMucmVkYXJvZGFzLmNvbQ=="
)
SPOOF_TITLE = "www.tenable.com@agfc.harper18.workers.dev/"


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def body(text: str) -> list[Indicator]:
    """Indicators from a page whose title is empty and whose text is `text`."""
    return extract("", text)


def pairs(indicators) -> list[tuple[str, str]]:
    return [(i.kind, i.value) for i in indicators]


def of_kind(indicators, kind: str) -> list[str]:
    return [i.value for i in indicators if i.kind == kind]


# --------------------------------------------------------------------------
# the record
# --------------------------------------------------------------------------


def test_kinds_are_the_five_planned():
    assert {"ip", "host", "url", "decoy", "token"} == KINDS


def test_indicator_is_a_frozen_record():
    indicator = Indicator("ip", "8.8.8.8", "title")
    with pytest.raises(AttributeError):
        indicator.value = "1.1.1.1"


def test_every_extracted_kind_is_a_known_kind():
    found = extract(POINTER_TITLE, POINTER_TITLE + "\nd\nhttp://a.com/x deadbeef" * 2)
    assert {i.kind for i in found} <= KINDS


# --------------------------------------------------------------------------
# the actor's shapes
# --------------------------------------------------------------------------


def test_pointer_title_gives_the_ip_the_front_and_the_decoy():
    found = extract(POINTER_TITLE, POINTER_TITLE + "\nHello,+world!\nHello,+world!")
    assert of_kind(found, "ip") == ["207.246.108.214"]
    assert of_kind(found, "decoy") == ["onmedservice.com.ua"]
    assert "opportunizz.pro" in of_kind(found, "host")


def test_pointer_title_decodes_the_hidden_host():
    found = extract(POINTER_TITLE, POINTER_TITLE)
    hidden = [i for i in found if i.value == "s3.redarodas.com"]
    assert hidden == [Indicator("host", "s3.redarodas.com", "title:base64")]


def test_pointer_title_keeps_the_undecodable_fields_as_tokens():
    found = extract(POINTER_TITLE, POINTER_TITLE)
    assert of_kind(found, "token") == [
        "dGViaQ==",
        "eWVsNA==",
        "czMucmVkYXJvZGFzLmNvbQ==",
    ]


def test_pointer_fixture_extracts_a_public_ip_and_a_front_host():
    page = fixture_page("Hello-10-17-154")
    found = extract(page["title"], page_text(page))
    assert len(of_kind(found, "ip")) == 1
    assert len(of_kind(found, "decoy")) == 1
    assert len(of_kind(found, "host")) >= 1
    assert all(i.source.startswith("title") for i in found)


def test_spoof_url_right_side_is_the_indicator_and_left_side_the_decoy():
    found = extract(SPOOF_TITLE, SPOOF_TITLE + "\nHello,+world!\nHello,+world!")
    assert pairs(found) == [
        ("decoy", "www.tenable.com"),
        ("host", "agfc.harper18.workers.dev"),
    ]


def test_a_decoy_is_never_reported_as_a_host_anywhere_on_the_page():
    # The bait host repeated in the body must not reach enrichment as a C2.
    found = extract(SPOOF_TITLE, SPOOF_TITLE + "\n\nvisit www.tenable.com today")
    assert "www.tenable.com" not in of_kind(found, "host")
    assert of_kind(found, "decoy") == ["www.tenable.com"]


AG_TITLE = "primewire.ag@agfc.harper18.workers.dev/"


def test_a_title_spoof_with_an_unlisted_decoy_still_gives_the_front_host():
    # Without this the front host never reaches enrichment: it follows an @,
    # so the bare-hostname scan skips it as an email's domain.
    found = extract(AG_TITLE, AG_TITLE + "\nHello,+world!\nHello,+world!")
    assert found == [
        Indicator("decoy", "primewire.ag", "title"),
        Indicator("host", "agfc.harper18.workers.dev", "title"),
    ]


def test_the_looser_spoof_pattern_is_not_used_on_body_text():
    found = extract("Netflix", "Netflix\n\nlogin solano.elsa@icloud.com today")
    assert found == []


def test_spoof_hosts_are_lowercased():
    found = extract("WWW.TENABLE.COM@AGFC.HARPER18.WORKERS.DEV/", "")
    assert pairs(found) == [
        ("decoy", "www.tenable.com"),
        ("host", "agfc.harper18.workers.dev"),
    ]


def test_a_spoof_inside_a_url_keeps_the_whole_url_too():
    found = body("open http://www.tenable.com@agfc.harper18.workers.dev/a/b now")
    assert pairs(found) == [
        ("decoy", "www.tenable.com"),
        ("host", "agfc.harper18.workers.dev"),
        ("url", "http://www.tenable.com@agfc.harper18.workers.dev/a/b"),
    ]


# --------------------------------------------------------------------------
# IPs, hosts, URLs
# --------------------------------------------------------------------------


def test_public_ips_are_extracted_and_private_ones_are_not():
    found = body("proxy 8.8.8.8 lan 192.168.1.1 and 10.0.0.1 and 0.0.0.0")
    assert pairs(found) == [("ip", "8.8.8.8")]


def test_an_ip_with_a_port_is_the_ip():
    assert pairs(body("connect 45.77.93.187:8443")) == [("ip", "45.77.93.187")]


def test_a_longer_dotted_number_is_not_an_ip():
    assert body("build 1.2.3.4.5") == []


def test_bare_hostnames_are_extracted_lowercased():
    assert pairs(body("see Example.COM and sub.example.org.")) == [
        ("host", "example.com"),
        ("host", "sub.example.org"),
    ]


def test_a_word_with_an_unknown_ending_is_not_a_host():
    assert body("read notes.txt and setup.py and solano.elsa") == []


def test_an_email_gives_no_host():
    # The domain of an address is where mail goes, not a pointer.
    assert of_kind(body("write to bob@gmail.com or first.last@icloud.com"), "host") == []


def test_urls_are_extracted_whole():
    found = body("get https://example.com/a/b?c=d&e=f here")
    assert pairs(found) == [("url", "https://example.com/a/b?c=d&e=f")]


def test_a_url_does_not_also_report_its_host_or_ip():
    found = body("http://example.com/x and http://8.8.8.8/y")
    assert pairs(found) == [("url", "http://example.com/x"), ("url", "http://8.8.8.8/y")]


def test_sentence_punctuation_after_a_url_is_dropped():
    assert pairs(body("go to http://example.com/x.")) == [("url", "http://example.com/x")]
    assert pairs(body("(see http://example.com/x)")) == [("url", "http://example.com/x")]


def test_a_url_to_a_private_address_or_unknown_host_is_not_an_indicator():
    assert body("http://192.168.1.1/admin http://localhost:8000/ http://intranet/x") == []


# --------------------------------------------------------------------------
# tokens and the decoders
# --------------------------------------------------------------------------


def test_a_padded_base64_token_is_kept_even_when_it_decodes_to_nothing_useful():
    assert pairs(body("key dGViaQ== end")) == [("token", "dGViaQ==")]


def test_a_base64_token_that_hides_an_ip_yields_the_ip():
    token = base64.b64encode(b"45.77.93.18").decode()
    assert token.endswith("=")
    found = body(f"x {token} y")
    assert found == [
        Indicator("token", token, "text"),
        Indicator("ip", "45.77.93.18", "text:base64"),
    ]


def test_an_unpadded_base64_token_that_hides_an_ip_yields_the_ip():
    token = base64.b64encode(b"45.77.93.187").decode()
    assert not token.endswith("=")
    assert body(f"x {token} y") == [
        Indicator("token", token, "text"),
        Indicator("ip", "45.77.93.187", "text:base64"),
    ]


def test_long_ordinary_words_are_not_tokens():
    # Unpadded runs are everywhere; only one that decodes to a pointer is kept.
    assert body("internationalization abcdefghijkl YztOEovieQIzZjY8") == []


def test_an_unpadded_token_is_not_tried_with_xor():
    hidden = bytes(b ^ 0x5A for b in b"cdn.example.com")
    token = base64.b64encode(hidden).decode()
    assert not token.endswith("=")
    assert body(f"x {token} y") == []


def test_a_version_string_is_not_an_ip():
    assert body("WhatsApp v2.22.23.12 and build_8.8.8.8") == []


def test_a_long_hex_run_is_a_token_and_is_decoded():
    token = b"s3.redarodas.com".hex()
    found = body(f"cfg {token} end")
    assert pairs(found) == [("token", token), ("host", "s3.redarodas.com")]
    assert found[1].source == "text:hex"


def test_a_short_hex_run_is_not_a_token():
    assert body("color deadbeef") == []


def test_a_decoded_url_is_a_url():
    token = base64.b64encode(b"http://s3.redarodas.com/a").decode()
    assert token.endswith("=")
    found = body(token)
    assert ("url", "http://s3.redarodas.com/a") in pairs(found)


def test_hashed_secrets_are_never_tokens():
    # 64 hex characters inside SECRET{...} would otherwise go to the hex decoder.
    found = body("pw SECRET{" + "ab" * 32 + "} and /!SECRET{" + "cd" * 32 + "}")
    assert found == []


# --------------------------------------------------------------------------
# order, repeats, sources
# --------------------------------------------------------------------------


def test_an_indicator_in_title_and_text_is_reported_once_from_the_title():
    found = extract("8.8.8.8", "8.8.8.8\n\nagain 8.8.8.8 and 1.1.1.1")
    assert found == [
        Indicator("ip", "8.8.8.8", "title"),
        Indicator("ip", "1.1.1.1", "text"),
    ]


def test_repeats_inside_one_field_are_reported_once():
    assert pairs(body("8.8.8.8 8.8.8.8 example.com EXAMPLE.com")) == [
        ("ip", "8.8.8.8"),
        ("host", "example.com"),
    ]


def test_extract_tolerates_none_and_empty():
    assert extract(None, None) == []
    assert extract("", "") == []


def test_benign_fixtures_give_no_pointer_from_the_decoders():
    for name in ("Hello-10-17-5", "Test-10-16"):
        page = fixture_page(name)
        found = extract(page["title"], page_text(page))
        assert not any(":" in i.source for i in found), name


# --------------------------------------------------------------------------
# pointer_kind
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pointer, kind",
    [
        ("45.77.93.187", "ip"),
        ("45.77.93.187:8443", "ip"),
        ("s3.redarodas.com", "host"),
        ("s3.redarodas.com:443", "host"),
        ("http://s3.redarodas.com/", "url"),
        ("HTTPS://45.77.93.187/", "url"),
    ],
)
def test_pointer_kind(pointer, kind):
    assert pointer_kind(pointer) == kind
