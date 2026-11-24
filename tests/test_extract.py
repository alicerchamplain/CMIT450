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
AG_TITLE = "primewire.ag@agfc.harper18.workers.dev/"
HEX_HOST = b"s3.redarodas.com".hex()


def fixture_page(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))["result"]


def body(text: str) -> list[Indicator]:
    """Indicators from a page whose title is empty and whose text is `text`."""
    return extract("", text)


def pairs(indicators) -> list[tuple[str, str]]:
    return [(i.kind, i.value) for i in indicators]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# --------------------------------------------------------------------------
# the record
# --------------------------------------------------------------------------


def test_indicator_is_a_frozen_record():
    indicator = Indicator("ip", "8.8.8.8", "title")
    with pytest.raises(AttributeError):
        indicator.value = "1.1.1.1"


def test_one_page_can_give_all_five_kinds_and_there_is_no_sixth():
    found = extract(POINTER_TITLE, POINTER_TITLE + "\nd\nhttp://a.com/x")
    assert {i.kind for i in found} == KINDS == {"ip", "host", "url", "decoy", "token"}


# --------------------------------------------------------------------------
# the actor's shapes
# --------------------------------------------------------------------------


def test_pointer_title_gives_the_decoy_the_front_the_ip_the_tokens_and_the_hidden_host():
    # The two hashed fields give nothing: 64 hex digits would otherwise be tokens.
    found = extract(POINTER_TITLE, POINTER_TITLE + "\nHello,+world!\nHello,+world!")
    assert found == [
        Indicator("decoy", "onmedservice.com.ua", "title"),
        Indicator("host", "opportunizz.pro", "title"),
        Indicator("ip", "207.246.108.214", "title"),
        Indicator("token", "dGViaQ==", "title"),
        Indicator("token", "eWVsNA==", "title"),
        Indicator("token", "czMucmVkYXJvZGFzLmNvbQ==", "title"),
        Indicator("host", "s3.redarodas.com", "title:base64"),
    ]


def test_pointer_fixture_gives_a_decoy_a_front_an_ip_and_two_tokens_all_from_the_title():
    page = fixture_page("Hello-10-17-154")
    found = extract(page["title"], page_text(page))
    assert [(i.kind, i.source) for i in found] == [
        ("decoy", "title"),
        ("host", "title"),
        ("ip", "title"),
        ("token", "title"),
        ("token", "title"),
    ]


@pytest.mark.parametrize("title", [SPOOF_TITLE, SPOOF_TITLE.upper()])
def test_spoof_url_right_side_is_the_indicator_and_left_side_the_decoy_both_lowercased(title):
    # From the title, whatever its case: the text repeats it and comes second
    found = extract(title, title + "\nHello,+world!\nHello,+world!")
    assert found == [
        Indicator("decoy", "www.tenable.com", "title"),
        Indicator("host", "agfc.harper18.workers.dev", "title"),
    ]


@pytest.mark.parametrize(
    "title, text, expected",
    [
        (
            SPOOF_TITLE.upper(),
            SPOOF_TITLE.upper() + "\n\nvisit www.tenable.com today",
            [("decoy", "www.tenable.com"), ("host", "agfc.harper18.workers.dev")],
        ),
        (
            # The bait is named before the spoof that makes it bait
            "",
            "www.tenable.com is at http://www.tenable.com@agfc.harper18.workers.dev/a",
            [
                ("decoy", "www.tenable.com"),
                ("host", "agfc.harper18.workers.dev"),
                ("url", "http://www.tenable.com@agfc.harper18.workers.dev/a"),
            ],
        ),
    ],
)
def test_a_decoy_is_never_reported_as_a_host_anywhere_on_the_page(title, text, expected):
    # The bait host repeated in the body must not reach enrichment as a C2.
    assert pairs(extract(title, text)) == expected


def test_a_title_spoof_with_an_unlisted_decoy_still_gives_the_front_host():
    # Without this the front host never reaches enrichment: it follows an @,
    # so the bare-hostname scan skips it as an email's domain.
    found = extract(AG_TITLE, AG_TITLE + "\nHello,+world!\nHello,+world!")
    assert found == [
        Indicator("decoy", "primewire.ag", "title"),
        Indicator("host", "agfc.harper18.workers.dev", "title"),
    ]


def test_the_looser_spoof_pattern_is_not_used_on_body_text():
    found = extract("Netflix", "Netflix\n\nlogin first.last@icloud.com today")
    assert found == []


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


@pytest.mark.parametrize("text", ["build 1.2.3.4.5", "WhatsApp v2.22.23.12", "build_8.8.8.8"])
def test_a_longer_dotted_number_or_a_version_string_is_not_an_ip(text):
    assert body(text) == []


def test_bare_hostnames_are_extracted_lowercased():
    assert pairs(body("see Example.COM and sub.example.org.")) == [
        ("host", "example.com"),
        ("host", "sub.example.org"),
    ]


@pytest.mark.parametrize(
    "text",
    [
        "read notes.txt and setup.py and first.last",  # no known ending
        "see photo.jpg",  # .jp is known, .jpg is not
        "node cdn.us-east-1",  # the name goes on after .us
        # The domain of an address is where mail goes, not a pointer
        "write to bob@gmail.com or first.last@icloud.com",
        "write to bob@my-mail.com",
        # nor is a local part that ends like a domain. The provider ends in
        # .kg, outside the TLD list, so this row is about the host scan alone:
        # with a listed provider on the right (ivan.pro@gmail.com) the spoof
        # pattern takes the address for decoy@host today, and no row here
        # says whether it should
        "write to ivan.pro@yandex.kg",
    ],
)
def test_a_file_name_a_longer_name_or_an_email_gives_no_host(text):
    assert body(text) == []


@pytest.mark.parametrize(
    "text, url",
    [
        ("get https://example.com/a/b?c=d&e=f here", "https://example.com/a/b?c=d&e=f"),
        ("get HTTP://Example.com/x here", "HTTP://Example.com/x"),  # kept as written
        ('"url": "http://example.com/x"', "http://example.com/x"),
        ("url = 'http://example.com/x'", "http://example.com/x"),
        ("<http://example.com/x>", "http://example.com/x"),
        ("http://example.com/x<br>", "http://example.com/x"),
        # every character of URL_TRAILING: sentence punctuation, not the URL's
        ("was it http://example.com/x.,;:!?)]} or not", "http://example.com/x"),
    ],
)
def test_a_url_is_extracted_whole_and_ends_at_a_space_a_quote_a_bracket_or_the_sentence(text, url):
    assert pairs(body(text)) == [("url", url)]


def test_a_url_does_not_also_report_its_host_or_ip():
    found = body("http://example.com/x and http://8.8.8.8/y")
    assert pairs(found) == [("url", "http://example.com/x"), ("url", "http://8.8.8.8/y")]


def test_an_address_behind_another_scheme_is_no_url_but_still_an_ip_or_a_host():
    found = body("tcp://45.77.93.187:8443 or ftp://files.example.com/x")
    assert pairs(found) == [("ip", "45.77.93.187"), ("host", "files.example.com")]


def test_a_url_to_a_private_address_or_unknown_host_is_not_an_indicator():
    assert body("http://192.168.1.1/admin http://localhost:8000/ http://intranet/x") == []


# --------------------------------------------------------------------------
# tokens and the decoders
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token, pointer",
    [
        (b64(b"45.77.93.18"), Indicator("ip", "45.77.93.18", "text:base64")),  # ends in =
        (b64(b"45.77.93.187"), Indicator("ip", "45.77.93.187", "text:base64")),  # no padding
        (
            b64(b"http://s3.redarodas.com/a"),
            Indicator("url", "http://s3.redarodas.com/a", "text:base64"),
        ),
        (HEX_HOST, Indicator("host", "s3.redarodas.com", "text:hex")),
        (HEX_HOST.upper(), Indicator("host", "s3.redarodas.com", "text:hex")),
        (b"ab.cd.ru".hex(), Indicator("host", "ab.cd.ru", "text:hex")),  # eight pairs: the fewest
    ],
)
def test_a_token_that_hides_a_pointer_yields_the_token_and_then_the_pointer(token, pointer):
    assert body(f"x {token} y") == [Indicator("token", token, "text"), pointer]


def test_long_ordinary_words_are_not_tokens():
    # Unpadded runs are everywhere; only one that decodes to a pointer is kept.
    assert body("internationalization abcdefghijkl YztOEovieQIzZjY8") == []


def test_an_unpadded_token_is_not_tried_with_xor():
    hidden = bytes(b ^ 0x5A for b in b"cdn.example.com")
    token = b64(hidden)
    assert not token.endswith("=")
    assert body(f"x {token} y") == []


@pytest.mark.parametrize(
    "text",
    [
        b"a.cd.ru".hex(),  # seven pairs: one too few
        f"0{HEX_HOST}",  # an odd number of digits is not pairs
        # inside a longer word
        f"g{HEX_HOST}",
        f"G{HEX_HOST}",
        f"{HEX_HOST}g",
        f"{HEX_HOST}G",
    ],
)
def test_a_hex_run_that_is_short_odd_or_inside_a_longer_word_is_not_a_token(text):
    assert body(f"cfg {text} end") == []


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
        ("s3.redarodas.com:443", "host"),
        ("http://s3.redarodas.com/", "url"),
        ("HTTPS://45.77.93.187/", "url"),
    ],
)
def test_pointer_kind(pointer, kind):
    assert pointer_kind(pointer) == kind


# --------------------------------------------------------------------------
# the front of a longer name that ends at an @ (23 November)
# --------------------------------------------------------------------------

# A decoy on an ending the TLD list does not hold. The addresses are made up.
UNLISTED_DECOY_TITLE = "example.com.ph@agfc.harper18.workers.dev/"


def test_the_front_of_a_decoy_on_an_unlisted_ending_is_not_a_host():
    # The stored text opens with a copy of the title. The title pass takes
    # the whole decoy; the text pass must not cut "example.com" out of it.
    text = UNLISTED_DECOY_TITLE + "\n\nHello,+world!"
    assert pairs(extract(UNLISTED_DECOY_TITLE, text)) == [
        ("decoy", "example.com.ph"),
        ("host", "agfc.harper18.workers.dev"),
    ]
    # With no title to say it is a decoy, it is still not the name on the
    # page. Nothing else is reported either: in text the right side of an @
    # is an email's domain more often than a destination, as before.
    for alone in (
        "example.com.ph@agfc.harper18.workers.dev/",
        "see example.com.ph@agfc.harper18.workers.dev now",
        "shop.example.co.zw@agfc.harper18.workers.dev",
        "a.example.com.x1.y2.zz@agfc.harper18.workers.dev",
    ):
        assert pairs(body(alone)) == [], alone


@pytest.mark.parametrize(
    "text,hosts",
    [
        ("c2.example.org", ["c2.example.org"]),
        ("visit c2.example.org. Then wait", ["c2.example.org"]),
        ("c2.example.org.", ["c2.example.org"]),
        ("c2.example.org and files.example.net", ["c2.example.org", "files.example.net"]),
        # an @ further on, after something that is not part of the name
        ("c2.example.org, mail me@example.net", ["c2.example.org"]),
        # a host with a path, a port or a bracket after it
        ("c2.example.org/gate.php", ["c2.example.org"]),
        ("(c2.example.org)", ["c2.example.org"]),
        # an ending of two labels that the list holds is the whole name
        ("files.example.com.ua", ["files.example.com.ua"]),
        # A name on an ending the list does not hold. Its front is another
        # server, which is not on the page: until 24 November it was reported,
        # looked up, and came back novel.
        ("c2.example.org.zz", []),
        ("c2.example.com.ph is down", []),
        ("Resolver: c2.example.com.ph", []),
        ("shop.example.co.za", []),
        ("see c2.example.com.ph.", []),
        # and a decoy of more labels than the look ahead for an @ counts, or in capitals
        ("paypal.com.secure.login.account.verify.id@agfc.harper18.workers.dev", []),
        ("GOOGLE.COM.PH@agfc.harper18.workers.dev", []),
        # The same whatever the case, and no shorter front either
        ("C2.EXAMPLE.COM.PH is down", []),
        ("C2.Example.Com.Ph", []),
        ("a.com.Net.zz", []),
        ("c2.example.org.2nd server", []),
        # The price: a sentence that lost its space reads as a longer name
        ("c2.example.org.Then wait", []),
        ("c2.example.org.then wait", []),
    ],
)
def test_a_host_is_reported_whole_or_not_at_all(text, hosts):
    assert [value for kind, value in pairs(body(text)) if kind == "host"] == hosts


def test_a_long_run_of_labels_is_searched_quickly(laptop_seconds):
    # The look ahead counts its labels, so a page of them costs no more than the page
    run = "a.co." * 12_000
    assert laptop_seconds(lambda: extract("", run)) < 1.0
    assert laptop_seconds(lambda: extract("", run + "@x.example.org")) < 1.0
