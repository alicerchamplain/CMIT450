"""Tests for graphwatch.config.

Every test writes its own config file under tmp_path. Nothing here reads the
real ~/.config/graphwatch/config.env.
"""

import logging

import pytest

from graphwatch.config import CONFIG, MIN_KEY_BYTES, hmac_key, load_config


def write(tmp_path, text: str):
    path = tmp_path / "config.env"
    path.write_text(text, encoding="utf-8")
    return path


# --- load_config -------------------------------------------------------------


def test_default_path_is_under_the_user_config_dir():
    assert CONFIG.parts[-3:] == (".config", "graphwatch", "config.env")


def test_load_config_reads_name_value_pairs(tmp_path):
    cfg = load_config(write(tmp_path, "A=1\nB=two\n"))
    assert cfg == {"A": "1", "B": "two"}


def test_load_config_skips_comments_and_blank_lines(tmp_path):
    # A commented-out setting is a comment too, indented or not.
    text = "# comment\n\n   \nA=1\n#A=0\n  # indented comment\n  # B=2\n"
    assert load_config(write(tmp_path, text)) == {"A": "1"}


def test_load_config_skips_lines_without_an_equals_sign(tmp_path):
    cfg = load_config(write(tmp_path, "NOEQUALS\nA=1\n"))
    assert cfg == {"A": "1"}


def test_load_config_strips_spaces_around_name_and_value(tmp_path):
    cfg = load_config(write(tmp_path, "  A  =  1  \n"))
    assert cfg == {"A": "1"}


@pytest.mark.parametrize("quoted", ['"abc"', "'abc'", ' "abc" '])
def test_load_config_strips_surrounding_quotes(tmp_path, quoted):
    cfg = load_config(write(tmp_path, f"A={quoted}\n"))
    assert cfg == {"A": "abc"}


def test_load_config_keeps_equals_signs_inside_the_value(tmp_path):
    # Only the first = splits; base64 padding and URLs with = survive.
    cfg = load_config(write(tmp_path, "A=dGViaQ==\nB=https://x/?a=1&b=2\n"))
    assert cfg == {"A": "dGViaQ==", "B": "https://x/?a=1&b=2"}


def test_load_config_last_definition_wins(tmp_path):
    cfg = load_config(write(tmp_path, "A=1\nA=2\n"))
    assert cfg == {"A": "2"}


def test_load_config_empty_value_is_an_empty_string(tmp_path):
    cfg = load_config(write(tmp_path, "A=\n"))
    assert cfg == {"A": ""}


def test_load_config_empty_file_is_an_empty_dict(tmp_path):
    assert load_config(write(tmp_path, "")) == {}


def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.env")


def test_load_config_does_not_print_or_log_values(tmp_path, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    load_config(write(tmp_path, "HMAC_KEY=sensitive\n"))
    out, err = capsys.readouterr()
    assert "sensitive" not in out + err + caplog.text


# --- hmac_key -------------------------------------------------------------------


# Every value below makes a key of 32 bytes or more. The rows are about how
# the value is read; the tests of a key that is too short come after them.
@pytest.mark.parametrize(
    "value, key",
    [
        # a 64-character hex token is decoded to 32 bytes
        ("00ff10" + "ab" * 29, b"\x00\xff\x10" + b"\xab" * 29),
        ("00FF10" + "AB" * 29, b"\x00\xff\x10" + b"\xab" * 29),  # in either case
        # anything else is a passphrase
        ("correct horse battery staple again", b"correct horse battery staple again"),
        ("abc" * 21, b"abc" * 21),  # 63 hex digits: odd, so not hex, and not an error
        ("пароль" * 3, ("пароль" * 3).encode("utf-8")),
    ],
)
def test_hmac_key_is_hex_decoded_or_else_the_utf8_passphrase(value, key):
    assert hmac_key({"HMAC_KEY": value}) == key


@pytest.mark.parametrize(
    "value",
    [
        "",
        "00ff",  # 2 bytes: hex is counted after it is decoded
        "00ff" * 15 + "00",  # 31 bytes
        "passphrase " * 2 + "too short",  # 31 bytes
        "пароль" * 2 + "abcdefg",  # 31 bytes, not 19 characters
    ],
)
def test_hmac_key_refuses_a_key_shorter_than_32_bytes_and_says_nothing_about_it(value):
    assert MIN_KEY_BYTES == 32
    with pytest.raises(ValueError) as error:
        hmac_key({"HMAC_KEY": value})
    # Neither the key nor its length: the message ends up in a log
    assert str(error.value) == "HMAC_KEY is shorter than 32 bytes"


@pytest.mark.parametrize("value", ["00ff" * 16, "passphrase " * 2 + "is enough."])
def test_hmac_key_accepts_a_key_of_exactly_32_bytes(value):
    assert len(hmac_key({"HMAC_KEY": value})) == 32


def test_hmac_key_missing_raises_key_error():
    with pytest.raises(KeyError):
        hmac_key({"OTHER": "x"})


def test_hmac_key_round_trip_through_load_config(tmp_path):
    cfg = load_config(write(tmp_path, "HMAC_KEY=" + "00ff" * 16 + "\n"))
    assert hmac_key(cfg) == b"\x00\xff" * 16
