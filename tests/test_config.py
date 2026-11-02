"""Tests for graphwatch.config.

Every test writes its own config file under tmp_path. Nothing here reads the
real ~/.config/graphwatch/config.env.
"""

import pytest

from graphwatch.config import CONFIG, hmac_key, load_config


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
    cfg = load_config(write(tmp_path, "# comment\n\n   \nA=1\n  # indented comment\n"))
    assert cfg == {"A": "1"}


def test_load_config_skips_lines_without_an_equals_sign(tmp_path):
    cfg = load_config(write(tmp_path, "NOEQUALS\nA=1\n"))
    assert cfg == {"A": "1"}


def test_load_config_strips_spaces_around_name_and_value(tmp_path):
    cfg = load_config(write(tmp_path, "  A  =  1  \n"))
    assert cfg == {"A": "1"}


@pytest.mark.parametrize("quoted", ['"abc"', "'abc'"])
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


def test_load_config_does_not_print_or_log_values(tmp_path, capsys):
    load_config(write(tmp_path, "HMAC_KEY=sensitive\n"))
    out, err = capsys.readouterr()
    assert "sensitive" not in out + err


# --- hmac_key -------------------------------------------------------------------


def test_hmac_key_decodes_hex():
    assert hmac_key({"HMAC_KEY": "00ff10"}) == b"\x00\xff\x10"


def test_hmac_key_decodes_a_64_char_token_hex_to_32_bytes():
    assert len(hmac_key({"HMAC_KEY": "ab" * 32})) == 32


def test_hmac_key_falls_back_to_utf8_for_a_passphrase():
    assert hmac_key({"HMAC_KEY": "correct horse"}) == b"correct horse"


def test_hmac_key_odd_length_hex_like_string_is_treated_as_a_passphrase():
    # "abc" is not valid hex (odd length), so it is a passphrase, not an error.
    assert hmac_key({"HMAC_KEY": "abc"}) == b"abc"


def test_hmac_key_non_ascii_passphrase():
    assert hmac_key({"HMAC_KEY": "пароль"}) == "пароль".encode("utf-8")


def test_hmac_key_missing_raises_key_error():
    with pytest.raises(KeyError):
        hmac_key({"OTHER": "x"})


def test_hmac_key_round_trip_through_load_config(tmp_path):
    cfg = load_config(write(tmp_path, "HMAC_KEY=00ff\n"))
    assert hmac_key(cfg) == b"\x00\xff"
