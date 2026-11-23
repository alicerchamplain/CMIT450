"""Tests for graphwatch.slugify.

Every (title, slug) pair below is a sighting recorded in
plan/reports/telegraph-path-probe-2026-10-25.md, by finding number.
"""

from pathlib import Path

import pytest

from graphwatch.slugify import (
    CROWD_ONLY,
    Entry,
    load_wordlists,
    normalize_slug,
    slugify,
)

WORDLISTS = Path(__file__).resolve().parents[1] / "wordlists"


# --------------------------------------------------------------------------
# finding 3: the Russian table
# --------------------------------------------------------------------------


# Enough sightings to show every letter the note saw; it lists more. The
# letters no sighting shows are in the alphabet test below.
@pytest.mark.parametrize(
    "title, slug",
    [
        ("Сергей", "Sergej"),
        ("Дмитрий", "Dmitrij"),
        ("Юлия", "Yuliya"),
        ("Заявление", "Zayavlenie"),
        ("Жанна", "Zhanna"),
        ("Борщ", "Borshch"),
        ("Цена", "Cena"),
        ("Пятница", "Pyatnica"),
        ("Хочу", "Hochu"),
        ("Хорошо", "Horosho"),
        ("Школа", "Shkola"),
        ("Чай", "Chaj"),
        ("Выход", "Vyhod"),
        ("Эксперт", "Ehkspert"),
        ("Ёлка", "Yolka"),
        ("Алёна", "Alyona"),
        ("Компьютер", "Kompyuter"),
        ("Объявление", "Obyavlenie"),
        ("Фото", "Foto"),
        ("Телефон", "Telefon"),
        ("Украина", "Ukraina"),
    ],
)
def test_russian_sightings(title, slug):
    assert slugify(title) == slug


def test_the_whole_russian_alphabet_in_both_cases():
    # One letter between each pair of hyphens. The soft and hard signs vanish,
    # and a capital that becomes several letters is title case, not upper.
    lower = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    assert len(lower) == 33
    assert slugify(" ".join(lower)) == (
        "a-b-v-g-d-e-yo-zh-z-i-j-k-l-m-n-o-p-r-s-t-u-f-h-c-ch-sh-shch--y--eh-yu-ya"
    )
    assert slugify(" ".join(lower.upper())) == (
        "A-B-V-G-D-E-Yo-Zh-Z-I-J-K-L-M-N-O-P-R-S-T-U-F-H-C-Ch-Sh-Shch--Y--Eh-Yu-Ya"
    )


# --------------------------------------------------------------------------
# finding 4: Ukrainian and pass-through letters
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title, slug",
    [
        ("Київ", "Kiiv"),
        ("Євген", "Yevgen"),
        ("Відео", "Vіdeo"),  # Cyrillic і stays
        ("Інструкція", "Іnstrukcіya"),  # Cyrillic І and і stay
        ("Повістка", "Povіstka"),
        ("Ґрати", "Grati"),
    ],
)
def test_ukrainian_sightings(title, slug):
    assert slugify(title) == slug


def test_ukrainian_i_is_the_cyrillic_letter_not_latin():
    # Written as escapes, because the two letters look the same on screen:
    # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I, U+0406 its capital.
    assert slugify("В\u0456део") == "V\u0456deo"
    assert slugify("\u0406сторія") == "\u0406stor\u0456ya"


def test_mojibake_spam_title_is_the_hard_case():
    # Й→J, Д→D, ё→yo, Е→E, е→e, Ґ→G converted; ќ, ђ, Ћ kept; », ‘, … dropped;
    # spaces to hyphens; case preserved letter by letter.
    assert slugify("Jk Й»‘Дёќ ЕђЋе…Ґ") == "Jk-JDyoќ-EђЋeG"


def test_serbian_and_macedonian_letters_pass_through():
    assert slugify("ќђЋ") == "ќђЋ"


# --------------------------------------------------------------------------
# finding 6: spaces and hyphens
# --------------------------------------------------------------------------


def test_space_becomes_hyphen():
    assert slugify("Hello World") == "Hello-World"
    assert slugify("Proxy List") == "Proxy-List"


def test_hyphen_runs_are_never_collapsed():
    # Issue #60 writes this sighting as "… до Penthouse - Ґрати" →
    # "…-do-Penthouse---Grati". The leading "…" there is the probe note's
    # abbreviation of a long path, not a character in the title: finding 9
    # shows a real ellipsis is dropped. The part that matters is that
    # space, hyphen, space become exactly three hyphens.
    assert slugify("до Penthouse - Ґрати") == "do-Penthouse---Grati"
    assert slugify("Rassekrechennoe delo … do Penthouse - Ґрати") == (
        "Rassekrechennoe-delo--do-Penthouse---Grati"
    )


def test_punctuation_next_to_a_space_leaves_only_the_space_hyphen():
    assert slugify("бикини». От") == "bikini-Ot"


def test_double_space_is_two_hyphens():
    assert slugify("a  b") == "a--b"


def test_leading_and_trailing_spaces_are_hyphens_too():
    # slugify does not strip; the loader strips lines before calling it.
    assert slugify(" a ") == "-a-"


# --------------------------------------------------------------------------
# finding 9: apostrophes and punctuation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title, slug",
    [
        ("Здоров'я", "Zdorovya"),
        ("об'єкт", "obyekt"),
        ("don't", "dont"),
        ("it's", "its"),
        ("Світ…", "Svіt"),
        ("Реєстр військовозобов'язаних", "Reyestr-vіjskovozobovyazanih"),
    ],
)
def test_punctuation_is_dropped_without_a_hyphen(title, slug):
    assert slugify(title) == slug


def test_typographic_apostrophe_and_quotes_are_dropped_too():
    assert slugify("don’t") == "dont"
    assert slugify("«Тест»") == "Test"
    assert slugify('"Test"') == "Test"


def test_underscore_and_dot_are_dropped():
    assert slugify("a_b.c") == "abc"


# --------------------------------------------------------------------------
# finding 2: case
# --------------------------------------------------------------------------


def test_case_is_preserved_letter_by_letter():
    assert slugify("TEST") == "TEST"
    assert slugify("Test") == "Test"
    assert slugify("test") == "test"
    assert slugify("ПРИВЕТ") == "PRIVET"


# --------------------------------------------------------------------------
# things the note did not probe: be conservative
# --------------------------------------------------------------------------


def test_latin_and_digits_pass_through():
    assert slugify("ki06") == "ki06"
    assert slugify("f8bfl6sp") == "f8bfl6sp"
    assert slugify("Hello") == "Hello"


def test_other_scripts_pass_through_as_letters():
    # Not probed; letters are kept, same as unknown Cyrillic.
    assert slugify("سلام") == "سلام"


def test_emoji_is_dropped_as_a_symbol():
    assert slugify("Hi 🔥") == "Hi-"


def test_empty_title_gives_empty_slug():
    assert slugify("") == ""
    assert slugify("…") == ""


# --------------------------------------------------------------------------
# load_wordlists
# --------------------------------------------------------------------------


def write_lists(tmp_path, **files):
    for name, text in files.items():
        (tmp_path / f"{name}.txt").write_text(text, encoding="utf-8")
    return tmp_path


def test_load_reads_utf8_one_title_per_line(tmp_path):
    d = write_lists(tmp_path, lures="Повістка\nСуд\n")
    entries = load_wordlists(d)
    assert entries == [
        Entry("Повістка", "Povіstka", "lures", False),
        Entry("Суд", "Sud", "lures", False),
    ]


def test_load_skips_blank_and_comment_lines(tmp_path):
    d = write_lists(tmp_path, a="\n# a comment\nHello\n\n  \n  # indented\nTest\n")
    assert [e.title for e in load_wordlists(d)] == ["Hello", "Test"]


def test_load_strips_surrounding_whitespace(tmp_path):
    d = write_lists(tmp_path, a="  Hello World \n")
    assert load_wordlists(d)[0].slug == "Hello-World"


def test_load_marks_pending_as_crowd_only(tmp_path):
    assert CROWD_ONLY == frozenset({"pending"})
    d = write_lists(tmp_path, lures="Суд\n", pending="Maybe\n")
    by_source = {e.source: e for e in load_wordlists(d)}
    assert by_source["lures"].crowd_only is False
    assert by_source["pending"].crowd_only is True


def test_load_drops_case_duplicates_keeping_the_first(tmp_path):
    # Lookups are case-insensitive, so TEST and Test are one page.
    d = write_lists(tmp_path, a="Test\n", b="TEST\ntest\nОЛЬГА\nOlga\n")
    entries = load_wordlists(d)
    assert [(e.slug, e.source) for e in entries] == [("Test", "a"), ("OLGA", "b")]


def test_load_drops_titles_that_slug_to_nothing(tmp_path):
    d = write_lists(tmp_path, a="…\n''\nOk\n")
    assert [e.slug for e in load_wordlists(d)] == ["Ok"]


def test_load_reads_files_in_name_order(tmp_path):
    d = write_lists(tmp_path, zed="Z\n", alpha="A\n")
    assert [e.source for e in load_wordlists(d)] == ["alpha", "zed"]


def test_load_ignores_non_txt_files(tmp_path):
    d = write_lists(tmp_path, a="Ok\n")
    (d / "notes.md").write_text("Nope\n", encoding="utf-8")
    assert [e.slug for e in load_wordlists(d)] == ["Ok"]


def test_load_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_wordlists(tmp_path / "nope")


def test_load_the_real_wordlists():
    entries = load_wordlists(WORDLISTS)
    assert len(entries) > 900
    assert all(e.slug for e in entries)
    assert all(" " not in e.slug and "'" not in e.slug for e in entries)
    slugs = {e.slug.casefold() for e in entries}
    assert len(slugs) == len(entries)
    # the known actor's daily title and the Ukrainian lure are both in there
    assert "hello" in slugs
    assert "povіstka" in slugs  # Cyrillic і
    assert not any(e.crowd_only for e in entries)  # no pending.txt yet


# --------------------------------------------------------------------------
# normalize_slug: the database key for a slug
#
# Telegraph matches paths case-insensitively with full Unicode rules and
# answers with its own spelling. The first sweep asked for Hi-10-30-261 and
# got back Hİ-10-30-261 (Turkish dotted capital I). SQLite's NOCASE only folds
# ASCII, so every slug column must hold one normalized key instead.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "slug, key",
    [
        ("Hi", "hi"),
        ("Hİ", "hi"),  # U+0130 folds to i + combining dot; the dot must go too
        # Cyrillic capital І (U+0406) folds to small і (U+0456) and stays
        # Cyrillic: folding must not transliterate.
        ("MOB\u0406L\u0406ZAC\u0406YA", "mob\u0456l\u0456zac\u0456ya"),
        ("Mob\u0456l\u0456zac\u0456ya", "mob\u0456l\u0456zac\u0456ya"),
        ("Привет", "привет"),  # a Cyrillic capital folds like a Latin one
        ("Mobile-Proxy-2024", "mobile-proxy-2024"),  # hyphens and digits stay
    ],
)
def test_normalize_slug_gives_one_key_per_page(slug, key):
    assert normalize_slug(slug) == key
    assert normalize_slug(key) == key  # a key is its own key
