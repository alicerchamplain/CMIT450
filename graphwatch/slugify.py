"""URL Slug translator for the Telegraph API (api.telegra.ph)."""

import unicodedata
from dataclasses import dataclass
from pathlib import Path

# Reverse engineered character table that Telegraph uses to convert cyrillic characters into latin characters.
_LOWER = {
    "а": "a",
    "б": "b",
    "в": "v",
    "г": "g",
    "д": "d",
    "е": "e",
    "ё": "yo",
    "ж": "zh",
    "з": "z",
    "и": "i",
    "й": "j",
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "n",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "s",
    "т": "t",
    "у": "u",
    "ф": "f",
    "х": "h",
    "ц": "c",
    "ч": "ch",
    "ш": "sh",
    "щ": "shch",
    "ъ": "",
    "ы": "y",
    "ь": "",
    "э": "eh",
    "ю": "yu",
    "я": "ya",
    "ї": "i",
    "є": "ye",
    "ґ": "g",
}

TABLE = dict(_LOWER)
for _cyr, _lat in _LOWER.items():
    TABLE[_cyr.upper()] = _lat.capitalize()


def slugify(title: str) -> str:
    """Function to properly convert strings into proper Telegraph slugs

    Args:
        title (str): wordlist entry / page title guess

    Returns:
        str: sluggified string for using in Telegraph lookups
    """
    out = []
    for ch in title:
        if ch in TABLE:
            out.append(TABLE[ch])
            continue
        if ch == "-":
            out.append("-")
            continue
        cat = unicodedata.category(ch)
        # Telegraph replaces spaces with -
        if cat == "Zs":
            out.append("-")
        # append letters and numbers as they are
        elif cat[0] in ("L", "N"):
            out.append(ch)
    return "".join(out)


CROWD_ONLY = frozenset(["pending"])


@dataclass(frozen=True)
class Entry:
    """Custom class for slug entries"""

    title: str  # the wordlist string
    slug: str  # the full slug
    source: str  # the wordlist name
    crowd_only: bool  # if this is crowd only usage


def load_wordlists(directory: str | Path) -> list[Entry]:
    """load and slugify wordlist entries

    Args:
        directory (str | Path): path where wordlists are stored

    Raises:
        FileNotFoundError: Error if directory is not a directory

    Returns:
        list[Entry]: Unique list of sluggified strings from wordlists
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(directory)
    entries = []
    seen = set()
    for file in sorted(directory.glob("*.txt")):
        source = file.stem
        for line in file.read_text(encoding="utf-8").splitlines():
            title = line.strip()
            if not title or title.startswith("#"):
                continue
            slug = slugify(title)
            key = slug.casefold()
            if not slug or key in seen:
                continue
            seen.add(key)
            entries.append(Entry(title, slug, source, source in CROWD_ONLY))
    return entries
