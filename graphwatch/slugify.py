"""URL Slug translator for the Telegraph API (api.telegra.ph)."""

import hashlib
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


def normalize_slug(slug: str) -> str:
    """Function to do proper slug normalization

    Args:
        slug (str): slug to normalize

    Returns:
        str: normalized slug
    """
    folded = unicodedata.normalize("NFKC", slug).casefold()
    decomposed = unicodedata.normalize("NFKD", folded)
    stripped = "".join(c for c in decomposed if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", stripped)


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


SUMS_FILE = "SHA256SUMS"


class WordlistsChanged(Exception):
    """Custom exception class to raise when wordlist changes unexpectedly

    Args:
        Exception (class): Exception class

    """


def file_sha256(path: str | Path) -> str:
    """Helper function to get the sha256sum of a file

    Args:
        path (str | Path): Path to the file to compute the hash of

    Returns:
        str: The hexdigest of sha256sum
    """
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_sums(directory: str | Path) -> Path:
    """Function to hash all of the txt files in a directory and write those hashes to a file

    Args:
        directory (str | Path): Directory of txt files to hash

    Returns:
        Path: Path to the written file containing the list of hashes
    """
    directory = Path(directory)
    lines = [
        f"{file_sha256(file)}  {file.name}" for file in sorted(directory.glob("*.txt"))
    ]
    out = directory / SUMS_FILE
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def read_sums(path: str | Path) -> dict[str, str]:
    """Function to read the list of sha256sums from the SUMS_FILE into a dictionary

    Args:
        path (str | Path): Path to the SUMS_FILE

    Returns:
        dict[str, str]: Dictionary containing the filename and sha256sum for that file
    """
    sums = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, sep, name = line.partition(" ")
        if not sep:
            continue
        sums[name.lstrip(" *")] = digest.lower()
    return sums


def verify_wordlists(directory: str | Path) -> list[str]:
    """Function to verify the wordlist files in a directory match the SUMS_FILE

    Args:
        directory (str | Path): Directory of the wordlist .txt files

    Returns:
        list[str]: List of problem files
    """
    directory = Path(directory)
    sums_path = directory / SUMS_FILE
    if not sums_path.is_file():
        return [f"not frozen: {sums_path}"]
    expected = read_sums(sums_path)
    problems = []
    for name, digest in expected.items():
        file = directory / name
        if not file.is_file():
            problems.append(f"missing: {name}")
        elif file_sha256(file) != digest:
            problems.append(f"modified: {name}")
    for file in directory.glob("*.txt"):
        if file.name not in expected:
            problems.append(f"unlisted: {file.name}")
    return sorted(problems)


CROWD_ONLY = frozenset(["pending"])


@dataclass(frozen=True)
class Entry:
    """Custom class for slug entries"""

    title: str  # the wordlist string
    slug: str  # the full slug
    source: str  # the wordlist name
    crowd_only: bool  # if this is crowd only usage


def load_wordlists(directory: str | Path, *, verify: bool = False) -> list[Entry]:
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
    if verify:
        problems = verify_wordlists(directory)
        if problems:
            raise WordlistsChanged("\n".join(problems))
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
