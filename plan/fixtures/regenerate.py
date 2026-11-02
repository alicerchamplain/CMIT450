"""Rebuild the fixtures in this directory from raw getPage responses.

Usage:
    python plan/fixtures/regenerate.py RAW_DIR
"""

import json
import sys
from pathlib import Path

from graphwatch.redact import redact_page

HERE = Path(__file__).resolve().parent
CONFIG = Path.home() / ".config" / "graphwatch" / "config.env"


def load_key(config: Path = CONFIG) -> bytes:
    """Loads HMAC Key from config

    Args:
        config (Path, optional): Path to the config file. Defaults to CONFIG.

    Raises:
        SystemExit: Exit if the hmac key isn't found

    Returns:
        bytes: HMAC key bytes
    """
    for line in config.read_text(encoding="utf-8").splitlines():
        name, sep, value = line.strip().partition("=")
        if sep and name.strip() == "HMAC_KEY":
            value = value.strip().strip("'\"")
            try:
                return bytes.fromhex(value)
            except ValueError:
                return value.encode("utf-8")
    raise SystemExit(f"HMAC_KEY not found in {config}")


def main(argv: list[str]) -> None:
    """Uses the API client to regenerate the fixtures of the eval set

    Args:
        argv (list[str]): Path to fixtures directory

    Raises:
        SystemExit: Exit if no args passed
    """
    if len(argv) != 1:
        raise SystemExit(__doc__)
    raw_dir = Path(argv[0])
    key = load_key()
    for raw_file in sorted(raw_dir.glob("*.json")):
        page = json.loads(raw_file.read_text(encoding="utf-8"))
        envelope = {"ok": True, "result": redact_page(page, key)}
        out = HERE / raw_file.name
        out.write_text(
            json.dumps(envelope, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
        )
        print(f"wrote {out.relative_to(HERE.parent.parent)}")


if __name__ == "__main__":
    main(sys.argv[1:])
