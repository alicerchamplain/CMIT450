"""Rebuild the fixtures in this directory from raw getPage responses.

Usage:
    python plan/fixtures/regenerate.py RAW_DIR
"""

import json
import sys
from pathlib import Path

from graphwatch.config import hmac_key, load_config
from graphwatch.redact import redact_page

HERE = Path(__file__).resolve().parent


def main(argv: list[str]) -> None:
    """Redacts every raw response in RAW_DIR and writes it as a fixture

    Args:
        argv (list[str]): the directory of raw responses

    Raises:
        SystemExit: Exit if no args passed
    """
    if len(argv) != 1:
        raise SystemExit(__doc__)
    raw_dir = Path(argv[0])
    try:
        key = hmac_key(load_config())
    except (FileNotFoundError, KeyError) as e:
        raise SystemExit(f"HMAC_KEY not available: {e}")
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
