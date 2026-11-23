"""Functions to handle the config.env file"""

from pathlib import Path

CONFIG = Path.home() / ".config" / "graphwatch" / "config.env"

# The shortest HMAC key that is accepted, in bytes: the length of the SHA-256
# digest it keys, which is what secrets.token_hex(32) gives. A stored
# SECRET{...} is only as hard to undo as the key is to guess.
MIN_KEY_BYTES = 32


def load_config(path: Path = CONFIG) -> dict[str, str]:
    """Loads the config.env file into a dictionary

    Args:
        path (Path, optional): Path to the config.env file. Defaults to CONFIG.

    Returns:
        dict[str, str]: Dictionary containing key, value config pairs
    """
    config = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep:
            continue
        config[name.strip()] = value.strip().strip("'\"")
    return config


def hmac_key(config: dict) -> bytes:
    """Function to ensure HMAC Key is in bytes format

    Args:
        config (dict): The config dictionary from load_config

    Raises:
        KeyError: if HMAC_KEY is not set
        ValueError: if the key is shorter than MIN_KEY_BYTES. The message
            says neither what the key is nor how long.

    Returns:
        bytes: HMAC key in bytes format
    """
    value = config["HMAC_KEY"]
    try:
        key = bytes.fromhex(value)
    except ValueError:
        key = value.encode("utf-8")
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"HMAC_KEY is shorter than {MIN_KEY_BYTES} bytes")
    return key
