"""Functions to handle the config.env file"""

from pathlib import Path

CONFIG = Path.home() / ".config" / "graphwatch" / "config.env"


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

    Returns:
        bytes: HMAC key in bytes format
    """
    value = config["HMAC_KEY"]
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode("utf-8")
