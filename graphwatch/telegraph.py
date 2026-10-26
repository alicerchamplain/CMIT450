import json
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum, auto

import requests

BASE_URL = "https://api.telegra.ph"
ALLOWED_HOSTS = frozenset(["api.telegra.ph"])
BLOCK_TAGS = frozenset(["p","br","li","h3","h4","blockquote","pre","figcaption","hr"])

class Outcome(Enum):
    """The three ways a page lookup can end
    """
    FOUND = auto()
    NOT_FOUND = auto()
    FAILED = auto()


@dataclass
class Fetch:
    """
    Class for storing telegraph page fetch results
    """
    path: str # the path to fetch
    outcome: Outcome # the outcome of the fetch request
    page: dict | None # the page result
    error: str | None # API error strings
    status: int | None # HTTP status codes
    elapsed_ms: int # How long the fetch took


def build_path(slug: str, month: int, day: int, n: int | None = None) -> str:
    """Takes in the page slug, month, day, and post # and returns the path string like Vizit-01-28


    Args:
        slug (str): page slug
        month (int): month the post was made
        day (int): day the post was made
        n (int | None, optional): the number of the post if multiple posts with the same slug exist. Defaults to None.

    Returns:
        str: Built and padded path string like Vizit-01-28
    """
    path = f"{slug}-{month:02d}-{day:02d}"
    if n is not None:
        path = path + "-" + str(n)
    return path


def parse_envelope(status: int, body: bytes) -> tuple[Outcome, dict | None, str | None]:
    """Parses the HTTP response data and returns the outcome of the fetch

    Args:
        status (int): HTTP response status
        body (bytes): HTTP response body

    Returns:
        tuple[Outcome, dict | None, str | None]: Tuple with outcome result

    """
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return Outcome.FAILED, None, f"{status}: {e}"

    if not isinstance(data, dict):
        return Outcome.FAILED, None, "Data is not a dict"

    ok = data.get("ok")
    result = data.get("result")
    if ok is True and isinstance(result, dict):
        return Outcome.FOUND, result, None
    if ok is False and data.get("error") == "PAGE_NOT_FOUND":
        return Outcome.NOT_FOUND, None, "PAGE_NOT_FOUND"

    return Outcome.FAILED, None, data.get("error") or f"Unexpected response envelope. Status: {status}"


def _node_text(node) -> str:
    """Walks nodes for text, takes one node and returns a string

    Args:
        node (str | dict): Node to check for text

    Returns:
        str: found text as a string
    """

    if isinstance(node,str):
        return node
    if isinstance(node,dict):
        pieces = []
        for child in node.get("children", []):
            pieces.append(_node_text(child))
        text = "".join(pieces)
        if node.get("tag") in BLOCK_TAGS:
            text = text + "\n"
        return text
    return ""


def _node_links(node) -> list[str]:
    """Walks nodes for links, takes one node and returns a list of links in string format

    Args:
        node (str | dict): text node to check for links

    Returns:
        list[str]: list of links found in node
    """
    if isinstance(node,str):
        return []

    if isinstance(node,dict):
        links = []
        attrs = node.get("attrs", {})
        for key in ("href", "src"):
            value = attrs.get(key)
            if value:
                links.append(value)
        for child in node.get("children", []):
            links.extend(_node_links(child))
        return links
    return []


def page_text(page: dict) -> str:
    """Takes the page content as a dictionary and returns the page title, page description, and page body content as a string

    Args:
        page (dict): dictionary containing the page content

    Returns:
        str: page content in string format
    """
    pieces = []
    for block in page.get("content", []):
        pieces.append(_node_text(block))
    body = "".join(pieces)
    result = [page.get("title", ""),page.get("description", ""), body]
    return "\n".join(result)


def page_links(page: dict) -> list[str]:
    """Takes the page content as a dictionary and returns a list of the links in the page

    Args:
        page (dict): dictionary containing the page content

    Returns:
        list[str]: list of links found in page content
    """
    links = []
    for block in page.get("content",[]):
        links.extend(_node_links(block))
    return links
