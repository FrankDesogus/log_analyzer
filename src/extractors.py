import re
from typing import Optional


MAC_REGEX = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
RSSI_RE = re.compile(r"rssi=(-?\d+)")
RADIO_RE = re.compile(r"\b(ra\d+)\b")
TAGGED_MAC_TEMPLATE = r"\b{tag}:\[([0-9a-fA-F:]{{17}})\]"


def extract_process_and_message(rest: str) -> tuple[Optional[str], str]:
    """Split `rest` into process prefix and syslog message body."""
    if ": " not in rest:
        return None, rest.strip()

    left, right = rest.split(": ", 1)
    return left.strip(), right.strip()


def extract_mac(message: str) -> Optional[str]:
    match = re.search(MAC_REGEX, message)
    if match:
        return match.group(1).lower()
    return None


def extract_rssi(message: str) -> Optional[int]:
    match = RSSI_RE.search(message)
    if match:
        return int(match.group(1))
    return None


def extract_radio(message: str) -> Optional[str]:
    match = RADIO_RE.search(message)
    if match:
        return match.group(1)
    return None


def extract_tagged_mac(message: str, tag: str) -> Optional[str]:
    tag_re = re.compile(TAGGED_MAC_TEMPLATE.format(tag=re.escape(tag)))
    match = tag_re.search(message)
    if match:
        return match.group(1).lower()
    return None


def extract_client_and_ap_mac(message: str, event_type: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if event_type == "auth_request":
        return extract_tagged_mac(message, "TA"), extract_tagged_mac(message, "RA")

    if event_type == "auth_response":
        return extract_tagged_mac(message, "RA"), extract_tagged_mac(message, "TA")

    if event_type == "disconnect":
        return extract_mac(message), None

    return None, None
