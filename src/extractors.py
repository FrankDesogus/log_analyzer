import re
from typing import Optional


MAC_REGEX = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
RSSI_RE = re.compile(r"rssi=(-?\d+)")
RADIO_RE = re.compile(r"\b(ra\d+)\b")


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
