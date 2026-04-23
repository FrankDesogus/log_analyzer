import re
from typing import Optional


MAC_REGEX = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
RSSI_RE = re.compile(r"rssi=(-?\d+)")
RADIO_RE = re.compile(r"\b(ra\d+)\b")
PROCESS_TOKEN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)(?:\[\d+\])?$")
MESSAGE_PROCESS_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\[\d+\]:")


def extract_process_and_message(rest: str) -> tuple[Optional[str], str]:
    """Split `rest` into process prefix and syslog message body."""
    if ": " not in rest:
        return None, rest.strip()

    left, right = rest.split(": ", 1)
    return left.strip(), right.strip()


def extract_process_name(process: Optional[str], raw_message: str) -> Optional[str]:
    """Extract clean process name from `process` field, with raw_message fallback."""
    if process:
        candidate = process.rsplit("\t", 1)[-1].strip()
        if candidate.startswith(":"):
            candidate = candidate[1:].strip()

        token_match = PROCESS_TOKEN_RE.match(candidate)
        if token_match:
            return token_match.group(1)

    message_match = MESSAGE_PROCESS_RE.match(raw_message)
    if message_match:
        return message_match.group(1)

    return None


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
