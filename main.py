import re
import json
from pathlib import Path
from typing import Optional, Dict, Any


MAC_REGEX = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'

# Header iniziale del file syslog:
# 10.10.30.5 Apr 17 09:20:05 U6-LR kernel warning ...
HEADER_RE = re.compile(
    r'^(?P<source_ip>\S+)\s+'
    r'(?P<month>[A-Z][a-z]{2})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<facility>\S+)\s+'
    r'(?P<severity>\S+)\s+'
    r'(?P<rest>.+)$'
)

RSSI_RE = re.compile(r'rssi=(-?\d+)')
EVENT_STA_LEAVE_RE = re.compile(r'\bEVENT_STA_LEAVE\b')
DISASSOCIATED_RE = re.compile(r'\bdisassociated\b', re.IGNORECASE)
RECV_AUTH_REQ_RE = re.compile(r'\brecv_auth_req\b')
SEND_AUTH_RSP_RE = re.compile(r'\bsend_auth_rsp\b')
RADIO_RE = re.compile(r'\b(ra\d+)\b')


def extract_process_and_message(rest: str) -> tuple[Optional[str], str]:
    """
    Prova a separare 'processo' e messaggio.
    Esempio:
      '0cea14f037c5,U6-LR-6.7.41+15623 hostapd[3891]: ra0: STA ...'
    """
    if ': ' in rest:
        left, right = rest.split(': ', 1)
        return left.strip(), right.strip()
    return None, rest.strip()


def normalize_event_type(message: str) -> Optional[str]:
    if EVENT_STA_LEAVE_RE.search(message):
        return "disconnect"
    if DISASSOCIATED_RE.search(message):
        return "disconnect"
    if RECV_AUTH_REQ_RE.search(message):
        return "auth_request"
    if SEND_AUTH_RSP_RE.search(message):
        return "auth_response"
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


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    header_match = HEADER_RE.match(line)
    if not header_match:
        return {
            "parse_status": "unparsed",
            "raw_line": line,
        }

    data = header_match.groupdict()
    process, message = extract_process_and_message(data["rest"])

    event = {
        "parse_status": "parsed",
        "source_ip": data["source_ip"],
        "timestamp": f'{data["month"]} {data["day"]} {data["time"]}',
        "host": data["host"],
        "facility": data["facility"],
        "severity": data["severity"],
        "process": process,
        "raw_message": message,
        "event_type": normalize_event_type(message),
        "mac": extract_mac(message),
        "radio": extract_radio(message),
        "rssi": extract_rssi(message),
        "raw_line": line,
    }

    return event


def parse_file(input_path: Path, output_path: Path) -> None:
    parsed_events = []

    with input_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            parsed = parse_line(line)
            if parsed is None:
                continue
            parsed["line_number"] = line_number
            parsed_events.append(parsed)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(parsed_events, f, indent=2, ensure_ascii=False)

    print(f"Lette {len(parsed_events)} righe.")
    print(f"Output scritto in: {output_path}")


if __name__ == "__main__":
    input_file = Path("data/raw/syslog")
    output_file = Path("data/output/parsed_events.json")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    parse_file(input_file, output_file)