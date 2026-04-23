import json
import re
from pathlib import Path
from typing import Optional

from src.classifiers import classify_event_category, classify_event_type
from src.extractors import (
    extract_client_ap_mac,
    extract_mac,
    extract_process_and_message,
    extract_process_name,
    extract_radio,
    extract_rssi,
)
from src.models import ParsedEvent


HEADER_RE = re.compile(
    r"^(?P<source_ip>\S+)\s+"
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<facility>\S+)\s+"
    r"(?P<severity>\S+)\s+"
    r"(?P<rest>.+)$"
)


def parse_line(line: str) -> Optional[ParsedEvent]:
    stripped_line = line.strip()
    if not stripped_line:
        return None

    header_match = HEADER_RE.match(stripped_line)
    if not header_match:
        return ParsedEvent(
            parse_status="unparsed",
            raw_line=stripped_line,
        )

    data = header_match.groupdict()
    process, message = extract_process_and_message(data["rest"])
    process_name = extract_process_name(process, message)
    event_type = classify_event_type(message)
    event_category = classify_event_category(message, process_name, event_type)
    current_mac = extract_mac(message)
    client_mac, ap_mac, mac = extract_client_ap_mac(message, current_mac)

    return ParsedEvent(
        parse_status="parsed",
        source_ip=data["source_ip"],
        timestamp=f'{data["month"]} {data["day"]} {data["time"]}',
        host=data["host"],
        facility=data["facility"],
        severity=data["severity"],
        process=process,
        process_name=process_name,
        raw_message=message,
        event_type=event_type,
        event_category=event_category,
        mac=mac,
        client_mac=client_mac,
        ap_mac=ap_mac,
        radio=extract_radio(message),
        rssi=extract_rssi(message),
        raw_line=stripped_line,
    )


def parse_file(input_path: Path, output_path: Path) -> None:
    parsed_events: list[dict] = []

    with input_path.open("r", encoding="utf-8", errors="ignore") as file_in:
        for line_number, line in enumerate(file_in, start=1):
            parsed = parse_line(line)
            if parsed is None:
                continue

            parsed.line_number = line_number
            parsed_events.append(parsed.to_dict())

    with output_path.open("w", encoding="utf-8") as file_out:
        json.dump(parsed_events, file_out, indent=2, ensure_ascii=False)

    print(f"Lette {len(parsed_events)} righe.")
    print(f"Output scritto in: {output_path}")
