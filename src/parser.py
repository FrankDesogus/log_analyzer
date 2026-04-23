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
INTERNAL_EVENT_TS_RE = re.compile(r"\[(\d+\.\d+)\]")


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
    internal_event_ts = extract_internal_event_ts(message)

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
        internal_event_ts=internal_event_ts,
        raw_line=stripped_line,
    )


def parse_file(input_path: Path, output_path: Path) -> None:
    parsed_records: list[ParsedEvent] = []
    group_sizes: dict[str, int] = {}
    fine_group_sizes: dict[str, int] = {}

    with input_path.open("r", encoding="utf-8", errors="ignore") as file_in:
        for line_number, line in enumerate(file_in, start=1):
            parsed = parse_line(line)
            if parsed is None:
                continue

            parsed.line_number = line_number
            duplicate_group_key = build_duplicate_group_key(parsed)
            parsed.duplicate_group_key = duplicate_group_key
            if duplicate_group_key is not None:
                group_sizes[duplicate_group_key] = group_sizes.get(duplicate_group_key, 0) + 1

            fine_duplicate_group_key = build_fine_duplicate_group_key(parsed)
            parsed.fine_duplicate_group_key = fine_duplicate_group_key
            if fine_duplicate_group_key is not None:
                fine_group_sizes[fine_duplicate_group_key] = fine_group_sizes.get(fine_duplicate_group_key, 0) + 1
            parsed_records.append(parsed)

    parsed_events: list[dict] = []
    for record in parsed_records:
        if record.duplicate_group_key is not None:
            group_size = group_sizes[record.duplicate_group_key]
            record.duplicate_group_size = group_size
            record.is_duplicate_candidate = group_size > 1
        else:
            record.duplicate_group_size = 1
            record.is_duplicate_candidate = False

        if record.fine_duplicate_group_key is not None:
            fine_group_size = fine_group_sizes[record.fine_duplicate_group_key]
            record.fine_duplicate_group_size = fine_group_size
            record.is_fine_duplicate_candidate = fine_group_size > 1
        else:
            record.fine_duplicate_group_size = 1
            record.is_fine_duplicate_candidate = False
        parsed_events.append(record.to_dict())

    with output_path.open("w", encoding="utf-8") as file_out:
        json.dump(parsed_events, file_out, indent=2, ensure_ascii=False)

    print(f"Lette {len(parsed_events)} righe.")
    print(f"Output scritto in: {output_path}")


def build_duplicate_group_key(event: ParsedEvent) -> Optional[str]:
    if not event.timestamp or not event.client_mac or not event.event_type:
        return None

    key_parts = [
        event.timestamp,
        event.source_ip or "",
        event.client_mac,
        event.radio or "",
        event.event_type,
    ]
    return "|".join(key_parts)


def extract_internal_event_ts(raw_message: Optional[str]) -> Optional[str]:
    if not raw_message:
        return None

    match = INTERNAL_EVENT_TS_RE.search(raw_message)
    if match:
        return match.group(1)
    return None


def build_fine_duplicate_group_key(event: ParsedEvent) -> Optional[str]:
    if not event.internal_event_ts or not event.client_mac or not event.event_type:
        return None

    key_parts = [
        event.source_ip or "",
        event.client_mac,
        event.radio or "",
        event.event_type,
        event.internal_event_ts,
    ]
    return "|".join(key_parts)
