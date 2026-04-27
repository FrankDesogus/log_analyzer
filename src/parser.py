import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Optional

from src.classifiers import classify_event_category, classify_event_type
from src.correlation import build_canonical_events
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

# Configurabile per adattare il raggruppamento fine a burst quasi-identici
# entro finestre temporali molto strette.
FINE_DUPLICATE_BUCKET_MS = 10


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
    internal_event_ts_float = to_float_or_none(internal_event_ts)
    timestamp = f'{data["month"]} {data["day"]} {data["time"]}'

    return ParsedEvent(
        parse_status="parsed",
        source_ip=data["source_ip"],
        timestamp=timestamp,
        original_timestamp=timestamp,
        normalized_timestamp=normalize_timestamp(timestamp),
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
        internal_event_ts_float=internal_event_ts_float,
        internal_event_bucket=build_internal_event_bucket(internal_event_ts_float),
        raw_line=stripped_line,
    )


def parse_file(
    input_path: Path,
    output_path: Path,
    canonical_output_path: Optional[Path] = None,
    parser_report_output_path: Optional[Path] = None,
    include_raw_in_canonical_output: bool = False,
) -> None:
    parsed_events = parse_file_to_events(input_path)

    with output_path.open("w", encoding="utf-8") as file_out:
        json.dump(parsed_events, file_out, indent=2, ensure_ascii=False)

    print(f"Lette {len(parsed_events)} righe.")
    print(f"Output raw scritto in: {output_path}")

    if canonical_output_path is None:
        return

    correlated_payload = build_canonical_events(parsed_events)
    canonical_payload: dict[str, Any] = {
        "canonical_events": correlated_payload["canonical_events"],
    }
    if include_raw_in_canonical_output:
        canonical_payload["raw_events"] = correlated_payload["raw_events"]

    with canonical_output_path.open("w", encoding="utf-8") as file_out:
        json.dump(canonical_payload, file_out, indent=2, ensure_ascii=False)

    print(f"Eventi canonici prodotti: {len(correlated_payload['canonical_events'])}")
    print(f"Output canonico scritto in: {canonical_output_path}")

    if parser_report_output_path is not None:
        parser_report = build_parser_report(parsed_events, correlated_payload["canonical_events"])
        with parser_report_output_path.open("w", encoding="utf-8") as file_out:
            json.dump(parser_report, file_out, indent=2, ensure_ascii=False)
        print(f"Report parser scritto in: {parser_report_output_path}")


def parse_file_with_canonical_events(input_path: Path, output_path: Path) -> None:
    parsed_events = parse_file_to_events(input_path)
    correlated_payload = build_canonical_events(parsed_events)

    with output_path.open("w", encoding="utf-8") as file_out:
        json.dump(correlated_payload, file_out, indent=2, ensure_ascii=False)

    print(f"Lette {len(parsed_events)} righe.")
    print(f"Eventi canonici prodotti: {len(correlated_payload['canonical_events'])}")
    print(f"Output scritto in: {output_path}")


def build_parser_report(parsed_events: list[dict[str, Any]], canonical_events: list[dict[str, Any]]) -> dict[str, Any]:
    parse_status_counts = Counter((event.get("parse_status") or "unknown") for event in parsed_events)
    event_type_counts = Counter((event.get("event_type") or "unknown") for event in parsed_events)
    canonical_event_type_counts = Counter(
        (event.get("canonical_event_type") or "unknown") for event in canonical_events
    )

    client_mac_counts = Counter(event.get("client_mac") for event in parsed_events if event.get("client_mac"))
    source_ip_counts = Counter(event.get("source_ip") for event in parsed_events if event.get("source_ip"))
    duplicate_candidates = sum(1 for event in parsed_events if event.get("is_duplicate_candidate"))
    fine_duplicate_candidates = sum(1 for event in parsed_events if event.get("is_fine_duplicate_candidate"))

    return {
        "total_raw_events": len(parsed_events),
        "total_canonical_events": len(canonical_events),
        "parse_status_counts": dict(parse_status_counts),
        "event_type_counts": dict(event_type_counts),
        "canonical_event_type_counts": dict(canonical_event_type_counts),
        "correlation_summary": {
            "duplicate_candidates": duplicate_candidates,
            "fine_duplicate_candidates": fine_duplicate_candidates,
            "raw_events_grouped_into_canonical": sum(
                int(event.get("raw_event_count") or 0) for event in canonical_events
            ),
            "canonical_events_with_multiple_raw_events": sum(
                1 for event in canonical_events if int(event.get("raw_event_count") or 0) > 1
            ),
        },
        "unknown_event_count": event_type_counts.get("unknown", 0),
        "events_without_client_mac": sum(1 for event in parsed_events if not event.get("client_mac")),
        "events_without_radio": sum(1 for event in parsed_events if not event.get("radio")),
        "top_client_mac_by_event_count": [
            {"client_mac": key, "event_count": count} for key, count in client_mac_counts.most_common(10)
        ],
        "top_source_ip_by_event_count": [
            {"source_ip": key, "event_count": count} for key, count in source_ip_counts.most_common(10)
        ],
    }


def parse_file_to_events(input_path: Path) -> list[dict]:
    parsed_records: list[ParsedEvent] = []
    coarse_group_sizes: dict[str, int] = {}
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
                coarse_group_sizes[duplicate_group_key] = coarse_group_sizes.get(duplicate_group_key, 0) + 1

            fine_duplicate_group_key = build_fine_duplicate_group_key(parsed)
            parsed.fine_duplicate_group_key = fine_duplicate_group_key
            if fine_duplicate_group_key is not None:
                fine_group_sizes[fine_duplicate_group_key] = fine_group_sizes.get(fine_duplicate_group_key, 0) + 1
            parsed_records.append(parsed)

    parsed_events: list[dict] = []
    for record in parsed_records:
        if record.duplicate_group_key is not None:
            coarse_group_size = coarse_group_sizes[record.duplicate_group_key]
            record.duplicate_group_size = coarse_group_size
            record.is_duplicate_candidate = coarse_group_size > 1
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

    return parsed_events


def build_duplicate_group_key(event: ParsedEvent) -> Optional[str]:
    # Chiave per il grouping "coarse": stesso secondo syslog + attributi evento.
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


def to_float_or_none(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def normalize_timestamp(timestamp: Optional[str]) -> Optional[str]:
    if not timestamp:
        return None

    year = resolve_log_year()
    if year is None:
        return None

    try:
        normalized = datetime.strptime(f"{year} {timestamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return normalized.isoformat()


def resolve_log_year() -> Optional[int]:
    configured_year = os.environ.get("UNIFI_LOG_YEAR")
    if configured_year is not None:
        try:
            return int(configured_year)
        except ValueError:
            return None
    return datetime.now(timezone.utc).year


def build_fine_duplicate_group_key(event: ParsedEvent) -> Optional[str]:
    # Chiave per il grouping "fine": bucket del timestamp interno + attributi evento.
    # Nota: hostapd/wevent spesso non includono internal_event_ts, quindi non entrano
    # nel fine grouping ma restano nel coarse grouping.
    mac_for_fine_grouping = event.client_mac or event.mac
    if (
        event.internal_event_bucket is None
        or not mac_for_fine_grouping
        or not event.event_type
    ):
        return None

    key_parts = [
        event.source_ip or "",
        mac_for_fine_grouping,
        event.radio or "",
        event.event_type,
        event.internal_event_bucket,
    ]
    return "|".join(key_parts)


def _bucket_decimal_places(bucket_ms: int) -> int:
    if bucket_ms % 100 == 0:
        return 1
    if bucket_ms % 10 == 0:
        return 2
    return 3


def build_internal_event_bucket(
    internal_event_ts_float: Optional[float], bucket_ms: int = FINE_DUPLICATE_BUCKET_MS
) -> Optional[str]:
    # Senza timestamp interno non si può fare fine grouping.
    if internal_event_ts_float is None:
        return None

    # Bucket temporale su timestamp interno (kernel/device), non sul syslog timestamp.
    bucket_seconds = bucket_ms / 1000
    bucket_start = math.floor(internal_event_ts_float / bucket_seconds) * bucket_seconds
    decimals = _bucket_decimal_places(bucket_ms)
    return f"{bucket_start:.{decimals}f}"
