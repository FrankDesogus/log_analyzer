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
UNKNOWN_EVENT_FIELDS = [
    "line_number",
    "source_ip",
    "timestamp",
    "normalized_timestamp",
    "host",
    "facility",
    "severity",
    "process",
    "process_name",
    "raw_message",
    "raw_line",
    "unknown_pattern",
    "event_type",
    "event_category",
    "client_mac",
    "radio",
    "internal_event_ts",
    "duplicate_group_key",
    "fine_duplicate_group_key",
]
MAC_PATTERN_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
IP_PATTERN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KERNEL_TS_PATTERN_RE = re.compile(r"\[\d+\.\d+\]")
LONG_NUM_PATTERN_RE = re.compile(r"\b\d{4,}\b")
DNS_TIMEOUT_DETAILS_RE = re.compile(
    r"\[STA:\s*(?P<client_mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\]"
    r"\[QUERY:\s*(?P<query>[^\]]+)\]\s*"
    r"\[DNS_SERVER\s*:(?P<dns_server>[^\]]+)\]\s*"
    r"\[TXN_ID\s+(?P<transaction_id>[^\]]+)\]\s*"
    r"\[SRCPORT\s+(?P<source_port>\d+)\]",
    re.IGNORECASE,
)
DROP_CACHES_DETAILS_RE = re.compile(
    r"(?:^|\]\s+)(?P<process_name>[A-Za-z_][A-Za-z0-9_-]*)\s*\((?P<pid>\d+)\):\s*drop_caches:\s*(?P<drop_value>\d+)\b",
    re.IGNORECASE,
)
CFG80211_STA_DEL_BSSID_RE = re.compile(
    r"CFG80211_OpsStaDel\s*==>\s*for bssid\s*\((?P<bssid>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\)",
    re.IGNORECASE,
)
EAP_PACKET_DETAILS_RE = re.compile(
    r"EAP Packet\s+PortSecure:\s*(?P<port_secure>\d+),\s*bClearFrame\s+(?P<clear_frame>\d+)",
    re.IGNORECASE,
)
STA_ASSOC_TRACKER_JSON_RE = re.compile(r"(\{.*\"message_type\"\s*:\s*\"STA_ASSOC_TRACKER\".*\})")
REASSOC_REQ_RE = re.compile(
    r"(?P<radio>rai?\d+):\s*\[recv\s+reassoc_req\]\.\s*TA:\[(?P<ta>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\],\s*RA:\[(?P<ra>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\]",
    re.IGNORECASE,
)
EAPOL_PACKET_DETAILS_RE = re.compile(
    r"rt28xx_send_packets\s+(?P<direction>Send|Recv)\s+EAPOL\s+of\s+length\s+(?P<length>\d+)(?:\s+from\s+(?P<source>[A-Za-z0-9_-]+))?",
    re.IGNORECASE,
)
EAPOL_KEY_DETAILS_RE = re.compile(
    r"(?P<radio>rai?\d+):\s*(?P<direction>Send|Recv)\s+EAPOL-Key\s+(?P<message>M[1-4]),\s*DA=(?P<da>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}),\s*SA=(?P<sa>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}),\s*len=(?P<length>\d+)",
    re.IGNORECASE,
)
KEY_ACTION_STA_RE = re.compile(
    r"(?:^|\s)\d+>\s*(?P<action>KeyAdd|KeyDel)\s+STA\((?P<sta>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\)",
    re.IGNORECASE,
)
DELETE_STA_REASON_RE = re.compile(
    r"Delete\s+STA\((?P<sta>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\)(?:,\s*reason:(?P<reason>0x[0-9A-Fa-f]+))?",
    re.IGNORECASE,
)
CFG80211_AP_STA_DEL_RE = re.compile(
    r"(?P<radio>rai?\d+):\s*\(CFG80211_ApStaDel\)\s*STA_DEL\s*\((?P<sta>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\)(?:\s*reason:(?P<reason>0x[0-9A-Fa-f]+))?",
    re.IGNORECASE,
)
SEND_DEAUTH_RE = re.compile(
    r"(?P<radio>rai?\d+):\[send\s+deauth\]\s*TA:\[(?P<ta>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\],\s*RA:\[(?P<ra>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\].*?reason:(?P<reason>\d+),\s*protection=(?P<protection>\d+)",
    re.IGNORECASE,
)
RADIUS_ENTRY_DEL_RE = re.compile(
    r"(?P<radio>rai?\d+):\s*\(CFG80211_ApStaDel\)\s*radius\s+entry\[\d+\]\s+DEL\s*\((?P<sta>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\)",
    re.IGNORECASE,
)
DRIVER_MISSING_ENTRY_RE = re.compile(r"Can't find pEntry in (?P<context>[A-Za-z0-9_]+)", re.IGNORECASE)
STA_JOIN_DETAILS_RE = re.compile(
    r"wevent:\s*STA_JOIN\s+(?P<radio>rai?\d+):(?P<aid>\d+)\s+\[(?P<client_mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\](?:.*?\bwcid[:=](?P<wcid>\d+))?",
    re.IGNORECASE,
)
REASSOC_RESPONSE_RE = re.compile(
    r"(?P<radio>rai?\d+):\s*\[send\s+reassoc_rsp\]\.\s*TA:\[(?P<ta>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\],\s*RA:\[(?P<ra>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\](?:.*?\bstatus[:=](?P<status>\d+))?(?:.*?\baid[:=](?P<aid>\d+))?",
    re.IGNORECASE,
)
ASSOC_REPORT_SUCCESS_RE = re.compile(
    r"\[assoc_report\]\s*(?P<radio>rai?\d+):\[(?P<client_mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\]\s*Success:\s*(?P<status>\d+)(?:.*?\baid[:=](?P<aid>\d+))?(?:.*?\bwcid[:=](?P<wcid>\d+))?(?:.*?\bphy[:=](?P<phy>[A-Za-z0-9._-]+))?(?:.*?\bbw[:=](?P<bandwidth>[A-Za-z0-9._-]+))?(?:.*?\bmcs[:=](?P<mcs>[A-Za-z0-9._-]+))?(?:.*?\bwmm[:=](?P<wmm>[A-Za-z0-9._-]+))?(?:.*?\brrm[:=](?P<rrm>[A-Za-z0-9._-]+))?",
    re.IGNORECASE,
)
MAC_TABLE_INSERT_RE = re.compile(
    r"MacTableInsertEntry\(\):\s*wcid\s*(?P<wcid>\d+)\s*EntryType:(?P<entry_type>\d+)",
    re.IGNORECASE,
)
MAC_TABLE_DELETE_RE = re.compile(
    r"MacTableDeleteEntryWithFlags\(\):\s*wcid\s*(?P<wcid>\d+)",
    re.IGNORECASE,
)
PEER_REASSOC_REQ_RE = re.compile(r"peer_reassoc_req:\s*(?P<duration_usec>\d+)\s*usec", re.IGNORECASE)
QOS_MAP_SUPPORT_RE = re.compile(r"entry\s+wcid\s*(?P<wcid>\d+)\s+QosMapSupport=(?P<qos_map_support>\d+)", re.IGNORECASE)
STATION_IDLE_PROBE_RE = re.compile(
    r"(?P<radio>rai?\d+):\s*Send NULL to STA-MAC\s+(?P<client_mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+idle\((?P<idle_seconds>\d+)\)\s+timeout\((?P<timeout_seconds>\d+)\)",
    re.IGNORECASE,
)
FAST_TRANSITION_ROAM_DETAILS_RE = re.compile(
    r"WPA:\s*Receive\s+FT:\s*(?P<ap_mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+STA\s+Roamed:\s*(?P<client_mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})",
    re.IGNORECASE,
)
WIRELESS_AGG_DNS_TIMEOUT_DETAILS_RE = re.compile(
    r"wireless_agg_stats\.log_sta_anomalies\(\):.*?\bbssid=(?P<bssid>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}).*?\bradio=(?P<radio>[A-Za-z0-9_-]+).*?\bvap=(?P<vap>[A-Za-z0-9_-]+).*?\bsta=(?P<client_mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?:.*?\bsatisfaction_now=(?P<satisfaction_now>-?\d+))?",
    re.IGNORECASE,
)
ACE_REPORTER_SAVE_CONFIG_DETAILS_RE = re.compile(
    r"ace_reporter\.reporter_save_config\(\):\s*(?P<config_key>[^:]+):\s*(?P<config_value>.+)$",
    re.IGNORECASE,
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
    internal_event_ts = extract_internal_event_ts(message)
    internal_event_ts_float = to_float_or_none(internal_event_ts)
    timestamp = f'{data["month"]} {data["day"]} {data["time"]}'
    additional_fields = extract_additional_event_fields(message, event_type)

    if "client_mac" in additional_fields:
        client_mac = additional_fields["client_mac"]
    if "process_name" in additional_fields:
        process_name = additional_fields["process_name"]
    if "process" in additional_fields:
        process = additional_fields["process"]
    if "event_type" in additional_fields:
        event_type = additional_fields["event_type"]
        event_category = classify_event_category(message, process_name, event_type)
    if "ap_mac" in additional_fields:
        ap_mac = additional_fields["ap_mac"]
    if "mac" in additional_fields:
        mac = additional_fields["mac"]
    if "internal_event_ts" in additional_fields:
        internal_event_ts = additional_fields["internal_event_ts"]
    if "internal_event_ts_float" in additional_fields:
        internal_event_ts_float = additional_fields["internal_event_ts_float"]
    else:
        internal_event_ts_float = to_float_or_none(internal_event_ts)
    if "radio" in additional_fields:
        radio = additional_fields["radio"]
    else:
        radio = extract_radio(message)

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
        radio=radio,
        rssi=extract_rssi(message),
        internal_event_ts=internal_event_ts,
        internal_event_ts_float=internal_event_ts_float,
        internal_event_bucket=build_internal_event_bucket(internal_event_ts_float),
        raw_line=stripped_line,
        query=additional_fields.get("query"),
        dns_server=additional_fields.get("dns_server"),
        transaction_id=additional_fields.get("transaction_id"),
        source_port=additional_fields.get("source_port"),
        error_type=additional_fields.get("error_type"),
        drop_caches_value=additional_fields.get("drop_caches_value"),
        bssid=additional_fields.get("bssid"),
        port_secure=additional_fields.get("port_secure"),
        clear_frame=additional_fields.get("clear_frame"),
        dns_queries=additional_fields.get("dns_queries"),
        dns_servers=additional_fields.get("dns_servers"),
        assoc_status=additional_fields.get("assoc_status"),
        tracker_message_type=additional_fields.get("tracker_message_type"),
        eapol_direction=additional_fields.get("eapol_direction"),
        eapol_length=additional_fields.get("eapol_length"),
        eapol_source=additional_fields.get("eapol_source"),
        eapol_message=additional_fields.get("eapol_message"),
        da_mac=additional_fields.get("da_mac"),
        sa_mac=additional_fields.get("sa_mac"),
        reason=additional_fields.get("reason"),
        protection=additional_fields.get("protection"),
        driver_context=additional_fields.get("driver_context"),
        aid=additional_fields.get("aid"),
        wcid=additional_fields.get("wcid"),
        entry_type=additional_fields.get("entry_type"),
        phy=additional_fields.get("phy"),
        bandwidth=additional_fields.get("bandwidth"),
        mcs=additional_fields.get("mcs"),
        wmm=additional_fields.get("wmm"),
        rrm=additional_fields.get("rrm"),
        duration_usec=additional_fields.get("duration_usec"),
        qos_map_support=additional_fields.get("qos_map_support"),
        idle_seconds=additional_fields.get("idle_seconds"),
        timeout_seconds=additional_fields.get("timeout_seconds"),
        vap=additional_fields.get("vap"),
        satisfaction_now=additional_fields.get("satisfaction_now"),
        auth_failures=additional_fields.get("auth_failures"),
        sta_tracker_event_id=additional_fields.get("sta_tracker_event_id"),
        config_key=additional_fields.get("config_key"),
        config_value=additional_fields.get("config_value"),
    )


def parse_file(
    input_path: Path,
    output_path: Path,
    canonical_output_path: Optional[Path] = None,
    parser_report_output_path: Optional[Path] = None,
    quality_report_output_path: Optional[Path] = None,
    unknown_events_output_path: Optional[Path] = None,
    unknown_summary_output_path: Optional[Path] = None,
    unknown_samples_output_path: Optional[Path] = None,
    include_raw_in_canonical_output: bool = False,
    export_parsed_events: bool = True,
    export_all_unknown_events: bool = True,
    max_unknown_events_export: Optional[int] = None,
    max_unknown_samples_per_pattern: int = 3,
) -> None:
    parsed_events = parse_file_to_events(input_path)

    if export_parsed_events:
        with output_path.open("w", encoding="utf-8") as file_out:
            json.dump(parsed_events, file_out, indent=2, ensure_ascii=False)

    print(f"Lette {len(parsed_events)} righe.")
    if export_parsed_events:
        print(f"Output raw scritto in: {output_path}")

    unknown_events = extract_unknown_events(
        parsed_events,
        export_all_unknown_events=export_all_unknown_events,
        max_unknown_events_export=max_unknown_events_export,
    )
    if unknown_events_output_path is not None:
        with unknown_events_output_path.open("w", encoding="utf-8") as file_out:
            json.dump(unknown_events, file_out, indent=2, ensure_ascii=False)
        print(f"Unknown events scritti in: {unknown_events_output_path}")

    unknown_summary, unknown_samples = build_unknown_summary(
        unknown_events,
        max_unknown_samples_per_pattern=max_unknown_samples_per_pattern,
    )
    if unknown_summary_output_path is not None:
        with unknown_summary_output_path.open("w", encoding="utf-8") as file_out:
            json.dump(unknown_summary, file_out, indent=2, ensure_ascii=False)
        print(f"Unknown summary scritto in: {unknown_summary_output_path}")
    if unknown_samples_output_path is not None:
        with unknown_samples_output_path.open("w", encoding="utf-8") as file_out:
            json.dump(unknown_samples, file_out, indent=2, ensure_ascii=False)
        print(f"Unknown samples scritti in: {unknown_samples_output_path}")

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

    parser_report: Optional[dict[str, Any]] = None
    if parser_report_output_path is not None:
        parser_report = build_parser_report(
            parsed_events,
            correlated_payload["canonical_events"],
            unknown_events,
            unknown_summary,
            output_path,
            canonical_output_path,
            unknown_events_output_path,
            unknown_summary_output_path,
            unknown_samples_output_path,
            export_parsed_events=export_parsed_events,
        )
        with parser_report_output_path.open("w", encoding="utf-8") as file_out:
            json.dump(parser_report, file_out, indent=2, ensure_ascii=False)
        print(f"Report parser scritto in: {parser_report_output_path}")

    quality_report = build_quality_report(
        parsed_events,
        correlated_payload["canonical_events"],
        unknown_events,
        unknown_summary,
        parser_report=parser_report,
    )
    if quality_report_output_path is not None:
        with quality_report_output_path.open("w", encoding="utf-8") as file_out:
            json.dump(quality_report, file_out, indent=2, ensure_ascii=False)
        print(f"Quality report scritto in: {quality_report_output_path}")

    print("QUALITY CHECK")
    print(f"- raw events: {quality_report['total_raw_events']}")
    print(f"- parsed events: {quality_report['total_parsed_events']}")
    print(f"- canonical events: {quality_report['total_canonical_events']}")
    print(f"- unknown events exported: {quality_report['unknown_events_exported']}")
    print(f"- unknown summary count: {quality_report['unknown_summary_count']}")
    print(f"- unknown counts consistent: {quality_report['unknown_files_are_consistent']}")
    print(f"- canonical unknown sequences: {quality_report['canonical_unknown_sequences']}")
    print(f"- wifi security sequences: {quality_report['canonical_wifi_security_sequences']}")
    print(
        "- known event types inside unknown sequences: "
        f"{quality_report['canonical_unknown_sequences_with_known_event_types']}"
    )


def parse_file_with_canonical_events(input_path: Path, output_path: Path) -> None:
    parsed_events = parse_file_to_events(input_path)
    correlated_payload = build_canonical_events(parsed_events)

    with output_path.open("w", encoding="utf-8") as file_out:
        json.dump(correlated_payload, file_out, indent=2, ensure_ascii=False)

    print(f"Lette {len(parsed_events)} righe.")
    print(f"Eventi canonici prodotti: {len(correlated_payload['canonical_events'])}")
    print(f"Output scritto in: {output_path}")


def build_parser_report(
    parsed_events: list[dict[str, Any]],
    canonical_events: list[dict[str, Any]],
    unknown_events: list[dict[str, Any]],
    unknown_summary: dict[str, Any],
    parsed_output_path: Path,
    canonical_output_path: Optional[Path] = None,
    unknown_events_output_path: Optional[Path] = None,
    unknown_summary_output_path: Optional[Path] = None,
    unknown_samples_output_path: Optional[Path] = None,
    export_parsed_events: bool = True,
) -> dict[str, Any]:
    parse_status_counts = Counter((event.get("parse_status") or "unknown") for event in parsed_events)
    event_type_counts = Counter((event.get("event_type") or "unknown") for event in parsed_events)
    event_category_counts = Counter((event.get("event_category") or "unknown") for event in parsed_events)
    canonical_event_type_counts = Counter(
        (event.get("canonical_event_type") or "unknown") for event in canonical_events
    )

    client_mac_counts = Counter(event.get("client_mac") for event in parsed_events if event.get("client_mac"))
    source_ip_counts = Counter(event.get("source_ip") for event in parsed_events if event.get("source_ip"))
    duplicate_candidates = sum(1 for event in parsed_events if event.get("is_duplicate_candidate"))
    fine_duplicate_candidates = sum(1 for event in parsed_events if event.get("is_fine_duplicate_candidate"))
    unknown_event_count_total = sum(1 for event in parsed_events if is_unknown_event(event))
    unknown_events_full = extract_unknown_events(parsed_events, export_all_unknown_events=True)
    unknown_by_source_ip = Counter((event.get("source_ip") or "unknown") for event in unknown_events_full)
    unknown_by_process_name = Counter((event.get("process_name") or "unknown") for event in unknown_events_full)
    unknown_by_event_category = Counter((event.get("event_category") or "unknown") for event in unknown_events_full)
    unknown_with_client_mac_count = sum(1 for event in unknown_events_full if event.get("client_mac"))
    unknown_with_radio_count = sum(1 for event in unknown_events_full if event.get("radio"))

    return {
        "total_raw_events": len(parsed_events),
        "total_canonical_events": len(canonical_events),
        "parse_status_counts": dict(parse_status_counts),
        "event_type_counts": dict(event_type_counts),
        "event_category_counts": dict(event_category_counts),
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
        "unknown_event_count": unknown_event_count_total,
        "unknown_event_count_total": unknown_event_count_total,
        "unknown_events_exported_count": len(unknown_events),
        "unknown_exported_count": len(unknown_events),
        "unknown_unique_pattern_count": int(unknown_summary.get("unique_pattern_count", 0)),
        "unknown_top_patterns": unknown_summary.get("top_patterns", []),
        "unknown_by_source_ip": dict(unknown_by_source_ip),
        "unknown_by_process_name": dict(unknown_by_process_name),
        "unknown_by_event_category": dict(unknown_by_event_category),
        "unknown_with_client_mac_count": unknown_with_client_mac_count,
        "unknown_without_client_mac_count": len(unknown_events_full) - unknown_with_client_mac_count,
        "unknown_with_radio_count": unknown_with_radio_count,
        "unknown_without_radio_count": len(unknown_events_full) - unknown_with_radio_count,
        "unknown_reason": {
            "event_type_null_or_empty_count": sum(
                1 for event in parsed_events if is_unknown_event_type(event.get("event_type"))
            ),
            "event_category_null_or_empty_count": sum(
                1 for event in parsed_events if is_unknown_event_category(event.get("event_category"))
            ),
            "event_type_literal_unknown_count": sum(
                1
                for event in parsed_events
                if isinstance(event.get("event_type"), str) and event.get("event_type", "").strip().lower() == "unknown"
            ),
            "event_category_literal_unknown_count": sum(
                1
                for event in parsed_events
                if isinstance(event.get("event_category"), str)
                and event.get("event_category", "").strip().lower() == "unknown"
            ),
        },
        "generated_files": {
            "parsed_events": str(parsed_output_path) if export_parsed_events else None,
            "canonical_events": str(canonical_output_path) if canonical_output_path is not None else None,
            "unknown_events": str(unknown_events_output_path) if unknown_events_output_path is not None else None,
            "unknown_summary": str(unknown_summary_output_path) if unknown_summary_output_path is not None else None,
            "unknown_samples": str(unknown_samples_output_path) if unknown_samples_output_path is not None else None,
        },
        "events_without_client_mac": sum(1 for event in parsed_events if not event.get("client_mac")),
        "events_without_radio": sum(1 for event in parsed_events if not event.get("radio")),
        "top_client_mac_by_event_count": [
            {"client_mac": key, "event_count": count} for key, count in client_mac_counts.most_common(10)
        ],
        "top_source_ip_by_event_count": [
            {"source_ip": key, "event_count": count} for key, count in source_ip_counts.most_common(10)
        ],
    }


def build_quality_report(
    parsed_events: list[dict[str, Any]],
    canonical_events: list[dict[str, Any]],
    unknown_events: list[dict[str, Any]],
    unknown_summary: dict[str, Any],
    parser_report: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    unknown_summary_count = int(unknown_summary.get("total_unknown_events", 0))
    parser_report_unknown_count = int(parser_report.get("unknown_event_count", 0)) if parser_report else unknown_summary_count
    unknown_files_are_consistent = (
        len(unknown_events) == unknown_summary_count == parser_report_unknown_count
    )

    unknown_sequences = [
        event for event in canonical_events if (event.get("canonical_event_type") or "") == "wifi_unknown_sequence"
    ]
    wifi_security_sequences = [
        event for event in canonical_events if (event.get("canonical_event_type") or "") == "wifi_security_sequence"
    ]
    unknown_sequences_with_known_types = []
    known_types_counter: Counter[str] = Counter()

    for canonical_event in unknown_sequences:
        known_types = [
            event_type for event_type in canonical_event.get("event_types_seen", []) if not is_unknown_event_type(event_type)
        ]
        if known_types:
            unknown_sequences_with_known_types.append(canonical_event)
            known_types_counter.update(known_types)

    return {
        "total_raw_events": len(parsed_events),
        "total_parsed_events": sum(1 for event in parsed_events if (event.get("parse_status") or "") == "parsed"),
        "total_canonical_events": len(canonical_events),
        "unknown_events_exported": len(unknown_events),
        "unknown_unique_patterns": int(unknown_summary.get("unique_pattern_count", 0)),
        "unknown_summary_count": unknown_summary_count,
        "parser_report_unknown_count": parser_report_unknown_count,
        "unknown_files_are_consistent": unknown_files_are_consistent,
        "canonical_unknown_sequences": len(unknown_sequences),
        "canonical_wifi_security_sequences": len(wifi_security_sequences),
        "canonical_unknown_sequences_truly_unknown": len(unknown_sequences) - len(unknown_sequences_with_known_types),
        "canonical_unknown_sequences_with_known_event_types": len(unknown_sequences_with_known_types),
        "known_event_types_inside_unknown_sequences": dict(known_types_counter),
        "top_unknown_patterns": unknown_summary.get("top_patterns", []),
    }


def is_unknown_event_type(event_type: Any) -> bool:
    if event_type is None:
        return True
    if isinstance(event_type, str) and event_type.strip().lower() in {"", "unknown"}:
        return True
    return False


def is_unknown_event_category(event_category: Any) -> bool:
    if event_category is None:
        return True
    if isinstance(event_category, str) and event_category.strip().lower() in {"", "unknown"}:
        return True
    return False


def is_known_event_type_exempt_from_unknown(event_type: Any) -> bool:
    if not isinstance(event_type, str):
        return False
    normalized = event_type.strip().lower()
    if not normalized or normalized == "unknown":
        return False
    if normalized in {
        "dns_timeout",
        "device_config_report",
        "system_cache_drop",
        "fast_transition_roam",
        "assoc_tracker_failure",
        "wifi_scan_error",
    }:
        return True
    if normalized.startswith("eapol") or normalized.startswith("eap_"):
        return True
    if normalized.startswith("driver_"):
        return True
    return False


def is_unknown_event(event: dict[str, Any]) -> bool:
    event_type = event.get("event_type")
    event_category = event.get("event_category")
    unknown_by_type = is_unknown_event_type(event_type)
    unknown_by_category = is_unknown_event_category(event_category)

    if not (unknown_by_type or unknown_by_category):
        return False
    if is_known_event_type_exempt_from_unknown(event_type):
        return False
    return True


def extract_unknown_events(
    parsed_events: list[dict[str, Any]],
    export_all_unknown_events: bool = True,
    max_unknown_events_export: Optional[int] = None,
) -> list[dict[str, Any]]:
    unknown_events: list[dict[str, Any]] = []
    for event in parsed_events:
        if not is_unknown_event(event):
            continue
        unknown_record = dict(event)
        unknown_record["unknown_pattern"] = normalize_unknown_message_pattern(event.get("raw_message") or "")
        unknown_events.append({field: unknown_record.get(field) for field in UNKNOWN_EVENT_FIELDS})
        if not export_all_unknown_events and max_unknown_events_export is not None and len(unknown_events) >= max_unknown_events_export:
            break
    return unknown_events


def build_unknown_summary(
    unknown_events: list[dict[str, Any]],
    max_unknown_samples_per_pattern: int = 3,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    count_by_source_ip = Counter((event.get("source_ip") or "unknown") for event in unknown_events)
    count_by_host = Counter((event.get("host") or "unknown") for event in unknown_events)
    count_by_facility = Counter((event.get("facility") or "unknown") for event in unknown_events)
    count_by_severity = Counter((event.get("severity") or "unknown") for event in unknown_events)
    count_by_process_name = Counter((event.get("process_name") or "unknown") for event in unknown_events)
    count_by_event_category = Counter((event.get("event_category") or "unknown") for event in unknown_events)

    pattern_to_events: dict[str, list[dict[str, Any]]] = {}
    for event in unknown_events:
        normalized_pattern = event.get("unknown_pattern") or normalize_unknown_message_pattern(event.get("raw_message") or "")
        pattern_to_events.setdefault(normalized_pattern, []).append(event)

    sorted_patterns = sorted(pattern_to_events.items(), key=lambda item: len(item[1]), reverse=True)
    top_raw_message_patterns = []
    for pattern, pattern_events in sorted_patterns[:20]:
        top_raw_message_patterns.append(
            {
                "pattern": pattern,
                "count": len(pattern_events),
                "sample_raw_message": pattern_events[0].get("raw_message"),
                "sample_line_numbers": [event.get("line_number") for event in pattern_events[:5]],
            }
        )

    samples = build_unknown_samples(sorted_patterns, max_unknown_samples_per_pattern=max_unknown_samples_per_pattern)

    summary = {
        "total_unknown_events": len(unknown_events),
        "unique_pattern_count": len(pattern_to_events),
        "count_by_source_ip": dict(count_by_source_ip),
        "count_by_host": dict(count_by_host),
        "count_by_facility": dict(count_by_facility),
        "count_by_severity": dict(count_by_severity),
        "count_by_process_name": dict(count_by_process_name),
        "count_by_event_category": dict(count_by_event_category),
        "top_raw_message_patterns": top_raw_message_patterns,
        "top_patterns": top_raw_message_patterns[:10],
    }
    return summary, samples


def normalize_unknown_message_pattern(raw_message: str) -> str:
    normalized = raw_message
    normalized = MAC_PATTERN_RE.sub("<MAC>", normalized)
    normalized = IP_PATTERN_RE.sub("<IP>", normalized)
    normalized = KERNEL_TS_PATTERN_RE.sub("[<KERNEL_TS>]", normalized)
    normalized = LONG_NUM_PATTERN_RE.sub("<NUM>", normalized)
    return normalized


def select_representative_unknown_samples(
    sorted_patterns: list[tuple[str, list[dict[str, Any]]]],
    max_samples: int,
) -> list[dict[str, Any]]:
    if max_samples <= 0:
        return []

    samples: list[dict[str, Any]] = []
    pattern_indexes = [0] * len(sorted_patterns)
    seen_line_numbers: set[int] = set()

    while len(samples) < max_samples:
        added_this_round = False
        for pattern_idx, (_, pattern_events) in enumerate(sorted_patterns):
            current_index = pattern_indexes[pattern_idx]
            if current_index >= len(pattern_events):
                continue

            event = pattern_events[current_index]
            pattern_indexes[pattern_idx] += 1
            line_number = event.get("line_number")
            if line_number is not None and line_number in seen_line_numbers:
                continue

            if line_number is not None:
                seen_line_numbers.add(line_number)
            samples.append(event)
            added_this_round = True
            if len(samples) >= max_samples:
                break

        if not added_this_round:
            break

    return samples


def build_unknown_samples(
    sorted_patterns: list[tuple[str, list[dict[str, Any]]]],
    max_unknown_samples_per_pattern: int,
) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for pattern, pattern_events in sorted_patterns:
        for event in pattern_events[:max_unknown_samples_per_pattern]:
            samples.append(
                {
                    "pattern": pattern,
                    "line_number": event.get("line_number"),
                    "source_ip": event.get("source_ip"),
                    "process_name": event.get("process_name"),
                    "event_category": event.get("event_category"),
                    "raw_message": event.get("raw_message"),
                    "client_mac": event.get("client_mac"),
                    "radio": event.get("radio"),
                }
            )
    return samples


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


def extract_additional_event_fields(message: str, event_type: Optional[str]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    tracker_payload = extract_sta_assoc_tracker_payload(message)

    if tracker_payload and str(tracker_payload.get("event_type") or "").strip().lower() == "dns timeout":
        queries, servers = extract_indexed_tracker_values(tracker_payload)
        client_mac = to_lower_or_none(tracker_payload.get("mac"))
        radio = to_lower_or_none(tracker_payload.get("vap"))
        assoc_status = tracker_payload.get("assoc_status")
        if assoc_status is not None:
            assoc_status = str(assoc_status)
        fields.update(
            {
                "event_type": "dns_timeout",
                "client_mac": client_mac,
                "mac": client_mac,
                "radio": radio,
                "process_name": "stahtd",
                "event_category": "network_dns",
                "dns_queries": queries,
                "dns_servers": servers,
                "assoc_status": assoc_status,
                "tracker_message_type": tracker_payload.get("message_type"),
            }
        )
    if tracker_payload and str(tracker_payload.get("event_type") or "").strip().lower() == "failure":
        client_mac = to_lower_or_none(tracker_payload.get("mac"))
        radio = to_lower_or_none(tracker_payload.get("vap"))
        internal_event_ts = tracker_payload.get("auth_ts")
        internal_event_ts_str = str(internal_event_ts) if internal_event_ts is not None else None
        fields.update(
            {
                "event_type": "assoc_tracker_failure",
                "client_mac": client_mac,
                "mac": client_mac,
                "radio": radio,
                "process_name": "stahtd",
                "event_category": "wifi_association",
                "internal_event_ts": internal_event_ts_str,
                "internal_event_ts_float": to_float_or_none(internal_event_ts_str),
                "assoc_status": str(tracker_payload.get("assoc_status")) if tracker_payload.get("assoc_status") is not None else None,
                "auth_failures": str(tracker_payload.get("auth_failures")) if tracker_payload.get("auth_failures") is not None else None,
                "sta_tracker_event_id": str(tracker_payload.get("event_id")) if tracker_payload.get("event_id") is not None else None,
                "tracker_message_type": tracker_payload.get("message_type"),
            }
        )

    if event_type == "dns_timeout" and not tracker_payload:
        match = DNS_TIMEOUT_DETAILS_RE.search(message)
        if match:
            source_port = to_int_or_none(match.group("source_port"))
            client_mac = match.group("client_mac")
            fields.update(
                {
                    "client_mac": client_mac.lower() if client_mac else None,
                    "query": match.group("query"),
                    "dns_server": match.group("dns_server"),
                    "transaction_id": match.group("transaction_id"),
                    "source_port": source_port,
                }
            )

    if event_type == "wifi_scan_error":
        fields["error_type"] = "invalid_bss_entry"

    if event_type == "system_cache_drop":
        match = DROP_CACHES_DETAILS_RE.search(message)
        if match:
            process_name = match.group("process_name")
            pid = to_int_or_none(match.group("pid"))
            fields.update(
                {
                    "process_name": process_name,
                    "process": f"{process_name}({pid})" if pid is not None else process_name,
                    "drop_caches_value": to_int_or_none(match.group("drop_value")),
                }
            )

    if event_type == "cfg80211_station_delete_start":
        match = CFG80211_STA_DEL_BSSID_RE.search(message)
        if match:
            fields["bssid"] = match.group("bssid").lower()

    if event_type == "eap_packet":
        match = EAP_PACKET_DETAILS_RE.search(message)
        if match:
            fields.update(
                {
                    "port_secure": to_int_or_none(match.group("port_secure")),
                    "clear_frame": to_int_or_none(match.group("clear_frame")),
                }
            )

    if event_type == "reassoc_request":
        match = REASSOC_REQ_RE.search(message)
        if match:
            client_mac = match.group("ta").lower()
            ap_mac = match.group("ra").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "ap_mac": ap_mac,
                    "radio": match.group("radio").lower(),
                }
            )
    if event_type == "fast_transition_roam":
        match = FAST_TRANSITION_ROAM_DETAILS_RE.search(message)
        if match:
            client_mac = match.group("client_mac").lower()
            fields.update(
                {
                    "ap_mac": match.group("ap_mac").lower(),
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "radio": None,
                }
            )

    if event_type == "dns_timeout":
        match = WIRELESS_AGG_DNS_TIMEOUT_DETAILS_RE.search(message)
        if match:
            client_mac = match.group("client_mac").lower()
            fields.update(
                {
                    "ap_mac": match.group("bssid").lower(),
                    "bssid": match.group("bssid").lower(),
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "radio": to_lower_or_none(match.group("radio")),
                    "vap": to_lower_or_none(match.group("vap")),
                    "satisfaction_now": to_int_or_none(match.group("satisfaction_now")),
                }
            )

    if event_type == "device_config_report":
        match = ACE_REPORTER_SAVE_CONFIG_DETAILS_RE.search(message)
        if match:
            fields.update(
                {
                    "process_name": "mcad",
                    "config_key": match.group("config_key").strip(),
                    "config_value": match.group("config_value").strip(),
                }
            )

    if event_type == "station_join":
        match = STA_JOIN_DETAILS_RE.search(message)
        if match:
            client_mac = match.group("client_mac").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "radio": match.group("radio").lower(),
                    "aid": to_int_or_none(match.group("aid")),
                    "wcid": to_int_or_none(match.group("wcid")),
                }
            )

    if event_type == "reassoc_response":
        match = REASSOC_RESPONSE_RE.search(message)
        if match:
            client_mac = match.group("ra").lower()
            ap_mac = match.group("ta").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "ap_mac": ap_mac,
                    "radio": match.group("radio").lower(),
                    "assoc_status": match.group("status"),
                    "aid": to_int_or_none(match.group("aid")),
                }
            )

    if event_type == "assoc_success":
        match = ASSOC_REPORT_SUCCESS_RE.search(message)
        if match:
            client_mac = match.group("client_mac").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "radio": match.group("radio").lower(),
                    "assoc_status": match.group("status"),
                    "aid": to_int_or_none(match.group("aid")),
                    "wcid": to_int_or_none(match.group("wcid")),
                    "phy": match.group("phy"),
                    "bandwidth": match.group("bandwidth"),
                    "mcs": match.group("mcs"),
                    "wmm": match.group("wmm"),
                    "rrm": match.group("rrm"),
                }
            )

    if event_type == "station_table_insert":
        match = MAC_TABLE_INSERT_RE.search(message)
        if match:
            fields.update(
                {
                    "wcid": to_int_or_none(match.group("wcid")),
                    "entry_type": to_int_or_none(match.group("entry_type")),
                }
            )

    if event_type == "station_table_delete":
        match = MAC_TABLE_DELETE_RE.search(message)
        if match:
            fields["wcid"] = to_int_or_none(match.group("wcid"))

    if event_type == "reassoc_processing_time":
        match = PEER_REASSOC_REQ_RE.search(message)
        if match:
            fields["duration_usec"] = to_int_or_none(match.group("duration_usec"))

    if event_type == "station_qos_map_support":
        match = QOS_MAP_SUPPORT_RE.search(message)
        if match:
            fields.update(
                {
                    "wcid": to_int_or_none(match.group("wcid")),
                    "qos_map_support": to_int_or_none(match.group("qos_map_support")),
                }
            )

    if event_type == "station_idle_probe":
        match = STATION_IDLE_PROBE_RE.search(message)
        if match:
            client_mac = match.group("client_mac").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "radio": match.group("radio").lower(),
                    "idle_seconds": to_int_or_none(match.group("idle_seconds")),
                    "timeout_seconds": to_int_or_none(match.group("timeout_seconds")),
                }
            )

    if event_type == "eapol_packet":
        match = EAPOL_PACKET_DETAILS_RE.search(message)
        if match:
            fields.update(
                {
                    "eapol_direction": match.group("direction").lower(),
                    "eapol_length": to_int_or_none(match.group("length")),
                    "eapol_source": match.group("source"),
                }
            )

    if event_type == "eapol_key":
        match = EAPOL_KEY_DETAILS_RE.search(message)
        if match:
            direction = match.group("direction").lower()
            da_mac = match.group("da").lower()
            sa_mac = match.group("sa").lower()
            if direction == "send":
                client_mac = da_mac
                ap_mac = sa_mac
            else:
                client_mac = sa_mac
                ap_mac = da_mac
            fields.update(
                {
                    "radio": match.group("radio").lower(),
                    "eapol_direction": direction,
                    "eapol_message": match.group("message").upper(),
                    "da_mac": da_mac,
                    "sa_mac": sa_mac,
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "ap_mac": ap_mac,
                    "eapol_length": to_int_or_none(match.group("length")),
                }
            )

    if event_type in {"wifi_key_add", "wifi_key_delete"}:
        match = KEY_ACTION_STA_RE.search(message)
        if match:
            client_mac = match.group("sta").lower()
            fields.update({"client_mac": client_mac, "mac": client_mac})

    if event_type == "station_delete":
        match = DELETE_STA_REASON_RE.search(message)
        if match:
            client_mac = match.group("sta").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "reason": match.group("reason"),
                }
            )

    if event_type == "cfg80211_station_delete":
        match = CFG80211_AP_STA_DEL_RE.search(message)
        if match:
            client_mac = match.group("sta").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "radio": match.group("radio").lower(),
                    "reason": match.group("reason"),
                }
            )

    if event_type == "deauth_sent":
        match = SEND_DEAUTH_RE.search(message)
        if match:
            client_mac = match.group("ra").lower()
            ap_mac = match.group("ta").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "ap_mac": ap_mac,
                    "radio": match.group("radio").lower(),
                    "reason": match.group("reason"),
                    "protection": to_int_or_none(match.group("protection")),
                }
            )

    if event_type == "radius_entry_delete":
        match = RADIUS_ENTRY_DEL_RE.search(message)
        if match:
            client_mac = match.group("sta").lower()
            fields.update(
                {
                    "client_mac": client_mac,
                    "mac": client_mac,
                    "radio": match.group("radio").lower(),
                }
            )

    if event_type == "driver_missing_station_entry":
        match = DRIVER_MISSING_ENTRY_RE.search(message)
        if match:
            fields["driver_context"] = match.group("context")

    return fields


def extract_sta_assoc_tracker_payload(message: str) -> Optional[dict[str, Any]]:
    match = STA_ASSOC_TRACKER_JSON_RE.search(message)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def extract_indexed_tracker_values(payload: dict[str, Any]) -> tuple[list[str], list[str]]:
    queries: list[tuple[int, str]] = []
    servers: list[tuple[int, str]] = []
    for key, value in payload.items():
        if value is None:
            continue
        q_match = re.match(r"query_(\d+)$", key)
        if q_match:
            queries.append((int(q_match.group(1)), str(value)))
            continue
        s_match = re.match(r"query_server_(\d+)$", key)
        if s_match:
            servers.append((int(s_match.group(1)), str(value)))
    queries.sort(key=lambda item: item[0])
    servers.sort(key=lambda item: item[0])
    return [value for _, value in queries], [value for _, value in servers]


def to_int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def to_lower_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value).lower()
